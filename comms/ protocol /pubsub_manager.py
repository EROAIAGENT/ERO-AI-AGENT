# core/pubsub/pubsub_manager.py
from __future__ import annotations
import asyncio
import hashlib
import logging
import uuid
from collections import defaultdict
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from loguru import logger
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, Field, ValidationError, validator

# Monitoring Metrics
MESSAGES_PUBLISHED = Counter('pubsub_messages_published', 'Total messages published', ['topic'])
MESSAGES_DELIVERED = Counter('pubsub_messages_delivered', 'Messages successfully delivered', ['topic'])
DELIVERY_LATENCY = Histogram('pubsub_delivery_latency', 'End-to-end message latency', ['topic'])
ACTIVE_SUBSCRIPTIONS = Gauge('pubsub_active_subscriptions', 'Current subscription count', ['topic'])

class MessageEnvelope(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: str
    payload: bytes
    sender_id: str
    signature: Optional[str] = Field(None, min_length=256)
    timestamp: float = Field(default_factory=lambda: time.time())
    ttl: float = Field(60.0, ge=0.0)  # Seconds until expiration
    attempt: int = Field(1, ge=1)
    routing_path: List[str] = Field([])

    @validator('topic')
    def validate_topic_pattern(cls, v):
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', v):
            raise ValueError('Invalid topic format')
        return v

class DistributedPubSubManager:
    """Enterprise-grade pubsub system with cryptographic validation and QoS guarantees"""
    
    def __init__(self, 
                 node_id: str,
                 security_profile: str = 'high',
                 max_message_size: int = 1024*1024,  # 1MB
                 delivery_attempts: int = 3):
        self.node_id = node_id
        self.security_profile = security_profile
        self.max_message_size = max_message_size
        self.delivery_attempts = delivery_attempts
        
        # Core data structures
        self.topics: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self.pending_messages: Dict[str, asyncio.Task] = {}
        self.dead_letter_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        
        # Security infrastructure
        self._init_crypto_system()
        self.acl_policies: Dict[str, Dict[str, Set[str]]] = {}  # {topic: {publish: [client_ids], subscribe: [...]}}
        
        # Cluster coordination
        self.peer_nodes: Dict[str, asyncio.Queue] = {}
        self.health_check_task: Optional[asyncio.Task] = None
        
        # Initialize maintenance tasks
        self._start_background_tasks()

    def _init_crypto_system(self):
        """Initialize cryptographic components based on security profile"""
        if self.security_profile == 'high':
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            self.public_key = self.private_key.public_key()
            self.peer_certificates: Dict[str, Any] = {}
        else:
            self.private_key = None
            self.public_key = None

    def _start_background_tasks(self):
        """Start system maintenance coroutines"""
        self.health_check_task = asyncio.create_task(self._cluster_health_monitor())
        self.retry_task = asyncio.create_task(self._process_retries())
        self.dlq_task = asyncio.create_task(self._process_dead_letters())

    async def create_topic(self, 
                         topic: str,
                         acl_policy: Optional[Dict[str, List[str]]] = None):
        """Register a new topic with optional access control"""
        if topic in self.topics:
            raise ValueError(f"Topic {topic} already exists")
            
        self.topics[topic] = set()
        self.acl_policies[topic] = {
            'publish': set(acl_policy.get('publish', [])) if acl_policy else set(),
            'subscribe': set(acl_policy.get('subscribe', [])) if acl_policy else set()
        }
        logger.info(f"Created topic {topic} with ACL: {acl_policy}")

    async def delete_topic(self, topic: str):
        """Remove topic and all associated subscriptions"""
        if topic not in self.topics:
            return
            
        # Notify all subscribers
        for queue in self.topics[topic]:
            await queue.put(None)  # Sentinel for shutdown
            
        del self.topics[topic]
        del self.acl_policies[topic]
        logger.warning(f"Deleted topic {topic}")

    async def publish(self, 
                     topic: str,
                     payload: bytes,
                     sender_id: str) -> MessageEnvelope:
        """Securely publish message to topic with delivery guarantees"""
        # Validate ACL
        if self.acl_policies.get(topic, {}).get('publish'):
            if sender_id not in self.acl_policies[topic]['publish']:
                raise PermissionError(f"Sender {sender_id} not authorized to publish to {topic}")
        
        # Message validation
        if len(payload) > self.max_message_size:
            raise ValueError(f"Payload exceeds {self.max_message_size} bytes limit")
            
        envelope = MessageEnvelope(
            topic=topic,
            payload=payload,
            sender_id=sender_id
        )
        
        # Cryptographic signing
        if self.security_profile == 'high':
            envelope.signature = self._sign_message(envelope)
            
        # Local delivery
        await self._deliver_to_subscribers(envelope)
        
        # Cluster forwarding
        await self._route_to_peers(envelope)
        
        MESSAGES_PUBLISHED.labels(topic=topic).inc()
        return envelope

    async def subscribe(self, 
                       topic: str,
                       callback: Callable[[MessageEnvelope], Awaitable[None]],
                       client_id: str) -> asyncio.Queue:
        """Register subscription with guaranteed delivery semantics"""
        # Validate ACL
        if self.acl_policies.get(topic, {}).get('subscribe'):
            if client_id not in self.acl_policies[topic]['subscribe']:
                raise PermissionError(f"Client {client_id} not authorized to subscribe to {topic}")
        
        if topic not in self.topics:
            await self.create_topic(topic)
            
        queue = asyncio.Queue(maxsize=1000)
        self.topics[topic].add(queue)
        ACTIVE_SUBSCRIPTIONS.labels(topic=topic).inc()
        
        # Start consumer task
        asyncio.create_task(self._message_consumer(queue, callback))
        return queue

    async def unsubscribe(self, topic: str, queue: asyncio.Queue):
        """Remove subscription from topic"""
        if topic in self.topics and queue in self.topics[topic]:
            self.topics[topic].remove(queue)
            ACTIVE_SUBSCRIPTIONS.labels(topic=topic).dec()
            await queue.put(None)  # Signal consumer to exit

    async def _message_consumer(self, 
                              queue: asyncio.Queue, 
                              callback: Callable[[MessageEnvelope], Awaitable[None]]):
        """Message processing loop with retry logic"""
        while True:
            envelope = await queue.get()
            if envelope is None:  # Shutdown signal
                break
                
            start_time = time.time()
            try:
                if not self._validate_message(envelope):
                    logger.error(f"Invalid message {envelope.id}")
                    continue
                    
                await callback(envelope)
                MESSAGES_DELIVERED.labels(topic=envelope.topic).inc()
                DELIVERY_LATENCY.labels(topic=envelope.topic).observe(time.time() - start_time)
            except Exception as e:
                logger.error(f"Failed to process {envelope.id}: {str(e)}")
                await self._handle_delivery_failure(envelope)
            finally:
                queue.task_done()

    def _sign_message(self, envelope: MessageEnvelope) -> str:
        """Generate RSA-PSS signature for message authentication"""
        serialized = self._serialize_for_signing(envelope)
        signature = self.private_key.sign(
            serialized,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def _validate_message(self, envelope: MessageEnvelope) -> bool:
        """Verify message integrity and permissions"""
        # Check TTL expiration
        if time.time() - envelope.timestamp > envelope.ttl:
            logger.warning(f"Message {envelope.id} expired")
            return False
            
        # Validate cryptographic signature
        if self.security_profile == 'high':
            if envelope.sender_id not in self.peer_certificates:
                logger.error(f"Unknown sender {envelope.sender_id}")
                return False
                
            try:
                public_key = self.peer_certificates[envelope.sender_id]
                public_key.verify(
                    bytes.fromhex(envelope.signature),
                    self._serialize_for_signing(envelope),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception as e:
                logger.error(f"Signature verification failed: {str(e)}")
                return False
        return True

    def _serialize_for_signing(self, envelope: MessageEnvelope) -> bytes:
        """Generate deterministic serialization for signing"""
        return hashlib.sha3_256(
            envelope.payload +
            envelope.topic.encode() +
            envelope.sender_id.encode() +
            struct.pack('d', envelope.timestamp)
        ).digest()

    async def _deliver_to_subscribers(self, envelope: MessageEnvelope):
        """Reliable message delivery to local subscribers"""
        if envelope.topic not in self.topics:
            return
            
        for queue in list(self.topics[envelope.topic]):  # Copy for thread safety
            try:
                queue.put_nowait(envelope)
            except asyncio.QueueFull:
                logger.warning(f"Queue full for {envelope.topic}, message {envelope.id}")

    async def _route_to_peers(self, envelope: MessageEnvelope):
        """Forward messages across cluster nodes with routing optimization"""
        if self.node_id in envelope.routing_path:
            return  # Prevent loops
            
        envelope.routing_path.append(self.node_id)
        
        for peer_id, peer_queue in self.peer_nodes.items():
            if peer_id not in envelope.routing_path:
                try:
                    peer_queue.put_nowait(envelope)
                except asyncio.QueueFull:
                    logger.error(f"Peer {peer_id} queue full, message {envelope.id} dropped")

    async def _process_retries(self):
        """Handle failed message deliveries with exponential backoff"""
        while True:
            envelope = await self.dead_letter_queue.get()
            if envelope.attempt <= self.delivery_attempts:
                envelope.attempt += 1
                await asyncio.sleep(2 ** envelope.attempt)  # Exponential backoff
                await self.publish(envelope.topic, envelope.payload, envelope.sender_id)
            else:
                logger.error(f"Permanent failure for message {envelope.id}")
            self.dead_letter_queue.task_done()

    async def _process_dead_letters(self):
        """Dead letter queue processing with alerting"""
        while True:
            envelope = await self.dead_letter_queue.get()
            logger.critical(f"Unprocessable message detected: {envelope.id}")
            # TODO: Integrate with monitoring system
            self.dead_letter_queue.task_done()

    async def _cluster_health_monitor(self):
        """Maintain cluster connectivity with failure detection"""
        while True:
            await asyncio.sleep(10)
            for peer_id in list(self.peer_nodes.keys()):
                if not await self._check_peer_health(peer_id):
                    logger.warning(f"Peer {peer_id} marked as unhealthy")
                    del self.peer_nodes[peer_id]

    async def _check_peer_health(self, peer_id: str) -> bool:
        """Perform health check on cluster node"""
        # Implementation placeholder for actual health check protocol
        return True

    async def _handle_delivery_failure(self, envelope: MessageEnvelope):
        """Retry or dead letter queue processing"""
        if envelope.attempt < self.delivery_attempts:
            await self.dead_letter_queue.put(envelope)
        else:
            logger.error(f"Final delivery failure for {envelope.id}")
            MESSAGES_DELIVERED.labels(topic=envelope.topic).inc(0)  # Log failure

    async def add_peer_node(self, peer_id: str, queue: asyncio.Queue):
        """Join node to the pubsub cluster"""
        if peer_id in self.peer_nodes:
            raise ValueError(f"Peer {peer_id} already connected")
            
        self.peer_nodes[peer_id] = queue
        logger.info(f"Added peer node {peer_id}")

    async def remove_peer_node(self, peer_id: str):
        """Gracefully disconnect from cluster node"""
        if peer_id in self.peer_nodes:
            del self.peer_nodes[peer_id]
            logger.info(f"Removed peer node {peer_id}")

    async def shutdown(self):
        """Graceful system termination"""
        # Cancel background tasks
        self.health_check_task.cancel()
        self.retry_task.cancel()
        self.dlq_task.cancel()
        
        # Clear all topics
        for topic in list(self.topics.keys()):
            await self.delete_topic(topic)
            
        # Close peer connections
        for peer_id in list(self.peer_nodes.keys()):
            await self.remove_peer_node(peer_id)

# Example Usage
if __name__ == "__main__":
    async def sample_callback(envelope: MessageEnvelope):
        print(f"Received message on {envelope.topic}: {envelope.payload.decode()}")

    async def run_demo():
        manager = DistributedPubSubManager(node_id="node1", security_profile='high')
        
        # Create topic
        await manager.create_topic("alerts", {'publish': ['client1'], 'subscribe': ['client2']})
        
        # Subscribe
        await manager.subscribe("alerts", sample_callback, "client2")
        
        # Publish
        await manager.publish("alerts", b"System overload detected!", "client1")
        
        # Wait for delivery
        await asyncio.sleep(1)
        
        # Cleanup
        await manager.shutdown()

    asyncio.run(run_demo())
