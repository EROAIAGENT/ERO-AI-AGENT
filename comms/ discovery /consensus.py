# core/consensus/consensus.py
from __future__ import annotations
import asyncio
import hashlib
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from loguru import logger
from pydantic import BaseModel, ValidationError, validator

class ConsensusError(Exception):
    """Critical failure in consensus process"""

class ByzantineBehaviorDetected(ConsensusError):
    """Evidence of malicious node behavior"""

class ConsensusMessage(BaseModel):
    epoch: int
    sequence: int
    msg_type: str
    sender_id: str
    payload: bytes
    signature: bytes
    timestamp: float = Field(default_factory=time.time)
    
    @validator('payload')
    def validate_payload_size(cls, v):
        if len(v) > 1_000_000:  # 1MB max payload
            raise ValueError("Payload exceeds size limit")
        return v

class ConsensusState(BaseModel):
    current_epoch: int
    last_applied: int
    commit_index: int
    node_status: Dict[str, str]  # NodeID -> status
    
class BaseConsensusProtocol(abc.ABC):
    """Abstract Byzantine Fault Tolerant Consensus Engine"""
    
    def __init__(self,
                 node_id: str,
                 private_key: rsa.RSAPrivateKey,
                 public_keys: Dict[str, rsa.RSAPublicKey],
                 batch_size: int = 100,
                 timeout_ms: int = 5000):
        self.node_id = node_id
        self.private_key = private_key
        self.peer_keys = public_keys
        self.batch_size = batch_size
        self.timeout = timeout_ms / 1000
        self.state = ConsensusState(
            current_epoch=0,
            last_applied=0,
            commit_index=0,
            node_status={}
        )
        self._message_queue = asyncio.Queue(maxsize=10_000)
        self._pipeline_lock = asyncio.Lock()
        self._prepare_watermarks()
        
    def _prepare_watermarks(self):
        """Initialize sequence number tracking"""
        self.high_watermark = 0
        self.low_watermark = 0
        self.next_sequence = 1
        
    def _sign_message(self, msg: ConsensusMessage) -> bytes:
        """Cryptographically sign consensus messages"""
        signer = self.private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signer.update(msg.payload)
        return signer.finalize()
    
    async def _verify_message(self, msg: ConsensusMessage) -> bool:
        """Validate message authenticity and integrity"""
        try:
            if msg.sender_id not in self.peer_keys:
                logger.warning(f"Unknown sender {msg.sender_id}")
                return False
                
            verifier = self.peer_keys[msg.sender_id].verifier(
                msg.signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verifier.update(msg.payload)
            verifier.verify()
            return True
        except InvalidSignature:
            logger.error(f"Invalid signature from {msg.sender_id}")
            return False
    
    @abc.abstractmethod
    async def propose(self, value: bytes) -> bool:
        """Submit value for consensus ordering"""
        
    @abc.abstractmethod    
    async def process_message(self, msg: ConsensusMessage):
        """Handle incoming consensus messages"""
        
    @abc.abstractmethod
    async def _commit_pipeline(self):
        """Ordered execution of committed values"""
        
class PBFTProtocol(BaseConsensusProtocol):
    """Practical Byzantine Fault Tolerance Implementation"""
    
    def __init__(self, *args, checkpoint_interval: int = 100, **kwargs):
        super().__init__(*args, **kwargs)
        self.checkpoint_interval = checkpoint_interval
        self._prepare_three_phase_vars()
        
    def _prepare_three_phase_vars(self):
        """Initialize PBFT protocol state"""
        self.pre_prepare = {}
        self.prepare = defaultdict(set)
        self.commit = defaultdict(set)
        self.checkpoints = {}
        
    async def propose(self, value: bytes) -> bool:
        async with self._pipeline_lock:
            if len(value) > 1_000_000:
                raise ConsensusError("Payload too large")
                
            sequence = self.next_sequence
            msg = ConsensusMessage(
                epoch=self.state.current_epoch,
                sequence=sequence,
                msg_type="PRE-PREPARE",
                sender_id=self.node_id,
                payload=value,
                signature=self._sign_message(value)
            )
            self._message_queue.put_nowait(msg)
            self.next_sequence += 1
            return await self._wait_for_commit(sequence)
            
    async def _wait_for_commit(self, sequence: int) -> bool:
        """Wait until value is committed or timeout"""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if sequence <= self.state.commit_index:
                return True
            await asyncio.sleep(0.01)
        return False
        
    async def process_message(self, msg: ConsensusMessage):
        """PBFT message processing state machine"""
        if not await self._verify_message(msg):
            return
            
        match msg.msg_type:
            case "PRE-PREPARE":
                await self._handle_pre_prepare(msg)
            case "PREPARE":
                await self._handle_prepare(msg)
            case "COMMIT":
                await self._handle_commit(msg)
            case "VIEW-CHANGE":
                await self._handle_view_change(msg)
                
    async def _handle_pre_prepare(self, msg: ConsensusMessage):
        """Phase 1: Primary proposal"""
        if msg.sequence in self.pre_prepare:
            return
            
        if not self._validate_sequence(msg.sequence):
            await self._request_checkpoint()
            return
            
        self.pre_prepare[msg.sequence] = msg
        prepare_msg = self._create_replica_message(msg, "PREPARE")
        await self._broadcast(prepare_msg)
        
    async def _handle_prepare(self, msg: ConsensusMessage):
        """Phase 2: Replica preparation"""
        if msg.sequence in self.prepare and msg.sender_id in self.prepare[msg.sequence]:
            return
            
        self.prepare[msg.sequence].add(msg.sender_id)
        if len(self.prepare[msg.sequence]) >= 2 * self._max_faulty_nodes() + 1:
            commit_msg = self._create_replica_message(msg, "COMMIT")
            await self._broadcast(commit_msg)
            
    async def _handle_commit(self, msg: ConsensusMessage):
        """Phase 3: Final commitment"""
        if msg.sequence in self.commit and msg.sender_id in self.commit[msg.sequence]:
            return
            
        self.commit[msg.sequence].add(msg.sender_id)
        if len(self.commit[msg.sequence]) >= 2 * self._max_faulty_nodes() + 1:
            await self._execute_commit(msg.sequence)
            
    def _max_faulty_nodes(self) -> int:
        """Calculate maximum allowed faulty nodes"""
        return (len(self.peer_keys) - 1) // 3
            
    async def _execute_commit(self, sequence: int):
        """Apply committed value to state machine"""
        if sequence <= self.state.commit_index:
            return
            
        msg = self.pre_prepare[sequence]
        async with self._pipeline_lock:
            # Apply to application state machine
            await self._apply_to_state_machine(msg.payload)
            self.state.commit_index = sequence
            
            # Checkpointing logic
            if sequence % self.checkpoint_interval == 0:
                await self._create_checkpoint()
                
    async def _create_checkpoint(self):
        """Periodic state checkpointing"""
        snapshot = await self._generate_state_snapshot()
        digest = hashlib.sha256(snapshot).digest()
        self.checkpoints[self.state.commit_index] = (digest, snapshot)
        
    async def _request_checkpoint(self):
        """Sync state with other nodes"""
        # Implementation for checkpoint synchronization
        pass
        
    async def _apply_to_state_machine(self, value: bytes):
        """Application-specific state transition"""
        # Implement in subclass
        pass
        
class ConsensusMetrics(BaseModel):
    """Performance and reliability metrics"""
    commit_latency: float
    throughput_tps: float
    fault_detections: int
    checkpoint_size: int
    active_nodes: int
    
class ConsensusOptimizer:
    """Dynamic parameter tuning for consensus"""
    
    def __init__(self, protocol: BaseConsensusProtocol):
        self.protocol = protocol
        self._adaptive_timer = AdaptiveTimeoutManager()
        
    async def optimize_parameters(self):
        """Adjust protocol parameters in real-time"""
        while True:
            await self._adjust_batch_size()
            await self._adjust_timeout()
            await asyncio.sleep(5)
            
    async def _adjust_batch_size(self):
        """Dynamic batching based on load"""
        current_load = self.protocol._message_queue.qsize()
        if current_load > 1000:
            self.protocol.batch_size = min(500, self.protocol.batch_size * 2)
        elif current_load < 100:
            self.protocol.batch_size = max(10, self.protocol.batch_size // 2)
            
    async def _adjust_timeout(self):
        """Network latency-aware timeout adjustment"""
        avg_latency = self._adaptive_timer.calculate_network_latency()
        self.protocol.timeout = avg_latency * 3  # 3x round trip time
        
class AdaptiveTimeoutManager:
    """Network performance monitoring"""
    
    def calculate_network_latency(self) -> float:
        # Implementation using sliding window of ping times
        return 0.1  # Simulated 100ms latency

# Example Usage
if __name__ == "__main__":
    async def demo_pbft():
        # Generate node keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_keys = {
            "node1": private_key.public_key(),
            # ... other nodes' keys
        }
        
        protocol = PBFTProtocol(
            node_id="node1",
            private_key=private_key,
            public_keys=public_keys,
            batch_size=100
        )
        
        # Start background tasks
        optimizer = ConsensusOptimizer(protocol)
        asyncio.create_task(optimizer.optimize_parameters())
        
        # Propose test value
        success = await protocol.propose(b"test_value")
        print(f"Consensus achieved: {success}")
        
    asyncio.run(demo_pbft())
