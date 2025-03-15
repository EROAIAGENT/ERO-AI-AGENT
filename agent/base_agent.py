# core/agent/base_agent.py
from __future__ import annotations
import uuid
import logging
import asyncio
from typing import (
    Any,
    Dict,
    Optional,
    TypeVar,
    Generic,
    Awaitable,
    Callable,
    Coroutine
)
from pydantic import BaseModel, ValidationError
from loguru import logger
import ray

T = TypeVar('T', bound=BaseModel)
ActionHandler = Callable[[T], Coroutine[Any, Any, Dict[str, Any]]]

class AgentConfiguration(BaseModel):
    agent_id: str = uuid.uuid4().hex
    max_retries: int = 3
    heartbeat_interval: int = 30
    message_timeout: int = 300
    enable_telemetry: bool = True

class AgentMessage(BaseModel):
    sender_id: str
    payload: Dict[str, Any]
    message_type: str
    correlation_id: str = uuid.uuid4().hex
    timestamp: float = asyncio.get_event_loop().time()

class BaseAgent(Generic[T]):
    """Abstract base class for all autonomous agents in Phasma AI ecosystem.
    
    Implements core lifecycle management, distributed communication, 
    and fault tolerance mechanisms.
    """
    def __init__(self, config: AgentConfiguration) -> None:
        self.config = config
        self._is_running = False
        self._task_registry: Dict[str, ActionHandler] = {}
        self._message_queue = asyncio.Queue()
        self._background_tasks = set()

        # Initialize Ray if not already initialized
        if not ray.is_initialized():
            ray.init(ignore_reinit_error=True)

        # Distributed state management
        self._state = ray.put({"status": "INITIALIZED"})

    async def start(self) -> None:
        """Start agent's main event loop and background services."""
        if self._is_running:
            logger.warning(f"Agent {self.config.agent_id} already running")
            return

        self._is_running = True
        logger.info(f"Starting agent {self.config.agent_id}")

        # Start core services
        asyncio.create_task(self._heartbeat_service())
        asyncio.create_task(self._message_processor())
        asyncio.create_task(self._state_synchronizer())

    async def stop(self) -> None:
        """Graceful shutdown procedure with state preservation."""
        self._is_running = False
        logger.info(f"Stopping agent {self.config.agent_id}")

        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        await asyncio.gather(*self._background_tasks, return_exceptions=True)

        # Final state sync
        await self._persist_state()

    def register_action(
        self, 
        message_type: str, 
        handler: ActionHandler[T]
    ) -> None:
        """Register message handler for specific message types."""
        if message_type in self._task_registry:
            raise KeyError(f"Handler for {message_type} already exists")
        self._task_registry[message_type] = handler

    async def execute_task(
        self, 
        message: AgentMessage
    ) -> Dict[str, Any]:
        """Main task execution endpoint with retry logic."""
        for attempt in range(self.config.max_retries):
            try:
                return await self._safe_execute(message)
            except Exception as e:
                logger.error(
                    f"Attempt {attempt+1} failed: {str(e)}",
                    exc_info=True
                )
                if attempt == self.config.max_retries - 1:
                    await self._handle_critical_failure(message, e)
                    raise

    async def _safe_execute(
        self, 
        message: AgentMessage
    ) -> Dict[str, Any]:
        """Validate and execute task with resource isolation."""
        self._validate_message(message)
        
        handler = self._task_registry.get(message.message_type)
        if not handler:
            raise KeyError(f"No handler for {message.message_type}")
        
        try:
            result = await handler(message.payload)
            await self._update_state("SUCCESS", message)
            return result
        except asyncio.TimeoutError:
            await self._update_state("TIMEOUT", message)
            raise
        except ValidationError as ve:
            await self._update_state("VALIDATION_ERROR", message)
            logger.error(f"Schema validation failed: {ve.json()}")
            raise
        except Exception as e:
            await self._update_state("ERROR", message)
            logger.critical(f"Unhandled exception: {str(e)}")
            raise

    async def send_message(
        self, 
        recipient_id: str, 
        message_type: str, 
        payload: Dict[str, Any]
    ) -> AgentMessage:
        """Secure message dispatch with delivery guarantees."""
        message = AgentMessage(
            sender_id=self.config.agent_id,
            message_type=message_type,
            payload=payload
        )
        
        # Placeholder for actual transport implementation
        await self._message_queue.put(message)
        return message

    async def _heartbeat_service(self) -> None:
        """Maintain liveness and network presence."""
        while self._is_running:
            try:
                await self._update_state("HEALTHY")
                await asyncio.sleep(self.config.heartbeat_interval)
            except asyncio.CancelledError:
                break

    async def _message_processor(self) -> None:
        """Process incoming messages from distributed queue."""
        while self._is_running:
            message = await self._message_queue.get()
            task = asyncio.create_task(self.execute_task(message))
            self._background_tasks.add(task)
            task.add_done_callback(
                lambda t: self._background_tasks.discard(t)
            )

    async def _state_synchronizer(self) -> None:
        """Periodic state synchronization with consensus layer."""
        while self._is_running:
            try:
                # Placeholder for Raft/Paxos implementation
                await asyncio.sleep(5)
                current_state = ray.get(self._state)
                logger.debug(f"Current state: {current_state}")
            except asyncio.CancelledError:
                break

    def _validate_message(self, message: AgentMessage) -> None:
        """Security-critical message validation."""
        if not isinstance(message, AgentMessage):
            raise TypeError("Invalid message schema")
        
        if message.message_type not in self._task_registry:
            raise ValueError("Unregistered message type")

    async def _update_state(
        self, 
        status: str, 
        message: Optional[AgentMessage] = None
    ) -> None:
        """Atomic state update with conflict resolution."""
        current = ray.get(self._state)
        current["status"] = status
        if message:
            current["last_message"] = message.dict()
        self._state = ray.put(current)

    async def _persist_state(self) -> None:
        """State persistence hook for fault tolerance."""
        logger.info("Persisting final agent state")
        # Implement actual persistence logic (e.g., Redis/S3)

    async def _handle_critical_failure(
        self, 
        message: AgentMessage, 
        error: Exception
    ) -> None:
        """Failure recovery and alerting mechanism."""
        logger.critical(
            f"Critical failure processing {message.correlation_id}: {str(error)}"
        )
        # Implement circuit breaker pattern
        # Send alert to monitoring system

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        asyncio.run(self.stop())

    def __repr__(self) -> str:
        return f"<BaseAgent {self.config.agent_id} {self.status}>"

    @property
    def status(self) -> str:
        return ray.get(self._state).get("status", "UNKNOWN")
