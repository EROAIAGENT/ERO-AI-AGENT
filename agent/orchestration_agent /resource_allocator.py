# core/agent/orchestration_agent/resource_allocator.py
from __future__ import annotations
import asyncio
import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, validator
from loguru import logger
from prometheus_client import Gauge, Histogram

# Metrics Definitions
RESOURCE_UTILIZATION = Gauge(
    'phasma_resource_utilization',
    'Current resource utilization percentage',
    ['resource_type']
)
ALLOCATION_LATENCY = Histogram(
    'phasma_allocation_latency_seconds',
    'Time taken for resource allocation operations',
    ['resource_class']
)

class ResourceValidationError(Exception):
    """Critical error in resource allocation parameters"""

class ResourceRequest(BaseModel):
    task_id: str
    min_cpu: float
    max_cpu: float
    min_mem: float
    max_mem: float
    gpu_type: Optional[str] = None
    gpu_count: int = 0
    timeout: float = 30.0
    priority: int = 1
    affinity: Dict[str, str] = {}
    anti_affinity: Dict[str, str] = {}

    @validator('task_id')
    def validate_task_id(cls, v):
        if not re.match(r'^[a-z0-9\-]{8,64}$', v):
            raise ValueError('Invalid task ID format')
        return v

class ResourcePool(BaseModel):
    total_cpu: float
    total_mem: float
    total_gpus: Dict[str, int]
    allocated_resources: Dict[str, Dict[str, float]] = {}
    utilization_history: Dict[str, List[float]] = {}

class PredictiveAllocator:
    """Enterprise-grade resource allocation engine with predictive scaling"""
    def __init__(self, initial_pool: ResourcePool):
        self.pool = initial_pool
        self._lock = asyncio.Lock()
        self._forecast_model = self._initialize_forecast_model()
        self._safety_margin = 0.2
        self._rebalance_threshold = 0.15

    async def allocate_resources(
        self,
        request: ResourceRequest
    ) -> Dict[str, Union[float, str]]:
        """Dynamic resource allocation with contention management"""
        start_time = time.monotonic()
        async with self._lock, ALLOCATION_LATENCY.labels('standard').time():
            try:
                validated = self._prevalidate_request(request)
                forecast = self._predict_demand(validated)
                allocation = self._calculate_allocation(validated, forecast)
                
                if not self._check_capacity(allocation):
                    allocation = self._fallback_strategy(validated)
                    
                self._apply_allocation(request.task_id, allocation)
                self._record_metrics(allocation)
                
                return {
                    "allocation_id": self._generate_allocation_hash(allocation),
                    "cpu": allocation['cpu'],
                    "mem": allocation['mem'],
                    "gpu": allocation.get('gpu', None),
                    "expires_at": datetime.now() + timedelta(seconds=request.timeout)
                }
            except ResourceValidationError as e:
                logger.error(f"Allocation failed: {e}")
                raise

    def _prevalidate_request(self, request: ResourceRequest) -> Dict:
        """Validate and normalize request parameters"""
        if request.min_cpu > request.max_cpu:
            raise ResourceValidationError("Invalid CPU range")
            
        if request.min_mem > request.max_mem:
            raise ResourceValidationError("Invalid memory range")
            
        return {
            "task_id": request.task_id,
            "cpu": (request.min_cpu + request.max_cpu) / 2,
            "mem": (request.min_mem + request.max_mem) / 2,
            "gpu": request.gpu_type,
            "gpu_count": request.gpu_count
        }

    def _predict_demand(self, request: Dict) -> Dict[str, float]:
        """Predict resource demand using time-series forecasting"""
        history = self.pool.utilization_history.get(request['task_id'], [])
        if len(history) < 10:
            return request  # Insufficient data for prediction
            
        predicted_cpu = self._forecast_model.predict(history, 'cpu')
        predicted_mem = self._forecast_model.predict(history, 'mem')
        
        return {
            "cpu": max(request['cpu'], predicted_cpu * (1 + self._safety_margin)),
            "mem": max(request['mem'], predicted_mem * (1 + self._safety_margin)),
            "gpu": request['gpu'],
            "gpu_count": request['gpu_count']
        }

    def _calculate_allocation(
        self,
        request: Dict,
        forecast: Dict
    ) -> Dict[str, float]:
        """Optimized resource distribution algorithm"""
        allocated_cpu = min(forecast['cpu'], request['cpu'] * 1.2)
        allocated_mem = min(forecast['mem'], request['mem'] * 1.2)
        
        return {
            "cpu": allocated_cpu,
            "mem": allocated_mem,
            "gpu": forecast['gpu'],
            "gpu_count": forecast['gpu_count']
        }

    def _check_capacity(self, allocation: Dict) -> bool:
        """Real-time capacity verification with safety margins"""
        cpu_available = self.pool.total_cpu - sum(
            a['cpu'] for a in self.pool.allocated_resources.values()
        )
        mem_available = self.pool.total_mem - sum(
            a['mem'] for a in self.pool.allocated_resources.values()
        )
        
        return (allocation['cpu'] <= cpu_available * (1 - self._safety_margin) and
                allocation['mem'] <= mem_available * (1 - self._safety_margin))

    def _fallback_strategy(self, request: Dict) -> Dict:
        """Degraded allocation when resources are constrained"""
        logger.warning("Initiating fallback allocation strategy")
        return {
            "cpu": request['cpu'] * 0.8,
            "mem": request['mem'] * 0.8,
            "gpu": request['gpu'],
            "gpu_count": max(0, request['gpu_count'] - 1)
        }

    def _apply_allocation(self, task_id: str, allocation: Dict) -> None:
        """Atomic resource commitment"""
        self.pool.allocated_resources[task_id] = allocation
        self._update_utilization()

    def _update_utilization(self) -> None:
        """Real-time utilization tracking"""
        cpu_used = sum(a['cpu'] for a in self.pool.allocated_resources.values())
        mem_used = sum(a['mem'] for a in self.pool.allocated_resources.values())
        
        RESOURCE_UTILIZATION.labels('cpu').set(cpu_used / self.pool.total_cpu * 100)
        RESOURCE_UTILIZATION.labels('mem').set(mem_used / self.pool.total_mem * 100)

    def _generate_allocation_hash(self, allocation: Dict) -> str:
        """Cryptographic allocation identifier"""
        return hashlib.sha3_256(
            f"{allocation['cpu']}:{allocation['mem']}:{datetime.now().isoformat()}".encode()
        ).hexdigest()

    def _initialize_forecast_model(self):
        """LSTM-based prediction model placeholder"""
        class ForecastModel:
            def predict(self, history: List[float], resource_type: str) -> float:
                if len(history) < 2:
                    return history[-1] if history else 0.0
                return 0.7 * history[-1] + 0.3 * sum(history[-3:-1])/2
        return ForecastModel()

class ResourceReclaimer:
    """Automated resource recycling system"""
    def __init__(self, allocator: PredictiveAllocator):
        self.allocator = allocator
        self._reclamation_interval = 60  # seconds

    async def start_reclamation_loop(self):
        """Background task for resource recovery"""
        while True:
            await asyncio.sleep(self._reclamation_interval)
            self._reclaim_expired_resources()

    def _reclaim_expired_resources(self):
        """Garbage collection of expired allocations"""
        current_time = datetime.now()
        expired = [
            task_id for task_id, alloc in self.allocator.pool.allocated_resources.items()
            if 'expires_at' in alloc and alloc['expires_at'] < current_time
        ]
        
        for task_id in expired:
            logger.info(f"Reclaiming resources from expired task: {task_id}")
            del self.allocator.pool.allocated_resources[task_id]

class AutoScaler:
    """Cloud-agnostic infrastructure scaling controller"""
    def __init__(self, allocator: PredictiveAllocator):
        self.allocator = allocator
        self._scale_up_threshold = 0.85
        self._scale_down_threshold = 0.4

    async def monitor_and_scale(self):
        """Continuous scaling adjustment loop"""
        while True:
            cpu_util = RESOURCE_UTILIZATION.labels('cpu')._value.get()
            mem_util = RESOURCE_UTILIZATION.labels('mem')._value.get()
            
            if cpu_util > self._scale_up_threshold * 100 or mem_util > self._scale_up_threshold * 100:
                self._scale_out()
            elif cpu_util < self._scale_down_threshold * 100 and mem_util < self._scale_down_threshold * 100:
                self._scale_in()
                
            await asyncio.sleep(30)

    def _scale_out(self):
        """Horizontal scaling implementation"""
        logger.warning("Initiating scale-out procedure")
        # Integration with cloud provider API would go here
        self.allocator.pool.total_cpu *= 1.5
        self.allocator.pool.total_mem *= 1.5

    def _scale_in(self):
        """Vertical scaling implementation"""
        logger.warning("Initiating scale-in procedure")
        # Integration with cloud provider API would go here
        self.allocator.pool.total_cpu = max(
            self.allocator.pool.total_cpu * 0.8,
            sum(a['cpu'] for a in self.allocator.pool.allocated_resources.values()) * 1.2
        )
        self.allocator.pool.total_mem = max(
            self.allocator.pool.total_mem * 0.8,
            sum(a['mem'] for a in self.allocator.pool.allocated_resources.values()) * 1.2
        )

# Example Usage
async def main_workflow():
    initial_pool = ResourcePool(
        total_cpu=32.0,
        total_mem=128.0,
        total_gpus={"A100": 4},
    )
    
    allocator = PredictiveAllocator(initial_pool)
    reclaimer = ResourceReclaimer(allocator)
    scaler = AutoScaler(allocator)
    
    # Start background services
    asyncio.create_task(reclaimer.start_reclamation_loop())
    asyncio.create_task(scaler.monitor_and_scale())
    
    # Simulate allocation requests
    request = ResourceRequest(
        task_id="deep-learning-1",
        min_cpu=4.0,
        max_cpu=8.0,
        min_mem=16.0,
        max_mem=32.0,
        gpu_type="A100",
        gpu_count=2
    )
    
    allocation = await allocator.allocate_resources(request)
    print(f"Allocation result: {allocation}")

# Unit Tests
def test_allocation_logic():
    pool = ResourcePool(
        total_cpu=16.0,
        total_mem=64.0,
        total_gpus={"T4": 2}
    )
    allocator = PredictiveAllocator(pool)
    request = ResourceRequest(
        task_id="data-process-1",
        min_cpu=2.0,
        max_cpu=4.0,
        min_mem=8.0,
        max_mem=16.0
    )
    
    async def test_run():
        return await allocator.allocate_resources(request)
    
    result = asyncio.run(test_run())
    assert result['cpu'] >= 2.0
    assert result['cpu'] <= 4.0 * 1.2
    assert 'allocation_id' in result

def test_over_allocation():
    pool = ResourcePool(
        total_cpu=2.0,
        total_mem=8.0,
        total_gpus={}
    )
    allocator = PredictiveAllocator(pool)
    request = ResourceRequest(
        task_id="overload-test",
        min_cpu=4.0,
        max_cpu=8.0,
        min_mem=16.0,
        max_mem=32.0
    )
    
    async def test_run():
        try:
            await allocator.allocate_resources(request)
            return False
        except ResourceValidationError:
            return True
    
    assert asyncio.run(test_run())
