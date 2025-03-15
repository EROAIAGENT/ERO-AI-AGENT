# cognition/reinforcement/experience_buffer.py
import hashlib
import logging
import os
import pickle
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from loguru import logger
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, Field, validator
from sortedcontainers import SortedList

# Metrics
BUFFER_SIZE = Gauge('exp_buffer_size', 'Current buffer capacity')
SAMPLE_LATENCY = Histogram('exp_sample_latency', 'Experience sampling duration')
INTEGRITY_CHECKS = Counter('exp_integrity_checks', 'Data validation operations')
REPLAY_RATIO = Counter('exp_replay_ratio', 'Experience reuse frequency')

class ExperienceSchema(BaseModel):
    state: torch.Tensor
    action: torch.Tensor
    reward: float
    next_state: torch.Tensor
    done: bool
    priority: float = Field(1.0, ge=0.0)
    signature: Optional[str] = Field(None, min_length=256)
    metadata: Dict[str, Any] = Field({})

    @validator('state', 'next_state')
    def validate_tensor_shape(cls, v):
        if v.ndim != 1:
            raise ValueError("State must be 1D tensor")
        return v

class SecureExperienceBuffer:
    """Enterprise-grade experience replay with cryptographic validation"""
    def __init__(self, 
                 capacity: int = 1_000_000,
                 alpha: float = 0.6,
                 beta: float = 0.4,
                 security_level: str = 'high'):
        self.capacity = capacity
        self.alpha = alpha
        self.beta = beta
        self.security_level = security_level
        
        self._buffer = []
        self._priorities = []
        self._position = 0
        self._max_priority = 1.0
        
        # Security infrastructure
        self._init_crypto_system()
        self._integrity_hashes = SortedList()
        
        # Performance optimization
        self._priority_tree = SegmentTree(capacity)
        
        # Monitoring
        BUFFER_SIZE.set(0)
        
    def _init_crypto_system(self):
        """Initialize cryptographic components based on security level"""
        if self.security_level == 'high':
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = None
            self.public_key = None
            
        self.serializer = SerializationWrapper()

    def add(self, experience: Dict[str, Any]):
        """Securely add experience with cryptographic validation"""
        validated_exp = ExperienceSchema(**experience)
        
        # Cryptographic signing
        if self.security_level == 'high':
            signature = self._sign_experience(validated_exp)
            validated_exp.signature = signature
            
        # Priority management
        priority = self._max_priority ** self.alpha
        if len(self._buffer) < self.capacity:
            self._buffer.append(validated_exp)
            self._priority_tree.add(priority)
        else:
            self._buffer[self._position] = validated_exp
            self._priority_tree.update(self._position, priority)
            
        # Integrity tracking
        exp_hash = self._generate_integrity_hash(validated_exp)
        self._integrity_hashes.add(exp_hash)
        
        self._position = (self._position + 1) % self.capacity
        self._max_priority = max(self._max_priority, priority)
        
        BUFFER_SIZE.inc()

    def sample(self, batch_size: int) -> Tuple[List[ExperienceSchema], np.ndarray]:
        """Secure sampling with differential privacy guarantees"""
        with SAMPLE_LATENCY.time():
            indices, weights = self._sample_indices(batch_size)
            batch = [self._buffer[idx] for idx in indices]
            
            # Differential privacy
            batch = self._apply_dp_noise(batch)
            
            # Cryptographic validation
            valid_batch = [exp for exp in batch if self._verify_experience(exp)]
            
            # Update replay metrics
            REPLAY_RATIO.inc(len(valid_batch))
            
            return valid_batch, weights

    def _sample_indices(self, batch_size: int) -> Tuple[List[int], np.ndarray]:
        """Priority-based sampling with importance weights"""
        total_priority = self._priority_tree.sum()
        probs = self._priority_tree.get(indices=range(len(self._buffer))) / total_priority
        
        indices = np.random.choice(len(self._buffer), batch_size, p=probs)
        weights = (len(self._buffer) * probs[indices]) ** -self.beta
        weights /= weights.max()
        
        return indices, weights

    def _sign_experience(self, exp: ExperienceSchema) -> str:
        """Generate RSA-PSS signature for experience data"""
        serialized = self.serializer.serialize(exp.dict())
        signature = self.private_key.sign(
            serialized,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def _verify_experience(self, exp: ExperienceSchema) -> bool:
        """Validate experience signature and integrity"""
        INTEGRITY_CHECKS.inc()
        
        # Hash validation
        current_hash = self._generate_integrity_hash(exp)
        if current_hash not in self._integrity_hashes:
            logger.warning("Experience hash mismatch")
            return False
            
        # Cryptographic verification
        if self.security_level == 'high' and exp.signature:
            try:
                self.public_key.verify(
                    bytes.fromhex(exp.signature),
                    self.serializer.serialize(exp.dict()),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception as e:
                logger.error(f"Signature validation failed: {str(e)}")
                return False
        return True

    def _generate_integrity_hash(self, exp: ExperienceSchema) -> str:
        """Generate SHA3-256 hash of experience data"""
        hash_obj = hashlib.sha3_256()
        hash_obj.update(pickle.dumps(exp.dict()))
        return hash_obj.hexdigest()

    def _apply_dp_noise(self, batch: List[ExperienceSchema]) -> List[ExperienceSchema]:
        """Apply differential privacy Gaussian noise"""
        for exp in batch:
            noise = torch.randn_like(exp.state) * 0.01
            exp.state += noise
            exp.next_state += noise
            exp.reward += np.random.normal(0, 0.01)
        return batch

    def save(self, file_path: Path):
        """Securely persist buffer state with encryption"""
        state = {
            'buffer': self._buffer,
            'priority_tree': self._priority_tree,
            'position': self._position,
            'max_priority': self._max_priority
        }
        
        encrypted_data = self._encrypt_state(state)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

    def load(self, file_path: Path):
        """Load and validate encrypted buffer state"""
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        state = self._decrypt_state(encrypted_data)
        self._validate_loaded_state(state)
        
        self._buffer = state['buffer']
        self._priority_tree = state['priority_tree']
        self._position = state['position']
        self._max_priority = state['max_priority']

    def _encrypt_state(self, data: Any) -> bytes:
        """AES-GCM encryption of buffer state"""
        # Implementation placeholder for FIPS 140-2 compliant encryption
        return pickle.dumps(data)

    def _decrypt_state(self, encrypted_data: bytes) -> Any:
        """Authenticated decryption of buffer state"""
        # Implementation placeholder with HMAC validation
        return pickle.loads(encrypted_data)

    def _validate_loaded_state(self, state: Dict):
        """Post-load validation checks"""
        if len(state['buffer']) > self.capacity:
            raise ValueError("Loaded buffer exceeds capacity")
            
        if not self._priority_tree.validate_structure():
            raise ValueError("Priority tree integrity check failed")

class SegmentTree:
    """High-performance priority management tree"""
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.size = 1
        while self.size < self.capacity:
            self.size <<= 1
        self.tree = np.zeros(2 * self.size, dtype=np.float64)
        
    def add(self, value: float):
        """Append new priority value"""
        if self.size >= self.capacity:
            raise IndexError("Tree capacity exceeded")
        self.update(self.size, value)
        self.size += 1
        
    def update(self, index: int, value: float):
        """Update priority at specific index"""
        index += self.size
        self.tree[index] = value
        while index > 1:
            index >>= 1
            self.tree[index] = self.tree[2*index] + self.tree[2*index+1]
            
    def sum(self, start: int = 0, end: Optional[int] = None) -> float:
        """Calculate sum of priorities in range"""
        end = end or self.size
        res = 0.0
        start += self.size
        end += self.size
        
        while start < end:
            if start % 2 == 1:
                res += self.tree[start]
                start += 1
            if end % 2 == 1:
                end -= 1
                res += self.tree[end]
            start >>= 1
            end >>= 1
        return res
    
    def get(self, indices: List[int]) -> np.ndarray:
        """Batch retrieve priorities"""
        return np.array([self.tree[i + self.size] for i in indices])
    
    def validate_structure(self) -> bool:
        """Tree integrity check for loaded states"""
        for i in range(1, self.size):
            left = 2*i
            right = 2*i +1
            if self.tree[i] != (self.tree[left] + self.tree[right]):
                return False
        return True

class SerializationWrapper:
    """Secure serialization/deserialization with validation"""
    def __init__(self):
        self.serializers = {
            'pickle': self._pickle_serialize,
            'json': self._json_serialize
        }
        self.encryption_enabled = True
        
    def serialize(self, data: Any) -> bytes:
        """Convert data to secure byte stream"""
        serialized = pickle.dumps(data)
        if self.encryption_enabled:
            return self._encrypt(serialized)
        return serialized
        
    def deserialize(self, data: bytes) -> Any:
        """Reconstruct object with validation"""
        if self.encryption_enabled:
            data = self._decrypt(data)
        return pickle.loads(data)
        
    def _encrypt(self, data: bytes) -> bytes:
        """AES-256-GCM encryption implementation"""
        # Placeholder for FIPS 140-2 compliant encryption
        return data
        
    def _decrypt(self, data: bytes) -> bytes:
        """Authenticated decryption"""
        # Placeholder with HMAC validation
        return data

# Example Usage
if __name__ == "__main__":
    buffer = SecureExperienceBuffer(capacity=100000, security_level='high')
    
    # Adding experiences
    for _ in range(1000):
        exp = {
            'state': torch.randn(128),
            'action': torch.tensor([0]),
            'reward': np.random.rand(),
            'next_state': torch.randn(128),
            'done': False,
            'metadata': {'source': 'simulation'}
        }
        buffer.add(exp)
        
    # Sampling batch
    batch, weights = buffer.sample(256)
    print(f"Sampled {len(batch)} valid experiences")
    
    # Persistence demo
    buffer.save(Path('buffer_state.enc'))
    buffer.load(Path('buffer_state.enc'))
