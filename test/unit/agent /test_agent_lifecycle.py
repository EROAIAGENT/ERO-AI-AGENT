# tests/integration/agents/test_agent_lifecycle.py
import asyncio
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

# Test Configuration
TEST_KEY = Fernet.generate_key()
TEST_AGENT_ID = uuid.UUID("d9f5b3e7-1a2b-4c5d-8e9f-0a1b2c3d4e5f")
SAMPLE_PAYLOAD = {
    "instruction": "analyze_network_traffic",
    "params": {"duration": "5m", "protocol_filter": ["tcp", "udp"]}
}

@pytest.fixture
def mock_db():
    """Simulated database with encryption layer"""
    class MockDB:
        def __init__(self):
            self.data = {}
            self.cipher = Fernet(TEST_KEY)

        async def store(self, agent_id: str, data: bytes):
            encrypted = self.cipher.encrypt(data)
            self.data[agent_id] = encrypted

        async def load(self, agent_id: str) -> bytes:
            return self.cipher.decrypt(self.data[agent_id])
    
    return MockDB()

@pytest.mark.asyncio
class TestAgentLifecycle:
    """Comprehensive agent lifecycle test suite"""

    async def test_agent_initialization(self, mock_db):
        """Validate secure agent instantiation with cryptographic identity"""
        with patch("core.agent.base_agent.KeyVault") as mock_vault:
            mock_vault.get_public_key.return_value = TEST_KEY
            
            agent = Agent(
                id=TEST_AGENT_ID,
                runtime="secure-container",
                policy="isolated-execution"
            )
            
            assert agent.status == "INITIALIZED"
            assert agent.identity_digest == hashlib.sha256(TEST_KEY).hexdigest()
            mock_vault.rotate_keys.assert_not_called()

    async def test_agent_activation_sequence(self, mock_db):
        """Full startup sequence with dependency validation"""
        async with AgentClusterSimulator(node_count=3) as cluster:
            agent = await cluster.deploy_agent(
                id=TEST_AGENT_ID,
                manifest=SAMPLE_PAYLOAD
            )
            
            # Validate initialization sequence
            assert agent.startup_time < datetime.utcnow()
            assert agent.resources.allocated_cpu == 2.0
            assert agent.health_check() == "HEALTHY"
            
            # Verify distributed ledger entry
            ledger_entry = await cluster.ledger.query(TEST_AGENT_ID)
            assert ledger_entry["status"] == "ACTIVE"

    async def test_task_execution_flow(self):
        """End-to-end workflow execution with fault injection"""
        with (
            patch("core.network.gateway.APIClient") as mock_api,
            patch("core.security.policy_enforcer.validate") as mock_validator
        ):
            mock_api.return_value.execute.side_effect = [
                {"result": "partial", "progress": 40},
                {"result": "complete", "data": [...]}
            ]
            mock_validator.return_value = {"allowed": True, "ttl": 300}
            
            agent = TestAgentFactory.build(
                id=TEST_AGENT_ID,
                capabilities=["network_analysis"]
            )
            
            async with agent:
                # Phase 1: Task initialization
                task = await agent.create_task(
                    payload=SAMPLE_PAYLOAD,
                    timeout=30
                )
                assert task.phase == "PRE_EXECUTION"
                
                # Phase 2: Execution with retries
                result = await task.execute(max_retries=2)
                assert result.metrics.duration > timedelta(seconds=1)
                assert result.artifacts.size > 0
                
                # Phase 3: Validation
                report = await result.validate()
                assert report.integrity_score == 1.0
                
                # Phase 4: Cleanup
                await result.purge(secure_wipe=True)
                assert not result.temporary_files.exist()

    async def test_failure_scenarios(self):
        """Comprehensive failure mode validation"""
        injected_errors = [
            TimeoutError("Network timeout"),
            RuntimeError("Resource exhaustion"),
            PermissionError("Policy violation")
        ]
        
        for error in injected_errors:
            with patch(
                "core.agent.base_agent.Agent._execute_task",
                side_effect=error
            ) as mock_execute:
                agent = TestAgentFactory.error_prone_agent()
                
                with pytest.raises(type(error)):
                    async with agent:
                        await agent.run_task(SAMPLE_PAYLOAD)
                        
                assert agent.status == "FAILED"
                assert agent.error_log.count(str(error)) == 1
                assert mock_execute.call_count == 3  # Retry logic

    async def test_persistence_cycle(self, mock_db):
        """Full state preservation and restoration test"""
        # Initial state capture
        agent = TestAgentFactory.persistent_agent()
        async with agent:
            await agent.run_task(SAMPLE_PAYLOAD)
            snapshot = await agent.snapshot()
            await mock_db.store(str(TEST_AGENT_ID), json.dumps(snapshot).encode())
            
        # State restoration
        encrypted_data = await mock_db.load(str(TEST_AGENT_ID))
        restored_state = json.loads(encrypted_data.decode())
        
        revived_agent = await Agent.restore(
            state=restored_state,
            key=TEST_KEY
        )
        
        assert revived_agent.last_task == "analyze_network_traffic"
        assert revived_agent.metrics.uptime > timedelta(0)
        assert revived_agent.identity_digest == agent.identity_digest

    async def test_security_boundaries(self):
        """Runtime security policy enforcement validation"""
        malicious_payload = {
            "instruction": "modify_security_groups",
            "params": {"group_id": "*"}
        }
        
        with patch(
            "core.security.policy_enforcer.validate",
            return_value={"allowed": False, "reason": "Overprivileged operation"}
        ):
            agent = TestAgentFactory.secure_agent()
            
            async with agent:
                with pytest.raises(PolicyViolationError) as exc:
                    await agent.run_task(malicious_payload)
                    
                assert "Overprivileged" in str(exc.value)
                assert agent.security_log.contains("CRITICAL")

# Test Execution Requirements
"""
1. Install dependencies:
   pip install pytest-asyncio cryptography pytest-mock

2. Run with coverage:
   pytest tests/integration/agents/test_agent_lifecycle.py \
     --cov=core.agent \
     --cov-report=term-missing \
     -v

3. Security validation:
   bandit -r core/agent/
   pytest --security-scan
"""
