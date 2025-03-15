# performance/locustfile.py
import json
import os
import time
import uuid
from datetime import datetime
from typing import Optional

from cryptography.fernet import Fernet
from locust import FastHttpUser, task, between, events, LoadTestShape
from locust.runners import MasterRunner, WorkerRunner
from locust.env import Environment

# Configuration
API_VERSION = "v1"
ENCRYPTION_KEY = Fernet.generate_key()
CONCURRENCY_PROFILE = {
    "low": {"users": 100, "spawn_rate": 10},
    "normal": {"users": 1000, "spawn_rate": 100},
    "peak": {"users": 5000, "spawn_rate": 500}
}

class PhasmaTestUser(FastHttpUser):
    abstract = True
    host = os.getenv("PHASMA_API_URL", "https://api.phasma.ai")
    wait_time = between(0.5, 5)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.access_token = None
        self.agent_ids = []
        self.session_id = str(uuid.uuid4())
        self.request_headers = {
            "Content-Type": "application/json",
            "X-Phasma-Client": "load-test/1.0"
        }
        self._setup_encryption()

    def _setup_encryption(self):
        self.cipher_suite = Fernet(ENCRYPTION_KEY)
        self.nonce = os.urandom(16)

    def _sign_request(self, payload: dict) -> str:
        timestamp = str(int(time.time()))
        signature_data = f"{timestamp}{json.dumps(payload)}".encode()
        return self.cipher_suite.encrypt(signature_data).decode()

    def _get_auth_header(self) -> dict:
        if not self.access_token:
            self._refresh_token()
        return {"Authorization": f"Bearer {self.access_token}"}

    def _refresh_token(self):
        response = self.client.post(
            "/auth/token",
            headers=self.request_headers,
            json={
                "client_id": os.getenv("CLIENT_ID"),
                "client_secret": os.getenv("CLIENT_SECRET")
            }
        )
        self.access_token = response.json()["access_token"]

    @task(5)
    def test_agent_lifecycle(self):
        # Create Agent
        agent_payload = self._encrypt_payload({
            "name": f"LoadTestAgent-{uuid.uuid4()}",
            "capabilities": ["research", "coding"]
        })
        create_response = self.client.post(
            f"/{API_VERSION}/agents",
            headers={**self.request_headers, **self._get_auth_header()},
            json=agent_payload
        )
        agent_id = create_response.json()["id"]
        self.agent_ids.append(agent_id)

        # Execute Task
        task_payload = self._encrypt_payload({
            "agent_id": agent_id,
            "command": "research",
            "params": {"query": "AI safety protocols"}
        })
        self.client.post(
            f"/{API_VERSION}/tasks",
            headers={**self.request_headers, **self._get_auth_header()},
            json=task_payload,
            name="/v1/tasks [execute]"
        )

    @task(3)
    def test_llm_integration(self):
        llm_payload = self._encrypt_payload({
            "prompt": "Generate Python code for secure file upload",
            "temperature": 0.7,
            "max_tokens": 500
        })
        self.client.post(
            f"/{API_VERSION}/llm/generate",
            headers={**self.request_headers, **self._get_auth_header()},
            json=llm_payload,
            name="/v1/llm/generate"
        )

    @task(2)
    def test_workflow_orchestration(self):
        workflow_payload = self._encrypt_payload({
            "name": f"TestWorkflow-{uuid.uuid4()}",
            "stages": [
                {"type": "data_ingestion", "params": {"source": "s3://test"}},
                {"type": "model_training", "params": {"epochs": 5}}
            ]
        })
        self.client.put(
            f"/{API_VERSION}/workflows",
            headers={**self.request_headers, **self._get_auth_header()},
            json=workflow_payload,
            name="/v1/workflows"
        )

    def _encrypt_payload(self, data: dict) -> dict:
        encrypted = self.cipher_suite.encrypt(
            json.dumps(data).encode()
        ).decode()
        return {
            "encrypted_data": encrypted,
            "nonce": self.nonce.hex(),
            "signature": self._sign_request(data)
        }

    def on_stop(self):
        # Cleanup test agents
        for agent_id in self.agent_ids:
            self.client.delete(
                f"/{API_VERSION}/agents/{agent_id}",
                headers={**self.request_headers, **self._get_auth_header()}
            )

class PhasmaLoadTestShape(LoadTestShape):
    stages = [
        {"duration": 300, "users": CONCURRENCY_PROFILE["low"]["users"], "spawn_rate": CONCURRENCY_PROFILE["low"]["spawn_rate"]},
        {"duration": 600, "users": CONCURRENCY_PROFILE["normal"]["users"], "spawn_rate": CONCURRENCY_PROFILE["normal"]["spawn_rate"]},
        {"duration": 900, "users": CONCURRENCY_PROFILE["peak"]["users"], "spawn_rate": CONCURRENCY_PROFILE["peak"]["spawn_rate"]},
        {"duration": 1200, "users": 0, "spawn_rate": 0}
    ]

    def tick(self):
        run_time = self.get_run_time()
        for stage in self.stages:
            if run_time < stage["duration"]:
                return (stage["users"], stage["spawn_rate"])
        return None

@events.init.add_listener
def on_locust_init(environment: Environment, **kwargs):
    if isinstance(environment.runner, MasterRunner):
        print("Initializing master node...")
    elif isinstance(environment.runner, WorkerRunner):
        print(f"Initializing worker node: {environment.runner.worker_index}")

@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
    if exception:
        print(f"Request failed: {name} | Error: {exception}")
        
@events.test_start.add_listener
def on_test_start(environment: Environment, **kwargs):
    print(f"Test started at {datetime.utcnow().isoformat()}")

@events.test_stop.add_listener
def on_test_stop(environment: Environment, **kwargs):
    print(f"Test stopped at {datetime.utcnow().isoformat()}")

# Custom client for enterprise security requirements
class SecurePhasmaClient(FastHttpUser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enable_secure_mode()
        
    def enable_secure_mode(self):
        self.client.verify = True  # Enable SSL verification
        self.client.cert = ("/path/to/client.crt", "/path/to/client.key")
        self.client.headers.update({
            "X-Phasma-Security": "v2",
            "X-Request-Signature": self._generate_request_signature()
        })
        
    def _generate_request_signature(self):
        timestamp = str(int(time.time()))
        return hashlib.sha256(f"{timestamp}{os.getenv('API_SECRET')}".encode()).hexdigest()

# Execution Documentation
"""
Install dependencies:
pip install locust cryptography pyjwt

Environment Setup:
export PHASMA_API_URL=https://api.phasma.ai
export CLIENT_ID=your_client_id
export CLIENT_SECRET=your_client_secret

Run tests:
locust -f locustfile.py --headless \
  -u 5000 -r 500 \
  --run-time 30m \
  --csv=phasma_load_test \
  --html=report.html \
  --prometheus \
  --tags production

Distributed Execution:
# Start master
locust -f locustfile.py --master

# Start workers
locust -f locustfile.py --worker --master-host=localhost
"""
