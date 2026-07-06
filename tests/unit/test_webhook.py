import asyncio
import base64
import json
import os
import tempfile
import time
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from blackwall.api.webhook_listener import WebhookListener
from blackwall.db.repository import SQLiteThreatRepository

# Session-scoped test keys to avoid generating RSA keys for every test (slow)
@pytest.fixture(scope="session")
def test_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    numbers = private_key.public_key().public_numbers()
    
    def int_to_b64url(val: int) -> str:
        b = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')
        
    n_b64 = int_to_b64url(numbers.n)
    e_b64 = int_to_b64url(numbers.e)
    
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-kid",
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64
            }
        ]
    }
    return private_key, jwks

@pytest.fixture
def generate_jwt(test_keys):
    private_key, _ = test_keys
    def _generate(claims, kid="test-kid", audience="test_audience"):
        headers = {"kid": kid, "alg": "RS256"}
        if "aud" not in claims and audience:
            claims = {**claims, "aud": audience}
        return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)
    return _generate

@pytest.fixture(autouse=True)
def mock_jwks_fetch(test_keys):
    _, jwks = test_keys
    
    class MockResponse:
        def __init__(self, status, json_data):
            self.status = status
            self.json_data = json_data
            
        async def json(self):
            return self.json_data
            
        async def __aenter__(self):
            return self
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_get.return_value = MockResponse(200, jwks)
        yield mock_get

class MockInteractions:
    def __init__(self):
        self.get_called_with = None
        self.return_value = None

    async def get(self, interaction_id):
        self.get_called_with = interaction_id
        if isinstance(self.return_value, Exception):
            raise self.return_value
        return self.return_value

class MockGeminiClient:
    def __init__(self):
        self.interactions = MockInteractions()

class TestWebhookListener(AioHTTPTestCase):

    @pytest.fixture(autouse=True)
    def setup_fixtures(self, test_keys, generate_jwt):
        self.private_key, self.jwks = test_keys
        self.generate_jwt = generate_jwt

    async def get_application(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.temp_dir.name, "test_webhook.db")
        self.db = SQLiteThreatRepository(db_path)
        await self.db.initialize()
        
        self.mock_gemini = MockGeminiClient()
        # Set default mock return value
        self.mock_gemini.interactions.return_value = {
            "task_id": "test_task_id",
            "threat_signature_candidates": [
                {"payloadPattern": "test_pattern", "attackerIntent": "test_intent"}
            ]
        }
        
        # Initialize listener with test audience
        self.listener = WebhookListener(self.db, gemini_client=self.mock_gemini, audience="test_audience")
        return self.listener.app

    async def setUpAsync(self):
        await super().setUpAsync()
        self.task_id = "test_task_id"
        await self.db.add_in_flight_task(self.task_id)
        
        self.interaction_id = str(uuid.uuid4())
        self.webhook_id = str(uuid.uuid4())
        self.timestamp = str(time.time())

        # Valid test token claims - must include sub or interaction_id matching payload
        self.claims = {
            "iss": "google",
            "exp": int(time.time()) + 3600,
            "sub": self.interaction_id  # Bind JWT to the interaction_id
        }
        self.valid_token = self.generate_jwt(self.claims)

    async def tearDownAsync(self):
        await self.db.close()
        self.temp_dir.cleanup()
        await super().tearDownAsync()

    @unittest_run_loop
    async def test_jwt_validation_missing_signature(self):
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        # Missing Webhook-Signature header -> 400
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)

    @unittest_run_loop
    async def test_jwt_validation_invalid_signature(self):
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": "invalid_jwt_signature",
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)

    @unittest_run_loop
    async def test_jwt_wrong_audience(self):
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        
        # Generate token with wrong audience
        bad_token = self.generate_jwt(self.claims, audience="wrong_audience")
        headers = {
            "Webhook-Signature": bad_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)

    @unittest_run_loop
    async def test_validation_success_and_response_time(self):
        # We verify fire-and-forget behavior by blocking the DB write and ensuring the response returns immediately.
        # This guarantees that the HTTP response is sent before the database write has completed.
        db_write_resume = asyncio.Event()
        original_write = self.db.write_signatures_batch

        async def blocking_write(signatures):
            await db_write_resume.wait()
            await original_write(signatures)

        self.db.write_signatures_batch = blocking_write

        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        
        start_time = time.time()
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        end_time = time.time()
        
        self.assertEqual(resp.status, 200)
        response_time_ms = (end_time - start_time) * 1000
        self.assertLess(response_time_ms, 500, f"Response time was too slow: {response_time_ms}ms")

        # Verify the signature is not in the database yet, proving it was non-blocking
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures WHERE payload_pattern = 'test_pattern'")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 0)

        # Allow the background write to complete and wait for background tasks
        db_write_resume.set()
        if self.listener.background_tasks:
            await asyncio.wait(self.listener.background_tasks, timeout=2.0)

        # Verify interactions.get was called with correct id
        self.assertEqual(self.mock_gemini.interactions.get_called_with, self.interaction_id)
        
        # Verify task is no longer in-flight
        is_valid = await self.db.is_task_valid(self.task_id)
        self.assertFalse(is_valid)
        
        # Verify the signature is now written
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures WHERE payload_pattern = 'test_pattern'")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 1)

    @unittest_run_loop
    async def test_stale_or_unknown_task_discarded(self):
        # Setup an interaction that returns a different (unknown) task_id
        unknown_task_id = str(uuid.uuid4())
        self.mock_gemini.interactions.return_value = {
            "task_id": unknown_task_id,
            "threat_signature_candidates": [{"payloadPattern": "test"}]
        }
        
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 200)

        # Wait for background tasks to complete
        if self.listener.background_tasks:
            await asyncio.wait(self.listener.background_tasks, timeout=2.0)

        # Ensure nothing was written because task was unknown
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 0)

    @unittest_run_loop
    async def test_atomic_signature_writes(self):
        self.mock_gemini.interactions.return_value = {
            "task_id": self.task_id,
            "threat_signature_candidates": [
                {"payloadPattern": "pattern1", "attackerIntent": "intent1", "targetTool": "tool1"},
                {"payloadPattern": "pattern2", "attackerIntent": "intent2", "targetTool": "tool1"}
            ]
        }
        
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 200)

        # Wait for background tasks to complete
        if self.listener.background_tasks:
            await asyncio.wait(self.listener.background_tasks, timeout=2.0)

        # Check that both signatures are written
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT payload_pattern FROM signatures ORDER BY payload_pattern")
            rows = await cursor.fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0][0], "pattern1")
            self.assertEqual(rows[1][0], "pattern2")

    @unittest_run_loop
    async def test_graceful_shutdown(self):
        # Mock the db to sleep during write
        original_write = self.db.write_signatures_batch
        
        async def slow_write(signatures):
            await asyncio.sleep(0.5)
            await original_write(signatures)
            
        self.db.write_signatures_batch = slow_write
        
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 200)
        
        start_stop_time = time.time()
        await self.listener.stop()
        end_stop_time = time.time()
        
        self.assertGreaterEqual((end_stop_time - start_stop_time), 0.5)
        
        # Verify the signature was written
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT payload_pattern FROM signatures")
            row = await cursor.fetchone()
            self.assertEqual(row[0], "test_pattern")

    @unittest_run_loop
    async def test_webhook_deduplication(self):
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }
        
        # First submission
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 200)

        # Wait for background tasks to complete
        if self.listener.background_tasks:
            await asyncio.wait(self.listener.background_tasks, timeout=2.0)

        # Make task valid again for second run
        await self.db.add_in_flight_task(self.task_id)

        # Second submission of same payload
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 200)

        # Wait for any potential background tasks (though it should be deduplicated)
        if self.listener.background_tasks:
            await asyncio.wait(self.listener.background_tasks, timeout=2.0)

        # Verify only 1 row exists in DB
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures WHERE payload_pattern = 'test_pattern'")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 1)

    @unittest_run_loop
    async def test_replay_rejection(self):
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        
        # Timestamp more than 5 minutes in the past
        stale_timestamp = str(time.time() - 301)
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": stale_timestamp,
            "webhook-id": self.webhook_id
        }
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)

    @unittest_run_loop
    async def test_jwt_replay_with_different_payload(self):
        # Test that JWT token cannot be replayed with a different payload
        different_interaction_id = str(uuid.uuid4())
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": different_interaction_id}  # Different ID than what's in JWT
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # Use valid_token which has self.interaction_id in the 'sub' claim
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": self.timestamp,
            "webhook-id": self.webhook_id
        }

        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)

    @unittest_run_loop
    async def test_future_timestamp_rejected(self):
        # Test that timestamps in the future are also rejected
        payload = {
            "type": "interaction.completed",
            "version": "1",
            "timestamp": "2026-07-06T00:00:00Z",
            "data": {"id": self.interaction_id}
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # Timestamp more than 5 minutes in the future
        future_timestamp = str(time.time() + 301)
        headers = {
            "Webhook-Signature": self.valid_token,
            "webhook-timestamp": future_timestamp,
            "webhook-id": self.webhook_id
        }

        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 400)


