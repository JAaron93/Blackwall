import asyncio
import hashlib
import hmac
import json
import time
import os
import uuid
from typing import Any, Dict

import pytest
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp import web

from blackwall.api.webhook_listener import WebhookListener
from blackwall.db.repository import SQLiteThreatRepository

SECRET = "test_secret_key"

@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setenv("BLACKWALL_WEBHOOK_SECRET", SECRET)

import tempfile

class TestWebhookListener(AioHTTPTestCase):

    async def get_application(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.temp_dir.name, "test_webhook.db")
        self.db = SQLiteThreatRepository(db_path)
        await self.db.initialize()
        # The tempfile-backed database needs to have in_flight_tasks created
        # which it does in our updated repository.py schema initialization.
        
        self.listener = WebhookListener(self.db, secret_key=SECRET)
        return self.listener.app

    async def setUpAsync(self):
        await super().setUpAsync()
        self.task_id = str(uuid.uuid4())
        await self.db.add_in_flight_task(self.task_id)

    async def tearDownAsync(self):
        await self.db.close()
        self.temp_dir.cleanup()
        await super().tearDownAsync()

    def generate_signature(self, payload: bytes, secret: str = SECRET) -> str:
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    @unittest_run_loop
    async def test_hmac_validation_failure(self):
        payload = {"task_id": self.task_id}
        payload_bytes = json.dumps(payload).encode("utf-8")
        
        # Wrong signature
        headers = {"X-Webhook-Signature": "wrong_signature"}
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 401)
        
        # Missing signature
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes)
        self.assertEqual(resp.status, 401)
        
        # Wrong secret
        bad_sig = self.generate_signature(payload_bytes, "wrong_secret")
        headers = {"X-Webhook-Signature": bad_sig}
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_hmac_validation_success_and_response_time(self):
        payload = {
            "task_id": self.task_id,
            "threat_signature_candidates": [
                {"payloadPattern": "test_pattern", "attackerIntent": "test_intent"}
            ]
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(payload_bytes)
        headers = {"X-Webhook-Signature": sig}
        
        start_time = time.time()
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        end_time = time.time()
        
        self.assertEqual(resp.status, 202)
        response_time_ms = (end_time - start_time) * 1000
        self.assertLess(response_time_ms, 50, "Response time should be < 50ms")
        
        # Wait a bit for background task to finish processing
        await asyncio.sleep(0.1)
        
        # Verify task is no longer in-flight
        is_valid = await self.db.is_task_valid(self.task_id)
        self.assertFalse(is_valid)

    @unittest_run_loop
    async def test_stale_or_unknown_task_discarded(self):
        unknown_task_id = str(uuid.uuid4())
        payload = {"task_id": unknown_task_id, "threat_signature_candidates": [{"payloadPattern": "test"}]}
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(payload_bytes)
        headers = {"X-Webhook-Signature": sig}
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 202)
        
        # Wait a bit
        await asyncio.sleep(0.1)
        
        # Ensure nothing was written because task was unknown
        # Since we use a tempfile-backed database, the signatures table should be empty
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 0)

    @unittest_run_loop
    async def test_atomic_signature_writes(self):
        payload = {
            "task_id": self.task_id,
            "threat_signature_candidates": [
                {"payloadPattern": "pattern1", "attackerIntent": "intent1", "targetTool": "tool1"},
                {"payloadPattern": "pattern2", "attackerIntent": "intent2", "targetTool": "tool1"}
            ]
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(payload_bytes)
        headers = {"X-Webhook-Signature": sig}
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 202)
        
        await asyncio.sleep(0.1)
        
        # Check that both signatures are written
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT payload_pattern FROM signatures ORDER BY payload_pattern")
            rows = await cursor.fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0][0], "pattern1")
            self.assertEqual(rows[1][0], "pattern2")

    @unittest_run_loop
    async def test_graceful_shutdown(self):
        # We need to simulate a long running background task
        # and ensure stop() waits for it.
        
        # Mock the db to sleep during write
        original_write = self.db.write_signatures_batch
        
        async def slow_write(signatures):
            await asyncio.sleep(0.5)
            await original_write(signatures)
            
        self.db.write_signatures_batch = slow_write
        
        payload = {
            "task_id": self.task_id,
            "threat_signature_candidates": [
                {"payloadPattern": "slow_pattern", "attackerIntent": "slow_intent"}
            ]
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(payload_bytes)
        headers = {"X-Webhook-Signature": sig}
        
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 202)
        
        # Now call stop on listener. It should block until the background task is done.
        start_stop_time = time.time()
        await self.listener.stop()
        end_stop_time = time.time()
        
        self.assertGreaterEqual((end_stop_time - start_stop_time), 0.5)
        
        # Verify the signature was written
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT payload_pattern FROM signatures")
            row = await cursor.fetchone()
            self.assertEqual(row[0], "slow_pattern")

    @unittest_run_loop
    async def test_webhook_deduplication(self):
        # We will write the same signature twice (once in first batch, once in second batch)
        # And verify that it doesn't create duplicate rows, but updates instead.
        payload = {
            "task_id": self.task_id,
            "threat_signature_candidates": [
                {"payloadPattern": "dup_pattern", "attackerIntent": "dup_intent", "targetTool": "tool1"}
            ]
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = self.generate_signature(payload_bytes)
        headers = {"X-Webhook-Signature": sig}
        
        # First submission
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 202)
        await asyncio.sleep(0.1)

        # Make task valid again for second run
        await self.db.add_in_flight_task(self.task_id)

        # Second submission of same payload
        resp = await self.client.post("/webhook/analysis_complete", data=payload_bytes, headers=headers)
        self.assertEqual(resp.status, 202)
        await asyncio.sleep(0.1)

        # Verify only 1 row exists in DB
        async with self.db.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures WHERE payload_pattern = 'dup_pattern'")
            row = await cursor.fetchone()
            self.assertEqual(row[0], 1)

