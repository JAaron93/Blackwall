import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List

from aiohttp import web
from opentelemetry import trace

from blackwall.analytics import Agent_Behavioral_Analytics
from blackwall.db.repository import SQLiteThreatRepository

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

class WebhookListener:
    def __init__(self, db_repository: SQLiteThreatRepository, secret_key: str = ""):
        self.db = db_repository
        self.secret_key = secret_key or os.environ.get("BLACKWALL_WEBHOOK_SECRET", "default_secret")
        self.port = int(os.environ.get("BLACKWALL_WEBHOOK_PORT", 8090))
        self.app = web.Application()
        self.app.router.add_post("/webhook/analysis_complete", self.handle_webhook)
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.background_tasks: set[asyncio.Task[Any]] = set()

    def _verify_signature(self, payload: bytes, signature: str) -> bool:
        if not signature:
            return False
        expected_signature = hmac.new(
            self.secret_key.encode("utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, signature)

    async def handle_webhook(self, request: web.Request) -> web.Response:
        signature = request.headers.get("X-Webhook-Signature", "")
        payload_bytes = await request.read()

        if not self._verify_signature(payload_bytes, signature):
            logger.warning("Invalid webhook signature.")
            return web.Response(status=401, text="Unauthorized")

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            return web.Response(status=400, text="Bad Request")

        # Offload processing to a background task
        task = asyncio.create_task(self._process_payload(payload))
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

        return web.Response(status=202, text="Accepted")

    async def _process_payload(self, payload: Dict[str, Any]) -> None:
        start_time = time.time()
        task_id = payload.get("task_id")
        threat_candidates = payload.get("threat_signature_candidates", [])
        
        with tracer.start_as_current_span("process_webhook_payload") as span:
            span.set_attribute("event_id", payload.get("event_id", ""))
            span.set_attribute("task_id", task_id or "")
            
            if not task_id:
                logger.warning("Webhook payload missing task_id")
                return

            # Check if task is valid and not stale
            is_valid = await self.db.is_task_valid(task_id)
            if not is_valid:
                logger.warning(f"Task ID {task_id} is unknown or stale. Discarding.")
                span.set_attribute("status", "discarded")
                return

            signatures = []
            for candidate in threat_candidates:
                try:
                    sig = await Agent_Behavioral_Analytics.generateSignature(candidate)
                    signatures.append(sig)
                except Exception as e:
                    logger.error(f"Failed to generate signature for candidate: {e}")

            if signatures:
                try:
                    await self.db.write_signatures_batch(signatures)
                except Exception as e:
                    logger.error(f"Failed to write signatures to DB: {e}")
            
            # Remove from in-flight
            await self.db.remove_in_flight_task(task_id)

            latency_ms = (time.time() - start_time) * 1000
            span.set_attribute("processing_latency_ms", latency_ms)
            span.set_attribute("signatures_created_count", len(signatures))
            logger.info(f"Processed webhook for task {task_id} in {latency_ms:.2f}ms")

    async def start(self) -> None:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", self.port)
        await self.site.start()
        logger.info(f"Webhook listener started on port {self.port}")

    async def stop(self) -> None:
        logger.info("Stopping webhook listener...")
        if self.runner:
            await self.runner.cleanup()
        
        # Wait for background tasks to complete with a grace period of 30 seconds
        if self.background_tasks:
            logger.info(f"Waiting for {len(self.background_tasks)} background tasks to complete...")
            done, pending = await asyncio.wait(
                self.background_tasks, timeout=30.0
            )
            if pending:
                logger.warning(f"{len(pending)} background tasks did not complete in time.")
                for task in pending:
                    task.cancel()
        logger.info("Webhook listener stopped.")
