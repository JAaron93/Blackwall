import asyncio
import collections
import datetime
import json
import logging
import os
import time
from typing import Any, Dict

import aiohttp
from aiohttp import web
import jwt
from jwt.algorithms import RSAAlgorithm
from opentelemetry import trace

from blackwall.analytics import Agent_Behavioral_Analytics
from blackwall.db.repository import SQLiteThreatRepository

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

class WebhookListener:
    def __init__(self, db_repository: SQLiteThreatRepository, gemini_client: Any, audience: str = ""):
        self.db = db_repository
        self.gemini_client = gemini_client
        self.port = int(os.environ.get("BLACKWALL_WEBHOOK_PORT", 8090))
        self.jwks_url = os.environ.get(
            "GEMINI_JWKS_URL",
            "https://generativelanguage.googleapis.com/.well-known/jwks.json"
        )
        self.audience = audience or os.environ.get("GEMINI_WEBHOOK_AUDIENCE", "")
        
        # JWKS key cache: { kid: public_key }
        self._jwks_cache: Dict[str, Any] = {}
        self._jwks_cache_expiry = 0.0
        self._jwks_cache_ttl = 3600.0  # 1 hour
        self._jwks_lock = asyncio.Lock()
        
        # Webhook deduplication
        self.processed_webhooks = set()
        self.processed_webhooks_queue = collections.deque(maxlen=10000)
        
        self.app = web.Application()
        self.app.router.add_post("/webhook/analysis_complete", self.handle_webhook)
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.background_tasks: set[asyncio.Task[Any]] = set()

    async def _fetch_jwks(self) -> dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(self.jwks_url) as resp:
                if resp.status != 200:
                    raise Exception(f"Failed to fetch JWKS from {self.jwks_url}: HTTP {resp.status}")
                return await resp.json()

    async def _get_public_key(self, kid: str) -> Any:
        now = time.time()
        if now > self._jwks_cache_expiry or kid not in self._jwks_cache:
            async with self._jwks_lock:
                if now > self._jwks_cache_expiry or kid not in self._jwks_cache:
                    try:
                        jwks = await self._fetch_jwks()
                        new_cache = {}
                        for key_data in jwks.get("keys", []):
                            k_id = key_data.get("kid")
                            if k_id:
                                pub_key = RSAAlgorithm.from_jwk(key_data)
                                new_cache[k_id] = pub_key
                        self._jwks_cache = new_cache
                        self._jwks_cache_expiry = now + self._jwks_cache_ttl
                    except Exception as e:
                        logger.error(f"Error fetching/parsing JWKS: {e}")
                        if kid in self._jwks_cache:
                            return self._jwks_cache[kid]
                        raise
        
        if kid not in self._jwks_cache:
            raise ValueError(f"Key ID {kid} not found in JWKS")
        return self._jwks_cache[kid]

    async def handle_webhook(self, request: web.Request) -> web.Response:
        request_start_time = time.time()
        
        token = request.headers.get("Webhook-Signature", "")
        if not token:
            logger.warning("Missing Webhook-Signature header.")
            return web.Response(status=400, text="Bad Request")
            
        timestamp_str = request.headers.get("webhook-timestamp", "")
        if not timestamp_str:
            logger.warning("Missing webhook-timestamp header.")
            return web.Response(status=400, text="Bad Request")
            
        webhook_id = request.headers.get("webhook-id", "")
        if not webhook_id:
            logger.warning("Missing webhook-id header.")
            return web.Response(status=400, text="Bad Request")

        # Validate timestamp (reject if older than 5 minutes)
        try:
            webhook_ts = float(timestamp_str)
        except ValueError:
            try:
                dt = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                webhook_ts = dt.timestamp()
            except ValueError:
                logger.warning(f"Invalid webhook-timestamp format: {timestamp_str}")
                return web.Response(status=400, text="Bad Request")

        if request_start_time - webhook_ts > 300:
            logger.warning(f"Webhook timestamp is stale: {webhook_ts} (current: {request_start_time})")
            return web.Response(status=400, text="Bad Request")

        # Deduplicate using webhook-id
        if webhook_id in self.processed_webhooks:
            logger.info(f"Duplicate webhook {webhook_id} ignored.")
            return web.Response(status=200, text="OK")

        if token.lower().startswith("bearer "):
            token = token[7:]

        # JWT RS256 Verification
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                logger.warning("JWT header missing kid.")
                return web.Response(status=400, text="Bad Request")
                
            public_key = await self._get_public_key(kid)
            
            decode_kwargs = {"algorithms": ["RS256"]}
            if self.audience:
                decode_kwargs["audience"] = self.audience
                
            jwt.decode(token, public_key, **decode_kwargs)
        except Exception as e:
            logger.warning(f"JWT verification failed: {e}")
            return web.Response(status=400, text="Bad Request")

        payload_bytes = await request.read()
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            logger.warning("Invalid JSON payload.")
            return web.Response(status=400, text="Bad Request")

        try:
            interaction_id = payload["data"]["id"]
        except (KeyError, TypeError):
            logger.warning("Payload missing data.id.")
            return web.Response(status=400, text="Bad Request")

        # Add to deduplication set
        if len(self.processed_webhooks_queue) >= 10000:
            oldest = self.processed_webhooks_queue.popleft()
            self.processed_webhooks.discard(oldest)
        self.processed_webhooks.add(webhook_id)
        self.processed_webhooks_queue.append(webhook_id)

        # Offload to background task
        webhook_latency_ms = (time.time() - request_start_time) * 1000
        task = asyncio.create_task(self._process_payload(interaction_id, webhook_latency_ms))
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)

        return web.Response(status=200, text="OK")

    async def _process_payload(self, interaction_id: str, webhook_latency_ms: float) -> None:
        fetch_start = time.time()
        
        with tracer.start_as_current_span("process_webhook_payload") as span:
            span.set_attribute("interaction_id", interaction_id)
            span.set_attribute("webhook_latency_ms", webhook_latency_ms)
            
            try:
                interaction = await self.gemini_client.interactions.get(interaction_id)
            except Exception as e:
                logger.error(f"Failed to fetch interaction {interaction_id}: {e}")
                span.set_status(trace.StatusCode.ERROR, str(e))
                return
                
            fetch_latency_ms = (time.time() - fetch_start) * 1000
            span.set_attribute("fetch_latency_ms", fetch_latency_ms)
            
            task_id = None
            candidates = []
            
            if isinstance(interaction, dict):
                task_id = interaction.get("task_id")
                candidates = interaction.get("threat_signature_candidates", [])
            else:
                task_id = getattr(interaction, "task_id", None)
                candidates = getattr(interaction, "threat_signature_candidates", [])
                
            if not task_id:
                logger.warning(f"Interaction {interaction_id} fetched output missing task_id.")
                span.set_attribute("status", "discarded")
                return
                
            span.set_attribute("task_id", task_id)
            
            is_valid = await self.db.is_task_valid(task_id)
            if not is_valid:
                logger.warning(f"Task ID {task_id} is unknown or stale. Discarding.")
                span.set_attribute("status", "discarded")
                return

            signatures = []
            for candidate in candidates:
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

            await self.db.remove_in_flight_task(task_id)

            span.set_attribute("signatures_created_count", len(signatures))
            logger.info(f"Processed webhook for task {task_id} (interaction {interaction_id}) in {webhook_latency_ms + fetch_latency_ms:.2f}ms")

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
