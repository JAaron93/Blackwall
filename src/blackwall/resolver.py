import asyncio
import inspect
import json
import logging
import os
import time
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from blackwall.models import (
    CallbackToken,
    EventType,
    SecurityEvent,
    ToolCallContext,
    Verdict,
    VerdictDecision,
    BatchPayload,
    BatchResponse,
    ResolverMetrics,
)
from blackwall.exceptions import APIRateLimitException
from blackwall.validators import normalize_text

logger = logging.getLogger(__name__)


class TokenBucketRateLimiter:
    """Thread-safe and async-safe token bucket rate limiter."""

    def __init__(self, capacity: float = 300.0, refill_rate: float = 5.0):
        # 300 RPM -> refill rate of 300 / 60 = 5 tokens per second
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, amount: float = 1.0) -> bool:
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class ContextHygiene:
    """Sanitizes tool call contexts by redacting sensitive data according to regex patterns."""

    DEFAULT_PATTERNS = [
        (
            "gcp_sa_json",
            r'\{\s*"type"\s*:\s*"service_account"[\s\S]+?\}',
            "[[GCP_SERVICE_ACCOUNT_KEY]]",
        ),
        (
            "rsa_key",
            r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----",
            "[[RSA_PRIVATE_KEY]]",
        ),
        (
            "openai_key",
            r"sk-[a-zA-Z0-9_\-]{10,}",
            "[[OPENAI_API_KEY]]",
        ),
        (
            "stripe_key",
            r"sk_test_[a-zA-Z0-9_\-]+",
            "[[STRIPE_SECRET_KEY]]",
        ),
        (
            "jwt_token",
            r"eyJ[a-zA-Z0-9_\-]{5,}(?:\.eyJ[a-zA-Z0-9_\-]{5,})?(?:\.[a-zA-Z0-9_\-]+)?",
            "[[JWT_TOKEN]]",
        ),
        (
            "aws_access_key",
            r"(?i)aws_access_key_id[\s:=]+['\"]?([^\s'\"]+)",
            "AWS_ACCESS_KEY_ID=[[AWS_ACCESS_KEY_ID]]",
        ),
        (
            "aws_secret_key",
            r"(?i)aws_secret_access_key[\s:=]+['\"]?([^\s'\"]+)",
            "AWS_SECRET_ACCESS_KEY=[[AWS_SECRET_ACCESS_KEY]]",
        ),
        (
            "api_key",
            r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{10,})",
            "[[API_KEY]]",
        ),
        ("url", r"https?://[^\s]+", "[[URL]]"),
        ("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[[IP_ADDRESS]]"),
        ("file_path", r"(?:/[^/\s]+)+/?", "[[FILE_PATH]]"),
        (
            "password",
            r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)",
            "[[PASSWORD]]",
        ),
        ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[[EMAIL]]"),
    ]

    IOC_PRESERVED_PATTERNS = [
        (
            "gcp_sa_json",
            r'\{\s*"type"\s*:\s*"service_account"[\s\S]+?\}',
            "[[GCP_SERVICE_ACCOUNT_KEY]]",
        ),
        (
            "rsa_key",
            r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----",
            "[[RSA_PRIVATE_KEY]]",
        ),
        (
            "openai_key",
            r"sk-[a-zA-Z0-9_\-]{10,}",
            "[[OPENAI_API_KEY]]",
        ),
        (
            "stripe_key",
            r"sk_test_[a-zA-Z0-9_\-]+",
            "[[STRIPE_SECRET_KEY]]",
        ),
        (
            "jwt_token",
            r"eyJ[a-zA-Z0-9_\-]{5,}(?:\.eyJ[a-zA-Z0-9_\-]{5,})?(?:\.[a-zA-Z0-9_\-]+)?",
            "[[JWT_TOKEN]]",
        ),
        (
            "aws_access_key",
            r"(?i)aws_access_key_id[\s:=]+['\"]?([^\s'\"]+)",
            "AWS_ACCESS_KEY_ID=[[AWS_ACCESS_KEY_ID]]",
        ),
        (
            "aws_secret_key",
            r"(?i)aws_secret_access_key[\s:=]+['\"]?([^\s'\"]+)",
            "AWS_SECRET_ACCESS_KEY=[[AWS_SECRET_ACCESS_KEY]]",
        ),
        (
            "bearer_token",
            r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{10,})",
            "[[API_KEY]]",
        ),
        (
            "url_query_secret",
            r"([?&](?:token|key|secret|password|api_key|auth)=)([^&\s'\"]+)",
            "[[API_KEY]]",
        ),
        (
            "api_key",
            r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{10,})",
            "[[API_KEY]]",
        ),
        (
            "password",
            r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)",
            "[[PASSWORD]]",
        ),
        ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[[EMAIL]]"),
    ]

    _COMPILED_DEFAULT_PATTERNS = []
    _name = _pat = _placeholder = None
    for _name, _pat, _placeholder in DEFAULT_PATTERNS:
        _COMPILED_DEFAULT_PATTERNS.append((_name, re.compile(_pat), _placeholder))
    del _name, _pat, _placeholder

    _COMPILED_IOC_PRESERVED_PATTERNS = []
    for _name, _pat, _placeholder in IOC_PRESERVED_PATTERNS:
        _COMPILED_IOC_PRESERVED_PATTERNS.append((_name, re.compile(_pat), _placeholder))
    del _name, _pat, _placeholder

    def __init__(
        self,
        patterns: Optional[List[tuple[str, str, str]]] = None,
        preserve_iocs: bool = False,
    ):
        self.preserve_iocs = preserve_iocs
        if patterns is None:
            if self.preserve_iocs:
                self.patterns = list(self._COMPILED_IOC_PRESERVED_PATTERNS)
                raw_patterns = [
                    (name, pat, placeholder)
                    for name, pat, placeholder in self.IOC_PRESERVED_PATTERNS
                ]
            else:
                self.patterns = list(self._COMPILED_DEFAULT_PATTERNS)
                raw_patterns = [
                    (name, pat, placeholder)
                    for name, pat, placeholder in self.DEFAULT_PATTERNS
                ]
        else:
            self.patterns = []
            raw_patterns = []
            for name, pat, placeholder in patterns:
                self.patterns.append((name, re.compile(pat), placeholder))
                raw_patterns.append((name, pat, placeholder))
        try:
            try:
                from blackwall import _core_rs
            except ImportError:
                import _core_rs

            self._rust_sanitizer = _core_rs.ContextSanitizer(raw_patterns)
        except (ImportError, AttributeError):
            self._rust_sanitizer = None

    def _repl(self, match: Any, placeholder_str: str) -> str:
        full: str = str(match.group(0))
        prefix: str = str(match.group(1))
        secret: str = str(match.group(2))
        start_idx = full.find(secret, len(prefix))
        if start_idx != -1:
            return (
                full[:start_idx]
                + placeholder_str
                + full[start_idx + len(secret) :]
            )
        return full

    def sanitize_string(self, text: str) -> str:
        if (
            not self.preserve_iocs
            and self._rust_sanitizer is not None
            and len(self.patterns) == len(self._COMPILED_DEFAULT_PATTERNS)
        ):
            try:
                return self._rust_sanitizer.sanitize_string(text, True)
            except Exception as e:
                logger.warning(
                    f"Rust sanitizer failed in resolver, falling back to Python: {e}"
                )

        for name, regex, placeholder in self.patterns:
            if name in ("password", "api_key", "bearer_token", "url_query_secret"):
                # Capture current placeholder via default-argument to avoid late-binding
                # of the loop variable during regex substitution callbacks.
                text = regex.sub(lambda m, p=placeholder: self._repl(m, p), text)
            else:
                text = regex.sub(placeholder, text)
        return text

    def sanitize_value(self, val: Any) -> Any:
        if isinstance(val, str):
            return self.sanitize_string(val)
        elif isinstance(val, dict):
            return {k: self.sanitize_value(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [self.sanitize_value(v) for v in val]
        return val

    def sanitize_context(self, context: ToolCallContext) -> ToolCallContext:
        sanitized_arguments = self.sanitize_value(context.arguments)
        sanitized_metadata = (
            self.sanitize_value(context.metadata) if context.metadata else None
        )
        return ToolCallContext(
            tool_name=context.tool_name,
            arguments=sanitized_arguments,
            metadata=sanitized_metadata,
        )


class BatchResolver:
    """Orchestrates synchronous and background Gemini Interactions API calls with rate limiting and context caching."""

    def __init__(
        self,
        client: Any,
        policy_snapshot: Optional[Dict[str, Any]] = None,
        webhook_port: int = 8090,
        repo: Any = None,
        aba: Any = None,
    ):
        self.client = client
        self.policy_snapshot = policy_snapshot or {}
        self.webhook_port = webhook_port
        self.repo = repo
        if aba is not None:
            self.aba = aba
        elif self.repo is not None:
            from blackwall.analytics import AgentBehavioralAnalytics

            self.aba = AgentBehavioralAnalytics(repo=self.repo, client=self.client)
        else:
            self.aba = None

        # Components
        self.rate_limiter = TokenBucketRateLimiter(capacity=300.0, refill_rate=5.0)
        self.hygiene = ContextHygiene(preserve_iocs=True)

        # Background task registry for self-learning loop lifecycle tracking
        self._background_tasks: set[asyncio.Task[Any]] = set()

        # Cache Tracking
        self.last_interaction_id: Optional[str] = None

        # Metrics
        self.total_batches = 0
        self.total_callbacks = 0
        self.total_latency_ms = 0.0
        self.rate_limit_hits = 0
        self.cache_hits = 0

        # Tier 3 background tasks
        self.background_tasks_submitted = 0
        self.webhook_callbacks_received = 0
        self.total_webhook_latency_ms = 0.0

    async def _acquire_rate_limit_token(self) -> None:
        """Acquires a token from the rate limiter or raises APIRateLimitException."""
        if not await self.rate_limiter.consume(1.0):
            self.rate_limit_hits += 1
            raise APIRateLimitException("Local rate limit exceeded (300 RPM cap)")

    def get_metrics(self) -> ResolverMetrics:
        """Returns the ResolverMetrics structure."""
        avg_batch_size = (
            self.total_callbacks / self.total_batches if self.total_batches > 0 else 0.0
        )
        avg_latency = (
            self.total_latency_ms / self.total_batches
            if self.total_batches > 0
            else 0.0
        )
        cache_hit_rate = (
            self.cache_hits / self.total_batches if self.total_batches > 0 else 0.0
        )
        return ResolverMetrics(
            total_batches=self.total_batches,
            average_batch_size=avg_batch_size,
            average_latency_ms=avg_latency,
            rate_limit_hits=self.rate_limit_hits,
            cache_hit_rate=cache_hit_rate,
        )

    def track_background_submission(self) -> None:
        """Metrics tracking hook for background tasks."""
        self.background_tasks_submitted += 1

    def track_webhook_callback(self, latency_ms: float) -> None:
        """Metrics tracking hook for webhook completions."""
        self.webhook_callbacks_received += 1
        self.total_webhook_latency_ms += latency_ms

    def _schedule_task(self, coro: Any) -> None:
        """Schedules background learning work with lifecycle tracking and error logging."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(coro)
            self._background_tasks.add(task)

            def _done(t: asyncio.Task[Any]) -> None:
                self._background_tasks.discard(t)
                if not t.cancelled() and t.exception():
                    logger.warning("Background learning task failed: %s", t.exception())

            task.add_done_callback(_done)
        except RuntimeError:
            pass

    async def flush_background_tasks(self) -> None:
        """Awaits all pending background learning tasks to complete."""
        if self._background_tasks:
            await asyncio.gather(*list(self._background_tasks), return_exceptions=True)

    async def close(self) -> None:
        """Flushes background tasks before closing."""
        await self.flush_background_tasks()

    async def process_batch(
        self, callback_tokens: List[CallbackToken]
    ) -> BatchResponse:
        """Entrypoint for Tier 2 evaluation of a batch of callback tokens."""
        from blackwall.telemetry import get_tracer, get_metric
        from opentelemetry.trace import Status, StatusCode, format_span_id

        tracer = get_tracer("blackwall.resolver")
        batch_size_metric = get_metric("batch_size")
        latency_metric = get_metric("api_latency_seconds")
        errors_metric = get_metric("errors_total")
        cache_hits_metric = get_metric("cache_hits_total")

        with tracer.start_as_current_span("resolve_batch") as span:
            span.set_attribute("blackwall.batch_size", len(callback_tokens))
            start_time = time.time()

            # Best-effort telemetry: track batch size
            try:
                if batch_size_metric:
                    batch_size_metric.add(len(callback_tokens))
            except Exception:
                logger.debug("Failed to record batch size metric", exc_info=True)

            if not callback_tokens:
                span.set_attribute("blackwall.cache_hit_count", 0)
                span.set_status(Status(StatusCode.OK))
                return BatchResponse(
                    verdicts=[],
                    processing_time=0.0,
                    tokens_consumed=0,
                    cache_hit_count=0,
                )

            # Apply Context Hygiene to all contexts
            sanitized_contexts = [
                (
                    self.hygiene.sanitize_context(token.tool_context)
                    if token.tool_context
                    else ToolCallContext(tool_name="", arguments={})
                )
                for token in callback_tokens
            ]

            # Retry loop with exponential backoff for APIRateLimitException
            backoff_delays = [0.1, 0.2, 0.4]  # 100ms, 200ms, 400ms
            max_retries = 3
            retry_count = 0

            while True:
                try:
                    # Ensure we conform to local rate limits
                    await self._acquire_rate_limit_token()

                    # Execute submitToGeminiSync (API call only) with a hardcoded 30-second timeout for local MVP.
                    # asyncio.wait_for() raises TimeoutError to the caller and cancels the wrapped coroutine.
                    response = await asyncio.wait_for(
                        self.submit_to_gemini_sync(sanitized_contexts), timeout=30.0
                    )

                    # Post-response telemetry (best-effort, guarded)
                    latency_ms = (time.time() - start_time) * 1000.0

                    try:
                        if latency_metric:
                            latency_metric.record(latency_ms / 1000.0)
                    except Exception:
                        logger.debug("Failed to record latency metric", exc_info=True)

                    self.total_batches += 1
                    self.total_callbacks += len(callback_tokens)
                    self.total_latency_ms += latency_ms

                    try:
                        span.set_attribute(
                            "blackwall.cache_hit_count", response.cache_hit_count
                        )
                        span.set_attribute(
                            "blackwall.tokens_consumed", response.tokens_consumed
                        )
                        span.set_attribute("blackwall.processing_time_ms", latency_ms)
                    except Exception:
                        logger.debug("Failed to set span attributes", exc_info=True)

                    if response.cache_hit_count > 0:
                        self.cache_hits += 1
                        try:
                            if cache_hits_metric:
                                cache_hits_metric.add(response.cache_hit_count)
                        except Exception:
                            logger.debug(
                                "Failed to record cache hits metric", exc_info=True
                            )

                    # Periodically log metrics for monitoring dashboards
                    try:
                        if self.total_batches % 10 == 0:
                            metrics = self.get_metrics()
                            logger.info(
                                f"BatchResolver Metrics: {metrics.model_dump_json()}"
                            )
                    except Exception:
                        logger.debug("Failed to log periodic metrics", exc_info=True)

                    try:
                        span.set_status(Status(StatusCode.OK))
                    except Exception:
                        logger.debug("Failed to log status", exc_info=True)

                    # Best-effort: attach span ID to callback tokens for correlation
                    try:
                        span_id_hex = format_span_id(span.get_span_context().span_id)
                        for token in callback_tokens:
                            token.telemetry_span_id = span_id_hex
                    except Exception:
                        logger.debug(
                            "Failed to attach span ID to callback tokens", exc_info=True
                        )

                    # Wire self-learning loop (ABA) after batch verdicts are produced
                    if self.aba:
                        for token, verdict in zip(callback_tokens, response.verdicts):
                            if verdict.decision == VerdictDecision.BLOCK:
                                try:
                                    sec_event = SecurityEvent(
                                        event_type=EventType.BLOCK,
                                        tool_context=token.tool_context or ToolCallContext(tool_name="unknown", arguments={}),
                                        verdict=verdict,
                                        telemetry_span_id=getattr(token, "telemetry_span_id", None),
                                    )
                                    self._schedule_task(self.aba.generateSignature(sec_event))
                                except Exception as aba_err:
                                    logger.debug("Failed to dispatch ABA generateSignature: %s", aba_err)
                            elif verdict.decision == VerdictDecision.QUARANTINE:
                                try:
                                    sec_event = SecurityEvent(
                                        event_type=EventType.QUARANTINE,
                                        tool_context=token.tool_context or ToolCallContext(tool_name="unknown", arguments={}),
                                        verdict=verdict,
                                        telemetry_span_id=getattr(token, "telemetry_span_id", None),
                                    )
                                    self._schedule_task(self.aba.triggerRefactoring(sec_event))
                                except Exception as aba_err:
                                    logger.debug("Failed to dispatch ABA triggerRefactoring: %s", aba_err)

                    return response

                except (APIRateLimitException, Exception) as e:
                    # Log critical error on timeout
                    if isinstance(e, asyncio.TimeoutError):
                        logger.critical(
                            "Evaluation pipeline API call timed out (30-second limit exceeded). Auto-restarting pipeline execution."
                        )

                    # Check if this exception is a rate limit error (status 429 or message)
                    err_msg = str(e).lower()
                    is_rate_limit = (
                        isinstance(e, APIRateLimitException)
                        or "429" in err_msg
                        or "rate_limit" in err_msg
                        or "rate limit" in err_msg
                        or "resourceexhausted" in err_msg
                        or "resource_exhausted" in err_msg
                    )

                    if is_rate_limit and retry_count < max_retries:
                        delay = backoff_delays[retry_count]
                        logger.warning(
                            f"Rate limit hit. Retrying batch in {delay*1000:.0f}ms (Attempt {retry_count + 1}/{max_retries})"
                        )
                        retry_count += 1
                        await asyncio.sleep(delay)
                        continue

                    # Best-effort telemetry in error path
                    try:
                        if errors_metric:
                            errors_metric.add(1)
                    except Exception:
                        logger.debug("Failed to record error metric", exc_info=True)

                    try:
                        span.record_exception(e)
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                    except Exception:
                        logger.debug(
                            "Failed to record exception in span", exc_info=True
                        )

                    # If we've exhausted retries or encountered a non-rate limit exception, fail-closed
                    logger.error(
                        f"Batch submission failed permanently: {e}. Applying fail-closed policy (QUARANTINE)."
                    )

                    # Fail-closed fallback: return QUARANTINE verdicts
                    verdicts = [
                        Verdict(
                            decision=VerdictDecision.QUARANTINE,
                            reasoning=f"Rate limit exceeded or permanent API failure - conservative deny pending re-evaluation: {e}",
                            confidence_score=1.0,
                        )
                        for _ in callback_tokens
                    ]

                    latency_ms = (time.time() - start_time) * 1000.0

                    # Best-effort telemetry in fail-closed path
                    try:
                        if latency_metric:
                            latency_metric.record(latency_ms / 1000.0)
                    except Exception:
                        logger.debug(
                            "Failed to record latency metric in fail-closed path",
                            exc_info=True,
                        )

                    self.total_batches += 1
                    self.total_callbacks += len(callback_tokens)
                    self.total_latency_ms += latency_ms

                    # Best-effort: attach span ID to callback tokens for correlation
                    try:
                        span_id_hex = format_span_id(span.get_span_context().span_id)
                        for token in callback_tokens:
                            token.telemetry_span_id = span_id_hex
                    except Exception:
                        logger.debug(
                            "Failed to attach span ID to callback tokens in fail-closed path",
                            exc_info=True,
                        )

                    return BatchResponse(
                        verdicts=verdicts,
                        processing_time=latency_ms,
                        tokens_consumed=0,
                        cache_hit_count=0,
                    )

    async def submit_to_gemini_sync(
        self, sanitized_contexts: List[ToolCallContext]
    ) -> BatchResponse:
        """Submits the sanitized batch synchronously to Gemini 3.5 Flash-Lite."""
        start_time = time.time()

        # Network-level timeout for the Gemini API call (25 seconds).
        # This applies a real HTTP timeout at the request level, which properly interrupts
        # blocking HTTP calls even when running in an executor thread.
        # The asyncio.wait_for(30s) in process_batch() acts as a secondary backstop.
        API_CALL_TIMEOUT = 25.0

        # Build payload
        payload = BatchPayload(
            sanitized_contexts=sanitized_contexts,
            policy_snapshot=self.policy_snapshot,
            previous_interaction_id=self.last_interaction_id,
        )

        payload_json = payload.model_dump_json()

        # Call Gemini Interactions API
        try:
            # Lazy import: keeps gateway import-time off the google-genai
            # chain so daemon cold start stays within the <2s budget.
            from blackwall.config import DEFAULT_RAPID_TRIAGE_MODEL, get_gemini_thinking_level

            # Call Gemini Interactions API
            thinking_lvl = get_gemini_thinking_level(
                model=DEFAULT_RAPID_TRIAGE_MODEL, task_type="rapid_triage"
            )
            create_kwargs = {
                "model": DEFAULT_RAPID_TRIAGE_MODEL,
                "input": payload_json,
                "previous_interaction_id": payload.previous_interaction_id,
                "response_schema": list[Verdict],
                "response_mime_type": "application/json",
                "thinking_level": thinking_lvl,
                "timeout": API_CALL_TIMEOUT,
            }
            aio_interactions = getattr(getattr(self.client, "aio", None), "interactions", None)
            aio_create = getattr(aio_interactions, "create", None)
            sync_create = getattr(getattr(self.client, "interactions", None), "create", None)

            if aio_create is not None and inspect.iscoroutinefunction(aio_create):
                interaction = await aio_create(**create_kwargs)
            elif sync_create is not None and inspect.iscoroutinefunction(sync_create):
                interaction = await sync_create(**create_kwargs)
            else:
                # Run synchronous call in executor with network-level timeout
                loop = asyncio.get_running_loop()
                interaction = await loop.run_in_executor(
                    None,
                    lambda: self.client.interactions.create(**create_kwargs),
                )

            # Update last interaction ID for server-side context caching
            if hasattr(interaction, "id"):
                self.last_interaction_id = interaction.id

            # Parse verdicts: first check native structured outputs (parsed / outputs), falling back to output_text
            parsed_output = getattr(interaction, "parsed", None)
            if not isinstance(parsed_output, (list, dict)):
                parsed_output = None
            if parsed_output is None and hasattr(interaction, "outputs") and isinstance(interaction.outputs, (list, dict)):
                parsed_output = interaction.outputs

            if parsed_output is not None:
                verdicts = self._parse_verdicts(parsed_output, len(sanitized_contexts))
            else:
                raw_text = getattr(interaction, "output_text", "")
                output_text = raw_text if isinstance(raw_text, str) else ""
                verdicts = self._parse_verdicts(output_text, len(sanitized_contexts))

            # Retrieve usage details
            usage = getattr(interaction, "usage", None)
            raw_tokens = getattr(usage, "total_tokens", 0) if usage else 0
            tokens_consumed = int(raw_tokens) if isinstance(raw_tokens, (int, float)) else 0
            raw_cached = (
                getattr(usage, "cached_content_token_count", 0) if usage else 0
            )
            cached_tokens = int(raw_cached) if isinstance(raw_cached, (int, float)) else 0

            # Target >=50% token reduction on cache hits
            cache_hit_count = (
                1
                if cached_tokens > 0 or (payload.previous_interaction_id is not None)
                else 0
            )

            processing_time = (time.time() - start_time) * 1000.0
            return BatchResponse(
                verdicts=verdicts,
                processing_time=processing_time,
                tokens_consumed=tokens_consumed,
                cache_hit_count=cache_hit_count,
            )

        except Exception as e:
            # Wrap as APIRateLimitException if rate limit matches
            err_msg = str(e).lower()
            if (
                "429" in err_msg
                or "rate_limit" in err_msg
                or "rate limit" in err_msg
                or "resourceexhausted" in err_msg
                or "resource_exhausted" in err_msg
            ):
                raise APIRateLimitException(f"Gemini API rate limit: {e}") from e
            raise e

    async def submit_to_gemini_background(
        self,
        quarantined_context: ToolCallContext,
        related_signatures: List[Any],
        cbm_chain: List[Any],
        threat_intel_data: Any = None,
        gti_data: Any = None,
    ) -> str:
        """Submits deep analysis in the background to Gemini 3.8 Flash.

        Returns:
            task_id: The ID of the background interaction.
        """
        ti_data = threat_intel_data if threat_intel_data is not None else gti_data
        # Ensure we conform to local rate limits
        await self._acquire_rate_limit_token()

        # Network-level timeout for background tasks (120s floor for Gemini 3.8 Flash extended reasoning).
        # This applies a real HTTP timeout at the request level.
        from blackwall.config import get_gemini_http_timeout

        API_CALL_TIMEOUT = get_gemini_http_timeout(task_type="analysis")

        # Build payload input
        payload_input = {
            "quarantined_context": quarantined_context.model_dump(),
            "related_signatures": [
                sig.model_dump() if hasattr(sig, "model_dump") else sig
                for sig in related_signatures
            ],
            "cbm_dependency_chain": cbm_chain,
            "threat_intel_ioc_data": ti_data,
            "gti_ioc_data": ti_data,
        }

        webhook_url = f"http://localhost:{self.webhook_port}/webhook/analysis_complete"
        webhook_config = {"uris": [webhook_url]}

        try:
            create_fn = self.client.interactions.create
            if inspect.iscoroutinefunction(create_fn):
                interaction = await create_fn(
                    model="gemini-3.8-flash",
                    input=json.dumps(payload_input),
                    background=True,
                    webhook_config=webhook_config,
                    timeout=API_CALL_TIMEOUT,
                )
            else:
                # Run synchronous call in executor with network-level timeout
                loop = asyncio.get_running_loop()
                interaction = await loop.run_in_executor(
                    None,
                    lambda: create_fn(
                        model="gemini-3.8-flash",
                        input=json.dumps(payload_input),
                        background=True,
                        webhook_config=webhook_config,
                        timeout=API_CALL_TIMEOUT,
                    ),
                )

            self.track_background_submission()

            task_id = getattr(interaction, "id", None) or str(uuid4())
            return task_id

        except Exception as e:
            err_msg = str(e).lower()
            if (
                "429" in err_msg
                or "rate_limit" in err_msg
                or "rate limit" in err_msg
                or "resourceexhausted" in err_msg
                or "resource_exhausted" in err_msg
            ):
                raise APIRateLimitException(f"Gemini API rate limit: {e}") from e
            raise e

    def _parse_verdicts(self, output_text: Any, batch_size: int) -> List[Verdict]:
        """Cleans and parses the LLM output into a list of Verdicts matching the batch size."""
        if batch_size == 0:
            return []

        # If output is already structured (e.g. from native structured outputs)
        if isinstance(output_text, list):
            data = output_text
        elif isinstance(output_text, dict) and "verdicts" in output_text:
            data = output_text["verdicts"]
        else:
            cleaned_text = str(output_text).strip() if output_text is not None else ""

            # Clean markdown code blocks if any
            if cleaned_text.startswith("```"):
                first_line_end = cleaned_text.find("\n")
                if first_line_end != -1:
                    cleaned_text = cleaned_text[first_line_end:]
                if cleaned_text.endswith("```"):
                    cleaned_text = cleaned_text[:-3]
                cleaned_text = cleaned_text.strip()

            try:
                data = json.loads(cleaned_text)
                if not isinstance(data, list):
                    raise ValueError("Expected a JSON list of verdicts")
            except Exception as e:
                logger.error(
                    f"Failed to parse LLM verdicts: {e}. Output was: {output_text}"
                )
                return [
                    Verdict(
                        decision=VerdictDecision.QUARANTINE,
                        reasoning=f"Failed to parse model response: {e}",
                        confidence_score=1.0,
                    )
                    for _ in range(batch_size)
                ]

        try:
            verdicts = []
            for item in data:
                if isinstance(item, Verdict):
                    verdicts.append(item)
                elif isinstance(item, dict):
                    verdicts.append(
                        Verdict(
                            decision=VerdictDecision(item.get("decision", "QUARANTINE")),
                            reasoning=item.get("reasoning", "Parsed from model response"),
                            confidence_score=float(item.get("confidence_score", 0.5)),
                        )
                    )
                else:
                    raise ValueError(f"Unsupported verdict item type: {type(item)}")

            # Check for size mismatch
            if len(verdicts) != batch_size:
                raise ValueError(
                    f"Verdict size mismatch: got {len(verdicts)}, expected {batch_size}"
                )

            return verdicts

        except Exception as e:
            logger.error(
                f"Failed to parse LLM verdicts: {e}. Output was: {output_text}"
            )
            # Fail-closed: return QUARANTINE verdicts for all items
            return [
                Verdict(
                    decision=VerdictDecision.QUARANTINE,
                    reasoning=f"Failed to parse model response: {e}",
                    confidence_score=1.0,
                )
                for _ in range(batch_size)
            ]


# ---------------------------------------------------------------------------
# Tier-detection factory
# ---------------------------------------------------------------------------


def create_resolver(
    client: Any,
    policy_server: Any = None,
    repo: Any = None,
    threat_intel: Any = None,
    cbm_client: Any = None,
    gti_client: Any = None,
    gti_budget_tracker: Any = None,
    webhook_port: int = 8090,
    policy_snapshot: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Factory: returns BatchResolver (default, 300 RPM batch mode) or SyncResolver
    (300 RPM synchronous mode) based on BLACKWALL_TIER or BLACKWALL_RESOLVER_MODE.
    Defaults to 'paid' (BatchResolver, 300 RPM) under 100% GCP Vertex AI Mode.

    Usage:
        resolver = create_resolver(client, policy_server=server, repo=repo)

    Environment:
        BLACKWALL_TIER=paid             → BatchResolver (default, 300 RPM)
        BLACKWALL_RESOLVER_MODE=sync    → SyncResolver (300 RPM)
    """
    mode = normalize_text(os.getenv("BLACKWALL_RESOLVER_MODE", ""))
    tier = normalize_text(os.getenv("BLACKWALL_TIER", "paid"))

    if mode == "sync" or tier in ("sync", "free"):
        from blackwall.sync_resolver import SyncResolver

        ti = threat_intel or gti_client
        if ti is None and repo is not None:
            try:
                from blackwall.threat_intel import ThreatIntelOrchestrator

                ti = ThreatIntelOrchestrator(repository=repo)
            except Exception:
                ti = None

        return SyncResolver(
            client=client,
            policy_server=policy_server,
            repo=repo,
            threat_intel=ti,
            cbm_client=cbm_client,
            gti_client=ti,
            gti_budget_tracker=gti_budget_tracker,
        )
    return BatchResolver(
        client=client,
        policy_snapshot=policy_snapshot or {},
        webhook_port=webhook_port,
        repo=repo,
    )
