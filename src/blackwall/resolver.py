import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from blackwall.models import (
    CallbackToken,
    ToolCallContext,
    Verdict,
    VerdictDecision,
    BatchPayload,
    BatchResponse,
    ResolverMetrics,
)
from blackwall.exceptions import APIRateLimitException

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
            "api_key",
            r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
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

    def __init__(self, patterns: Optional[List[tuple]] = None):
        import re

        self.patterns = []
        raw_patterns = patterns or self.DEFAULT_PATTERNS
        for name, pat, placeholder in raw_patterns:
            self.patterns.append((name, re.compile(pat), placeholder))

    def sanitize_string(self, text: str) -> str:
        for name, regex, placeholder in self.patterns:
            if name in ("password", "api_key"):

                def repl(match):
                    full = match.group(0)
                    prefix = match.group(1)
                    secret = match.group(2)
                    start_idx = full.find(secret, len(prefix))
                    if start_idx != -1:
                        return (
                            full[:start_idx]
                            + placeholder
                            + full[start_idx + len(secret) :]
                        )
                    return full

                text = regex.sub(repl, text)
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
    ):
        self.client = client
        self.policy_snapshot = policy_snapshot or {}
        self.webhook_port = webhook_port

        # Components
        self.rate_limiter = TokenBucketRateLimiter(capacity=300.0, refill_rate=5.0)
        self.hygiene = ContextHygiene()

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

    async def _acquire_rate_limit_token(self):
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

    def track_background_submission(self):
        """Metrics tracking hook for background tasks."""
        self.background_tasks_submitted += 1

    def track_webhook_callback(self, latency_ms: float):
        """Metrics tracking hook for webhook completions."""
        self.webhook_callbacks_received += 1
        self.total_webhook_latency_ms += latency_ms

    async def process_batch(
        self, callback_tokens: List[CallbackToken]
    ) -> BatchResponse:
        """Entrypoint for Tier 2 evaluation of a batch of callback tokens."""
        from blackwall.telemetry import get_tracer, get_metric
        from opentelemetry.trace import Status, StatusCode
        import json

        tracer = get_tracer("blackwall.resolver")
        batch_size_metric = get_metric("batch_size")
        latency_metric = get_metric("api_latency_seconds")
        errors_metric = get_metric("errors_total")
        cache_hits_metric = get_metric("cache_hits_total")

        if batch_size_metric:
            batch_size_metric.add(len(callback_tokens))

        with tracer.start_as_current_span("resolve_batch") as span:
            span.set_attribute("blackwall.batch_size", len(callback_tokens))
            start_time = time.time()

            if not callback_tokens:
                span.set_attribute("blackwall.cache_hit_count", 0)
                span.set_status(Status(StatusCode.OK))
                return BatchResponse(
                    verdicts=[], processing_time=0.0, tokens_consumed=0, cache_hit_count=0
                )

            # Apply Context Hygiene to all contexts
            sanitized_contexts = [
                self.hygiene.sanitize_context(token.tool_context)
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

                    # Execute submitToGeminiSync
                    response = await self.submit_to_gemini_sync(sanitized_contexts)

                    # Update metrics
                    latency_ms = (time.time() - start_time) * 1000.0
                    
                    if latency_metric:
                        latency_metric.record(latency_ms / 1000.0)
                    
                    self.total_batches += 1
                    self.total_callbacks += len(callback_tokens)
                    self.total_latency_ms += latency_ms
                    
                    span.set_attribute("blackwall.cache_hit_count", response.cache_hit_count)
                    span.set_attribute("blackwall.tokens_consumed", response.tokens_consumed)
                    span.set_attribute("blackwall.processing_time_ms", latency_ms)
                    
                    if response.cache_hit_count > 0:
                        self.cache_hits += 1
                        if cache_hits_metric:
                            cache_hits_metric.add(response.cache_hit_count)

                    # Periodically log metrics for monitoring dashboards
                    if self.total_batches % 10 == 0:
                        metrics = self.get_metrics()
                        logger.info(f"BatchResolver Metrics: {metrics.model_dump_json()}")

                    span.set_status(Status(StatusCode.OK))
                    
                    # Attach span IDs to callback tokens for later logging
                    for token in callback_tokens:
                        token.telemetry_span_id = str(span.get_span_context().span_id)
                        
                    return response

                except (APIRateLimitException, Exception) as e:
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

                    if errors_metric:
                        errors_metric.add(1)
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))

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
                    if latency_metric:
                        latency_metric.record(latency_ms / 1000.0)
                    
                    self.total_batches += 1
                    self.total_callbacks += len(callback_tokens)
                    self.total_latency_ms += latency_ms

                    # Attach span IDs to callback tokens for later logging
                    for token in callback_tokens:
                        token.telemetry_span_id = str(span.get_span_context().span_id)

                    return BatchResponse(
                        verdicts=verdicts,
                        processing_time=latency_ms,
                        tokens_consumed=0,
                        cache_hit_count=0,
                    )

    async def submit_to_gemini_sync(
        self, sanitized_contexts: List[ToolCallContext]
    ) -> BatchResponse:
        """Submits the sanitized batch synchronously to Gemini 3.1 Flash-Lite."""
        start_time = time.time()

        # Build payload
        payload = BatchPayload(
            sanitized_contexts=sanitized_contexts,
            policy_snapshot=self.policy_snapshot,
            previous_interaction_id=self.last_interaction_id,
        )

        payload_json = payload.model_dump_json()

        # Call Gemini Interactions API
        try:
            # We call the client.interactions.create asynchronously to prevent blocking the event loop
            # If the client library has sync methods, we can run them in an executor or call the async version if available.
            # We assume client.interactions.create is a coroutine or we call it directly if it supports it.
            # To be safe, we check if it's a coroutine or run it.
            create_fn = self.client.interactions.create
            if asyncio.iscoroutinefunction(create_fn):
                interaction = await create_fn(
                    model="gemini-3.1-flash-lite",
                    input=payload_json,
                    previous_interaction_id=payload.previous_interaction_id,
                )
            else:
                interaction = create_fn(
                    model="gemini-3.1-flash-lite",
                    input=payload_json,
                    previous_interaction_id=payload.previous_interaction_id,
                )

            # Update last interaction ID for server-side context caching
            if hasattr(interaction, "id"):
                self.last_interaction_id = interaction.id

            # Parse verdicts
            output_text = getattr(interaction, "output_text", "") or ""
            verdicts = self._parse_verdicts(output_text, len(sanitized_contexts))

            # Retrieve usage details
            usage = getattr(interaction, "usage", None)
            tokens_consumed = getattr(usage, "total_tokens", 0) if usage else 0
            cached_tokens = (
                getattr(usage, "cached_content_token_count", 0) if usage else 0
            )

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
        gti_data: Any,
    ) -> str:
        """Submits deep analysis in the background to Gemini 3.1 Pro-Preview.

        Returns:
            task_id: The ID of the background interaction.
        """
        # Ensure we conform to local rate limits
        await self._acquire_rate_limit_token()

        # Build payload input
        payload_input = {
            "quarantined_context": quarantined_context.model_dump(),
            "related_signatures": [
                sig.model_dump() if hasattr(sig, "model_dump") else sig
                for sig in related_signatures
            ],
            "cbm_dependency_chain": cbm_chain,
            "gti_ioc_data": gti_data,
        }

        webhook_url = f"http://localhost:{self.webhook_port}/webhook/analysis_complete"
        webhook_config = {"uris": [webhook_url]}

        try:
            create_fn = self.client.interactions.create
            if asyncio.iscoroutinefunction(create_fn):
                interaction = await create_fn(
                    model="gemini-3.1-pro-preview",
                    input=json.dumps(payload_input),
                    background=True,
                    webhook_config=webhook_config,
                )
            else:
                interaction = create_fn(
                    model="gemini-3.1-pro-preview",
                    input=json.dumps(payload_input),
                    background=True,
                    webhook_config=webhook_config,
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

    def _parse_verdicts(self, output_text: str, batch_size: int) -> List[Verdict]:
        """Cleans and parses the LLM output into a list of Verdicts matching the batch size."""
        cleaned_text = output_text.strip()

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

            verdicts = []
            for item in data:
                verdicts.append(
                    Verdict(
                        decision=VerdictDecision(item.get("decision", "QUARANTINE")),
                        reasoning=item.get("reasoning", "Parsed from model response"),
                        confidence_score=float(item.get("confidence_score", 0.5)),
                    )
                )

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
