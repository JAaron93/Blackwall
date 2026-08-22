"""Unit tests for BatchResolver, TokenBucketRateLimiter, and ContextHygiene.

Tests cover: _parse_verdicts, _acquire_rate_limit_token, submit_to_gemini_sync,
submit_to_gemini_background, track_background_submission, track_webhook_callback,
TokenBucketRateLimiter.consume/refill, ContextHygiene.sanitize_value.
"""

import pytest
import asyncio
import json
import time
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

from blackwall.resolver import BatchResolver, ContextHygiene, TokenBucketRateLimiter
from blackwall.models import (
    BatchResponse,
    ResolverMetrics,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)
from blackwall.exceptions import APIRateLimitException


# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------


def make_batch_resolver():
    mock_client = MagicMock()
    return BatchResolver(client=mock_client)


# ===========================================================================
# Section 1: TokenBucketRateLimiter tests
# ===========================================================================


class TestTokenBucketRateLimiter:
    """Tests for TokenBucketRateLimiter."""

    async def test_token_bucket_consume_returns_true_when_available(self):
        """consume() returns True when tokens > 0."""
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=1.0)
        result = await limiter.consume(1.0)
        assert result is True

    async def test_token_bucket_consume_returns_false_when_empty(self):
        """consume() returns False after draining capacity."""
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=0.0)
        # Drain all tokens
        await limiter.consume(2.0)
        result = await limiter.consume(1.0)
        assert result is False

    async def test_token_bucket_tokens_decrease_after_consume(self):
        """Tokens reduced by amount after consume."""
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=0.0)
        # Set last_refill to now to avoid any refill
        limiter.last_refill = time.time()
        initial_tokens = limiter.tokens
        await limiter.consume(3.0)
        # Tokens should be approximately initial - 3 (small time delta may add tiny refill)
        assert limiter.tokens < initial_tokens
        assert limiter.tokens == pytest.approx(initial_tokens - 3.0, abs=0.1)

    async def test_token_bucket_refill_over_time(self):
        """Manipulate last_refill to test token replenishment."""
        limiter = TokenBucketRateLimiter(capacity=100.0, refill_rate=10.0)
        # Drain all tokens
        limiter.tokens = 0.0
        # Simulate 5 seconds elapsed
        limiter.last_refill = time.time() - 5.0
        result = await limiter.consume(1.0)
        # Should have refilled ~50 tokens (5s * 10/s), so consume(1) should succeed
        assert result is True
        # tokens should be approximately 49 (50 refilled - 1 consumed)
        assert limiter.tokens == pytest.approx(49.0, abs=1.0)

    async def test_token_bucket_cap_at_capacity(self):
        """Tokens never exceed capacity after refill."""
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=100.0)
        # Simulate a huge elapsed time
        limiter.last_refill = time.time() - 1000.0
        await limiter.consume(1.0)
        # Even with massive refill, tokens capped at capacity - consumed
        assert limiter.tokens <= limiter.capacity

    async def test_token_bucket_custom_capacity(self):
        """capacity=2.0, drain 2, 3rd consume returns False."""
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=0.0)
        assert await limiter.consume(1.0) is True
        assert await limiter.consume(1.0) is True
        assert await limiter.consume(1.0) is False

    async def test_token_bucket_fractional_amount(self):
        """consume(0.5) works correctly."""
        limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
        assert await limiter.consume(0.5) is True
        assert await limiter.consume(0.5) is True
        # Now at ~0, next consume should fail
        assert await limiter.consume(0.5) is False


# ===========================================================================
# Section 2: ContextHygiene.sanitize_value() tests
# ===========================================================================


class TestContextHygiene:
    """Tests for ContextHygiene.sanitize_value()."""

    def test_sanitize_value_plain_string_passthrough(self):
        """'hello world' unchanged (no sensitive patterns)."""
        h = ContextHygiene()
        assert h.sanitize_value("hello world") == "hello world"

    def test_sanitize_value_string_with_ip(self):
        """'connect to 192.168.1.1' → IP redacted."""
        h = ContextHygiene()
        result = h.sanitize_value("connect to 192.168.1.1")
        assert "[[IP_ADDRESS]]" in result
        assert "192.168.1.1" not in result

    def test_sanitize_value_string_with_url(self):
        """'https://evil.com/malware' → URL substituted."""
        h = ContextHygiene()
        result = h.sanitize_value("visit https://evil.com/malware now")
        assert "[[URL]]" in result
        assert "https://evil.com/malware" not in result

    def test_sanitize_value_string_with_email(self):
        """'user@example.com' → EMAIL redacted."""
        h = ContextHygiene()
        result = h.sanitize_value("contact user@example.com please")
        assert "[[EMAIL]]" in result
        assert "user@example.com" not in result

    def test_sanitize_value_dict_nested(self):
        """Dict with api key pattern → key value sanitized."""
        h = ContextHygiene()
        result = h.sanitize_value({"key": "api_key=secretvalue123456789abc"})
        assert "secretvalue123456789abc" not in result["key"]
        assert "[[API_KEY]]" in result["key"]

    def test_sanitize_value_dict_recursive(self):
        """Nested dict with IP → all levels sanitized."""
        h = ContextHygiene()
        data = {"outer": {"inner": "server at 10.0.0.1"}}
        result = h.sanitize_value(data)
        assert "[[IP_ADDRESS]]" in result["outer"]["inner"]
        assert "10.0.0.1" not in result["outer"]["inner"]

    def test_sanitize_value_list_of_strings(self):
        """['safe text', '192.168.0.1'] → second item sanitized."""
        h = ContextHygiene()
        result = h.sanitize_value(["safe text", "192.168.0.1"])
        assert result[0] == "safe text"
        assert "[[IP_ADDRESS]]" in result[1]

    def test_sanitize_value_int_passthrough(self):
        """Integer values pass through unchanged."""
        h = ContextHygiene()
        assert h.sanitize_value(42) == 42

    def test_sanitize_value_none_passthrough(self):
        """None passes through unchanged."""
        h = ContextHygiene()
        assert h.sanitize_value(None) is None

    def test_sanitize_value_empty_dict(self):
        """{} → {}."""
        h = ContextHygiene()
        assert h.sanitize_value({}) == {}

    def test_sanitize_value_empty_list(self):
        """[] → []."""
        h = ContextHygiene()
        assert h.sanitize_value([]) == []

    def test_sanitize_value_file_path(self):
        """'/etc/passwd' → contains [[FILE_PATH]]."""
        h = ContextHygiene()
        result = h.sanitize_value("/etc/passwd")
        assert "[[FILE_PATH]]" in result


# ===========================================================================
# Section 3: BatchResolver._parse_verdicts() tests
# ===========================================================================


class TestParseVerdicts:
    """Tests for BatchResolver._parse_verdicts()."""

    def test_parse_verdicts_valid_json_single(self):
        """JSON with 1 ALLOW verdict, batch_size=1 → [Verdict(ALLOW)]."""
        resolver = make_batch_resolver()
        text = json.dumps([{"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9}])
        verdicts = resolver._parse_verdicts(text, 1)
        assert len(verdicts) == 1
        assert verdicts[0].decision == VerdictDecision.ALLOW
        assert verdicts[0].reasoning == "Safe"

    def test_parse_verdicts_valid_json_multiple(self):
        """JSON with 3 verdicts, batch_size=3 → 3 Verdict objects."""
        resolver = make_batch_resolver()
        data = [
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
            {"decision": "BLOCK", "reasoning": "Dangerous", "confidence_score": 0.95},
            {"decision": "QUARANTINE", "reasoning": "Suspicious", "confidence_score": 0.7},
        ]
        verdicts = resolver._parse_verdicts(json.dumps(data), 3)
        assert len(verdicts) == 3
        assert verdicts[0].decision == VerdictDecision.ALLOW
        assert verdicts[1].decision == VerdictDecision.BLOCK
        assert verdicts[2].decision == VerdictDecision.QUARANTINE

    def test_parse_verdicts_with_markdown_code_block(self):
        """'```json\\n[...]\\n```' → parses correctly."""
        resolver = make_batch_resolver()
        inner = json.dumps([{"decision": "ALLOW", "reasoning": "OK", "confidence_score": 0.8}])
        text = f"```json\n{inner}\n```"
        verdicts = resolver._parse_verdicts(text, 1)
        assert len(verdicts) == 1
        assert verdicts[0].decision == VerdictDecision.ALLOW

    def test_parse_verdicts_size_mismatch_smaller(self):
        """JSON has 2 verdicts but batch_size=3 → 3 QUARANTINE verdicts (fail-closed)."""
        resolver = make_batch_resolver()
        data = [
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
        ]
        verdicts = resolver._parse_verdicts(json.dumps(data), 3)
        assert len(verdicts) == 3
        assert all(v.decision == VerdictDecision.QUARANTINE for v in verdicts)

    def test_parse_verdicts_size_mismatch_larger(self):
        """JSON has 3 verdicts but batch_size=2 → 2 QUARANTINE verdicts (fail-closed)."""
        resolver = make_batch_resolver()
        data = [
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
            {"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9},
        ]
        verdicts = resolver._parse_verdicts(json.dumps(data), 2)
        assert len(verdicts) == 2
        assert all(v.decision == VerdictDecision.QUARANTINE for v in verdicts)

    def test_parse_verdicts_malformed_json(self):
        """'not json' → batch_size QUARANTINE verdicts."""
        resolver = make_batch_resolver()
        verdicts = resolver._parse_verdicts("not json at all", 3)
        assert len(verdicts) == 3
        assert all(v.decision == VerdictDecision.QUARANTINE for v in verdicts)

    def test_parse_verdicts_not_a_list(self):
        """'{"decision": "ALLOW"}' (dict not list) → QUARANTINE fallback."""
        resolver = make_batch_resolver()
        text = json.dumps({"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9})
        verdicts = resolver._parse_verdicts(text, 1)
        assert len(verdicts) == 1
        assert verdicts[0].decision == VerdictDecision.QUARANTINE

    def test_parse_verdicts_confidence_score_parsed(self):
        """confidence_score=0.87 in JSON → Verdict.confidence_score=0.87."""
        resolver = make_batch_resolver()
        text = json.dumps([{"decision": "ALLOW", "reasoning": "OK", "confidence_score": 0.87}])
        verdicts = resolver._parse_verdicts(text, 1)
        assert verdicts[0].confidence_score == pytest.approx(0.87)

    def test_parse_verdicts_default_confidence(self):
        """Missing confidence_score key → 0.5 default."""
        resolver = make_batch_resolver()
        text = json.dumps([{"decision": "ALLOW", "reasoning": "OK"}])
        verdicts = resolver._parse_verdicts(text, 1)
        assert verdicts[0].confidence_score == pytest.approx(0.5)

    def test_parse_verdicts_quarantine_fallback_on_empty_text(self):
        """Empty string → QUARANTINE verdicts."""
        resolver = make_batch_resolver()
        verdicts = resolver._parse_verdicts("", 2)
        assert len(verdicts) == 2
        assert all(v.decision == VerdictDecision.QUARANTINE for v in verdicts)

    def test_parse_verdicts_empty_batch_size(self):
        """batch_size=0 → []."""
        resolver = make_batch_resolver()
        verdicts = resolver._parse_verdicts("invalid", 0)
        assert verdicts == []


# ===========================================================================
# Section 4: BatchResolver._acquire_rate_limit_token() tests
# ===========================================================================


class TestAcquireRateLimitToken:
    """Tests for BatchResolver._acquire_rate_limit_token()."""

    async def test_acquire_token_succeeds_when_available(self):
        """Tokens available → no exception raised."""
        resolver = make_batch_resolver()
        # Should not raise
        await resolver._acquire_rate_limit_token()

    async def test_acquire_token_raises_when_exhausted(self):
        """Drain rate_limiter, then _acquire_rate_limit_token raises APIRateLimitException."""
        resolver = make_batch_resolver()
        # Drain all tokens
        resolver.rate_limiter.tokens = 0.0
        resolver.rate_limiter.refill_rate = 0.0
        resolver.rate_limiter.last_refill = time.time()
        with pytest.raises(APIRateLimitException):
            await resolver._acquire_rate_limit_token()

    async def test_acquire_token_increments_rate_limit_hits(self):
        """When exhausted, rate_limit_hits incremented."""
        resolver = make_batch_resolver()
        resolver.rate_limiter.tokens = 0.0
        resolver.rate_limiter.refill_rate = 0.0
        resolver.rate_limiter.last_refill = time.time()
        assert resolver.rate_limit_hits == 0
        with pytest.raises(APIRateLimitException):
            await resolver._acquire_rate_limit_token()
        assert resolver.rate_limit_hits == 1


# ===========================================================================
# Section 5: BatchResolver.submit_to_gemini_sync() tests
# ===========================================================================


class TestSubmitToGeminiSync:
    """Tests for BatchResolver.submit_to_gemini_sync()."""

    async def test_submit_to_gemini_sync_with_async_client(self):
        """client.interactions.create is async coroutine returning mock interaction."""
        interaction = MagicMock()
        interaction.id = "interaction-123"
        interaction.output_text = json.dumps(
            [{"decision": "ALLOW", "reasoning": "Safe", "confidence_score": 0.9}]
        )
        interaction.usage = MagicMock(total_tokens=100, cached_content_token_count=0)

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        contexts = [ToolCallContext(tool_name="test_tool", arguments={"a": 1})]
        response = await resolver.submit_to_gemini_sync(contexts)
        assert isinstance(response, BatchResponse)
        assert len(response.verdicts) == 1
        assert response.verdicts[0].decision == VerdictDecision.ALLOW

    async def test_submit_to_gemini_sync_with_sync_client(self):
        """client.interactions.create is sync function."""
        interaction = MagicMock()
        interaction.id = "interaction-sync-456"
        interaction.output_text = json.dumps(
            [{"decision": "BLOCK", "reasoning": "Dangerous", "confidence_score": 0.95}]
        )
        interaction.usage = MagicMock(total_tokens=50, cached_content_token_count=0)

        mock_client = MagicMock()
        # Ensure it's NOT detected as a coroutine function
        mock_client.interactions.create = MagicMock(return_value=interaction)

        resolver = BatchResolver(client=mock_client)
        contexts = [ToolCallContext(tool_name="test_tool", arguments={"b": 2})]
        response = await resolver.submit_to_gemini_sync(contexts)
        assert isinstance(response, BatchResponse)
        assert response.verdicts[0].decision == VerdictDecision.BLOCK

    async def test_submit_to_gemini_sync_updates_last_interaction_id(self):
        """interaction.id set → last_interaction_id updated."""
        interaction = MagicMock()
        interaction.id = "new-id-789"
        interaction.output_text = json.dumps(
            [{"decision": "ALLOW", "reasoning": "OK", "confidence_score": 0.8}]
        )
        interaction.usage = MagicMock(total_tokens=80, cached_content_token_count=0)

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        assert resolver.last_interaction_id is None
        contexts = [ToolCallContext(tool_name="t", arguments={})]
        await resolver.submit_to_gemini_sync(contexts)
        assert resolver.last_interaction_id == "new-id-789"

    async def test_submit_to_gemini_sync_cache_hit_on_previous_id(self):
        """previous_interaction_id set → cache_hit_count=1."""
        interaction = MagicMock()
        interaction.id = "id-2"
        interaction.output_text = json.dumps(
            [{"decision": "ALLOW", "reasoning": "OK", "confidence_score": 0.8}]
        )
        interaction.usage = MagicMock(total_tokens=50, cached_content_token_count=0)

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        # Set previous interaction ID so cache hit condition triggers
        resolver.last_interaction_id = "id-1"
        contexts = [ToolCallContext(tool_name="t", arguments={})]
        response = await resolver.submit_to_gemini_sync(contexts)
        assert response.cache_hit_count == 1

    async def test_submit_to_gemini_sync_returns_batch_response(self):
        """Returns BatchResponse with verdicts."""
        interaction = MagicMock()
        interaction.id = "resp-id"
        interaction.output_text = json.dumps(
            [{"decision": "QUARANTINE", "reasoning": "Uncertain", "confidence_score": 0.6}]
        )
        interaction.usage = MagicMock(total_tokens=120, cached_content_token_count=0)

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        contexts = [ToolCallContext(tool_name="tool", arguments={})]
        response = await resolver.submit_to_gemini_sync(contexts)
        assert isinstance(response, BatchResponse)
        assert response.tokens_consumed == 120
        assert response.processing_time > 0.0

    async def test_submit_to_gemini_sync_rate_limit_wraps_as_api_exception(self):
        """Client raises 'rate_limit' exception → APIRateLimitException raised."""
        mock_client = MagicMock()

        async def mock_create(**kwargs):
            raise Exception("rate_limit exceeded")

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        contexts = [ToolCallContext(tool_name="t", arguments={})]
        with pytest.raises(APIRateLimitException):
            await resolver.submit_to_gemini_sync(contexts)

    async def test_submit_to_gemini_sync_non_rate_limit_exception_propagates(self):
        """Client raises ValueError → ValueError propagates."""
        mock_client = MagicMock()

        async def mock_create(**kwargs):
            raise ValueError("Something else went wrong")

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        contexts = [ToolCallContext(tool_name="t", arguments={})]
        with pytest.raises(ValueError, match="Something else went wrong"):
            await resolver.submit_to_gemini_sync(contexts)


# ===========================================================================
# Section 6: BatchResolver.submit_to_gemini_background() tests
# ===========================================================================


class TestSubmitToGeminiBackground:
    """Tests for BatchResolver.submit_to_gemini_background()."""

    async def test_submit_to_gemini_background_returns_task_id(self):
        """Mock client, returns string task_id."""
        interaction = MagicMock()
        interaction.id = "bg-task-456"

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        context = ToolCallContext(tool_name="tool", arguments={"x": 1})
        task_id = await resolver.submit_to_gemini_background(context, [], [], None)
        assert task_id == "bg-task-456"

    async def test_submit_to_gemini_background_increments_counter(self):
        """background_tasks_submitted incremented."""
        interaction = MagicMock()
        interaction.id = "bg-task-789"

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        assert resolver.background_tasks_submitted == 0
        context = ToolCallContext(tool_name="tool", arguments={})
        await resolver.submit_to_gemini_background(context, [], [], None)
        assert resolver.background_tasks_submitted == 1

    async def test_submit_to_gemini_background_uses_interaction_id(self):
        """interaction.id returned as task_id."""
        interaction = MagicMock()
        interaction.id = "unique-interaction-id"

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        context = ToolCallContext(tool_name="tool", arguments={})
        task_id = await resolver.submit_to_gemini_background(context, [], [], None)
        assert task_id == "unique-interaction-id"

    async def test_submit_to_gemini_background_fallback_uuid_when_no_id(self):
        """Interaction has no id attr → uuid4 used."""
        interaction = MagicMock(spec=[])  # Empty spec means no attributes

        mock_client = MagicMock()

        async def mock_create(**kwargs):
            return interaction

        mock_client.interactions.create = mock_create

        resolver = BatchResolver(client=mock_client)
        context = ToolCallContext(tool_name="tool", arguments={})
        task_id = await resolver.submit_to_gemini_background(context, [], [], None)
        # Should be a valid UUID string (36 chars with hyphens)
        assert isinstance(task_id, str)
        assert len(task_id) == 36
        assert task_id.count("-") == 4


# ===========================================================================
# Section 7: BatchResolver.track_background_submission() and track_webhook_callback()
# ===========================================================================


class TestTrackingMethods:
    """Tests for track_background_submission and track_webhook_callback."""

    def test_track_background_submission_increments(self):
        """background_tasks_submitted += 1."""
        resolver = make_batch_resolver()
        assert resolver.background_tasks_submitted == 0
        resolver.track_background_submission()
        assert resolver.background_tasks_submitted == 1
        resolver.track_background_submission()
        assert resolver.background_tasks_submitted == 2

    def test_track_webhook_callback_increments_and_records_latency(self):
        """webhook_callbacks_received += 1, total_webhook_latency_ms updated."""
        resolver = make_batch_resolver()
        assert resolver.webhook_callbacks_received == 0
        assert resolver.total_webhook_latency_ms == 0.0
        resolver.track_webhook_callback(150.0)
        assert resolver.webhook_callbacks_received == 1
        assert resolver.total_webhook_latency_ms == 150.0
        resolver.track_webhook_callback(200.0)
        assert resolver.webhook_callbacks_received == 2
        assert resolver.total_webhook_latency_ms == 350.0


# ===========================================================================
# Section 8: BatchResolver.get_metrics() tests
# ===========================================================================


class TestGetMetrics:
    """Tests for BatchResolver.get_metrics()."""

    def test_get_metrics_initial(self):
        """total_batches=0 → averages are 0.0, rate_limit_hits=0."""
        resolver = make_batch_resolver()
        metrics = resolver.get_metrics()
        assert metrics.total_batches == 0
        assert metrics.average_batch_size == 0.0
        assert metrics.average_latency_ms == 0.0
        assert metrics.rate_limit_hits == 0
        assert metrics.cache_hit_rate == 0.0

    def test_get_metrics_with_data(self):
        """Set total_batches=5, total_callbacks=15, total_latency_ms=500.0 → avg_batch_size=3.0, avg_latency=100.0."""
        resolver = make_batch_resolver()
        resolver.total_batches = 5
        resolver.total_callbacks = 15
        resolver.total_latency_ms = 500.0
        metrics = resolver.get_metrics()
        assert metrics.total_batches == 5
        assert metrics.average_batch_size == pytest.approx(3.0)
        assert metrics.average_latency_ms == pytest.approx(100.0)

    def test_get_metrics_cache_hit_rate(self):
        """total_batches=10, cache_hits=2 → cache_hit_rate=0.2."""
        resolver = make_batch_resolver()
        resolver.total_batches = 10
        resolver.cache_hits = 2
        metrics = resolver.get_metrics()
        assert metrics.cache_hit_rate == pytest.approx(0.2)

    def test_get_metrics_returns_resolver_metrics_type(self):
        """Returns ResolverMetrics instance."""
        resolver = make_batch_resolver()
        metrics = resolver.get_metrics()
        assert isinstance(metrics, ResolverMetrics)
