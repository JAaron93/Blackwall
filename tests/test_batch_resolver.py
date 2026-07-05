import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis.strategies import lists, integers

from blackwall.models import (
    CallbackToken,
    ToolCallContext,
    VerdictDecision,
)
from blackwall.resolver import BatchResolver, TokenBucketRateLimiter, ContextHygiene

# --- Mocks ---


class MockUsage:
    def __init__(self, total, cached):
        self.total_tokens = total
        self.cached_content_token_count = cached


class MockInteraction:
    def __init__(self, interaction_id="mock-id-123", output_text="", usage=None):
        self.id = interaction_id
        self.output_text = output_text
        self.usage = usage or MockUsage(100, 0)


def create_mock_client(verdicts_to_return=None, raise_rate_limit_count=0):
    current_calls = 0

    def create_fn(*args, **kwargs):
        nonlocal current_calls
        if current_calls < raise_rate_limit_count:
            current_calls += 1
            raise Exception("Gemini API rate limit: 429 ResourceExhausted")

        # Determine number of contexts in batch input
        payload_data = json.loads(kwargs.get("input", "{}"))
        contexts = payload_data.get("sanitized_contexts", [])
        num_verdicts = len(contexts)

        # Build verdicts list
        if verdicts_to_return:
            verdicts = verdicts_to_return[:num_verdicts]
        else:
            verdicts = [
                {
                    "decision": "ALLOW",
                    "reasoning": "Benign tool call",
                    "confidence_score": 0.95,
                }
                for _ in range(num_verdicts)
            ]

        # Context Caching: check if previous_interaction_id was sent
        prev_id = kwargs.get("previous_interaction_id")
        cached_tokens = 80 if prev_id else 0
        total_tokens = (
            100 if not prev_id else 20
        )  # >= 50% token reduction on cache hit!

        return MockInteraction(
            interaction_id="new-interaction-id-xyz",
            output_text=json.dumps(verdicts),
            usage=MockUsage(total_tokens, cached_tokens),
        )

    # We mock it as an async function since process_batch expects a coroutine if iscoroutinefunction is true.
    # Otherwise fallback to sync call. We will make it async to test async paths.
    mock_create = AsyncMock(side_effect=create_fn)

    client = MagicMock()
    client.interactions = MagicMock()
    client.interactions.create = mock_create
    return client


# --- Basic unit tests ---


@pytest.mark.asyncio
async def test_context_hygiene_sanitization():
    hygiene = ContextHygiene()

    # Test api_key redacting
    ctx1 = ToolCallContext(
        tool_name="test_tool",
        arguments={"key": "api_key=AIzaSyA1234567890BCDEF1", "other": "clean"},
        metadata={"user": "admin"},
    )
    sanitized1 = hygiene.sanitize_context(ctx1)
    assert sanitized1.arguments["key"] == "api_key=[[API_KEY]]"
    assert sanitized1.arguments["other"] == "clean"

    # Test URL redacting
    ctx2 = ToolCallContext(
        tool_name="test_tool",
        arguments={"url": "http://example.com/sensitive/endpoint", "ip": "192.168.1.1"},
        metadata=None,
    )
    sanitized2 = hygiene.sanitize_context(ctx2)
    assert sanitized2.arguments["url"] == "[[URL]]"
    assert sanitized2.arguments["ip"] == "[[IP_ADDRESS]]"

    # Test nested dict/list sanitization
    ctx3 = ToolCallContext(
        tool_name="test_tool",
        arguments={
            "nested": {
                "secret": "password:admin:supersecret123",
                "emails": ["user@domain.com", "other@domain.com"],
            }
        },
        metadata=None,
    )
    sanitized3 = hygiene.sanitize_context(ctx3)
    assert sanitized3.arguments["nested"]["secret"] == "password:[[PASSWORD]]"
    assert sanitized3.arguments["nested"]["emails"] == ["[[EMAIL]]", "[[EMAIL]]"]


def test_token_bucket_limiter():
    # Capacity 5, refill rate 1 per second
    limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0)

    # Consume 5 successfully
    for _ in range(5):
        assert asyncio.run(limiter.consume(1.0)) is True

    # 6th consume fails (no tokens left)
    assert asyncio.run(limiter.consume(1.0)) is False


@pytest.mark.asyncio
async def test_batch_resolver_sync_triage():
    client = create_mock_client()
    resolver = BatchResolver(client=client)

    tokens = [
        CallbackToken(
            thread_id="thread-1",
            tool_context=ToolCallContext(
                tool_name="tool1", arguments={"param": "val1"}
            ),
        ),
        CallbackToken(
            thread_id="thread-2",
            tool_context=ToolCallContext(
                tool_name="tool2", arguments={"param": "val2"}
            ),
        ),
    ]

    response = await resolver.process_batch(tokens)

    assert len(response.verdicts) == 2
    assert response.verdicts[0].decision == VerdictDecision.ALLOW
    assert response.cache_hit_count == 0  # No previous interaction yet
    assert resolver.last_interaction_id == "new-interaction-id-xyz"

    # Verify client was called with correct parameters
    client.interactions.create.assert_called_once()
    call_kwargs = client.interactions.create.call_args[1]
    assert call_kwargs["model"] == "gemini-3.1-flash-lite"
    assert call_kwargs["previous_interaction_id"] is None

    # Second call should include previous_interaction_id for context caching
    client.interactions.create.reset_mock()
    response2 = await resolver.process_batch(tokens)
    assert response2.cache_hit_count == 1  # Should hit the cache

    call_kwargs2 = client.interactions.create.call_args[1]
    assert call_kwargs2["previous_interaction_id"] == "new-interaction-id-xyz"

    # Check metrics
    metrics = resolver.get_metrics()
    assert metrics.total_batches == 2
    assert metrics.average_batch_size == 2.0
    assert metrics.cache_hit_rate == 0.5


@pytest.mark.asyncio
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_batch_resolver_backoff_and_retry(mock_sleep):
    # API raises rate limit error 2 times, then succeeds on 3rd attempt
    client = create_mock_client(raise_rate_limit_count=2)
    resolver = BatchResolver(client=client)

    tokens = [
        CallbackToken(
            thread_id="thread-1",
            tool_context=ToolCallContext(tool_name="tool1", arguments={}),
        )
    ]

    response = await resolver.process_batch(tokens)
    assert response.verdicts[0].decision == VerdictDecision.ALLOW

    # Verify backoff sleeps: 100ms then 200ms
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(0.1)
    mock_sleep.assert_any_call(0.2)

    # Check that it incremented rate limit hits locally too if token bucket is exhausted,
    # but here rate limit came from mock API. Let's check API was called 3 times.
    assert client.interactions.create.call_count == 3


@pytest.mark.asyncio
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_batch_resolver_fail_closed(mock_sleep):
    # API always raises rate limit error
    client = create_mock_client(raise_rate_limit_count=10)
    resolver = BatchResolver(client=client)

    tokens = [
        CallbackToken(
            thread_id="thread-1",
            tool_context=ToolCallContext(tool_name="tool1", arguments={}),
        )
    ]

    response = await resolver.process_batch(tokens)

    # Should fail-closed to QUARANTINE
    assert len(response.verdicts) == 1
    assert response.verdicts[0].decision == VerdictDecision.QUARANTINE
    assert "conservative deny" in response.verdicts[0].reasoning

    # Checked that it tried 3 retries (total 4 attempts)
    assert client.interactions.create.call_count == 4
    assert mock_sleep.call_count == 3
    mock_sleep.assert_any_call(0.1)
    mock_sleep.assert_any_call(0.2)
    mock_sleep.assert_any_call(0.4)


@pytest.mark.asyncio
async def test_batch_resolver_background_submission():
    client = MagicMock()
    # Mock background creation
    mock_interaction = MockInteraction("bg-task-456")
    client.interactions.create = MagicMock(return_value=mock_interaction)

    resolver = BatchResolver(client=client, webhook_port=9090)
    ctx = ToolCallContext(tool_name="terminal", arguments={"cmd": "whoami"})

    task_id = await resolver.submit_to_gemini_background(
        quarantined_context=ctx,
        related_signatures=[],
        cbm_chain=["db_sink"],
        gti_data={"is_malicious": False},
    )

    assert task_id == "bg-task-456"
    assert resolver.background_tasks_submitted == 1

    # Verify parameters passed
    client.interactions.create.assert_called_once()
    call_kwargs = client.interactions.create.call_args[1]
    assert call_kwargs["model"] == "gemini-3.1-pro-preview"
    assert call_kwargs["background"] is True
    assert call_kwargs["webhook_config"]["uris"] == [
        "http://localhost:9090/webhook/analysis_complete"
    ]


# --- Property 9: Rate Limit Compliance with Hypothesis ---


class HypothesisVirtualTimeLimiter(TokenBucketRateLimiter):
    """Token bucket rate limiter that runs in virtual time for rapid property validation."""

    def __init__(self, capacity: float = 300.0, refill_rate: float = 5.0):
        super().__init__(capacity, refill_rate)
        self.virtual_now = 0.0

    async def consume(self, amount: float = 1.0) -> bool:
        # Override refill checking to use virtual time
        elapsed = self.virtual_now - self.last_refill
        self.last_refill = self.virtual_now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


@settings(max_examples=50, deadline=None)
@given(
    lists(
        # Represents sequences of (time_delta_ms, count_of_requests)
        # Generates bursts of requests separated by small delays in a virtual timeline
        # Up to 600 requests total, simulated within a 60-second window
        lists(integers(min_value=1, max_value=5), min_size=1, max_size=15),
        min_size=5,
        max_size=30,
    )
)
def test_rate_limit_compliance_property(burst_groups):
    # Create the virtual rate limiter
    limiter = HypothesisVirtualTimeLimiter(capacity=300.0, refill_rate=5.0)

    api_calls_timestamps = []
    current_virtual_time = 0.0

    # Feed burst groups into the limiter
    for group in burst_groups:
        # Increment time between burst groups (simulate random delays in ms, converted to sec)
        current_virtual_time += 0.5  # 500ms delay between bursts
        limiter.virtual_now = current_virtual_time

        for req_size in group:
            for _ in range(req_size):
                # We check if we can make the API call
                # Run the consume coroutine synchronously in virtual time
                loop = asyncio.new_event_loop()
                try:
                    allowed = loop.run_until_complete(limiter.consume(1.0))
                finally:
                    loop.close()

                if allowed:
                    api_calls_timestamps.append(current_virtual_time)

    # Now, assert the core property:
    # Within any sliding 60-second window, the total API calls made is at most 300
    for t_start in api_calls_timestamps:
        t_end = t_start + 60.0
        calls_in_window = [t for t in api_calls_timestamps if t_start <= t <= t_end]
        assert len(calls_in_window) <= 300, (
            f"Rate limit exceeded in window [{t_start:.2f}s, {t_end:.2f}s]: "
            f"made {len(calls_in_window)} calls, limit is 300"
        )
