import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from pytest_bdd import scenarios, given, when, then

from blackwall.models import CallbackToken, ToolCallContext, VerdictDecision
from blackwall.resolver import BatchResolver, TokenBucketRateLimiter
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_batch_resolver import create_mock_client

# Link to Gherkin feature file
scenarios("../features/batch_resolver.feature")


# --- Fixtures / State Container ---
class BDDState:
    def __init__(self):
        self.client = None
        self.resolver = None
        self.context = None
        self.response = None
        self.responses = []
        self.rate_limiter = None
        self.allowed_calls = 0
        self.blocked_calls = 0
        self.sleep_mock = None


@pytest.fixture
def state():
    return BDDState()


# --- Scenario: Redacting sensitive data before submitting to Gemini API ---


@given("a Batch Resolver is initialized with a mock Gemini client")
def init_resolver(state):
    state.client = create_mock_client()
    state.resolver = BatchResolver(client=state.client)


@given(
    'a tool call context contains sensitive "api_key=AIzaSyA1234567890BCDEF1" and "password:admin:supersecret123"'
)
def set_sensitive_context(state):
    state.context = ToolCallContext(
        tool_name="test_tool",
        arguments={
            "key": "api_key=AIzaSyA1234567890BCDEF1",
            "nested": {"secret": "password:admin:supersecret123"},
        },
    )


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@when("the batch is processed by the resolver")
def process_batch(state):
    token = CallbackToken(thread_id="thread-1", tool_context=state.context)
    if state.client and getattr(state.client.interactions.create, "side_effect", None):
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            state.sleep_mock = mock_sleep
            state.response = run_async(state.resolver.process_batch([token]))
    else:
        state.response = run_async(state.resolver.process_batch([token]))


@then(
    'the submitted payload must be redacted to "api_key=[[API_KEY]]" and "password:[[PASSWORD]]"'
)
def verify_redacted(state):
    state.client.interactions.create.assert_called_once()
    call_kwargs = state.client.interactions.create.call_args[1]
    payload_data = json.loads(call_kwargs["input"])
    sanitized = payload_data["sanitized_contexts"][0]

    assert sanitized["arguments"]["key"] == "api_key=[[API_KEY]]"
    assert sanitized["arguments"]["nested"]["secret"] == "password:[[PASSWORD]]"


# --- Scenario: Context caching decreases token usage on subsequent calls ---


@when("a batch is processed for the first time")
def process_batch_first_time(state):
    state.context = ToolCallContext(tool_name="tool", arguments={})
    token = CallbackToken(thread_id="thread-1", tool_context=state.context)
    state.response = run_async(state.resolver.process_batch([token]))
    state.responses.append(state.response)


@then("the response indicates no cache hit")
def verify_no_cache_hit(state):
    assert state.responses[0].cache_hit_count == 0


@when("the same batch is processed a second time")
def process_batch_second_time(state):
    token = CallbackToken(thread_id="thread-1", tool_context=state.context)
    # Reset mock call count to track next call
    state.client.interactions.create.reset_mock()
    response = run_async(state.resolver.process_batch([token]))
    state.responses.append(response)


@then("the response indicates a cache hit")
def verify_cache_hit(state):
    assert state.responses[1].cache_hit_count == 1


@then("the token consumption is reduced by at least 50%")
def verify_token_reduction(state):
    # Initial request consumed 100 tokens, cached request consumed 20 tokens
    assert (
        state.responses[1].tokens_consumed <= state.responses[0].tokens_consumed * 0.5
    )


# --- Scenario: Local rate limiting prevents exceeding the 300 RPM ceiling ---


@given("a Batch Resolver is initialized with a local rate limiter")
def init_rate_limiter_resolver(state):
    pass


@given("the rate limiter has a capacity of 5 tokens and no refill")
def init_limiter_capacity(state):
    state.rate_limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=0.0)


@when("5 requests are made to the rate limiter")
def make_5_requests(state):
    for _ in range(5):
        if run_async(state.rate_limiter.consume(1.0)):
            state.allowed_calls += 1
        else:
            state.blocked_calls += 1


@then("all 5 requests must be allowed")
def verify_all_allowed(state):
    assert state.allowed_calls == 5
    assert state.blocked_calls == 0


@when("a 6th request is made")
def make_6th_request(state):
    if run_async(state.rate_limiter.consume(1.0)):
        state.allowed_calls += 1
    else:
        state.blocked_calls += 1


@then("the 6th request must be blocked by the rate limiter")
def verify_6th_blocked(state):
    assert state.allowed_calls == 5
    assert state.blocked_calls == 1


# --- Scenario: Rate limit exhaustion triggers fail-closed quarantine ---


@given(
    "a Batch Resolver is initialized with a mock Gemini client that always returns 429 errors"
)
def init_resolver_always_429(state):
    # Setup mock to raise rate limit exception 10 times
    state.client = create_mock_client(raise_rate_limit_count=10)
    state.resolver = BatchResolver(client=state.client)
    state.context = ToolCallContext(tool_name="tool", arguments={})


@then("the resolver must retry the submission 3 times with exponential backoff")
def assert_retries_happened(state):
    assert state.client.interactions.create.call_count == 4
    assert state.sleep_mock.call_count == 3
    state.sleep_mock.assert_any_call(0.1)
    state.sleep_mock.assert_any_call(0.2)
    state.sleep_mock.assert_any_call(0.4)


@then('the final verdicts must all be "QUARANTINE" with reason "Rate limit exceeded"')
def verify_quarantine_verdict(state):
    assert len(state.response.verdicts) == 1
    assert state.response.verdicts[0].decision == VerdictDecision.QUARANTINE
    assert "Rate limit exceeded" in state.response.verdicts[0].reasoning
