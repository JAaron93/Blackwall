"""Property-based tests for Error Handling, Resilience, and Resource Throttling."""

import asyncio
from typing import Any
import pytest
from hypothesis import given, settings, strategies as st

from blackwall.enterprise.advanced_threat_detection.resilience import (
    ResourceThrottler,
    SafeDetectionRunner,
)
from tests.step_defs.async_utils import run_async


# Property 73: Safe Detection Runner Exception Isolation
@settings(max_examples=50, deadline=None)
@given(
    error_msg=st.text(min_size=1, max_size=50),
    fallback_val=st.integers() | st.text() | st.lists(st.integers()),
)
def test_safe_detection_runner_exception_isolation_property(
    error_msg: str, fallback_val: Any
) -> None:
    """SafeDetectionRunner must isolate general runtime/operational exceptions and return fallback."""
    runner = SafeDetectionRunner(default_timeout_seconds=0.5)

    async def _failing_coro() -> Any:
        raise RuntimeError(error_msg)

    async def _run() -> Any:
        return await runner.run_safe(
            detector_name="prop_test_detector",
            coro=_failing_coro(),
            fallback=fallback_val,
        )

    res = run_async(_run())
    assert res == fallback_val


# Property 74: Safe Detection Runner Parameter Validation Non-Suppression
@settings(max_examples=50, deadline=None)
@given(
    exc_type=st.sampled_from([TypeError, ValueError, KeyError]),
    error_msg=st.text(min_size=1, max_size=50),
)
def test_safe_detection_runner_raises_validation_errors_property(
    exc_type: type[Exception], error_msg: str
) -> None:
    """SafeDetectionRunner must never suppress TypeError, ValueError, or KeyError per Rule 8."""
    runner = SafeDetectionRunner(default_timeout_seconds=0.5)

    async def _validation_err_coro() -> Any:
        raise exc_type(error_msg)

    async def _run() -> Any:
        return await runner.run_safe(
            detector_name="prop_test_detector",
            coro=_validation_err_coro(),
            fallback="never_returned",
        )

    with pytest.raises(exc_type):
        run_async(_run())


# Property 75: Resource Throttler Analysis Depth Bounds
@settings(max_examples=50, deadline=None)
@given(
    base_depth=st.integers(min_value=1, max_value=20),
    queue_size=st.integers(min_value=0, max_value=1000),
    max_queue_size=st.integers(min_value=1, max_value=100),
    events_recorded=st.integers(min_value=0, max_value=200),
)
def test_resource_throttler_depth_bounds_property(
    base_depth: int,
    queue_size: int,
    max_queue_size: int,
    events_recorded: int,
) -> None:
    """ResourceThrottler get_analysis_depth must always return an integer bounded in [1, base_depth]."""
    throttler = ResourceThrottler(
        max_events_per_second=50,
        max_queue_size=max_queue_size,
    )
    for _ in range(events_recorded):
        throttler.record_event()

    depth = throttler.get_analysis_depth(
        base_depth=base_depth, current_queue_size=queue_size
    )
    assert 1 <= depth <= base_depth


# Property 76: Resource Throttler Rate Monotonicity
@settings(max_examples=50, deadline=None)
@given(
    event_count=st.integers(min_value=0, max_value=100),
    window_seconds=st.floats(min_value=0.1, max_value=10.0),
)
def test_resource_throttler_rate_monotonicity_property(
    event_count: int, window_seconds: float
) -> None:
    """ResourceThrottler current event rate must be non-negative."""
    throttler = ResourceThrottler(
        sliding_window_seconds=window_seconds,
    )
    for _ in range(event_count):
        throttler.record_event()

    rate = throttler.current_rate()
    assert rate >= 0.0
