from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock
import pytest

from blackwall.threat_intel.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitBreakerProvider,
    CircuitState,
    ProviderTimeoutError,
)
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)


class MockFlakyProvider:
    name: str = "flaky"
    supported_indicators: set[ThreatIndicatorType] = {ThreatIndicatorType.IPV4}

    def __init__(self) -> None:
        self.call_count = 0
        self.should_timeout = False
        self.should_fail = False

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse:
        self.call_count += 1
        if self.should_timeout:
            await asyncio.sleep(timeout + 0.5)
        if self.should_fail:
            raise ConnectionError("Connection refused by remote host")
        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=False,
            risk_score=0.0,
            provider_name=self.name,
        )

    async def is_healthy(self) -> bool:
        return True

    def get_remaining_budget(self) -> int:
        return 1000


@pytest.mark.asyncio
async def test_circuit_breaker_normal_execution() -> None:
    cb = CircuitBreaker(name="test", timeout=0.1)
    assert cb.state == CircuitState.CLOSED

    async def quick_task() -> str:
        return "success"

    result = await cb.call(quick_task)
    assert result == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_failures == 0


@pytest.mark.asyncio
async def test_circuit_breaker_timeout_aborts_at_threshold() -> None:
    cb = CircuitBreaker(name="test", timeout=0.05)

    async def slow_task() -> str:
        await asyncio.sleep(0.2)
        return "too slow"

    start = time.monotonic()
    with pytest.raises(ProviderTimeoutError):
        await cb.call(slow_task)
    elapsed = time.monotonic() - start

    assert elapsed < 0.15  # Aborted at ~0.05s
    assert cb.consecutive_failures == 1


@pytest.mark.asyncio
async def test_circuit_breaker_transitions_to_open_after_5_failures() -> None:
    cb = CircuitBreaker(
        name="test",
        failure_threshold=5,
        recovery_threshold=3,
        recovery_timeout=0.1,
        timeout=0.05,
    )

    async def failing_task() -> str:
        raise ConnectionError("Network down")

    for i in range(5):
        assert cb.state == CircuitState.CLOSED
        with pytest.raises(ConnectionError):
            await cb.call(failing_task)

    # After 5 failures, state transitions to OPEN
    assert cb.state == CircuitState.OPEN

    # In OPEN state, calls immediately fail with CircuitBreakerOpenError without invoking task
    mock_task = AsyncMock()
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call(mock_task)
    mock_task.assert_not_called()


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_and_recovery_to_closed() -> None:
    cb = CircuitBreaker(
        name="test",
        failure_threshold=5,
        recovery_threshold=3,
        recovery_timeout=0.08,
        timeout=0.05,
    )

    async def failing_task() -> str:
        raise ConnectionError("Network down")

    async def healthy_task() -> str:
        return "ok"

    for _ in range(5):
        with pytest.raises(ConnectionError):
            await cb.call(failing_task)

    assert cb.state == CircuitState.OPEN

    # Wait for recovery timeout
    await asyncio.sleep(0.1)
    assert cb.state == CircuitState.HALF_OPEN

    # 3 successful probes in HALF-OPEN restore to CLOSED
    for i in range(3):
        assert cb.state == CircuitState.HALF_OPEN or (i == 2 and cb.consecutive_failures == 0)
        res = await cb.call(healthy_task)
        assert res == "ok"

    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_failure_reverts_to_open() -> None:
    cb = CircuitBreaker(
        name="test",
        failure_threshold=5,
        recovery_threshold=3,
        recovery_timeout=0.05,
        timeout=0.05,
    )

    async def failing_task() -> str:
        raise ConnectionError("Network down")

    for _ in range(5):
        with pytest.raises(ConnectionError):
            await cb.call(failing_task)

    assert cb.state == CircuitState.OPEN
    await asyncio.sleep(0.08)
    assert cb.state == CircuitState.HALF_OPEN

    # Failure during HALF-OPEN immediately trips back to OPEN
    with pytest.raises(ConnectionError):
        await cb.call(failing_task)
    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_provider_wrapper_graceful_degradation() -> None:
    raw_provider = MockFlakyProvider()
    cb = CircuitBreaker(
        name="flaky",
        failure_threshold=5,
        recovery_threshold=3,
        recovery_timeout=0.05,
        timeout=0.05,
    )
    wrapped = CircuitBreakerProvider(raw_provider, circuit_breaker=cb)

    assert wrapped.name == "flaky"
    assert ThreatIndicatorType.IPV4 in wrapped.supported_indicators

    # Test 1: Successful lookup
    resp = await wrapped.lookup("198.51.100.1", ThreatIndicatorType.IPV4)
    assert resp.indicator == "198.51.100.1"
    assert resp.is_malicious is False
    assert resp.error is None

    # Test 2: Provider timeout returns fallback heuristics without raising unhandled exception
    raw_provider.should_timeout = True
    resp_timeout = await wrapped.lookup("198.51.100.2", ThreatIndicatorType.IPV4)
    assert resp_timeout.indicator == "198.51.100.2"
    assert resp_timeout.is_malicious is False
    assert resp_timeout.risk_score == 0.0
    assert resp_timeout.error is not None
    assert "timed out" in resp_timeout.error.lower() or "timeout" in resp_timeout.error.lower()

    # Test 3: Trip circuit breaker to OPEN with 5 failures
    raw_provider.should_timeout = False
    raw_provider.should_fail = True
    for _ in range(4):
        r = await wrapped.lookup("198.51.100.3", ThreatIndicatorType.IPV4)
        assert r.error is not None

    assert cb.state == CircuitState.OPEN

    # When OPEN, wrapped provider returns fallback heuristics immediately and bypasses inner provider
    call_count_before = raw_provider.call_count
    resp_open = await wrapped.lookup("198.51.100.4", ThreatIndicatorType.IPV4)
    assert resp_open.indicator == "198.51.100.4"
    assert resp_open.is_malicious is False
    assert resp_open.error is not None
    assert "open" in resp_open.error.lower()
    # Inner provider was not called!
    assert raw_provider.call_count == call_count_before


@pytest.mark.asyncio
async def test_circuit_breaker_does_not_trip_on_value_error() -> None:
    cb = CircuitBreaker(name="input-error-test", failure_threshold=3, timeout=0.1)

    async def bad_arg_func() -> None:
        raise ValueError("Invalid indicator format")

    for _ in range(5):
        with pytest.raises(ValueError, match="Invalid indicator"):
            await cb.call(bad_arg_func)

    # ValueError should NOT increment consecutive_failures or trip circuit breaker
    assert cb.consecutive_failures == 0
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_provider_does_not_swallow_value_error() -> None:
    class StrictIPOnlyProvider:
        name = "strict_ip"
        supported_indicators = {ThreatIndicatorType.IPV4}

        async def lookup(
            self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
        ) -> ThreatIntelResponse:
            if indicator_type != ThreatIndicatorType.IPV4:
                raise ValueError("Only IPV4 is supported")
            return ThreatIntelResponse(
                indicator=indicator,
                indicator_type=indicator_type,
                is_malicious=False,
                provider_name=self.name,
            )

        async def is_healthy(self) -> bool:
            return True

        def get_remaining_budget(self) -> int:
            return 100

    wrapped = CircuitBreakerProvider(StrictIPOnlyProvider(), failure_threshold=3)

    # Calling with DOMAIN should raise ValueError, NOT return a fallback benign response
    for _ in range(4):
        with pytest.raises(ValueError, match="Only IPV4 is supported"):
            await wrapped.lookup("example.com", ThreatIndicatorType.DOMAIN)

    # Circuit breaker must remain CLOSED
    assert wrapped.circuit_breaker.state == CircuitState.CLOSED
    assert wrapped.circuit_breaker.consecutive_failures == 0


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_concurrency_probe_limit() -> None:
    cb = CircuitBreaker(
        name="half-open-limit",
        failure_threshold=2,
        recovery_threshold=2,
        recovery_timeout=0.05,
        timeout=0.5,
    )

    async def fail_task() -> None:
        raise ConnectionError("down")

    # Trip to OPEN
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(fail_task)
    assert cb.state == CircuitState.OPEN

    # Wait for recovery timeout -> HALF-OPEN
    await asyncio.sleep(0.08)
    assert cb.state == CircuitState.HALF_OPEN

    # Simultaneous slow probes
    started_barrier = asyncio.Event()
    release_barrier = asyncio.Event()

    async def slow_probe() -> str:
        started_barrier.set()
        await release_barrier.wait()
        return "recovered"

    # Launch 2 probes (recovery_threshold=2)
    task1 = asyncio.create_task(cb.call(slow_probe))
    task2 = asyncio.create_task(cb.call(slow_probe))

    await started_barrier.wait()

    # 3rd probe should exceed recovery_threshold and raise CircuitBreakerOpenError
    with pytest.raises(CircuitBreakerOpenError, match="HALF-OPEN"):
        await cb.call(slow_probe)

    # Release running probes
    release_barrier.set()
    res1, res2 = await asyncio.gather(task1, task2)
    assert res1 == "recovered"
    assert res2 == "recovered"
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_state_property_does_not_reset_active_probes() -> None:
    """Assert that accessing cb.state property during HALF-OPEN probing does NOT reset cb._active_probes."""
    cb = CircuitBreaker(
        name="test-probe-preservation",
        failure_threshold=1,
        recovery_threshold=3,
        recovery_timeout=0.05,
        timeout=1.0,
    )

    async def fail_task() -> None:
        raise ConnectionError("down")

    with pytest.raises(ConnectionError):
        await cb.call(fail_task)
    assert cb._state == CircuitState.OPEN

    # Wait for recovery timeout
    await asyncio.sleep(0.08)

    started_probe = asyncio.Event()
    continue_probe = asyncio.Event()

    async def in_flight_probe() -> str:
        started_probe.set()
        await continue_probe.wait()
        return "success"

    probe_task = asyncio.create_task(cb.call(in_flight_probe))
    await started_probe.wait()

    # Active probe is in-flight under HALF-OPEN
    assert cb._active_probes == 1
    assert cb._state == CircuitState.HALF_OPEN

    # Read state property multiple times
    for _ in range(5):
        assert cb.state == CircuitState.HALF_OPEN
        # Active probes counter must NOT be reset by property access!
        assert cb._active_probes == 1

    continue_probe.set()
    res = await probe_task
    assert res == "success"

