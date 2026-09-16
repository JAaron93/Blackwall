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
