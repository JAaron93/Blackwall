"""Circuit Breaker & Timeout Safeguards for Threat Intelligence Providers.

Provides a 3-state circuit breaker (CLOSED, OPEN, HALF-OPEN) with configurable
consecutive failure thresholds, 3.0s asynchronous timeouts, and automatic probe recovery.
"""

from __future__ import annotations

import asyncio
from enum import Enum
import logging
import time
from typing import Any, Callable, Coroutine, Optional, Set, TypeVar

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
    ThreatIntelResponse,
)

logger = logging.getLogger("blackwall.threat_intel.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    """3-state Circuit Breaker lifecycle states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF-OPEN"


class CircuitBreakerError(Exception):
    """Base exception for circuit breaker faults."""

    pass


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""

    pass


class ProviderTimeoutError(CircuitBreakerError):
    """Raised when an external threat intelligence provider times out."""

    pass


class CircuitBreaker:
    """3-State Circuit Breaker enforcing failure threshold and recovery probe rules."""

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_threshold: int = 3,
        recovery_timeout: float = 60.0,
        timeout: float = 3.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_threshold = recovery_threshold
        self.recovery_timeout = recovery_timeout
        self.timeout = timeout

        self._state: CircuitState = CircuitState.CLOSED
        self.consecutive_failures: int = 0
        self.successful_probes: int = 0
        self.last_state_change: float = 0.0
        self._lock = asyncio.Lock()
        self._active_probes: int = 0

    @property
    def state(self) -> CircuitState:
        """Current state of the circuit breaker (read-only projection).

        Returns HALF-OPEN if the recovery timeout has elapsed while OPEN,
        without mutating internal state or probe counters outside the lock.
        """
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self.last_state_change > self.recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state

    def _update_state_unlocked(self) -> None:
        """Internal helper to transition state under self._lock."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self.last_state_change > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self.successful_probes = 0
                self._active_probes = 0
                logger.info("Circuit breaker %s transitioned to HALF-OPEN", self.name)

    def record_success(self) -> None:
        """Record a successful provider operation."""
        self.consecutive_failures = 0
        self._update_state_unlocked()
        if self._state == CircuitState.HALF_OPEN:
            self.successful_probes += 1
            if self.successful_probes >= self.recovery_threshold:
                self._state = CircuitState.CLOSED
                self.successful_probes = 0
                self.consecutive_failures = 0
                self._active_probes = 0
                logger.info(
                    "Circuit breaker %s restored to CLOSED after %d successful probes",
                    self.name,
                    self.recovery_threshold,
                )

    def record_failure(self, exception: Optional[Exception] = None) -> None:
        """Record a failed provider operation or timeout."""
        self._update_state_unlocked()
        self.consecutive_failures += 1
        current_state = self._state

        if current_state == CircuitState.HALF_OPEN or self.consecutive_failures >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self.last_state_change = time.monotonic()
            self.successful_probes = 0
            self._active_probes = 0
            logger.warning(
                "Circuit breaker %s tripped to OPEN (consecutive failures: %d, reason: %s)",
                self.name,
                self.consecutive_failures,
                str(exception) if exception else "unspecified",
            )

    async def call(
        self,
        func: Callable[..., Coroutine[Any, Any, T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Executes a coroutine with timeout and circuit breaker tracking."""
        import inspect

        async with self._lock:
            self._update_state_unlocked()
            current_state = self._state
            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker for {self.name} is OPEN (cooldown: {self.recovery_timeout}s)"
                )
            if current_state == CircuitState.HALF_OPEN:
                if self._active_probes >= self.recovery_threshold:
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker for {self.name} is HALF-OPEN (max probes in flight)"
                    )
                self._active_probes += 1

        call_timeout = kwargs.get("timeout", self.timeout)
        sig = inspect.signature(func)
        call_kwargs = dict(kwargs)
        if "timeout" not in sig.parameters and not any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        ):
            call_kwargs.pop("timeout", None)
        else:
            call_kwargs["timeout"] = call_timeout

        is_half_open = current_state == CircuitState.HALF_OPEN
        try:
            result = await asyncio.wait_for(func(*args, **call_kwargs), timeout=call_timeout)
            async with self._lock:
                if is_half_open:
                    self._active_probes = max(0, self._active_probes - 1)
                self.record_success()
            return result
        except asyncio.TimeoutError as e:
            async with self._lock:
                if is_half_open:
                    self._active_probes = max(0, self._active_probes - 1)
                self.record_failure(e)
            raise ProviderTimeoutError(
                f"Operation timed out after {call_timeout}s in {self.name}"
            ) from e
        except (ValueError, TypeError):
            async with self._lock:
                if is_half_open:
                    self._active_probes = max(0, self._active_probes - 1)
            raise
        except Exception as e:
            async with self._lock:
                if is_half_open:
                    self._active_probes = max(0, self._active_probes - 1)
                self.record_failure(e)
            raise


class CircuitBreakerProvider:
    """Wraps any ThreatIntelProvider with CircuitBreaker and timeout protection.

    Gracefully catches provider timeouts and connection errors, returning standardized
    fallback responses without unhandled exceptions.
    """

    def __init__(
        self,
        provider: ThreatIntelProvider,
        circuit_breaker: Optional[CircuitBreaker] = None,
        timeout: float = 3.0,
        failure_threshold: int = 5,
        recovery_threshold: int = 3,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.provider = provider
        self.timeout = timeout
        self.circuit_breaker = circuit_breaker or CircuitBreaker(
            name=provider.name,
            failure_threshold=failure_threshold,
            recovery_threshold=recovery_threshold,
            recovery_timeout=recovery_timeout,
            timeout=timeout,
        )

    @property
    def name(self) -> str:
        return self.provider.name

    @property
    def supported_indicators(self) -> Set[ThreatIndicatorType]:
        return self.provider.supported_indicators

    def get_remaining_budget(self) -> int:
        return self.provider.get_remaining_budget()

    async def is_healthy(self) -> bool:
        if self.circuit_breaker.state == CircuitState.OPEN:
            return False
        try:
            return await self.provider.is_healthy()
        except Exception:
            return False

    def _make_fallback_response(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        error: str,
    ) -> ThreatIntelResponse:
        """Constructs a normalized benign fallback response when provider is degraded."""
        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=False,
            risk_score=0.0,
            detection_count=0,
            total_engines=0,
            threat_categories=[],
            malware_families=[],
            pulse_count=0,
            references=[],
            provider_name=self.name,
            cached=False,
            error=error,
        )

    async def lookup(
        self,
        indicator: str,
        indicator_type: ThreatIndicatorType,
        timeout: Optional[float] = None,
    ) -> ThreatIntelResponse:
        """Protected lookup execution returning fallback heuristics on errors/timeouts."""
        effective_timeout = timeout if timeout is not None else self.timeout

        if self.circuit_breaker.state == CircuitState.OPEN:
            logger.warning(
                "Provider %s circuit breaker is OPEN. Bypassing provider for %s",
                self.name,
                indicator,
            )
            return self._make_fallback_response(
                indicator,
                indicator_type,
                error=f"Circuit breaker for {self.name} is OPEN",
            )

        try:
            return await self.circuit_breaker.call(
                self.provider.lookup,
                indicator,
                indicator_type,
                timeout=effective_timeout,
            )
        except (ValueError, TypeError):
            # Propagate client input validation errors without swallowing
            raise
        except (CircuitBreakerOpenError, ProviderTimeoutError, Exception) as e:
            logger.warning(
                "Protected provider call %s failed for %s: %s",
                self.name,
                indicator,
                str(e),
            )
            return self._make_fallback_response(
                indicator,
                indicator_type,
                error=str(e),
            )
