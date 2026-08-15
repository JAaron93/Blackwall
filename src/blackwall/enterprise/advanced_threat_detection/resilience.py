"""Resilience, crash isolation, and resource throttling for Blackwall Advanced Threat Detection."""

import asyncio
from collections import deque
import logging
import time
from typing import Any, Coroutine, TypeVar

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.resilience")

T = TypeVar("T")


class SafeDetectionRunner:
    """Safe execution wrapper for detection algorithms ensuring crash isolation and timeout containment."""

    def __init__(self, default_timeout_seconds: float = 5.0) -> None:
        self.default_timeout_seconds = default_timeout_seconds

    async def run_safe(
        self,
        detector_name: str,
        coro: Coroutine[Any, Any, T],
        fallback: T,
        timeout_seconds: float | None = None,
    ) -> T:
        """Execute a single detection coroutine safely with timeout and error containment.

        Exceptions of type TypeError, ValueError, and KeyError are immediately re-raised
        to preserve contract validation per architecture rules.
        """
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )

        try:
            if timeout is not None and timeout > 0:
                return await asyncio.wait_for(coro, timeout=timeout)
            return await coro
        except (TypeError, ValueError, KeyError):
            # Architecture Rule 8: Never catch/swallow TypeError, ValueError, KeyError
            raise
        except asyncio.TimeoutError:
            logger.warning(
                "Detection algorithm '%s' timed out after %.3fs; returning safe fallback",
                detector_name,
                timeout,
            )
            return fallback
        except Exception as exc:
            logger.warning(
                "Detection algorithm '%s' crashed with error: %s; returning safe fallback",
                detector_name,
                exc,
                exc_info=True,
            )
            return fallback

    async def run_parallel_safe(
        self,
        tasks: dict[str, tuple[Coroutine[Any, Any, Any], Any, float | None]],
    ) -> dict[str, Any]:
        """Execute multiple detection algorithms in parallel with individual crash and timeout isolation.

        Parameters
        ----------
        tasks : dict
            Mapping of detector_name -> (coro, fallback_value, optional_timeout_seconds)

        Returns
        -------
        dict
            Mapping of detector_name -> execution result or fallback value
        """
        if not tasks:
            return {}

        keys = list(tasks.keys())
        safe_coros = [
            self.run_safe(
                detector_name=name,
                coro=spec[0],
                fallback=spec[1],
                timeout_seconds=spec[2],
            )
            for name, spec in tasks.items()
        ]

        results = await asyncio.gather(*safe_coros, return_exceptions=False)
        return dict(zip(keys, results))


class ResourceThrottler:
    """Resource manager and rate throttler protecting the detection pipeline under high load."""

    def __init__(
        self,
        max_events_per_second: int = 1000,
        max_queue_size: int = 10000,
        sliding_window_seconds: float = 1.0,
        max_memory_mb: int = 512,
    ) -> None:
        if max_events_per_second <= 0:
            raise ValueError("max_events_per_second must be positive")
        if max_queue_size <= 0:
            raise ValueError("max_queue_size must be positive")
        if sliding_window_seconds <= 0:
            raise ValueError("sliding_window_seconds must be positive")
        if max_memory_mb <= 0:
            raise ValueError("max_memory_mb must be positive")

        self.max_events_per_second = max_events_per_second
        self.max_queue_size = max_queue_size
        self.sliding_window_seconds = sliding_window_seconds
        self.max_memory_mb = max_memory_mb
        self._timestamps: deque[float] = deque()

    def record_event(self) -> None:
        """Record an event timestamp in the sliding window and prune expired entries."""
        now = time.monotonic()
        self._timestamps.append(now)
        cutoff = now - self.sliding_window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def current_rate(self) -> float:
        """Calculate the current event arrival rate in events per second."""
        now = time.monotonic()
        cutoff = now - self.sliding_window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        if not self._timestamps:
            return 0.0
        return len(self._timestamps) / self.sliding_window_seconds

    def should_throttle(
        self,
        current_queue_size: int = 0,
        current_memory_mb: float = 0.0,
    ) -> bool:
        """Check whether incoming events or analysis should be throttled."""
        if current_queue_size >= self.max_queue_size:
            return True
        if self.current_rate() >= self.max_events_per_second:
            return True
        if current_memory_mb > 0 and current_memory_mb >= self.max_memory_mb:
            return True
        return False

    def get_analysis_depth(
        self, base_depth: int = 5, current_queue_size: int = 0
    ) -> int:
        """Calculate dynamic analysis depth based on current queue load and event rate."""
        if base_depth <= 0:
            raise ValueError("base_depth must be positive")

        rate = self.current_rate()
        is_severe = (
            current_queue_size >= self.max_queue_size
            or rate >= (self.max_events_per_second * 1.5)
        )
        if is_severe:
            return max(1, base_depth // 3)

        is_moderate = (
            current_queue_size >= (self.max_queue_size * 0.7)
            or rate >= (self.max_events_per_second * 0.9)
        )
        if is_moderate:
            return max(1, base_depth // 2)

        return base_depth
