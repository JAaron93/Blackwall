"""GTI Query Budget Tracker.

Implements a token bucket rate limiter that enforces the VirusTotal free-tier
constraint of 4 queries per 60-second sliding window (1 token / 15 seconds).

The tracker is entirely separate from the circuit breaker in GTIMCPClient.
Budget exhaustion (no tokens) is NOT a service failure — it is a planned
graceful degradation path that triggers weight redistribution in the Semantic
Gating Engine.

Usage::

    tracker = GTIQueryBudgetTracker()
    await tracker.start()

    if tracker.tryAcquire():
        result = await gti_client.queryIOC(...)
    else:
        # Apply 0.2 threat score penalty; redistribute GTI weight to CBM + Context
        threat_score += 0.2
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("blackwall.mcp.gti_budget_tracker")

# ────────────────────────────────────────────────────────────
# Public data model
# ────────────────────────────────────────────────────────────


class GTIBudgetMetrics(BaseModel):
    """Snapshot metrics for the GTI Query Budget Tracker.

    Attributes:
        queries_attempted: Total tryAcquire() calls received.
        queries_executed: Calls where a token was successfully consumed.
        queries_deferred: Calls rejected due to budget exhaustion (0 tokens).
        cache_hits: Responses served from local 24-hour TTL cache (no token consumed).
        budget_exhaustion_count: Number of distinct times the bucket hit 0 tokens.
        avg_token_replenishment_interval: Average wall-clock seconds between replenishments.
    """

    queries_attempted: int = Field(default=0, ge=0)
    queries_executed: int = Field(default=0, ge=0)
    queries_deferred: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    budget_exhaustion_count: int = Field(default=0, ge=0)
    avg_token_replenishment_interval: float = Field(default=15.0, ge=0.0)


# ────────────────────────────────────────────────────────────
# Token bucket implementation
# ────────────────────────────────────────────────────────────

_BUCKET_CAPACITY: int = 4  # VirusTotal free tier: 4 queries/minute
_REPLENISHMENT_INTERVAL: float = 15.0  # seconds — 1 token every 15 s = 4/minute


class GTIQueryBudgetTracker:
    """Token bucket rate limiter for GTI (VirusTotal) queries.

    Enforces a hard cap of 4 live GTI queries per 60-second sliding window by
    modelling the VirusTotal free-tier limit as a token bucket with:

    * capacity  : 4 tokens
    * refill     : +1 token every 15 seconds
    * initial    : full (4 tokens)

    All public methods are safe to call from concurrent asyncio tasks — a single
    ``asyncio.Lock`` guards the token counter and all metric counters.

    Lifecycle::

        tracker = GTIQueryBudgetTracker()
        await tracker.start()   # spawns background replenishment task
        ...
        await tracker.stop()    # cancels replenishment task on shutdown
    """

    def __init__(
        self,
        capacity: int = _BUCKET_CAPACITY,
        replenishment_interval: float = _REPLENISHMENT_INTERVAL,
    ) -> None:
        self._capacity: int = capacity
        self._replenishment_interval: float = replenishment_interval
        self._tokens: int = capacity  # start full
        self._lock: asyncio.Lock = asyncio.Lock()
        self._replenishment_task: Optional[asyncio.Task[None]] = None

        # ── Metrics counters ──────────────────────────────────────────────
        self._queries_attempted: int = 0
        self._queries_executed: int = 0
        self._queries_deferred: int = 0
        self._cache_hits: int = 0
        self._budget_exhaustion_count: int = 0

        # Track replenishment timing for avg_token_replenishment_interval
        self._replenishment_timestamps: list[float] = []

    # ──────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn the background token replenishment coroutine.

        Safe to call multiple times — additional calls are no-ops if the
        replenishment task is already running.
        """
        if self._replenishment_task is None or self._replenishment_task.done():
            self._replenishment_task = asyncio.create_task(
                self._replenish_loop(), name="gti_budget_replenishment"
            )
            logger.info(
                "GTIQueryBudgetTracker started. capacity=%d, interval=%.1fs",
                self._capacity,
                self._replenishment_interval,
            )

    async def stop(self) -> None:
        """Cancel the background replenishment task gracefully."""
        if self._replenishment_task and not self._replenishment_task.done():
            self._replenishment_task.cancel()
            try:
                await self._replenishment_task
            except asyncio.CancelledError:
                pass
            logger.info("GTIQueryBudgetTracker stopped.")

    # ──────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────

    def tryAcquire(self) -> bool:  # noqa: N802 — matches design spec casing
        """Attempt to consume one GTI query token synchronously.

        This method is intentionally **synchronous** because it is called in the
        hot path of SemanticGatingEngine.evaluate() inside an already-running
        event loop.  The internal ``asyncio.Lock`` cannot be used here — instead
        we use a non-blocking counter that is protected by the GIL for CPython.
        For cross-task safety in the async context, use ``async_try_acquire()``
        when calling from a coroutine.

        Returns:
            True  — token consumed; caller may proceed with live GTI query.
            False — budget exhausted; caller should apply 0.2 penalty and
                    redistribute signal weights (GTI 40% → CBM+20%, Context+20%).
        """
        self._queries_attempted += 1

        if self._tokens > 0:
            self._tokens -= 1
            self._queries_executed += 1
            # Increment exhaustion counter only on transition from non-zero to zero
            if self._tokens == 0:
                self._budget_exhaustion_count += 1
            logger.debug(
                "GTI token acquired. remaining_tokens=%d", self._tokens
            )
            return True
        else:
            self._queries_deferred += 1
            logger.info(
                "GTI budget exhausted. queries_deferred=%d", self._queries_deferred
            )
            return False

    async def async_try_acquire(self) -> bool:
        """Coroutine-safe version of tryAcquire using asyncio.Lock.

        Use this variant when calling from an async context where multiple
        concurrent tasks may race to consume the same token.

        Returns:
            True  — token consumed successfully.
            False — no tokens available; budget exhausted.
        """
        async with self._lock:
            self._queries_attempted += 1

            if self._tokens > 0:
                self._tokens -= 1
                self._queries_executed += 1
                # Increment exhaustion counter only on transition from non-zero to zero
                if self._tokens == 0:
                    self._budget_exhaustion_count += 1
                logger.debug(
                    "GTI token acquired (async). remaining_tokens=%d", self._tokens
                )
                return True
            else:
                self._queries_deferred += 1
                logger.info(
                    "GTI budget exhausted (async). queries_deferred=%d",
                    self._queries_deferred,
                )
                return False

    def getAvailableTokens(self) -> int:  # noqa: N802 — matches design spec
        """Return the current token count without consuming any.

        Returns:
            Integer in the range [0, capacity].
        """
        return self._tokens

    def record_cache_hit(self) -> None:
        """Record that an IOC response was served from local cache.

        Cache hits do NOT consume a token; calling this keeps the ``cache_hit_rate``
        metric accurate without modifying the bucket.
        """
        self._cache_hits += 1

    def getMetrics(self) -> GTIBudgetMetrics:  # noqa: N802 — matches design spec
        """Return a snapshot of current budget tracking metrics.

        Returns:
            GTIBudgetMetrics with all counters at the time of the call.
        """
        avg_interval = self._compute_avg_replenishment_interval()
        return GTIBudgetMetrics(
            queries_attempted=self._queries_attempted,
            queries_executed=self._queries_executed,
            queries_deferred=self._queries_deferred,
            cache_hits=self._cache_hits,
            budget_exhaustion_count=self._budget_exhaustion_count,
            avg_token_replenishment_interval=avg_interval,
        )

    def reset(self) -> None:
        """Reset token bucket to full capacity and clear all metrics.

        Intended for use in tests and demo resets only.
        """
        self._tokens = self._capacity
        self._queries_attempted = 0
        self._queries_executed = 0
        self._queries_deferred = 0
        self._cache_hits = 0
        self._budget_exhaustion_count = 0
        self._replenishment_timestamps.clear()
        logger.debug("GTIQueryBudgetTracker reset to full capacity.")

    # ──────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────

    async def _replenish_loop(self) -> None:
        """Background coroutine that adds 1 token every replenishment_interval seconds.

        Runs until cancelled (via stop()). Enforces hard cap at _capacity.
        """
        while True:
            await asyncio.sleep(self._replenishment_interval)
            async with self._lock:
                if self._tokens < self._capacity:
                    self._tokens += 1
                    now = time.monotonic()
                    self._replenishment_timestamps.append(now)
                    # Keep only the last 60 timestamps to bound memory
                    if len(self._replenishment_timestamps) > 60:
                        self._replenishment_timestamps = self._replenishment_timestamps[-60:]
                    logger.debug(
                        "GTI token replenished. current_tokens=%d", self._tokens
                    )

    def _compute_avg_replenishment_interval(self) -> float:
        """Compute the average wall-clock seconds between replenishment events."""
        timestamps = self._replenishment_timestamps
        if len(timestamps) < 2:
            return self._replenishment_interval  # default to configured value
        intervals = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]
        return sum(intervals) / len(intervals)
