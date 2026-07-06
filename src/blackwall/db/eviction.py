"""
Blackwall Threat Signature Graph – Eviction Manager
====================================================
TASK-PERF-01: Build Graph LFU/TTL Eviction Routine

Background asyncio loop that runs every 60 seconds and enforces two
complementary eviction policies on the SQLite threat signature graph:

TTL Eviction
    Delete signatures whose ``last_matched_at`` is older than
    ``ttl_seconds`` (default: 900 s / 15 min) AND whose ``match_count``
    is below the high-value threshold.

LFU Eviction
    When total signatures exceed ``max_signatures`` (default: 10 000),
    delete the lowest ``match_count`` signatures (excluding high-value
    ones) until the count falls below the threshold.

High-value protection
    Any signature with ``match_count`` > ``high_value_threshold``
    (default: 10) is **never** evicted by either policy.

The manager also updates a ``graph_eviction_stats`` table that
``SQLiteThreatRepository.getStatistics()`` reads to expose live
eviction telemetry.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from blackwall.db.pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration defaults (per TASK-PERF-01 acceptance criteria)
# ---------------------------------------------------------------------------
DEFAULT_TTL_SECONDS: int = 900          # 15 minutes
DEFAULT_MAX_SIGNATURES: int = 10_000    # LFU trigger threshold
DEFAULT_HIGH_VALUE_THRESHOLD: int = 10  # match_count > this → never evict
DEFAULT_INTERVAL_SECONDS: float = 60.0  # background loop cadence


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class EvictionResult:
    """Summary of a single eviction pass."""

    ttl_evicted: int = 0
    lfu_evicted: int = 0
    total_evicted: int = field(init=False)
    signatures_remaining: int = 0
    duration_ms: float = 0.0
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        self.total_evicted = self.ttl_evicted + self.lfu_evicted

    def refresh_total(self) -> None:
        """Recalculate total_evicted after mutation (used internally)."""
        self.total_evicted = self.ttl_evicted + self.lfu_evicted


# ---------------------------------------------------------------------------
# EvictionManager
# ---------------------------------------------------------------------------
class EvictionManager:
    """
    Asynchronous background eviction engine for the Threat Signature Graph.

    Lifecycle
    ---------
    Start the background loop with ``start()``, stop it with ``stop()``.
    Both methods are coroutines and must be awaited.

    Parameters
    ----------
    pool:
        Shared ``AsyncConnectionPool`` from the threat repository.
    ttl_seconds:
        Seconds after which an un-matched signature qualifies for TTL eviction.
    max_signatures:
        LFU eviction activates when total signatures exceed this value.
    high_value_threshold:
        Signatures with ``match_count`` **greater than** this value are exempt
        from all eviction.
    interval_seconds:
        How often (in seconds) the background loop fires.
    """

    def __init__(
        self,
        pool: AsyncConnectionPool,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_signatures: int = DEFAULT_MAX_SIGNATURES,
        high_value_threshold: int = DEFAULT_HIGH_VALUE_THRESHOLD,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self.pool = pool
        self.ttl_seconds = ttl_seconds
        self.max_signatures = max_signatures
        self.high_value_threshold = high_value_threshold
        self.interval_seconds = interval_seconds

        self._task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()

        # Running lifetime totals (cumulative across all passes)
        self._lifetime_ttl_evicted: int = 0
        self._lifetime_lfu_evicted: int = 0
        self._last_result: Optional[EvictionResult] = None

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background eviction loop (non-blocking)."""
        if self._task is not None and not self._task.done():
            logger.warning("EvictionManager already running – ignoring start()")
            return

        await self._ensure_stats_schema()

        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="eviction-manager")
        logger.info(
            f"EvictionManager started "
            f"interval_seconds={self.interval_seconds} "
            f"ttl_seconds={self.ttl_seconds} "
            f"max_signatures={self.max_signatures}"
        )

    async def stop(self) -> None:
        """Signal the background loop to stop and await its termination."""
        self._stop_event.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("EvictionManager did not stop cleanly – cancelling task")
                self._task.cancel()
            except asyncio.CancelledError:
                pass
        logger.info("EvictionManager stopped")

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------
    async def _loop(self) -> None:
        """
        Core eviction loop.  Fires every ``interval_seconds`` until
        ``_stop_event`` is set.
        """
        while not self._stop_event.is_set():
            try:
                await self.run_eviction_pass()
            except Exception:
                logger.exception("Unhandled error in eviction pass – will retry next cycle")

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except asyncio.TimeoutError:
                # Expected: interval elapsed, run next pass
                pass

    # ------------------------------------------------------------------
    # Eviction logic (public for testing)
    # ------------------------------------------------------------------
    async def run_eviction_pass(self) -> EvictionResult:
        """
        Execute one full eviction pass (TTL → LFU) and return a summary.

        This is intentionally a public coroutine so unit tests can call it
        directly without waiting for the background timer.
        """
        t0 = time.monotonic()
        result = EvictionResult()

        ttl_count = await self.prune_stale(self.ttl_seconds)
        result.ttl_evicted = ttl_count

        lfu_count = await self.evict_lfu(self.max_signatures)
        result.lfu_evicted = lfu_count
        result.refresh_total()

        # Count remaining signatures
        async with self.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            result.signatures_remaining = row[0] if row else 0

        result.duration_ms = (time.monotonic() - t0) * 1000.0
        result.timestamp = int(time.time())

        # Accumulate lifetime totals
        self._lifetime_ttl_evicted += ttl_count
        self._lifetime_lfu_evicted += lfu_count
        self._last_result = result

        await self._update_stats(result)

        logger.info(
            f"Eviction pass complete "
            f"ttl_evicted={ttl_count} "
            f"lfu_evicted={lfu_count} "
            f"remaining={result.signatures_remaining} "
            f"duration_ms={round(result.duration_ms, 2)}"
        )

        return result

    async def prune_stale(self, ttl_seconds: int) -> int:
        """
        TTL eviction: delete signatures whose ``last_matched_at`` is older
        than ``ttl_seconds`` ago AND whose ``match_count`` does not exceed
        the high-value threshold.

        Cascade-delete of related ``signature_relationships`` edges is
        handled automatically by the ``ON DELETE CASCADE`` foreign-key
        constraint defined in the schema.  The FTS5 ``signatures_ad``
        trigger keeps the full-text index in sync.

        Parameters
        ----------
        ttl_seconds:
            Age threshold in seconds.  Signatures last matched more than
            this many seconds ago qualify for deletion.

        Returns
        -------
        int
            Number of signatures deleted.
        """
        cutoff = int(time.time()) - ttl_seconds

        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                """
                DELETE FROM signatures
                WHERE last_matched_at IS NOT NULL
                  AND last_matched_at < ?
                  AND match_count <= ?
                """,
                (cutoff, self.high_value_threshold),
            )
            deleted = cursor.rowcount if cursor.rowcount is not None else 0

        if deleted > 0:
            logger.debug(f"TTL eviction removed signatures count={deleted} cutoff={cutoff}")

        return deleted

    async def evict_lfu(self, max_signatures: int) -> int:
        """
        LFU eviction: if total signatures exceed ``max_signatures``, delete
        the lowest ``match_count`` non-high-value signatures until the graph
        falls below the threshold.

        High-value signatures (``match_count > high_value_threshold``) are
        **never** touched.

        Parameters
        ----------
        max_signatures:
            Delete candidates until count falls below this value.

        Returns
        -------
        int
            Number of signatures deleted during this LFU pass.
        """
        async with self.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            total = row[0] if row else 0

        if total <= max_signatures:
            return 0

        to_delete = total - max_signatures

        # Select the ``to_delete`` lowest-frequency candidates, excluding
        # high-value signatures.  Sort by match_count ASC, then by
        # last_matched_at ASC (oldest first) to break ties deterministically.
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                """
                SELECT signature_id
                FROM signatures
                WHERE match_count <= ?
                ORDER BY match_count ASC, last_matched_at ASC
                LIMIT ?
                """,
                (self.high_value_threshold, to_delete),
            )
            rows = await cursor.fetchall()

        if not rows:
            logger.warning(
                f"LFU eviction needed but no evictable candidates found "
                f"(all remaining signatures are high-value) "
                f"total={total} max_signatures={max_signatures}"
            )
            return 0

        candidate_ids = [r[0] for r in rows]

        # Batch-delete using a single parameterised statement.
        # SQLite supports up to 999 host parameters; chunk to be safe.
        deleted_total = 0
        chunk_size = 900
        for i in range(0, len(candidate_ids), chunk_size):
            chunk = candidate_ids[i : i + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            async with self.pool.connection() as conn:
                cursor = await conn.execute(
                    f"DELETE FROM signatures WHERE signature_id IN ({placeholders})",
                    chunk,
                )
                deleted_total += cursor.rowcount if cursor.rowcount is not None else 0

        if deleted_total > 0:
            logger.debug(f"LFU eviction removed signatures count={deleted_total}")

        return deleted_total

    # ------------------------------------------------------------------
    # Statistics tracking
    # ------------------------------------------------------------------
    async def _ensure_stats_schema(self) -> None:
        """
        Create the ``graph_eviction_stats`` table if it does not yet exist.
        This table is append-only (one row per eviction pass) and is used
        by ``SQLiteThreatRepository.getStatistics()`` to expose live
        eviction counts to callers.
        """
        async with self.pool.connection() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_eviction_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_at INTEGER NOT NULL,
                    ttl_evicted INTEGER NOT NULL DEFAULT 0,
                    lfu_evicted INTEGER NOT NULL DEFAULT 0,
                    total_evicted INTEGER NOT NULL DEFAULT 0,
                    signatures_remaining INTEGER NOT NULL DEFAULT 0,
                    duration_ms REAL NOT NULL DEFAULT 0.0
                )
                """
            )

    async def _update_stats(self, result: EvictionResult) -> None:
        """Append one row to ``graph_eviction_stats`` for this pass."""
        async with self.pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO graph_eviction_stats
                    (run_at, ttl_evicted, lfu_evicted, total_evicted,
                     signatures_remaining, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp,
                    result.ttl_evicted,
                    result.lfu_evicted,
                    result.total_evicted,
                    result.signatures_remaining,
                    result.duration_ms,
                ),
            )

    async def get_lifetime_eviction_count(self) -> int:
        """Return total signatures evicted since this manager was created."""
        return self._lifetime_ttl_evicted + self._lifetime_lfu_evicted

    async def get_total_eviction_count_from_db(self) -> int:
        """
        Return the cumulative eviction count persisted in the database.
        Useful after a restart when in-memory counters have been reset.
        """
        try:
            async with self.pool.connection() as conn:
                cursor = await conn.execute(
                    "SELECT COALESCE(SUM(total_evicted), 0) FROM graph_eviction_stats"
                )
                row = await cursor.fetchone()
                return int(row[0]) if row else 0
        except Exception:
            return 0
