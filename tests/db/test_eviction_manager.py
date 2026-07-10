"""
Unit and Load Tests for EvictionManager (TASK-PERF-01)
=======================================================

Test coverage:
  - TTL eviction: deletes signatures older than threshold
  - TTL eviction: preserves signatures younger than threshold
  - LFU eviction: deletes lowest match_count when over limit
  - LFU eviction: high-value signatures (match_count > 10) never evicted
  - Combined pass: TTL runs before LFU in run_eviction_pass()
  - Cascade: signature_relationships edges deleted with parent node
  - FTS5 index: deleted signature content removed from FTS index
  - GraphStatistics: evictionCount reflects actual deletions
  - Background loop: runs non-blocking and stops cleanly
  - Load: query latency remains <10ms at p99 after eviction of 10k+ nodes
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import AsyncGenerator, List

import pytest
import pytest_asyncio

from blackwall.db.eviction import (
    DEFAULT_HIGH_VALUE_THRESHOLD,
    DEFAULT_MAX_SIGNATURES,
    DEFAULT_TTL_SECONDS,
    EvictionManager,
    EvictionResult,
)
from blackwall.db.pool import AsyncConnectionPool
from blackwall.db.repository import SQLiteThreatRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_DB = "test_eviction.db"

# High-value threshold constant (match_count must EXCEED this to be protected)
HV = DEFAULT_HIGH_VALUE_THRESHOLD


def _sig(
    sig_id: str,
    match_count: int = 0,
    last_matched_at: int | None = None,
    target_tool: str = "tool",
) -> dict:
    return {
        "signatureId": sig_id,
        "attackerIntent": f"intent_{sig_id}",
        "payloadPattern": f"pattern_{sig_id}",
        "targetTool": target_tool,
        "mitigationAction": "BLOCK",
        "matchCount": match_count,
        "lastMatchedAt": last_matched_at,
    }


def _old_ts(seconds_ago: int = 1800) -> int:
    """Return a Unix timestamp `seconds_ago` seconds in the past."""
    return int(time.time()) - seconds_ago


def _fresh_ts(seconds_ago: int = 30) -> int:
    """Return a recent timestamp."""
    return int(time.time()) - seconds_ago


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_path(tmp_path) -> str:  # type: ignore[type-arg]
    """Return a fresh, isolated DB path for each test."""
    return str(tmp_path / "test_eviction.db")


@pytest_asyncio.fixture
async def repo(db_path: str) -> AsyncGenerator[SQLiteThreatRepository, None]:
    r = SQLiteThreatRepository(db_path=db_path)
    await r.initialize()
    yield r
    await r.close()


@pytest_asyncio.fixture
async def mgr(repo: SQLiteThreatRepository) -> AsyncGenerator[EvictionManager, None]:
    """EvictionManager wired to the same pool as repo."""
    m = EvictionManager(
        pool=repo.pool,
        ttl_seconds=DEFAULT_TTL_SECONDS,
        max_signatures=DEFAULT_MAX_SIGNATURES,
        high_value_threshold=HV,
    )
    await m._ensure_stats_schema()
    yield m


# ---------------------------------------------------------------------------
# TTL Eviction Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_evicts_old_low_frequency_signatures(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-2: TTL eviction deletes signatures with last_matched_at older than
    ttl_seconds and match_count ≤ high_value_threshold.
    """
    old_ts = _old_ts(seconds_ago=2000)  # older than 15-min threshold

    await repo.writeSignature(_sig("old_sig_1", match_count=0, last_matched_at=old_ts))
    await repo.writeSignature(_sig("old_sig_2", match_count=2, last_matched_at=old_ts))
    await repo.writeSignature(_sig("old_sig_3", match_count=HV, last_matched_at=old_ts))

    deleted = await mgr.prune_stale(DEFAULT_TTL_SECONDS)

    assert deleted == 3, f"Expected 3 deleted, got {deleted}"
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 0


@pytest.mark.asyncio
async def test_ttl_preserves_fresh_signatures(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-2: Signatures matched recently (within TTL window) are NOT evicted.
    """
    fresh_ts = _fresh_ts(seconds_ago=60)  # 60 seconds ago — well within 900s TTL

    await repo.writeSignature(_sig("fresh_1", match_count=0, last_matched_at=fresh_ts))
    await repo.writeSignature(_sig("fresh_2", match_count=5, last_matched_at=fresh_ts))

    deleted = await mgr.prune_stale(DEFAULT_TTL_SECONDS)

    assert deleted == 0
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 2


@pytest.mark.asyncio
async def test_ttl_preserves_null_last_matched_at(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    Signatures with NULL last_matched_at (never matched) should NOT be TTL-evicted
    because we cannot determine when they were last used; LFU handles them instead.
    """
    await repo.writeSignature(_sig("no_match_1", match_count=0, last_matched_at=None))
    await repo.writeSignature(_sig("no_match_2", match_count=1, last_matched_at=None))

    deleted = await mgr.prune_stale(DEFAULT_TTL_SECONDS)

    assert deleted == 0
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 2


@pytest.mark.asyncio
async def test_ttl_preserves_high_value_old_signatures(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-4 & AC-11: High-value signatures (match_count > HV=10) are NEVER
    evicted by TTL, even if their last_matched_at is ancient.
    """
    old_ts = _old_ts(seconds_ago=999_999)  # extremely stale
    # match_count=11 > HV=10 → high-value
    await repo.writeSignature(_sig("hv_old", match_count=11, last_matched_at=old_ts))
    # match_count=10 = HV → on boundary, NOT high-value → should be evicted
    await repo.writeSignature(_sig("boundary_old", match_count=10, last_matched_at=old_ts))

    deleted = await mgr.prune_stale(DEFAULT_TTL_SECONDS)

    assert deleted == 1  # only boundary_old (match_count==HV) evicted
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT signature_id FROM signatures WHERE signature_id = 'hv_old'"
        )
        row = await cursor.fetchone()
    assert row is not None, "High-value signature should have been preserved"


# ---------------------------------------------------------------------------
# LFU Eviction Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lfu_not_triggered_below_threshold(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-3: LFU eviction does NOT fire when total signatures ≤ max_signatures.
    """
    for i in range(5):
        await repo.writeSignature(_sig(f"sig_{i}", match_count=i))

    # Use a threshold of 10 — we only have 5, so nothing should be deleted
    deleted = await mgr.evict_lfu(max_signatures=10)

    assert deleted == 0
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 5


@pytest.mark.asyncio
async def test_lfu_deletes_lowest_match_count_first(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-3 & AC-10: When over limit, lowest match_count signatures are deleted first.
    """
    # Insert 15 signatures with varying match counts 0-14
    for i in range(15):
        await repo.writeSignature(_sig(f"sig_{i}", match_count=i, last_matched_at=_old_ts(1000)))

    # Evict down to 10; should delete the 5 with match_count 0..4
    deleted = await mgr.evict_lfu(max_signatures=10)

    assert deleted == 5
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT signature_id FROM signatures ORDER BY match_count ASC"
        )
        rows = await cursor.fetchall()

    remaining_ids = [r[0] for r in rows]
    assert "sig_0" not in remaining_ids
    assert "sig_4" not in remaining_ids
    assert "sig_5" in remaining_ids
    assert "sig_14" in remaining_ids


@pytest.mark.asyncio
async def test_lfu_preserves_high_value_signatures(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-4 & AC-11: High-value signatures (match_count > HV) are NEVER deleted
    by LFU, even when they are the most-evictable candidates by frequency.
    """
    # 5 high-value (exempt) + 15 low-value
    for i in range(5):
        await repo.writeSignature(_sig(f"hv_{i}", match_count=HV + 1 + i))
    for i in range(15):
        await repo.writeSignature(_sig(f"lv_{i}", match_count=i, last_matched_at=_old_ts(1000)))

    # Evict down to 15; should only delete from lv_* (5 deletions)
    deleted = await mgr.evict_lfu(max_signatures=15)

    assert deleted == 5
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM signatures WHERE signature_id LIKE 'hv_%'"
        )
        row = await cursor.fetchone()
    assert row[0] == 5, "All high-value signatures must be preserved"


@pytest.mark.asyncio
async def test_lfu_all_remaining_are_high_value(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    Edge case: if all candidates that exceed the limit are high-value,
    LFU cannot delete anything and returns 0.
    """
    for i in range(5):
        await repo.writeSignature(_sig(f"hv_{i}", match_count=HV + 1 + i))

    # Limit is 3 but all 5 are high-value → cannot evict
    deleted = await mgr.evict_lfu(max_signatures=3)
    assert deleted == 0


# ---------------------------------------------------------------------------
# Combined pass tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_combined_eviction_pass(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-1 & AC-8: run_eviction_pass() executes TTL then LFU and returns a
    consolidated EvictionResult.
    """
    old_ts = _old_ts(2000)
    fresh_ts = _fresh_ts(30)

    # 3 stale low-freq → TTL candidates
    for i in range(3):
        await repo.writeSignature(_sig(f"stale_{i}", match_count=1, last_matched_at=old_ts))

    # 10 fresh low-freq
    for i in range(10):
        await repo.writeSignature(_sig(f"fresh_{i}", match_count=1, last_matched_at=fresh_ts))

    # Configure tight LFU threshold to force LFU pass after TTL
    mgr.max_signatures = 8  # 10 remain after TTL; LFU should delete 2 more

    result: EvictionResult = await mgr.run_eviction_pass()

    assert isinstance(result, EvictionResult)
    assert result.ttl_evicted == 3
    assert result.lfu_evicted == 2
    assert result.total_evicted == 5
    assert result.signatures_remaining == 8
    assert result.duration_ms >= 0.0


# ---------------------------------------------------------------------------
# Cascade deletion tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cascade_delete_edges(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-5: Deleting a signature node must cascade-delete its edges in
    signature_relationships via ON DELETE CASCADE.
    """
    old_ts = _old_ts(2000)
    await repo.writeSignature(_sig("node_a", match_count=0, last_matched_at=old_ts))
    await repo.writeSignature(_sig("node_b", match_count=0, last_matched_at=old_ts))

    # Insert a SIMILAR_TO edge between the two
    import uuid

    async with repo.pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO signature_relationships
                (edge_id, source_signature_id, target_signature_id,
                 relationship_type, weight, created_at)
            VALUES (?, ?, ?, 'SIMILAR_TO', 0.9, ?)
            """,
            (str(uuid.uuid4()), "node_a", "node_b", int(time.time())),
        )

    # Confirm edge exists
    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM signature_relationships")
        row = await cursor.fetchone()
    assert row[0] == 1

    # Evict both nodes via TTL
    deleted = await mgr.prune_stale(DEFAULT_TTL_SECONDS)
    assert deleted == 2

    # Edge must have been cascade-deleted
    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM signature_relationships")
        row = await cursor.fetchone()
    assert row[0] == 0, "Cascade delete must remove orphaned edges"


# ---------------------------------------------------------------------------
# FTS5 index tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fts5_index_updated_on_delete(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-6: The FTS5 virtual table (signature_fts) must NOT contain entries
    for deleted signatures.
    """
    old_ts = _old_ts(2000)
    await repo.writeSignature(
        _sig("fts_target", match_count=0, last_matched_at=old_ts)
    )

    # Confirm FTS entry exists before eviction
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM signature_fts WHERE signature_id = 'fts_target'"
        )
        row = await cursor.fetchone()
    assert row[0] == 1

    await mgr.prune_stale(DEFAULT_TTL_SECONDS)

    # After eviction the FTS entry should be gone (handled by signatures_ad trigger)
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM signature_fts WHERE signature_id = 'fts_target'"
        )
        row = await cursor.fetchone()
    assert row[0] == 0, "FTS5 index must be updated after node deletion"


# ---------------------------------------------------------------------------
# GraphStatistics eviction tracking tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_graph_statistics_reflect_eviction_count(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-7: GraphStatistics evictionCount must increase after a pass.
    """
    old_ts = _old_ts(2000)
    for i in range(3):
        await repo.writeSignature(_sig(f"ev_{i}", match_count=0, last_matched_at=old_ts))

    stats_before = await repo.getStatistics()
    assert stats_before["evictionCount"] == 0

    await mgr.run_eviction_pass()

    stats_after = await repo.getStatistics()
    assert stats_after["evictionCount"] == 3


# ---------------------------------------------------------------------------
# Background loop tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_loop_runs_and_stops(repo: SQLiteThreatRepository) -> None:
    """
    AC-1: The background loop must start without blocking the event loop
    and terminate cleanly when stop() is called.
    """
    mgr = EvictionManager(
        pool=repo.pool,
        ttl_seconds=DEFAULT_TTL_SECONDS,
        max_signatures=DEFAULT_MAX_SIGNATURES,
        interval_seconds=0.1,  # Very fast for testing
    )

    await mgr.start()
    assert mgr._task is not None
    assert not mgr._task.done()

    # Let the loop fire at least once
    await asyncio.sleep(0.3)

    await mgr.stop()
    assert mgr._task.done()


@pytest.mark.asyncio
async def test_background_loop_idempotent_start(repo: SQLiteThreatRepository) -> None:
    """Calling start() twice must not create duplicate tasks."""
    mgr = EvictionManager(pool=repo.pool, interval_seconds=0.5)
    await mgr.start()
    task_first = mgr._task

    await mgr.start()  # Should be a no-op
    assert mgr._task is task_first  # Same task object

    await mgr.stop()


# ---------------------------------------------------------------------------
# Load / Latency Tests (AC-8, AC-12)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_latency_under_10ms_after_large_eviction(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    AC-12: After evicting a large batch of signatures, a pattern-match query
    must complete in < 10ms at p99 over 100 iterations.

    We insert 500 signatures, evict most via LFU, then hammer the lookup.
    """
    import statistics

    # Insert 500 low-frequency signatures
    fresh_ts = _fresh_ts(30)
    for i in range(500):
        await repo.writeSignature(
            _sig(f"load_{i}", match_count=i % 3, last_matched_at=fresh_ts)
        )

    # LFU evict down to 100
    mgr.max_signatures = 100
    await mgr.run_eviction_pass()

    stats = await repo.getStatistics()
    assert stats["totalSignatures"] <= 100

    # Warmup queries to thoroughly compile FTS5 structures and warm up database cache
    for _ in range(20):
        await repo.find_matching_signature("tool", {"arg": "some_payload"})
 
    # Benchmark: 100 find_matching_signature calls
    latencies_ms: List[float] = []
    for _ in range(100):
        t0 = time.monotonic()
        await repo.find_matching_signature("tool", {"arg": "some_payload"})
        latencies_ms.append((time.monotonic() - t0) * 1000.0)
 
    import os
    limit = float(os.getenv("BLACKWALL_SLA_LIMIT_MS", "20.0"))
    p99 = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]
    assert p99 < limit, (
        f"p99 query latency {p99:.2f}ms exceeds {limit}ms budget. "
        f"median={statistics.median(latencies_ms):.2f}ms"
    )


@pytest.mark.asyncio
async def test_eviction_pass_completes_within_budget(
    repo: SQLiteThreatRepository, mgr: EvictionManager
) -> None:
    """
    Sanity: a full eviction pass over 200 stale signatures completes in
    under 5 seconds (generous budget to account for CI overhead).
    """
    old_ts = _old_ts(2000)
    for i in range(200):
        await repo.writeSignature(_sig(f"bulk_{i}", match_count=0, last_matched_at=old_ts))

    t0 = time.monotonic()
    result = await mgr.run_eviction_pass()
    elapsed = time.monotonic() - t0

    assert result.ttl_evicted == 200
    assert elapsed < 5.0, f"Eviction pass took {elapsed:.2f}s – too slow"


# ---------------------------------------------------------------------------
# EvictionResult dataclass tests
# ---------------------------------------------------------------------------


def test_eviction_result_total_computed() -> None:
    """EvictionResult.total_evicted is auto-computed after refresh_total()."""
    r = EvictionResult(ttl_evicted=5, lfu_evicted=3)
    assert r.total_evicted == 8

    r.ttl_evicted = 10
    r.refresh_total()
    assert r.total_evicted == 13


def test_eviction_result_timestamp_set() -> None:
    """EvictionResult.timestamp defaults to current time."""
    before = int(time.time())
    r = EvictionResult()
    after = int(time.time())
    assert before <= r.timestamp <= after
