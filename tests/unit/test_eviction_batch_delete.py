import time
import pytest
from blackwall.db.eviction import EvictionManager
from blackwall.db.repository import SQLiteThreatRepository


def _sig(sig_id: str, match_count: int = 0) -> dict:
    return {
        "signatureId": sig_id,
        "attackerIntent": f"intent_{sig_id}",
        "payloadPattern": f"pattern_{sig_id}",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "matchCount": match_count,
        "lastMatchedAt": int(time.time()),
    }


@pytest.mark.asyncio
async def test_lfu_batch_eviction_single_query_chunking(tmp_path):
    """Verify LFU eviction executes batch parameterized deletions and preserves high-value signatures."""
    db_file = str(tmp_path / "test_lfu_eviction.db")
    repo = SQLiteThreatRepository(db_path=db_file)
    await repo.initialize()

    eviction_mgr = EvictionManager(
        pool=repo.pool,
        max_signatures=100,
        high_value_threshold=10,
    )

    # Insert 120 low-value signatures (matchCount = 1 <= 10)
    for i in range(120):
        await repo.writeSignature(_sig(f"sig_low_{i:04d}", match_count=1))

    # Insert 10 high-value signatures (matchCount = 20 > 10)
    for i in range(10):
        await repo.writeSignature(_sig(f"sig_high_{i:04d}", match_count=20))

    stats_before = await repo.getStatistics()
    assert stats_before["totalSignatures"] == 130

    # Run LFU eviction down to max_signatures=100
    deleted_count = await eviction_mgr.evict_lfu(max_signatures=100)

    # 130 total - 100 max_signatures = 30 signatures to delete
    assert deleted_count == 30

    stats_after = await repo.getStatistics()
    assert stats_after["totalSignatures"] == 100  # 130 - 30

    # Verify high-value signatures were preserved
    async with repo.pool.connection() as conn:
        for i in range(10):
            cursor = await conn.execute(
                "SELECT signature_id FROM signatures WHERE signature_id = ?",
                (f"sig_high_{i:04d}",),
            )
            row = await cursor.fetchone()
            assert row is not None, f"High-value signature sig_high_{i:04d} was improperly evicted"

    await repo.close()
