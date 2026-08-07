import time
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.db.eviction import EvictionManager
from blackwall.db.repository import SQLiteThreatRepository
from tests.step_defs.async_utils import run_async

scenarios("../features/lfu_eviction_security.feature")


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


class LFUBDDState:
    def __init__(self):
        self.repo = None
        self.eviction_mgr = None
        self.deleted_count = 0


@pytest.fixture
def lfu_state():
    return LFUBDDState()


@given("a threat repository populated with 120 low-value signatures and 10 high-value signatures")
def given_populated_repo(lfu_state, tmp_path):
    db_file = str(tmp_path / "test_lfu_bdd.db")
    lfu_state.repo = SQLiteThreatRepository(db_path=db_file)
    run_async(lfu_state.repo.initialize())

    lfu_state.eviction_mgr = EvictionManager(
        pool=lfu_state.repo.pool,
        max_signatures=100,
        high_value_threshold=10,
    )

    for i in range(120):
        run_async(lfu_state.repo.writeSignature(_sig(f"sig_low_{i:04d}", match_count=1)))

    for i in range(10):
        run_async(lfu_state.repo.writeSignature(_sig(f"sig_high_{i:04d}", match_count=20)))


@when("LFU eviction is executed with a max signature limit of 100")
def when_lfu_eviction_executed(lfu_state):
    lfu_state.deleted_count = run_async(lfu_state.eviction_mgr.evict_lfu(max_signatures=100))


@then("30 low-value signatures are evicted in batch")
def then_check_evicted_count(lfu_state):
    assert lfu_state.deleted_count == 30
    stats = run_async(lfu_state.repo.getStatistics())
    assert stats["totalSignatures"] == 100


@then("all 10 high-value signatures remain intact in the database")
def then_check_high_value_preserved(lfu_state):
    async def check_sigs():
        async with lfu_state.repo.pool.connection() as conn:
            for i in range(10):
                cursor = await conn.execute(
                    "SELECT signature_id FROM signatures WHERE signature_id = ?",
                    (f"sig_high_{i:04d}",),
                )
                row = await cursor.fetchone()
                assert row is not None, f"High-value signature sig_high_{i:04d} missing"
    run_async(check_sigs())
    run_async(lfu_state.repo.close())
