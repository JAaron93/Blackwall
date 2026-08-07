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
        self.db_file = None
        self.deleted_count = 0
        self.total_remaining = 0
        self.high_value_preserved = False


@pytest.fixture
def lfu_state(tmp_path):
    state = LFUBDDState()
    state.db_file = str(tmp_path / "test_lfu_bdd.db")
    return state


@given("a threat repository populated with 120 low-value signatures and 10 high-value signatures")
def given_populated_repo(lfu_state):
    pass


@when("LFU eviction is executed with a max signature limit of 100")
def when_lfu_eviction_executed(lfu_state):
    async def _run_scenario():
        repo = SQLiteThreatRepository(db_path=lfu_state.db_file)
        await repo.initialize()
        try:
            eviction_mgr = EvictionManager(
                pool=repo.pool,
                max_signatures=100,
                high_value_threshold=10,
            )

            # Insert 120 low-value signatures
            for i in range(120):
                await repo.writeSignature(_sig(f"sig_low_{i:04d}", match_count=1))

            # Insert 10 high-value signatures
            for i in range(10):
                await repo.writeSignature(_sig(f"sig_high_{i:04d}", match_count=20))

            # Run LFU eviction
            lfu_state.deleted_count = await eviction_mgr.evict_lfu(max_signatures=100)

            # Retrieve total remaining count
            stats = await repo.getStatistics()
            lfu_state.total_remaining = stats["totalSignatures"]

            # Verify high-value signature preservation
            all_preserved = True
            async with repo.pool.connection() as conn:
                for i in range(10):
                    cursor = await conn.execute(
                        "SELECT signature_id FROM signatures WHERE signature_id = ?",
                        (f"sig_high_{i:04d}",),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        all_preserved = False
                        break
            lfu_state.high_value_preserved = all_preserved
        finally:
            await repo.close()

    run_async(_run_scenario())


@then("30 low-value signatures are evicted in batch")
def then_check_evicted_count(lfu_state):
    assert lfu_state.deleted_count == 30
    assert lfu_state.total_remaining == 100


@then("all 10 high-value signatures remain intact in the database")
def then_check_high_value_preserved(lfu_state):
    assert lfu_state.high_value_preserved is True
