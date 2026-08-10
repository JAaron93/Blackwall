import asyncio
import time
from contextlib import asynccontextmanager
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.db.eviction import EvictionManager
from blackwall.db.repository import SQLiteThreatRepository

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
        self.repo = None
        self.eviction_mgr = None
        self.deleted_count = 0
        self.total_remaining = 0
        self.high_value_preserved = False
        self.delete_execute_queries = []
        self.executemany_calls = []
        self.loop = None

    def run(self, coro):
        return self.loop.run_until_complete(coro)


@pytest.fixture
def lfu_state(tmp_path):
    state = LFUBDDState()
    state.db_file = str(tmp_path / "test_lfu_bdd.db")
    state.loop = asyncio.new_event_loop()
    asyncio.set_event_loop(state.loop)
    try:
        yield state
    finally:
        if state.repo is not None:
            try:
                state.loop.run_until_complete(state.repo.close())
            except Exception:
                pass
        state.loop.close()


@given("a threat repository populated with 120 low-value signatures and 10 high-value signatures")
def given_populated_repo(lfu_state):
    async def _setup():
        lfu_state.repo = SQLiteThreatRepository(db_path=lfu_state.db_file)
        await lfu_state.repo.initialize()

        lfu_state.eviction_mgr = EvictionManager(
            pool=lfu_state.repo.pool,
            max_signatures=100,
            high_value_threshold=10,
        )

        # Insert 120 low-value signatures
        for i in range(120):
            await lfu_state.repo.writeSignature(_sig(f"sig_low_{i:04d}", match_count=1))

        # Insert 10 high-value signatures
        for i in range(10):
            await lfu_state.repo.writeSignature(_sig(f"sig_high_{i:04d}", match_count=20))

    lfu_state.run(_setup())


@when("LFU eviction is executed with a max signature limit of 100")
def when_lfu_eviction_executed(lfu_state):
    async def _evict():
        # Spy on SQL query execution during evict_lfu
        orig_connection = lfu_state.repo.pool.connection

        @asynccontextmanager
        async def _spy_connection():
            async with orig_connection() as conn:
                orig_execute = conn.execute
                orig_executemany = conn.executemany

                async def _spied_execute(query, parameters=()):
                    query_str = str(query).strip()
                    if "DELETE FROM signatures" in query_str:
                        lfu_state.delete_execute_queries.append((query_str, list(parameters)))
                    return await orig_execute(query, parameters)

                async def _spied_executemany(query, seq_of_parameters=()):
                    query_str = str(query).strip()
                    if "DELETE FROM signatures" in query_str:
                        lfu_state.executemany_calls.append((query_str, list(seq_of_parameters)))
                    return await orig_executemany(query, seq_of_parameters)

                conn.execute = _spied_execute
                conn.executemany = _spied_executemany
                yield conn

        lfu_state.repo.pool.connection = _spy_connection

        # Run LFU eviction
        lfu_state.deleted_count = await lfu_state.eviction_mgr.evict_lfu(max_signatures=100)

        # Restore connection pool
        lfu_state.repo.pool.connection = orig_connection

        # Retrieve total remaining count
        stats = await lfu_state.repo.getStatistics()
        lfu_state.total_remaining = stats["totalSignatures"]

        # Verify high-value signature preservation
        all_preserved = True
        async with lfu_state.repo.pool.connection() as conn:
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

    lfu_state.run(_evict())


@then("30 low-value signatures are evicted in batch")
def then_check_evicted_count(lfu_state):
    assert lfu_state.deleted_count == 30
    assert lfu_state.total_remaining == 100


@then("all 10 high-value signatures remain intact in the database")
def then_check_high_value_preserved(lfu_state):
    assert lfu_state.high_value_preserved is True


@then("single-query parameterized batch deletion is executed without per-row executemany calls")
def then_check_batch_deletion_behavior(lfu_state):
    # Verify zero per-row executemany calls were made
    assert len(lfu_state.executemany_calls) == 0, (
        f"Expected 0 executemany calls, but found {len(lfu_state.executemany_calls)}"
    )

    # Verify single-query batch execution was used for the candidate chunk
    assert len(lfu_state.delete_execute_queries) == 1, (
        f"Expected 1 batch execute call for chunk, but found {len(lfu_state.delete_execute_queries)}"
    )

    query_str, params = lfu_state.delete_execute_queries[0]
    assert "WHERE signature_id IN (" in query_str, (
        f"Query '{query_str}' does not use 'WHERE signature_id IN (...)' batch deletion"
    )
    # 1 high_value_threshold + 1 excess_count parameter = 2 parameters
    assert len(params) == 2, f"Expected 2 bound parameters in batch subquery, got {len(params)}"
