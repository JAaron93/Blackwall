import os
import asyncio
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.db.pool import AsyncConnectionPool

TEST_DB_PATH = "test_blackwall.db"


@pytest_asyncio.fixture
async def repo() -> AsyncGenerator[SQLiteThreatRepository, None]:
    # Setup
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    repository = SQLiteThreatRepository(db_path=TEST_DB_PATH)
    await repository.initialize()
    yield repository

    # Teardown
    await repository.close()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


@pytest.mark.asyncio
async def test_wal_mode_activation(repo: SQLiteThreatRepository) -> None:
    """Verify that WAL mode is activated correctly."""
    # We can acquire a connection directly from the pool to test pragma
    async with repo.pool.connection() as conn:
        cursor = await conn.execute("PRAGMA journal_mode;")
        result = await cursor.fetchone()
        assert result is not None
        assert result[0].lower() == "wal"


@pytest.mark.asyncio
async def test_connection_pool_limits() -> None:
    """Verify that the connection pool maintains exactly max_connections."""
    pool = AsyncConnectionPool(db_path=":memory:", max_connections=5)
    await pool.initialize()

    assert pool._pool is not None
    assert pool._pool.qsize() == 5

    # Acquire all 5 connections
    connections = []
    for _ in range(5):
        conn = await pool.acquire()
        connections.append(conn)

    assert pool._pool.empty()

    # Trying to acquire a 6th connection should block
    # We can test this by using asyncio.wait_for and expecting a TimeoutError
    try:
        await asyncio.wait_for(pool.acquire(), timeout=0.1)
        raise AssertionError("Should have timed out acquiring beyond max_connections")
    except asyncio.TimeoutError:
        pass

    # Release connections back to the pool
    for conn in connections:
        pool.release(conn)

    assert pool._pool.qsize() == 5
    await pool.close()


@pytest.mark.asyncio
async def test_concurrent_writes(repo: SQLiteThreatRepository) -> None:
    """Verify concurrent writes don't produce database lock errors."""

    async def write_task(i: int) -> None:
        # We need a small sleep to ensure concurrency really overlaps
        await asyncio.sleep(0.01)
        sig_data = {
            "signatureId": f"sig_{i}",
            "attackerIntent": f"intent_{i}",
            "payloadPattern": f"pattern_{i}",
            "targetTool": "test_tool",
            "mitigationAction": "BLOCK",
        }
        await repo.writeSignature(sig_data)

    # Create 50 concurrent write tasks
    tasks = [asyncio.create_task(write_task(i)) for i in range(50)]
    await asyncio.gather(*tasks)

    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 50


@pytest.mark.asyncio
async def test_atomic_uniqueness_insert_or_ignore(repo: SQLiteThreatRepository) -> None:
    """Verify atomic uniqueness using INSERT OR IGNORE."""
    sig_data = {
        "signatureId": "unique_sig",
        "attackerIntent": "test intent",
        "payloadPattern": "pattern",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "matchCount": 5,
    }

    # Write the signature
    await repo.writeSignature(sig_data)

    # Try writing the exact same signature ID but with different data
    sig_data_different = sig_data.copy()
    sig_data_different["matchCount"] = 10

    await repo.writeSignature(sig_data_different)

    # Verify there is still only 1 signature
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 1

    # Verify the original data was kept (the new data was ignored)
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT match_count FROM signatures WHERE signature_id = 'unique_sig'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 5


@pytest.mark.asyncio
async def test_write_signature_similarity_vector_coercion(
    repo: SQLiteThreatRepository,
) -> None:
    """Verify that similarityVector is coerced correctly into bytes."""
    # 1. Test None similarity vector
    sig_id_none = "sig_none"
    sig_data_none = {
        "signatureId": sig_id_none,
        "attackerIntent": "test intent",
        "payloadPattern": "pattern",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "similarityVector": None,
    }
    await repo.writeSignature(sig_data_none)
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT similarity_vector FROM signatures WHERE signature_id = ?",
            (sig_id_none,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] is None

    # 2. Test list similarity vector
    sig_id_list = "sig_list"
    vector_list = [0.1, 0.2, 0.3]
    import array

    expected_bytes = array.array("f", vector_list).tobytes()

    sig_data_list = {
        "signatureId": sig_id_list,
        "attackerIntent": "test intent",
        "payloadPattern": "pattern",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "similarityVector": vector_list,
    }
    await repo.writeSignature(sig_data_list)
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT similarity_vector FROM signatures WHERE signature_id = ?",
            (sig_id_list,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == expected_bytes

    # 3. Test object with tobytes() method (mimicking numpy array)
    class MockNumpyArray:
        def __init__(self, data: list[float]):
            self.data = data

        def tobytes(self) -> bytes:
            import array

            return array.array("f", self.data).tobytes()

    sig_id_numpy = "sig_numpy"
    mock_array = MockNumpyArray(vector_list)
    sig_data_numpy = {
        "signatureId": sig_id_numpy,
        "attackerIntent": "test intent",
        "payloadPattern": "pattern",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "similarityVector": mock_array,
    }
    await repo.writeSignature(sig_data_numpy)
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT similarity_vector FROM signatures WHERE signature_id = ?",
            (sig_id_numpy,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == expected_bytes
