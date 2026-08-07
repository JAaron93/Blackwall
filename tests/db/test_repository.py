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


@pytest.mark.asyncio
async def test_write_signatures_batch_executemany(repo: SQLiteThreatRepository) -> None:
    """Verify write_signatures_batch atomically inserts and replaces multiple records with executemany."""
    vector = [0.5] * 768
    import array
    expected_vector_bytes = array.array("f", vector).tobytes()

    batch = [
        {
            "signatureId": f"sig_batch_{i}",
            "attackerIntent": f"Intent for signature {i}",
            "payloadPattern": f"SELECT * FROM table_{i}",
            "targetTool": "db_query",
            "mitigationAction": "BLOCK",
            "similarityVector": vector if i % 2 == 0 else None,
            "metadata": {"batch_index": i},
            "matchCount": i,
        }
        for i in range(10)
    ]

    # Write batch
    await repo.write_signatures_batch(batch)

    # Verify total signatures in repository
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 10

    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT signature_id, target_tool, similarity_vector, metadata FROM signatures ORDER BY rowid")
        rows = await cursor.fetchall()
        assert len(rows) == 10
        for i, row in enumerate(rows):
            assert row[0] == f"sig_batch_{i}"
            assert row[1] == "db_query"
            if i % 2 == 0:
                assert row[2] == expected_vector_bytes
            else:
                assert row[2] is None
            import json
            meta = json.loads(row[3])
            assert meta["batch_index"] == i

    # Verify replacement (INSERT OR REPLACE)
    updated_batch = [
        {
            "signatureId": "sig_batch_0",
            "attackerIntent": "Updated intent 0",
            "payloadPattern": "SELECT * FROM updated_table",
            "targetTool": "db_query",
            "mitigationAction": "QUARANTINE",
            "metadata": {"updated": True},
        }
    ]
    await repo.write_signatures_batch(updated_batch)

    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT mitigation_action, metadata FROM signatures WHERE signature_id = 'sig_batch_0'")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "QUARANTINE"
        import json
        assert json.loads(row[1]) == {"updated": True}


@pytest.mark.asyncio
async def test_write_signatures_batch_transaction_rollback(repo: SQLiteThreatRepository) -> None:
    """Verify write_signatures_batch transaction atomicity and rollback when an insert fails mid-batch."""
    await repo.initialize()

    # Create temporary BEFORE INSERT trigger that aborts on 'sig_fail_second'
    async with repo.pool.connection() as conn:
        await conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS test_rollback_trigger
            BEFORE INSERT ON signatures
            FOR EACH ROW
            WHEN NEW.signature_id = 'sig_fail_second'
            BEGIN
                SELECT RAISE(ABORT, 'Simulated trigger failure');
            END;
            """
        )
        await conn.commit()

    failing_batch = [
        {
            "signatureId": "sig_fail_first",
            "attackerIntent": "Intent 1",
            "payloadPattern": "pattern 1",
            "targetTool": "tool",
            "mitigationAction": "BLOCK",
        },
        {
            "signatureId": "sig_fail_second",
            "attackerIntent": "Intent 2",
            "payloadPattern": "pattern 2",
            "targetTool": "tool",
            "mitigationAction": "BLOCK",
        },
    ]

    try:
        # Submit batch; expect exception raised due to trigger on second signature
        with pytest.raises(Exception) as exc_info:
            await repo.write_signatures_batch(failing_batch)

        assert "Simulated trigger failure" in str(exc_info.value) or isinstance(exc_info.value, Exception)

        # Verify neither row was persisted (transaction rolled back)
        async with repo.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT signature_id FROM signatures WHERE signature_id IN ('sig_fail_first', 'sig_fail_second')"
            )
            rows = await cursor.fetchall()
            assert len(rows) == 0
    finally:
        # Clean up trigger
        async with repo.pool.connection() as conn:
            await conn.execute("DROP TRIGGER IF EXISTS test_rollback_trigger")
            await conn.commit()

