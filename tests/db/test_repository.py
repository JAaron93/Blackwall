import os
import asyncio
import pytest
import pytest_asyncio
import aiosqlite
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.db.pool import AsyncConnectionPool

TEST_DB_PATH = "test_blackwall.db"

@pytest_asyncio.fixture
async def repo():
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
async def test_wal_mode_activation(repo):
    """Verify that WAL mode is activated correctly."""
    # We can acquire a connection directly from the pool to test pragma
    async with repo.pool.connection() as conn:
        cursor = await conn.execute("PRAGMA journal_mode;")
        result = await cursor.fetchone()
        assert result is not None
        assert result[0].lower() == "wal"

@pytest.mark.asyncio
async def test_connection_pool_limits():
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
async def test_concurrent_writes(repo):
    """Verify concurrent writes don't produce database lock errors."""
    async def write_task(i):
        # We need a small sleep to ensure concurrency really overlaps
        await asyncio.sleep(0.01)
        sig_data = {
            "signatureId": f"sig_{i}",
            "attackerIntent": f"intent_{i}",
            "payloadPattern": f"pattern_{i}",
            "targetTool": "test_tool",
            "mitigationAction": "BLOCK"
        }
        await repo.writeSignature(sig_data)
        
    # Create 50 concurrent write tasks
    tasks = [asyncio.create_task(write_task(i)) for i in range(50)]
    await asyncio.gather(*tasks)
    
    stats = await repo.getStatistics()
    assert stats["totalSignatures"] == 50

@pytest.mark.asyncio
async def test_atomic_uniqueness_insert_or_ignore(repo):
    """Verify atomic uniqueness using INSERT OR IGNORE."""
    sig_data = {
        "signatureId": "unique_sig",
        "attackerIntent": "test intent",
        "payloadPattern": "pattern",
        "targetTool": "tool",
        "mitigationAction": "BLOCK",
        "matchCount": 5
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
        cursor = await conn.execute("SELECT match_count FROM signatures WHERE signature_id = 'unique_sig'")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 5
