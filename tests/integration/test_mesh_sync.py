"""Integration tests for Task M02: Mesh Receiver & SQLite Ingestion Worker.

Verifies end-to-end ZeroMQ signature broadcast and SQLite ingestion
across simulated cluster nodes, asserting the < 15ms latency SLA (NFR-02).
"""

import asyncio
import os
import shutil
import tempfile
import time
import uuid

import pytest

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.enterprise.mesh.broadcaster import MeshBroadcaster
from blackwall.enterprise.mesh.receiver import MeshReceiver


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_mesh.db")
    yield db_path
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_mesh_sync_end_to_end_and_latency_sla(temp_db):
    """Verify broadcaster transmits signature over ZeroMQ and receiver ingests into SQLite within 15ms."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    # Use unique dynamic port for test isolation
    endpoint = "tcp://127.0.0.1:5591"

    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, connect=True)

    await broadcaster.start()
    await receiver.start()

    # Allow ZeroMQ subscription handshake to settle
    await asyncio.sleep(0.1)

    sig_id = f"sig_test_{uuid.uuid4().hex[:8]}"
    test_signature = {
        "signature_id": sig_id,
        "payload_pattern": "nc -e /bin/sh",
        "attacker_intent": "REMOTE_CODE_EXECUTION",
        "threat_level": "CRITICAL",
        "target_tool": "bash",
        "target_sink": "PROCESS",
        "mitigation_action": "BLOCK",
        "created_at": int(time.time()),
    }

    ingested_event = asyncio.Event()

    def _on_ingested(payload):
        if payload.get("signature_id") == sig_id or payload.get("signatureId") == sig_id:
            ingested_event.set()

    receiver.on_signature_received = _on_ingested

    start_time = time.perf_counter()
    broadcast_success = await broadcaster.broadcast(test_signature)
    assert broadcast_success is True

    # Wait for ingestion into SQLite
    await asyncio.wait_for(ingested_event.wait(), timeout=1.0)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    # Verify NFR-02: Propagation & SQLite persistence must be < 15 ms
    assert duration_ms < 15.0, f"Sync took {duration_ms:.2f} ms; must be < 15.0 ms SLA"

    # Verify record was physically written to SQLite
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT signature_id, payload_pattern, mitigation_action FROM signatures WHERE signature_id = ?",
            (sig_id,),
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == sig_id
        assert row[1] == "nc -e /bin/sh"
        assert row[2] == "BLOCK"

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()


@pytest.mark.asyncio
async def test_mesh_sync_deduplication(temp_db):
    """Verify duplicate signatures broadcast across the mesh do not raise errors and maintain uniqueness."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    endpoint = "tcp://127.0.0.1:5592"
    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, connect=True)

    await broadcaster.start()
    await receiver.start()
    await asyncio.sleep(0.1)

    sig_id = f"sig_dedup_{uuid.uuid4().hex[:8]}"
    signature = {
        "signature_id": sig_id,
        "payload_pattern": "curl -O malware.sh",
        "attacker_intent": "PAYLOAD_DOWNLOAD",
        "threat_level": "HIGH",
    }

    # Broadcast twice
    await broadcaster.broadcast(signature)
    await asyncio.sleep(0.05)
    await broadcaster.broadcast(signature)
    await asyncio.sleep(0.05)

    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM signatures WHERE signature_id = ?",
            (sig_id,),
        )
        count = (await cursor.fetchone())[0]
        assert count == 1, "Duplicate signature must be safely ignored"

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()


@pytest.mark.asyncio
async def test_mesh_receiver_topic_filtering(temp_db):
    """Verify receiver only ingests signatures matching its subscribed topic."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    endpoint = "tcp://127.0.0.1:5593"
    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    # Receiver only subscribes to "threat_signatures"
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, topic="threat_signatures", connect=True)

    await broadcaster.start()
    await receiver.start()
    await asyncio.sleep(0.1)

    ignored_sig_id = "sig_ignored_topic"
    accepted_sig_id = "sig_accepted_topic"

    # Publish on mismatched topic
    await broadcaster.broadcast({"signature_id": ignored_sig_id, "payload_pattern": "test"}, topic="audit_logs")
    # Publish on matching topic
    await broadcaster.broadcast({"signature_id": accepted_sig_id, "payload_pattern": "test"}, topic="threat_signatures")
    await asyncio.sleep(0.05)

    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", (ignored_sig_id,))
        assert await cursor.fetchone() is None

        cursor = await conn.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", (accepted_sig_id,))
        assert await cursor.fetchone() is not None

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()


@pytest.mark.asyncio
async def test_mesh_sync_burst_throughput(temp_db):
    """Verify mesh processes a rapid burst of 20 signatures without message loss."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    endpoint = "tcp://127.0.0.1:5594"
    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, connect=True)

    await broadcaster.start()
    await receiver.start()
    await asyncio.sleep(0.1)

    burst_count = 20
    for i in range(burst_count):
        await broadcaster.broadcast({
            "signature_id": f"burst_{i}",
            "payload_pattern": f"attack_vector_{i}",
            "threat_level": "CRITICAL",
        })

    # Wait for burst completion
    await asyncio.sleep(0.2)

    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM signatures WHERE signature_id LIKE 'burst_%'")
        count = (await cursor.fetchone())[0]
        assert count == burst_count, f"Expected {burst_count} signatures, found {count}"

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()


@pytest.mark.asyncio
async def test_mesh_receiver_rejects_empty_payload_pattern(temp_db):
    """Verify receiver rejects signatures with empty or whitespace-only patterns to avoid matching all commands."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    endpoint = "tcp://127.0.0.1:5595"
    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, connect=True)

    await broadcaster.start()
    await receiver.start()
    await asyncio.sleep(0.1)

    empty_sig_id = "sig_empty_pattern"
    valid_sig_id = "sig_valid_pattern"

    # Message with target_tool but empty pattern
    await broadcaster.broadcast({
        "signature_id": empty_sig_id,
        "payload_pattern": "   ",
        "target_tool": "bash",
        "threat_level": "CRITICAL",
        "mitigation_action": "BLOCK",
    })

    # Valid message
    await broadcaster.broadcast({
        "signature_id": valid_sig_id,
        "payload_pattern": "cat /etc/shadow",
        "target_tool": "bash",
        "threat_level": "CRITICAL",
        "mitigation_action": "BLOCK",
    })

    await asyncio.sleep(0.1)

    async with repo.pool.connection() as conn:
        # Empty pattern signature must NOT be ingested
        cursor = await conn.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", (empty_sig_id,))
        assert await cursor.fetchone() is None, "Empty payload pattern must be rejected to prevent wildcard match"

        # Valid pattern signature must be ingested
        cursor = await conn.execute("SELECT signature_id FROM signatures WHERE signature_id = ?", (valid_sig_id,))
        assert await cursor.fetchone() is not None

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()


@pytest.mark.asyncio
async def test_mesh_receiver_receive_one_queue_without_socket_race(temp_db):
    """Verify receive_one safely consumes messages via internal queue without racing against background worker."""
    repo = SQLiteThreatRepository(db_path=temp_db)
    await repo.initialize()

    endpoint = "tcp://127.0.0.1:5596"
    broadcaster = MeshBroadcaster(endpoint=endpoint, bind=True)
    receiver = MeshReceiver(endpoint=endpoint, repository=repo, connect=True)

    await broadcaster.start()
    await receiver.start()
    await asyncio.sleep(0.1)

    test_payload = {
        "signature_id": "sig_queue_race_test",
        "payload_pattern": "rm -rf /",
        "threat_level": "CRITICAL",
    }

    # Broadcast message
    await broadcaster.broadcast(test_payload)

    # receive_one should cleanly obtain the message from queue without timing out or racing on socket
    received = await receiver.receive_one(timeout=1.0)
    assert received is not None
    assert received.get("signature_id") == "sig_queue_race_test"

    await broadcaster.stop()
    await receiver.stop()
    await repo.close()

