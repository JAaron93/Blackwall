"""Unit tests for Task M01: ZeroMQ Pub/Sub Mesh Broadcaster (TASK-M01).

Verifies that MeshBroadcaster publishes threat signatures over ZeroMQ sockets,
integrates cleanly with ActiveReactionEngine, and provides safe lifecycle management.
"""

import uuid
from datetime import UTC, datetime

import pytest

from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    ReactionActionType,
)
from blackwall.enterprise.mesh.broadcaster import MeshBroadcaster
from blackwall.models import SinkType, ThreatSignature


@pytest.mark.asyncio
async def test_mesh_broadcaster_initialization():
    """Verify MeshBroadcaster initializes with custom and default parameters."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-init", topic="threat_signatures")
    assert broadcaster.endpoint == "inproc://test-mesh-init"
    assert broadcaster.topic == "threat_signatures"
    assert broadcaster.is_active is False

    await broadcaster.start()
    assert broadcaster.is_active is True

    await broadcaster.stop()
    assert broadcaster.is_active is False


@pytest.mark.asyncio
async def test_mesh_broadcaster_idempotent_stop():
    """Verify calling stop() multiple times or on an unstarted broadcaster is safe."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-idempotent")
    # Stop when never started
    await broadcaster.stop()
    assert broadcaster.is_active is False

    await broadcaster.start()
    await broadcaster.stop()
    await broadcaster.stop()  # Second stop
    assert broadcaster.is_active is False


@pytest.mark.asyncio
async def test_mesh_broadcaster_context_manager():
    """Verify async context manager activates and deactivates broadcaster."""
    async with MeshBroadcaster(endpoint="inproc://test-mesh-cm") as broadcaster:
        assert broadcaster.is_active is True
    assert broadcaster.is_active is False


@pytest.mark.asyncio
async def test_mesh_broadcaster_broadcast_dict():
    """Verify broadcast() dispatches dict payload successfully."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-dict")
    await broadcaster.start()
    try:
        payload = {
            "signature_id": str(uuid.uuid4()),
            "pattern": "nc -e /bin/sh",
            "threat_level": "CRITICAL",
            "timestamp": datetime.now(UTC).isoformat(),
        }
        success = await broadcaster.broadcast(payload)
        assert success is True
    finally:
        await broadcaster.stop()


@pytest.mark.asyncio
async def test_mesh_broadcaster_broadcast_threat_signature_model():
    """Verify broadcast() dispatches Pydantic ThreatSignature model successfully."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-model")
    await broadcaster.start()
    try:
        sig = ThreatSignature(
            signature_id=uuid.uuid4(),
            pattern="rm -rf / --no-preserve-root",
            description="Dangerous root deletion command",
            sink_type=SinkType.PROCESS,
        )
        success = await broadcaster.broadcast(sig)
        assert success is True
    finally:
        await broadcaster.stop()


@pytest.mark.asyncio
async def test_mesh_broadcaster_broadcast_sync():
    """Verify broadcast_sync() dispatches payload synchronously without event loop issues."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-sync")
    # Use sync broadcast
    payload = {
        "signature_id": "sig-sync-01",
        "pattern": "curl http://169.254.169.254/latest/meta-data/",
        "threat_level": "HIGH",
    }
    success = broadcaster.broadcast_sync(payload)
    assert success is True
    await broadcaster.stop()


@pytest.mark.asyncio
async def test_mesh_broadcaster_duck_typed_reaction_engine_contract():
    """Verify ActiveReactionEngine invokes broadcast_threat_signature method on MeshBroadcaster."""
    broadcaster = MeshBroadcaster(endpoint="inproc://test-mesh-reaction")
    await broadcaster.start()
    try:
        engine = ActiveReactionEngine(mesh_broadcaster=broadcaster)
        payload = ActiveReactionPayload(
            trigger_evidence_id=uuid.uuid4(),
            target_agent_id="adversarial-agent-007",
            action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
            metadata={"pattern": "python -c 'import socket'"},
        )

        success = await engine.broadcast_fleet_signature(payload)
        assert success is True
        assert payload.status == "COMPLETED"
        assert payload.execution_duration_ms < 15.0
    finally:
        await broadcaster.stop()
