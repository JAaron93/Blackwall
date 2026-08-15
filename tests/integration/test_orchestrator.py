"""Integration tests for AdvancedThreatDetection main orchestrator (Task 21.1)."""

import asyncio
from datetime import UTC, datetime, timedelta
import uuid
import pytest
from unittest.mock import AsyncMock, patch

from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.orchestrator import (
    AdvancedThreatDetection,
)


@pytest.mark.asyncio
async def test_component_wiring():
    """Verify all subcomponents and engines are properly initialized and wired (Req 12.6, 12.7)."""
    config = AdvancedThreatDetectionConfig(
        in_memory=True,
        min_path_length=2,
        temporal_window_seconds=300.0,
        swarm_min_agents=2,
    )
    atd = AdvancedThreatDetection(config=config)

    # Core subsystem components
    assert atd.config == config
    assert atd.store is not None
    assert atd.collector is not None
    assert atd.alert_bus is not None
    assert atd.runner is not None
    assert atd.throttler is not None

    # Detection engines
    assert atd.path_correlator is not None
    assert atd.swarm_detector is not None
    assert atd.exploit_analyzer is not None
    assert atd.ailm_tracker is not None
    assert atd.c2_detector is not None
    assert atd.k8s_defense is not None
    assert atd.registry_monitor is not None
    assert atd.retrospective_analyzer is not None

    # Verify shared store references
    assert atd.path_correlator.store is atd.store
    assert atd.swarm_detector.store is atd.store
    assert atd.exploit_analyzer.store is atd.store
    assert atd.ailm_tracker.store is atd.store
    assert atd.c2_detector.store is atd.store
    assert atd.k8s_defense.store is atd.store
    assert atd.registry_monitor.store is atd.store
    assert atd.retrospective_analyzer.store is atd.store


@pytest.mark.asyncio
async def test_engine_toggles():
    """Verify engine enablement toggles in config."""
    config = AdvancedThreatDetectionConfig(
        in_memory=True,
        enable_path_correlation=False,
        enable_swarm_detection=False,
        enable_c2_detection=False,
    )
    atd = AdvancedThreatDetection(config=config)

    assert atd.path_correlator is None
    assert atd.swarm_detector is None
    assert atd.c2_detector is None
    assert atd.exploit_analyzer is not None
    assert atd.ailm_tracker is not None


@pytest.mark.asyncio
async def test_lifecycle_start_stop():
    """Verify orchestrator start, stop, and async context manager lifecycle."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    atd = AdvancedThreatDetection(config=config)

    assert atd.is_running is False

    await atd.start()
    assert atd.is_running is True

    # Ingest event while running
    raw_event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "agent_id": "agent-lifecycle-01",
        "action": "ls",
        "target": "/tmp",
    }
    event = await atd.ingest_event(EventSource.KERNEL_SYSCALL, raw_event)
    assert event.agent_id == "agent-lifecycle-01"

    await atd.stop()
    assert atd.is_running is False

    # Async context manager test
    async with AdvancedThreatDetection(config=config) as context_atd:
        assert context_atd.is_running is True
    assert context_atd.is_running is False


@pytest.mark.asyncio
async def test_passive_event_ingestion_and_storage():
    """Verify passive event ingestion stores events without delay (Req 12.7)."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        t0 = datetime.now(UTC)
        raw_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "agent_id": "agent-007",
            "action": "bash",
            "target": "/bin/bash",
            "metadata": {"command": "whoami"},
        }

        normalized = await atd.ingest_event(EventSource.KERNEL_SYSCALL, raw_event)
        assert isinstance(normalized, NormalizedEvent)
        assert normalized.agent_id == "agent-007"
        assert normalized.action == "bash"

        # Verify event persisted in attack graph store
        nodes = await atd.get_attack_graph(agent_id="agent-007")
        assert len(nodes) >= 1
        assert nodes[0].event.event_id == normalized.event_id


@pytest.mark.asyncio
async def test_attack_path_detection_and_alert_generation():
    """Verify multi-step events trigger detection and publish alerts to alert bus."""
    config = AdvancedThreatDetectionConfig(
        in_memory=True,
        min_path_length=2,
        temporal_window_seconds=300.0,
    )
    async with AdvancedThreatDetection(config=config) as atd:
        alerts_received: list[Alert] = []
        atd.alert_bus.subscribe(lambda a: alerts_received.append(a))

        t0 = datetime.now(UTC) - timedelta(seconds=20)
        agent_id = "attacker-agent-x"

        # Step 1: Kernel command execution
        e1 = {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "agent_id": agent_id,
            "action": "bash_exec",
            "target": "/bin/bash",
            "risk_score": 0.8,
        }
        await atd.ingest_event(EventSource.KERNEL_SYSCALL, e1)

        # Step 2: Privilege escalation
        e2 = {
            "event_id": str(uuid.uuid4()),
            "timestamp": (t0 + timedelta(seconds=5)).isoformat(),
            "agent_id": agent_id,
            "action": "sudo_elevate",
            "target": "/etc/sudoers",
            "risk_score": 0.9,
        }
        await atd.ingest_event(EventSource.TOOL_CALL, e2)

        # Process / correlate
        await atd.correlate_agent_threats(agent_id=agent_id)

        active_alerts = atd.get_active_alerts(agent_id=agent_id)
        assert len(active_alerts) > 0
        path_alerts = [a for a in active_alerts if a.threat_type == "attack_path"]
        assert len(path_alerts) > 0
        assert path_alerts[0].severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)


@pytest.mark.asyncio
async def test_detection_crash_isolation():
    """Verify safe detection runner prevents detector exceptions from crashing the orchestrator."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        # Simulate a crashing detector
        if atd.path_correlator:
            atd.path_correlator.correlate_attack_paths = AsyncMock(
                side_effect=RuntimeError("Simulated detector unexpected crash")
            )

        raw_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": "safe-agent-1",
            "action": "read_file",
            "target": "/etc/hosts",
        }

        # Ingestion and correlation should complete without raising RuntimeError
        event = await atd.ingest_event(EventSource.KERNEL_SYSCALL, raw_event)
        assert event is not None
        await atd.correlate_agent_threats(agent_id="safe-agent-1")


@pytest.mark.asyncio
async def test_startup_db_connection_failure():
    """Verify ValueError is raised when DSN provided with in_memory=False and connection fails (Arch rule 3)."""
    config = AdvancedThreatDetectionConfig(
        database_url="postgresql://invalid_user:invalid_pass@127.0.0.1:54329/nonexistent",
        in_memory=False,
    )
    atd = AdvancedThreatDetection(config=config)

    with pytest.raises(ValueError):
        await atd.start()
