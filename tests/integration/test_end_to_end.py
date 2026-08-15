"""End-to-End System Integration tests validating Property 64 (Passive Observation Invariant) and full ATD pipeline."""

import asyncio
from datetime import UTC, datetime, timedelta
import time
from typing import Any
import uuid
import pytest
from hypothesis import given, settings, strategies as st

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
async def test_property_64_passive_observation_payload_integrity():
    """Property 64: Non-blocking passive observation.

    Ingestion MUST NOT alter original caller raw event dictionaries or payloads in-place.
    """
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        original_dict = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": "caller-agent-01",
            "action": "execute_shell",
            "target": "/bin/zsh",
            "metadata": {"param": "value", "nested": {"key": 123}},
            "risk_score": 0.45,
        }
        # Copy dictionary before calling ingest_event
        dict_copy = {
            "event_id": original_dict["event_id"],
            "timestamp": original_dict["timestamp"],
            "agent_id": original_dict["agent_id"],
            "action": original_dict["action"],
            "target": original_dict["target"],
            "metadata": {"param": "value", "nested": {"key": 123}},
            "risk_score": original_dict["risk_score"],
        }

        normalized = await atd.ingest_event(EventSource.TOOL_CALL, original_dict)

        # Assert caller dictionary keys and values remain unmodified
        assert original_dict == dict_copy
        assert normalized.agent_id == "caller-agent-01"
        assert normalized.action == "execute_shell"


@pytest.mark.asyncio
async def test_property_64_passive_observation_non_blocking_performance():
    """Property 64: Passive observation non-blocking execution performance.

    Ingest event latency should be sub-millisecond on fast-path.
    """
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        raw_events = [
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(UTC).isoformat(),
                "agent_id": f"perf-agent-{i}",
                "action": "exec",
                "target": f"/bin/tool-{i}",
                "risk_score": 0.1,
            }
            for i in range(100)
        ]

        t0 = time.monotonic()
        for raw in raw_events:
            await atd.ingest_event(EventSource.KERNEL_SYSCALL, raw)
        duration = time.monotonic() - t0

        avg_latency_ms = (duration / len(raw_events)) * 1000
        # Ingestion should average well under 5ms per event in-memory
        assert avg_latency_ms < 5.0, f"Average ingestion latency {avg_latency_ms:.2f}ms exceeded 5ms"


@pytest.mark.asyncio
async def test_end_to_end_full_detection_cycle():
    """End-to-end test verifying multi-pillar ingestion -> detection -> alert publishing -> graph query."""
    config = AdvancedThreatDetectionConfig(
        in_memory=True,
        min_path_length=2,
        temporal_window_seconds=600.0,
    )
    async with AdvancedThreatDetection(config=config) as atd:
        collected_alerts: list[Alert] = []
        atd.alert_bus.subscribe(lambda a: collected_alerts.append(a))

        now = datetime.now(UTC) - timedelta(seconds=100)
        agent_id = "agent-e2e-threat"

        # Step 1: Kernel command execution (Pillar 1)
        await atd.ingest_event(
            EventSource.KERNEL_SYSCALL,
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "agent_id": agent_id,
                "action": "bash_exec",
                "target": "/bin/bash",
                "risk_score": 0.7,
            },
        )

        # Step 2: Identity token theft (Pillar 3)
        await atd.ingest_event(
            EventSource.IDENTITY_ACCESS,
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": (now + timedelta(seconds=10)).isoformat(),
                "agent_id": agent_id,
                "action": "sudo_token_access",
                "target": "/etc/shadow",
                "risk_score": 0.9,
            },
        )

        # Step 3: Forensic alert (Pillar 5)
        await atd.ingest_event(
            EventSource.FORENSIC_ALERT,
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": (now + timedelta(seconds=20)).isoformat(),
                "agent_id": agent_id,
                "action": "exfiltration_alert",
                "target": "c2://198.51.100.1",
                "risk_score": 0.95,
            },
        )

        # Trigger detection
        alerts = await atd.correlate_agent_threats(agent_id=agent_id)
        assert len(alerts) > 0

        # Flush alert bus to deliver buffered batch to subscribers
        await atd.alert_bus.flush()

        # Verify alert bus received alerts
        assert len(collected_alerts) > 0
        path_alert = next((a for a in collected_alerts if a.threat_type == "attack_path"), None)
        assert path_alert is not None
        assert path_alert.agent_id == agent_id
        assert path_alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)

        # Verify attack graph retrieval
        nodes = await atd.get_attack_graph(agent_id=agent_id)
        assert len(nodes) == 3

        # Verify retrospective analysis
        if atd.retrospective_analyzer:
            retro_paths = await atd.retrospective_analyzer.detect_retrospective_paths(
                agent_id=agent_id
            )
            assert isinstance(retro_paths, list)
