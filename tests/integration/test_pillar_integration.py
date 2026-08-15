"""Integration tests for all 5 pillar stream subscriptions into ATD (Task 21.2)."""

import asyncio
from datetime import UTC, datetime
from typing import Any, AsyncIterator
import uuid
import pytest

from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.orchestrator import (
    AdvancedThreatDetection,
)


async def sample_stream(
    source: EventSource,
    agent_id: str,
    action: str,
    target: str,
    count: int = 3,
) -> AsyncIterator[dict[str, Any]]:
    """Generate synthetic async event stream for a pillar."""
    for i in range(count):
        yield {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": agent_id,
            "action": f"{action}_{i}",
            "target": f"{target}_{i}",
            "risk_score": 0.5,
            "metadata": {"source_name": source.value, "seq": i},
        }


@pytest.mark.asyncio
async def test_pillar_1_kernel_integration():
    """Verify Pillar 1 (Kernel eBPF/Audit) events stream into ATD."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        events = []
        async for ev in atd.collector.collect_from_kernel(
            sample_stream(
                EventSource.KERNEL_SYSCALL,
                "agent-kernel-01",
                "sys_execve",
                "/usr/bin/python",
            )
        ):
            events.append(ev)
            await atd.store.insert_event(ev)

        assert len(events) == 3
        assert all(e.source == EventSource.KERNEL_SYSCALL for e in events)
        nodes = await atd.get_attack_graph(agent_id="agent-kernel-01")
        assert len(nodes) == 3


@pytest.mark.asyncio
async def test_pillar_2_threat_mesh_integration():
    """Verify Pillar 2 (Threat Mesh) signature events stream into ATD."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        raw_signature_events = [
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(UTC).isoformat(),
                "agent_id": "agent-mesh-01",
                "action": "mesh_signature_broadcast",
                "target": "mesh://signature/sig_001",
                "risk_score": 0.7,
            }
        ]
        async def _mesh_stream():
            for e in raw_signature_events:
                yield e

        events = []
        async for ev in atd.collector.collect_with_reconnect(
            EventSource.FORENSIC_ALERT, _mesh_stream
        ):
            events.append(ev)
            await atd.store.insert_event(ev)

        assert len(events) == 1
        assert events[0].source == EventSource.FORENSIC_ALERT
        nodes = await atd.get_attack_graph(agent_id="agent-mesh-01")
        assert len(nodes) == 1


@pytest.mark.asyncio
async def test_pillar_3_identity_sidecar_integration():
    """Verify Pillar 3 (Identity Sidecar) events stream into ATD."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        events = []
        async for ev in atd.collector.collect_from_identity(
            sample_stream(
                EventSource.IDENTITY_ACCESS,
                "agent-identity-01",
                "vault_token_access",
                "vault://credentials/db",
            )
        ):
            events.append(ev)
            await atd.store.insert_event(ev)

        assert len(events) == 3
        assert all(e.source == EventSource.IDENTITY_ACCESS for e in events)
        nodes = await atd.get_attack_graph(agent_id="agent-identity-01")
        assert len(nodes) == 3


@pytest.mark.asyncio
async def test_pillar_4_pipeline_wrappers_integration():
    """Verify Pillar 4 (Pipeline Wrappers) events stream into ATD."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        events = []
        async for ev in atd.collector.collect_from_pipeline(
            sample_stream(
                EventSource.PIPELINE_EXECUTION,
                "agent-pipeline-01",
                "dataset_loader_eval",
                "dataset://s3/train.pkl",
            )
        ):
            events.append(ev)
            await atd.store.insert_event(ev)

        assert len(events) == 3
        assert all(e.source == EventSource.PIPELINE_EXECUTION for e in events)
        nodes = await atd.get_attack_graph(agent_id="agent-pipeline-01")
        assert len(nodes) == 3


@pytest.mark.asyncio
async def test_pillar_5_forensics_integration():
    """Verify Pillar 5 (Forensic Triage Engine) events stream into ATD."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        events = []
        async for ev in atd.collector.collect_from_forensics(
            sample_stream(
                EventSource.FORENSIC_ALERT,
                "agent-forensics-01",
                "forensic_triage_alert",
                "otel://span/tr_001",
            )
        ):
            events.append(ev)
            await atd.store.insert_event(ev)

        assert len(events) == 3
        assert all(e.source == EventSource.FORENSIC_ALERT for e in events)
        nodes = await atd.get_attack_graph(agent_id="agent-forensics-01")
        assert len(nodes) == 3


@pytest.mark.asyncio
async def test_multi_pillar_concurrent_streaming():
    """Verify concurrent streaming from all 5 pillars simultaneously."""
    config = AdvancedThreatDetectionConfig(in_memory=True)
    async with AdvancedThreatDetection(config=config) as atd:
        pillar_streams = {
            EventSource.KERNEL_SYSCALL: lambda: sample_stream(
                EventSource.KERNEL_SYSCALL, "agent-multi", "kernel_call", "target1", count=2
            ),
            EventSource.IDENTITY_ACCESS: lambda: sample_stream(
                EventSource.IDENTITY_ACCESS, "agent-multi", "identity_check", "target2", count=2
            ),
            EventSource.PIPELINE_EXECUTION: lambda: sample_stream(
                EventSource.PIPELINE_EXECUTION, "agent-multi", "pipeline_run", "target3", count=2
            ),
            EventSource.FORENSIC_ALERT: lambda: sample_stream(
                EventSource.FORENSIC_ALERT, "agent-multi", "forensic_log", "target4", count=2
            ),
            EventSource.TOOL_CALL: lambda: sample_stream(
                EventSource.TOOL_CALL, "agent-multi", "tool_intercept", "target5", count=2
            ),
        }

        collected_events = []
        async for event in atd.collector.collect_all_streams(pillar_streams):
            collected_events.append(event)
            await atd.store.insert_event(event)

        assert len(collected_events) == 10
        sources_seen = {e.source for e in collected_events}
        assert len(sources_seen) == 5

        nodes = await atd.get_attack_graph(agent_id="agent-multi")
        assert len(nodes) == 10
