"""Unit tests for WeaveTraced detector wrappers (Subtask 22.3)."""

import uuid
from datetime import UTC, datetime

import pytest

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
    PermissionGrant,
)
from blackwall.enterprise.advanced_threat_detection.weave_traced import (
    WeaveTracedAgentSwarmDetector,
    WeaveTracedAILMTracker,
    WeaveTracedC2InfrastructureDetector,
    WeaveTracedExploitChainAnalyzer,
    WeaveTracedPathCorrelator,
    weave_traced,
)


@pytest.mark.asyncio
async def test_weave_traced_decorator_fallback() -> None:
    @weave_traced
    def sample_fn(x: int) -> int:
        return x * 2

    assert sample_fn(5) == 10


@pytest.mark.asyncio
async def test_weave_traced_decorator_nested_sanitization() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="agent-nested",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="cat",
        target="/etc/shadow",
        risk_score=0.9,
    )

    @weave_traced
    def handler(payload: dict) -> dict:
        return {"status": "ok", "echo": payload}

    res = handler({"event": event, "api_key": "supersecret"})
    assert res["status"] == "ok"
    assert res["echo"]["api_key"] == "supersecret"


@pytest.mark.asyncio
async def test_weave_traced_attack_path_correlator() -> None:
    wrapper = WeaveTracedPathCorrelator()
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="agent-01",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="execute_shell_command",
        target="whoami",
        risk_score=0.8,
    )
    await wrapper.store.insert_event(event1)
    paths = await wrapper.correlate_attack_paths("agent-01", (now, now))
    assert isinstance(paths, list)


@pytest.mark.asyncio
async def test_weave_traced_swarm_coordinator() -> None:
    wrapper = WeaveTracedAgentSwarmDetector()
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    swarms = await wrapper.detect_swarms((now, now))
    assert isinstance(swarms, list)


@pytest.mark.asyncio
async def test_weave_traced_ailm_tracker() -> None:
    wrapper = WeaveTracedAILMTracker()
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    grant = PermissionGrant(
        permission="root",
        granted_by=uuid.uuid4(),
        granted_to=uuid.uuid4(),
        timestamp=now,
        scope="kernel_space",
    )
    await wrapper.track_permission_grant(grant)
    evidences = await wrapper.detect_permission_composition(str(grant.granted_to), (now, now))
    assert isinstance(evidences, list)


@pytest.mark.asyncio
async def test_weave_traced_exploit_analyzer() -> None:
    wrapper = WeaveTracedExploitChainAnalyzer()
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    chains = await wrapper.detect_chains("agent-04", (now, now))
    assert isinstance(chains, list)


@pytest.mark.asyncio
async def test_weave_traced_c2_detector() -> None:
    wrapper = WeaveTracedC2InfrastructureDetector()
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="agent-05",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="connect",
        target="webhook.site",
        risk_score=0.88,
    )
    findings = await wrapper.analyze_event(event)
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0].agent_id == "agent-05"
    assert "webhook.site" in findings[0].c2_endpoints

    evidences = await wrapper.detect_c2_establishment("agent-05", (now, now))
    assert len(evidences) == 1
