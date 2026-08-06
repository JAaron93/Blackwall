"""Property-based tests for AgentSwarmDetector using Hypothesis (Pillar 6 Task 7 / Properties 21-25, 28)."""

from datetime import datetime, timezone, timedelta
import uuid

from hypothesis import given, settings, strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    AttackGraphStore,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector


@st.composite
def event_sequences(draw, agent_id: str, base_time: datetime = None):
    """Strategy to generate a sequence of events for a given agent."""
    if base_time is None:
        base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    num_events = draw(st.integers(min_value=1, max_value=10))
    events = []
    for i in range(num_events):
        offset = draw(st.integers(min_value=0, max_value=3000))
        action = draw(st.sampled_from(["exec", "read", "write", "connect", "scan", "exfil"]))
        target = draw(st.sampled_from(["/bin/bash", "/etc/passwd", "10.0.0.1", "c2-domain.com"]))
        ip = draw(st.sampled_from(["192.168.1.10", "192.168.1.20", "10.0.0.5"]))
        domain = draw(st.sampled_from(["c2.evil.com", "api.service.org"]))
        source = draw(st.sampled_from(list(EventSource)))
        risk_score = draw(st.floats(min_value=0.0, max_value=1.0))

        e = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=base_time + timedelta(seconds=offset),
            source=source,
            agent_id=agent_id,
            action=action,
            target=target,
            metadata={"ip": ip, "domain": domain},
            risk_score=risk_score,
        )
        events.append(e)

    return sorted(events, key=lambda x: x.timestamp)


# Property 21: Behavioral Fingerprint Generation
@pytest.mark.asyncio
@given(agent_id=st.text(min_size=1, max_size=20).filter(lambda s: s.strip() != ""))
@settings(max_examples=50)
async def test_property_21_behavioral_fingerprint_generation(agent_id: str):
    """Property 21: For any agent and specified time window, fingerprint_agent SHALL generate a consistent behavioral fingerprint."""
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=base_time + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="exec_bash",
        target="/bin/bash",
        metadata={},
        risk_score=0.5,
    )
    await store.insert_event(e1)

    fp_a = await detector.fingerprint_agent(agent_id, window=3600, end_time=base_time + timedelta(seconds=60))
    fp_b = await detector.fingerprint_agent(agent_id, window=3600, end_time=base_time + timedelta(seconds=60))

    assert isinstance(fp_a, str)
    assert len(fp_a) > 0
    assert fp_a == fp_b


# Property 22 & Property 23: Swarm Correlation Threshold and Minimum Size Enforcement
@pytest.mark.asyncio
@given(
    threshold=st.floats(min_value=0.5, max_value=0.95),
    min_agents=st.integers(min_value=2, max_value=5),
)
@settings(max_examples=30)
async def test_property_22_23_swarm_threshold_and_min_size(threshold: float, min_agents: int):
    """Property 22 & 23: Swarm evidence MUST satisfy temporal_correlation >= threshold and len(agent_ids) >= min_agents."""
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    # Insert events for multiple agents
    for idx in range(min_agents):
        agent_id = f"agent-prop-sw-{idx}"
        for sec in range(0, 30, 5):
            e = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=base_time + timedelta(seconds=sec),
                source=EventSource.TOOL_CALL,
                agent_id=agent_id,
                action="scan_network",
                target="target.local",
                metadata={"ip": "10.0.0.1"},
                risk_score=0.7,
            )
            await store.insert_event(e)

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(time_win, min_agents=min_agents, correlation_threshold=threshold)

    for swarm in swarms:
        assert len(swarm.agent_ids) >= min_agents
        assert swarm.temporal_correlation >= threshold


# Property 24: Shared Infrastructure Identification
@pytest.mark.asyncio
@given(shared_ip=st.sampled_from(["192.168.1.100", "10.200.1.5", "172.16.0.42"]))
@settings(max_examples=30)
async def test_property_24_shared_infrastructure_identification(shared_ip: str):
    """Property 24: For any detected swarm, shared infrastructure elements MUST be identified."""
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=base_time + timedelta(seconds=10),
        source=EventSource.IDENTITY_ACCESS,
        agent_id="agent-infra-1",
        action="connect",
        target="srv.domain",
        metadata={"ip": shared_ip},
        risk_score=0.8,
    )
    e2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=base_time + timedelta(seconds=11),
        source=EventSource.IDENTITY_ACCESS,
        agent_id="agent-infra-2",
        action="connect",
        target="srv.domain",
        metadata={"ip": shared_ip},
        risk_score=0.8,
    )

    await store.insert_event(e1)
    await store.insert_event(e2)

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(time_win, min_agents=2, correlation_threshold=0.5)

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert any(shared_ip in item for item in swarm.shared_patterns)


# Property 25 & Property 28: Coordination Score Computation & High Confidence Threshold
@pytest.mark.asyncio
@given(num_agents=st.integers(min_value=2, max_value=4))
@settings(max_examples=30)
async def test_property_25_28_coordination_score(num_agents: int):
    """Property 25 & 28: coordination_score SHALL be computed in [0.0, 1.0], and high-confidence swarms MUST have score >= 0.75."""
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    agent_ids = [f"agent-coord-{i}" for i in range(num_agents)]
    for aid in agent_ids:
        e = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=base_time + timedelta(seconds=5),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=aid,
            action="exfil_db",
            target="remote_server",
            metadata={"ip": "10.0.0.99"},
            risk_score=0.9,
        )
        await store.insert_event(e)

    time_win = (base_time, base_time + timedelta(seconds=60))
    score = await detector.compute_coordination_score(agent_ids, time_win)

    assert 0.0 <= score <= 1.0
    assert score >= 0.75  # Synchronous identical events must achieve high confidence
