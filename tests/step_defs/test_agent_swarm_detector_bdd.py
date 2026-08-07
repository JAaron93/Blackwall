"""BDD Step Definitions for Agent Swarm Detector (`tests/features/agent_swarm_detector.feature`)."""

from datetime import UTC, datetime, timedelta
import uuid
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    AttackGraphStore,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from tests.step_defs.async_utils import run_async

scenarios("../features/agent_swarm_detector.feature")


class SwarmBDDState:
    def __init__(self):
        self.store = None
        self.detector = None
        self.base_time = None
        self.time_window = None
        self.fingerprint = None
        self.swarms = None
        self.coordination_score = None


@pytest.fixture
def swarm_state():
    return SwarmBDDState()


@given("an agent with a set of action events in a time window")
def given_agent_events(swarm_state):
    swarm_state.store = AttackGraphStore(in_memory=True)
    run_async(swarm_state.store.initialize())
    swarm_state.detector = AgentSwarmDetector(store=swarm_state.store)
    now = datetime.now(UTC)
    swarm_state.base_time = now

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-fp",
        action="read_config",
        target="/etc/app.conf",
        risk_score=0.5,
    )
    e2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=20),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-fp",
        action="spawn_proc",
        target="/bin/sh",
        risk_score=0.6,
    )
    run_async(swarm_state.store.insert_event(e1))
    run_async(swarm_state.store.insert_event(e2))


@when("fingerprint_agent is called over the time window")
def when_fingerprint_called(swarm_state):
    swarm_state.fingerprint = run_async(
        swarm_state.detector.fingerprint_agent(
            "agent-bdd-fp", window=3600, end_time=swarm_state.base_time + timedelta(seconds=60)
        )
    )


@then("a deterministic 64-character SHA-256 behavioral fingerprint is generated")
def then_fingerprint_valid(swarm_state):
    assert isinstance(swarm_state.fingerprint, str)
    assert len(swarm_state.fingerprint) == 64


@given("two agents executing correlated actions closely in time")
def given_correlated_agents(swarm_state):
    swarm_state.store = AttackGraphStore(in_memory=True)
    run_async(swarm_state.store.initialize())
    swarm_state.detector = AgentSwarmDetector(store=swarm_state.store)
    now = datetime.now(UTC)
    swarm_state.base_time = now

    for offset in [0, 5, 10]:
        e1 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset),
            source=EventSource.TOOL_CALL,
            agent_id="agent-corr-1",
            action="scan",
            target="target.local",
            risk_score=0.7,
        )
        e2 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset + 1),
            source=EventSource.TOOL_CALL,
            agent_id="agent-corr-2",
            action="scan",
            target="target.local",
            risk_score=0.7,
        )
        run_async(swarm_state.store.insert_event(e1))
        run_async(swarm_state.store.insert_event(e2))

    swarm_state.time_window = (now - timedelta(seconds=5), now + timedelta(seconds=60))


@when("detect_swarms is called with correlation threshold 0.75")
def when_detect_swarms_called(swarm_state):
    swarm_state.swarms = run_async(
        swarm_state.detector.detect_swarms(
            swarm_state.time_window, min_agents=2, correlation_threshold=0.75
        )
    )


@then("a SwarmEvidence instance is returned containing both agent IDs")
def then_swarm_returned(swarm_state):
    assert len(swarm_state.swarms) >= 1
    swarm = swarm_state.swarms[0]
    assert isinstance(swarm, SwarmEvidence)
    assert swarm.agent_ids == {"agent-corr-1", "agent-corr-2"}


@given("a single agent executing security events")
def given_single_agent(swarm_state):
    swarm_state.store = AttackGraphStore(in_memory=True)
    run_async(swarm_state.store.initialize())
    swarm_state.detector = AgentSwarmDetector(store=swarm_state.store)
    now = datetime.now(UTC)
    swarm_state.base_time = now

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="solo-agent",
        action="exec",
        target="/bin/bash",
        risk_score=0.5,
    )
    run_async(swarm_state.store.insert_event(e1))
    swarm_state.time_window = (now - timedelta(seconds=5), now + timedelta(seconds=60))


@when("detect_swarms is called with min_agents set to 2")
def when_detect_swarms_min_agents(swarm_state):
    swarm_state.swarms = run_async(
        swarm_state.detector.detect_swarms(
            swarm_state.time_window, min_agents=2, correlation_threshold=0.5
        )
    )


@then("an empty swarm list is returned")
def then_empty_swarm_list(swarm_state):
    assert swarm_state.swarms == []


@given('two agents sharing IP address "192.168.1.50" and domain "evil.c2.org"')
def given_shared_infra_agents(swarm_state):
    swarm_state.store = AttackGraphStore(in_memory=True)
    run_async(swarm_state.store.initialize())
    swarm_state.detector = AgentSwarmDetector(store=swarm_state.store)
    now = datetime.now(UTC)

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=5),
        source=EventSource.IDENTITY_ACCESS,
        agent_id="infra-agent-1",
        action="connect",
        target="evil.c2.org",
        metadata={"ip": "192.168.1.50"},
        risk_score=0.8,
    )
    e2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=6),
        source=EventSource.IDENTITY_ACCESS,
        agent_id="infra-agent-2",
        action="connect",
        target="evil.c2.org",
        metadata={"ip": "192.168.1.50"},
        risk_score=0.8,
    )
    run_async(swarm_state.store.insert_event(e1))
    run_async(swarm_state.store.insert_event(e2))
    swarm_state.time_window = (now - timedelta(seconds=5), now + timedelta(seconds=60))


@when("detect_swarms is executed")
def when_detect_swarms_executed(swarm_state):
    swarm_state.swarms = run_async(
        swarm_state.detector.detect_swarms(
            swarm_state.time_window, min_agents=2, correlation_threshold=0.5
        )
    )


@then("SwarmEvidence.shared_patterns contains the shared IP and domain")
def then_shared_patterns_found(swarm_state):
    assert len(swarm_state.swarms) >= 1
    swarm = swarm_state.swarms[0]
    assert "ip:192.168.1.50" in swarm.shared_patterns
    assert "domain:evil.c2.org" in swarm.shared_patterns


@given("a set of agents with highly aligned timestamps and identical actions")
def given_aligned_agents(swarm_state):
    swarm_state.store = AttackGraphStore(in_memory=True)
    run_async(swarm_state.store.initialize())
    swarm_state.detector = AgentSwarmDetector(store=swarm_state.store)
    now = datetime.now(UTC)

    for offset in [0, 5, 10]:
        e1 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="high-agent-1",
            action="exfil",
            target="srv.local",
            risk_score=0.9,
        )
        e2 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="high-agent-2",
            action="exfil",
            target="srv.local",
            risk_score=0.9,
        )
        run_async(swarm_state.store.insert_event(e1))
        run_async(swarm_state.store.insert_event(e2))

    swarm_state.time_window = (now - timedelta(seconds=5), now + timedelta(seconds=60))


@when("compute_coordination_score is executed")
def when_compute_coordination_score(swarm_state):
    swarm_state.coordination_score = run_async(
        swarm_state.detector.compute_coordination_score(
            ["high-agent-1", "high-agent-2"], swarm_state.time_window
        )
    )


@then("a coordination score of at least 0.75 is returned")
def then_high_coordination_returned(swarm_state):
    assert swarm_state.coordination_score >= 0.75
