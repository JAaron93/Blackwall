"""BDD Step Definitions for Advanced Threat Detection (`tests/features/advanced_threat_detection.feature`)."""

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from tests.step_defs.async_utils import run_async

scenarios("../features/advanced_threat_detection.feature")


class ATDBDDState:
    def __init__(self):
        self.raw_event_id = None
        self.raw_timestamp = None
        self.normalized_event = None
        self.nodes = []
        self.attack_path = None
        self.agent_ids = set()
        self.swarm_evidence = None
        self.correlator_paths = None



@pytest.fixture
def atd_state():
    return ATDBDDState()


# Scenario 1 steps
@given(
    'a raw event payload with event ID "550e8400-e29b-41d4-a716-446655440000" and UTC timestamp'
)
def given_raw_event_payload(atd_state):
    atd_state.raw_event_id = "550e8400-e29b-41d4-a716-446655440000"
    atd_state.raw_timestamp = datetime.now(UTC)


@when("the event is normalized into a NormalizedEvent model")
def when_event_normalized(atd_state):
    atd_state.normalized_event = NormalizedEvent(
        event_id=atd_state.raw_event_id,
        timestamp=atd_state.raw_timestamp,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-01",
        action="execve",
        target="/usr/bin/cat",
        risk_score=0.3,
    )


@then("the NormalizedEvent model accepts the valid UUID v4 and UTC timestamp")
def then_normalized_event_accepts(atd_state):
    assert atd_state.normalized_event.event_id == uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
    assert atd_state.normalized_event.timestamp.tzinfo is not None


@then("invalid UUIDs or non-UTC timestamps are rejected with a validation error")
def then_invalid_uuid_or_ts_rejected(atd_state):
    # Invalid UUID v1
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=str(uuid.uuid1()),
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-bdd-01",
            action="execve",
            target="/usr/bin/cat",
            risk_score=0.3,
        )
    # Naive timestamp
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-bdd-01",
            action="execve",
            target="/usr/bin/cat",
            risk_score=0.3,
        )
    # Non-UTC timezone-aware timestamp
    est = timezone(timedelta(hours=-5))
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(est),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-bdd-01",
            action="execve",
            target="/usr/bin/cat",
            risk_score=0.3,
        )


# Scenario 2 steps
@given("a set of normalized attack nodes")
def given_set_of_attack_nodes(atd_state):
    now = datetime.now(UTC)
    event1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-01",
        action="execve",
        target="/usr/bin/python3",
        risk_score=0.2,
    )
    event2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=5),
        source=EventSource.TOOL_CALL,
        agent_id="agent-bdd-01",
        action="connect",
        target="10.0.0.1:8080",
        risk_score=0.7,
    )
    atd_state.nodes = [
        AttackNode(node_id=uuid.uuid4(), event=event1),
        AttackNode(node_id=uuid.uuid4(), event=event2),
    ]


@when("an AttackPath is constructed with at least 2 nodes and valid temporal sequence")
def when_attack_path_constructed(atd_state):
    now = datetime.now(UTC)
    atd_state.attack_path = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-bdd-01",
        nodes=atd_state.nodes,
        start_time=now,
        end_time=now + timedelta(seconds=10),
        risk_score=0.8,
        correlation_score=0.9,
    )


@then("the AttackPath model is created successfully")
def then_attack_path_created(atd_state):
    assert len(atd_state.attack_path.nodes) == 2
    assert atd_state.attack_path.end_time >= atd_state.attack_path.start_time


@then(
    "AttackPaths with fewer than 2 nodes or end_time earlier than start_time are rejected"
)
def then_invalid_attack_path_rejected(atd_state):
    now = datetime.now(UTC)
    # Fewer than 2 nodes
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=uuid.uuid4(),
            agent_id="agent-bdd-01",
            nodes=[atd_state.nodes[0]],
            start_time=now,
            end_time=now + timedelta(seconds=10),
            risk_score=0.8,
            correlation_score=0.9,
        )
    # end_time < start_time
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=uuid.uuid4(),
            agent_id="agent-bdd-01",
            nodes=atd_state.nodes,
            start_time=now,
            end_time=now - timedelta(seconds=1),
            risk_score=0.8,
            correlation_score=0.9,
        )


# Scenario 3 steps
@given("a group of correlated agent identifiers")
def given_correlated_agents(atd_state):
    atd_state.agent_ids = {"agent-alpha", "agent-beta"}


@when(
    "SwarmEvidence is constructed with 2 or more distinct agent IDs and valid time window"
)
def when_swarm_evidence_constructed(atd_state):
    now = datetime.now(UTC)
    atd_state.swarm_evidence = SwarmEvidence(
        swarm_id=uuid.uuid4(),
        agent_ids=atd_state.agent_ids,
        temporal_correlation=0.85,
        coordination_score=0.9,
        first_seen=now,
        last_seen=now + timedelta(minutes=15),
    )


@then("the SwarmEvidence model is created successfully")
def then_swarm_evidence_created(atd_state):
    assert len(atd_state.swarm_evidence.agent_ids) == 2
    assert atd_state.swarm_evidence.last_seen >= atd_state.swarm_evidence.first_seen


@then(
    "SwarmEvidence with fewer than 2 agents or last_seen earlier than first_seen is rejected"
)
def then_invalid_swarm_evidence_rejected(atd_state):
    now = datetime.now(UTC)
    # Fewer than 2 agents
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id=uuid.uuid4(),
            agent_ids={"agent-alpha"},
            temporal_correlation=0.85,
            coordination_score=0.9,
            first_seen=now,
            last_seen=now + timedelta(minutes=15),
        )
    # last_seen < first_seen
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id=uuid.uuid4(),
            agent_ids=atd_state.agent_ids,
            temporal_correlation=0.85,
            coordination_score=0.9,
            first_seen=now,
            last_seen=now - timedelta(seconds=1),
        )


# Scenario 4 steps (AttackGraphStore)


@given("an initialized AttackGraphStore instance")
def given_initialized_attack_graph_store(atd_state):
    store = AttackGraphStore(in_memory=True)
    run_async(store.initialize())
    atd_state.store = store


@when("security events are ingested and causally linked")
def when_events_ingested_and_linked(atd_state):
    now = datetime.now(UTC)
    ev1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-store",
        action="execve",
        target="/usr/bin/python3",
        risk_score=0.5,
    )
    ev2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=2),
        source=EventSource.TOOL_CALL,
        agent_id="agent-bdd-store",
        action="connect",
        target="192.168.1.1:4444",
        risk_score=0.9,
    )
    n1 = run_async(atd_state.store.insert_event(ev1))
    n2 = run_async(atd_state.store.insert_event(ev2))
    run_async(atd_state.store.link_events(n1.node_id, n2.node_id, "SPAWNED"))
    atd_state.start_time = now
    atd_state.end_time = now + timedelta(seconds=2)


@then(
    "the AttackGraphStore persists node edges and returns correlated multi-hop attack paths"
)
def then_store_persists_and_returns_paths(atd_state):
    time_window = (
        atd_state.start_time - timedelta(minutes=1),
        atd_state.end_time + timedelta(minutes=1),
    )
    paths = run_async(
        atd_state.store.query_paths(
            agent_id="agent-bdd-store", time_window=time_window, min_path_length=2
        )
    )
    assert len(paths) >= 1
    assert len(paths[0].nodes) == 2
    assert len(paths[0].nodes[0].outgoing_edges) == 1
    run_async(atd_state.store.close())


# Scenario 5 steps (EventStreamCollector)


@given("an EventStreamCollector instance and heterogeneous raw events from 5 pillars")
def given_event_collector_and_raw_events(atd_state):
    atd_state.collector = EventStreamCollector()
    atd_state.raw_pillar_events = {
        EventSource.KERNEL_SYSCALL: [
            {"action": "execve", "target": "/bin/ls", "agent_id": "agent-bdd-k"}
        ],
        EventSource.TOOL_CALL: [
            {"action": "run_command", "target": "ls", "agent_id": "agent-bdd-t"}
        ],
        EventSource.IDENTITY_ACCESS: [
            {"action": "get_token", "target": "vault", "agent_id": "agent-bdd-i"}
        ],
        EventSource.PIPELINE_EXECUTION: [
            {"action": "pipeline", "target": "build", "agent_id": "agent-bdd-p"}
        ],
        EventSource.FORENSIC_ALERT: [
            {"action": "alert", "target": "rule1", "agent_id": "agent-bdd-f"}
        ],
    }


@when("the raw events are ingested through the EventStreamCollector")
def when_events_ingested(atd_state):
    normalized_list = []
    for source, events in atd_state.raw_pillar_events.items():
        norm = atd_state.collector.normalize_event(source, events[0])
        normalized_list.append(norm)
    atd_state.normalized_list = normalized_list


@then("each event is normalized with UUID v4 ID, UTC timestamp, and pillar source enum")
def then_each_event_normalized(atd_state):
    assert len(atd_state.normalized_list) == 5
    for norm in atd_state.normalized_list:
        assert isinstance(norm.event_id, uuid.UUID)
        assert norm.event_id.version == 4
        assert norm.timestamp.tzinfo is not None
        assert isinstance(norm.source, EventSource)


@then("malformed events or non-callable reconnect attempts are rejected cleanly")
def then_malformed_events_rejected(atd_state):
    with pytest.raises(ValueError):
        atd_state.collector.normalize_event(EventSource.KERNEL_SYSCALL, "not_a_dict")

    with pytest.raises(ValueError, match="stream_factory must be a callable"):

        async def dummy_iter():
            yield {}

        run_async(
            atd_state.collector.collect_with_reconnect(
                EventSource.TOOL_CALL, dummy_iter()
            ).__anext__()
        )


# Scenario 6 steps (PathCorrelator)
@given("an agent with a temporal sequence of security events")
def given_agent_with_temporal_events(atd_state):
    store = AttackGraphStore(in_memory=True)
    run_async(store.initialize())
    atd_state.store = store
    atd_state.correlator = PathCorrelator(store=store)

    agent_id = "agent-bdd-correlator"
    now = datetime.now(UTC)

    ev1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve bash",
        target="/bin/bash",
        risk_score=0.4,
    )
    ev2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=30),
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action="sudo privilege elevate",
        target="root",
        risk_score=0.8,
    )
    ev3 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=60),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=agent_id,
        action="read token secret",
        target="/var/run/secrets/kubernetes.io/serviceaccount/token",
        risk_score=0.95,
    )

    run_async(store.insert_event(ev1))
    run_async(store.insert_event(ev2))
    run_async(store.insert_event(ev3))

    atd_state.agent_id = agent_id
    atd_state.time_window = (now - timedelta(seconds=10), now + timedelta(seconds=300))


@when("the PathCorrelator correlates attack paths within the time window")
def when_correlator_correlates_paths(atd_state):
    atd_state.correlator_paths = run_async(
        atd_state.correlator.correlate_attack_paths(
            atd_state.agent_id, atd_state.time_window, min_path_length=2
        )
    )


@then(
    "correlated AttackPath instances are returned with valid risk scores, correlation scores, and mapped MITRE technique IDs"
)
def then_correlator_returns_valid_paths(atd_state):
    assert len(atd_state.correlator_paths) >= 1
    top_path = atd_state.correlator_paths[0]
    assert 0.0 <= top_path.risk_score <= 1.0
    assert 0.0 <= top_path.correlation_score <= 1.0
    assert len(top_path.attack_stages) > 0
    # MITRE technique IDs mapping check
    assert any(tech in top_path.attack_stages for tech in ["T1059", "T1068", "T1552"])


@given(
    "an initialized AgentSwarmDetector instance and correlated security events for multiple agents"
)
def given_initialized_swarm_detector(atd_state):
    from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector

    store = AttackGraphStore(in_memory=True)
    run_async(store.initialize())
    atd_state.swarm_detector = AgentSwarmDetector(store=store)

    now = datetime.now(UTC)
    for offset in [0, 5, 10]:
        ev1 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="swarm-agent-1",
            action="exfil_db",
            target="evil.c2.domain",
            metadata={"ip": "192.168.1.99"},
            risk_score=0.8,
        )
        ev2 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=offset + 1),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="swarm-agent-2",
            action="exfil_db",
            target="evil.c2.domain",
            metadata={"ip": "192.168.1.99"},
            risk_score=0.8,
        )
        run_async(store.insert_event(ev1))
        run_async(store.insert_event(ev2))

    atd_state.swarm_base_time = now
    atd_state.swarm_time_window = (now - timedelta(seconds=10), now + timedelta(seconds=60))


@when("agent action sequences are fingerprinted and swarms are detected")
def when_fingerprinted_and_swarms_detected(atd_state):
    atd_state.swarm_fingerprint = run_async(
        atd_state.swarm_detector.fingerprint_agent("swarm-agent-1", window=3600, end_time=atd_state.swarm_base_time + timedelta(seconds=30))
    )
    atd_state.detected_swarms = run_async(
        atd_state.swarm_detector.detect_swarms(atd_state.swarm_time_window, min_agents=2, correlation_threshold=0.75)
    )


@then("deterministic SHA-256 behavioral fingerprints are generated")
def then_deterministic_fingerprints_generated(atd_state):
    assert isinstance(atd_state.swarm_fingerprint, str)
    assert len(atd_state.swarm_fingerprint) == 64


@then(
    "SwarmEvidence is produced with temporal correlation, coordination score, and shared infrastructure patterns"
)
def then_swarm_evidence_produced(atd_state):
    assert len(atd_state.detected_swarms) >= 1
    swarm = atd_state.detected_swarms[0]
    assert isinstance(swarm, SwarmEvidence)
    assert swarm.agent_ids == {"swarm-agent-1", "swarm-agent-2"}
    assert 0.0 <= swarm.temporal_correlation <= 1.0
    assert 0.0 <= swarm.coordination_score <= 1.0
    assert len(swarm.shared_patterns) >= 1


