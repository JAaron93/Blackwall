"""Unit tests for Blackwall Advanced Threat Detection data models."""

from datetime import datetime, timezone, timedelta
import uuid

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.enums import (
    EventSource,
    ExploitCategory,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    AILMEvidence,
    AttackNode,
    AttackPath,
    C2Evidence,
    ExploitChainEvidence,
    K8sThreatEvidence,
    NormalizedEvent,
    RegistryThreatEvidence,
    SwarmEvidence,
)


def create_valid_event(
    event_id: str = None,
    timestamp: datetime = None,
    agent_id: str = "agent-007",
    risk_score: float = 0.5,
) -> NormalizedEvent:
    """Helper function to create a valid NormalizedEvent."""
    return NormalizedEvent(
        event_id=event_id or str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve",
        target="/usr/bin/python3",
        metadata={"pid": 1234},
        risk_score=risk_score,
    )


def test_normalized_event_valid():
    """Test valid NormalizedEvent creation."""
    event = create_valid_event()
    assert UUID_is_v4(event.event_id)
    assert event.timestamp.tzinfo is not None
    assert event.agent_id == "agent-007"
    assert event.risk_score == 0.5


def test_normalized_event_invalid_uuid():
    """Test NormalizedEvent with non-UUID or non-v4 UUID raises ValueError."""
    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(event_id="not-a-uuid")

    uuid_v1 = str(uuid.uuid1())
    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(event_id=uuid_v1)


def test_normalized_event_invalid_timestamp():
    """Test NormalizedEvent with naive or non-UTC timestamp raises ValueError."""
    naive_dt = datetime.now()
    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(timestamp=naive_dt)

    est = timezone(timedelta(hours=-5))
    est_dt = datetime.now(est)
    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(timestamp=est_dt)


def test_normalized_event_invalid_agent_id():
    """Test NormalizedEvent with empty or whitespace agent_id raises ValueError."""
    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(agent_id="")

    with pytest.raises((ValueError, ValidationError)):
        create_valid_event(agent_id="   ")


def test_normalized_event_risk_score_bounds():
    """Test NormalizedEvent risk score bounds [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        create_valid_event(risk_score=-0.1)

    with pytest.raises(ValidationError):
        create_valid_event(risk_score=1.1)


def test_attack_node_valid():
    """Test AttackNode construction."""
    event = create_valid_event()
    node = AttackNode(node_id="node-1", event=event)
    assert node.node_id == "node-1"
    assert node.incoming_edges == []
    assert node.outgoing_edges == []


def test_attack_path_valid():
    """Test AttackPath valid construction with >= 2 nodes and valid temporal ordering."""
    now = datetime.now(timezone.utc)
    event1 = create_valid_event(timestamp=now)
    event2 = create_valid_event(timestamp=now + timedelta(seconds=10))
    node1 = AttackNode(node_id="n1", event=event1)
    node2 = AttackNode(node_id="n2", event=event2)

    path = AttackPath(
        path_id="path-1",
        agent_id="agent-007",
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=10),
        risk_score=0.8,
        attack_stages=["T1059"],
        correlation_score=0.9,
    )
    assert len(path.nodes) == 2
    assert path.end_time >= path.start_time


def test_attack_path_min_nodes_validation():
    """Test AttackPath raises ValidationError when nodes count is less than 2."""
    now = datetime.now(timezone.utc)
    node = AttackNode(node_id="n1", event=create_valid_event())

    with pytest.raises(ValidationError):
        AttackPath(
            path_id="path-1",
            agent_id="agent-007",
            nodes=[node],
            start_time=now,
            end_time=now,
            risk_score=0.5,
            correlation_score=0.5,
        )


def test_attack_path_temporal_ordering_validation():
    """Test AttackPath raises ValidationError when end_time < start_time."""
    now = datetime.now(timezone.utc)
    node1 = AttackNode(node_id="n1", event=create_valid_event())
    node2 = AttackNode(node_id="n2", event=create_valid_event())

    with pytest.raises(ValidationError):
        AttackPath(
            path_id="path-1",
            agent_id="agent-007",
            nodes=[node1, node2],
            start_time=now,
            end_time=now - timedelta(seconds=1),
            risk_score=0.5,
            correlation_score=0.5,
        )


def test_attack_path_naive_or_non_utc_timestamps_validation():
    """Test AttackPath raises ValidationError for naive or non-UTC start_time / end_time."""
    now_utc = datetime.now(timezone.utc)
    now_naive = datetime.now()
    est = timezone(timedelta(hours=-5))
    now_est = datetime.now(est)
    node1 = AttackNode(node_id="n1", event=create_valid_event())
    node2 = AttackNode(node_id="n2", event=create_valid_event())

    # Naive start_time
    with pytest.raises(ValidationError):
        AttackPath(
            path_id="p1",
            agent_id="a1",
            nodes=[node1, node2],
            start_time=now_naive,
            end_time=now_utc,
            risk_score=0.5,
            correlation_score=0.5,
        )

    # Naive end_time
    with pytest.raises(ValidationError):
        AttackPath(
            path_id="p1",
            agent_id="a1",
            nodes=[node1, node2],
            start_time=now_utc,
            end_time=now_naive,
            risk_score=0.5,
            correlation_score=0.5,
        )

    # Non-UTC end_time
    with pytest.raises(ValidationError):
        AttackPath(
            path_id="p1",
            agent_id="a1",
            nodes=[node1, node2],
            start_time=now_utc,
            end_time=now_est,
            risk_score=0.5,
            correlation_score=0.5,
        )


def test_swarm_evidence_valid():
    """Test SwarmEvidence construction."""
    now = datetime.now(timezone.utc)
    swarm = SwarmEvidence(
        swarm_id="swarm-1",
        agent_ids={"agent-1", "agent-2"},
        shared_patterns=["pattern-a"],
        temporal_correlation=0.85,
        coordination_score=0.9,
        first_seen=now,
        last_seen=now + timedelta(minutes=5),
    )
    assert len(swarm.agent_ids) == 2


def test_swarm_evidence_min_agents_validation():
    """Test SwarmEvidence raises ValidationError when fewer than 2 agents."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id="swarm-1",
            agent_ids={"agent-1"},
            temporal_correlation=0.85,
            coordination_score=0.9,
            first_seen=now,
            last_seen=now,
        )


def test_swarm_evidence_time_window_validation():
    """Test SwarmEvidence rejects last_seen < first_seen, naive datetimes, or non-UTC datetimes."""
    now_utc = datetime.now(timezone.utc)
    now_naive = datetime.now()
    est = timezone(timedelta(hours=-5))
    now_est = datetime.now(est)

    # last_seen < first_seen
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id="sw-1",
            agent_ids={"a1", "a2"},
            temporal_correlation=0.8,
            coordination_score=0.8,
            first_seen=now_utc,
            last_seen=now_utc - timedelta(seconds=1),
        )

    # Naive first_seen
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id="sw-1",
            agent_ids={"a1", "a2"},
            temporal_correlation=0.8,
            coordination_score=0.8,
            first_seen=now_naive,
            last_seen=now_utc,
        )

    # Non-UTC last_seen
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id="sw-1",
            agent_ids={"a1", "a2"},
            temporal_correlation=0.8,
            coordination_score=0.8,
            first_seen=now_utc,
            last_seen=now_est,
        )


def test_exploit_chain_evidence_valid():
    """Test ExploitChainEvidence construction."""
    evidence = ExploitChainEvidence(
        chain_id="chain-1",
        exploits=[("CVE-2026-1234", ExploitCategory.RCE)],
        novelty_score=0.95,
        chaining_confidence=0.9,
    )
    assert evidence.chain_id == "chain-1"


def test_ailm_evidence_valid():
    """Test AILMEvidence construction."""
    evidence = AILMEvidence(
        agent_id="agent-1",
        composed_permissions={"read:db", "write:storage"},
        boundary_crossings=["vpc-peering"],
        risk_level="HIGH",
    )
    assert evidence.agent_id == "agent-1"


def test_c2_evidence_valid():
    """Test C2Evidence construction."""
    evidence = C2Evidence(
        agent_id="agent-1",
        c2_endpoints=["https://c2.example.com"],
        communication_pattern="beaconing",
        persistence_indicators=["cronjob"],
    )
    assert evidence.communication_pattern == "beaconing"


def test_k8s_threat_evidence_valid():
    """Test K8sThreatEvidence construction."""
    evidence = K8sThreatEvidence(
        threat_type="pod_token_theft",
        namespace="default",
        pod_name="pod-123",
        service_account="sa-admin",
        evidence={"token_path": "/var/run/secrets/..."},
    )
    assert evidence.threat_type == "pod_token_theft"


def test_registry_threat_evidence_valid():
    """Test RegistryThreatEvidence construction."""
    evidence = RegistryThreatEvidence(
        registry_type="npm",
        package_name="malicious-pkg",
        exploit_indicators=["eval_in_postinstall"],
        cve_candidates=["CVE-2026-9999"],
    )
    assert evidence.registry_type == "npm"


def UUID_is_v4(val: str) -> bool:
    try:
        u = uuid.UUID(val)
        return u.version == 4
    except Exception:
        return False
