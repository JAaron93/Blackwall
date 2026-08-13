"""Property-based tests for Alert Generation using Hypothesis (Pillar 6 Task 15.5 / Properties 57-63)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection import (
    AILMEvidence,
    Alert,
    AlertBus,
    AlertSeverity,
    AttackNode,
    AttackPath,
    C2Evidence,
    EventSource,
    ExploitCategory,
    ExploitChainEvidence,
    K8sThreatEvidence,
    NormalizedEvent,
    RegistryThreatEvidence,
    SwarmEvidence,
)

valid_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{1,20}", fullmatch=True)


# ---------------------------------------------------------------------------
# Property 57: Swarm Detection Alert Generation
# ---------------------------------------------------------------------------
@given(
    swarm_id=st.uuids(version=4),
    agents=st.sets(valid_id_strategy, min_size=2, max_size=5),
    correlation=st.floats(min_value=0.0, max_value=1.0),
    coordination=st.floats(min_value=0.0, max_value=1.0),
)
@settings(max_examples=100)
def test_property_57_swarm_detection_alert_generation_valid(
    swarm_id: uuid.UUID,
    agents: set,
    correlation: float,
    coordination: float,
):
    """Feature: blackwall-advanced-threat-detection, Property 57: Swarm Detection Alert Generation

    For any detected agent swarm, an alert with CRITICAL severity SHALL be published to the Alert Bus.
    """
    bus = AlertBus()
    now = datetime.now(UTC)
    swarm = SwarmEvidence(
        swarm_id=swarm_id,
        agent_ids=agents,
        shared_patterns=["pattern"],
        temporal_correlation=correlation,
        coordination_score=coordination,
        first_seen=now,
        last_seen=now + timedelta(seconds=10),
    )

    alert = bus.generate_swarm_alert(swarm)
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.threat_type == "swarm_detection"
    assert alert.evidence_id == swarm.swarm_id
    assert set(alert.agent_ids) == agents


# ---------------------------------------------------------------------------
# Property 58: AILM Alert Severity Mapping
# ---------------------------------------------------------------------------
@given(
    agent_id=valid_id_strategy,
    risk_level=st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
)
@settings(max_examples=100)
def test_property_58_ailm_alert_severity_mapping_valid(agent_id: str, risk_level: str):
    """Feature: blackwall-advanced-threat-detection, Property 58: AILM Alert Severity Mapping

    For any detected AILM event, the published alert severity SHALL be HIGH or CRITICAL based on the computed risk_level.
    """
    bus = AlertBus()
    ailm = AILMEvidence(
        agent_id=agent_id,
        composed_permissions={"perm1"},
        boundary_crossings=["boundary"],
        risk_level=risk_level,
    )

    alert = bus.generate_ailm_alert(ailm)
    if risk_level == "CRITICAL":
        assert alert.severity == AlertSeverity.CRITICAL
    elif risk_level == "HIGH":
        assert alert.severity == AlertSeverity.HIGH
    elif risk_level == "MEDIUM":
        assert alert.severity == AlertSeverity.MEDIUM
    else:
        assert alert.severity == AlertSeverity.LOW


# ---------------------------------------------------------------------------
# Property 59: Exploit Chain Alert Severity Mapping
# ---------------------------------------------------------------------------
@given(
    chain_id=st.uuids(version=4),
    novelty_score=st.floats(min_value=0.0, max_value=1.0),
    chaining_confidence=st.floats(min_value=0.0, max_value=1.0),
)
@settings(max_examples=100)
def test_property_59_exploit_chain_alert_severity_mapping_valid(
    chain_id: uuid.UUID,
    novelty_score: float,
    chaining_confidence: float,
):
    """Feature: blackwall-advanced-threat-detection, Property 59: Exploit Chain Alert Severity Mapping

    For any detected exploit chain, the published alert severity SHALL be based on the novelty_score.
    """
    bus = AlertBus()
    chain = ExploitChainEvidence(
        chain_id=chain_id,
        exploits=[("exploit_1", ExploitCategory.RCE)],
        novelty_score=novelty_score,
        chaining_confidence=chaining_confidence,
    )

    alert = bus.generate_exploit_chain_alert(chain)
    if novelty_score >= 0.8:
        assert alert.severity == AlertSeverity.CRITICAL
    elif novelty_score >= 0.5:
        assert alert.severity == AlertSeverity.HIGH
    elif novelty_score >= 0.3:
        assert alert.severity == AlertSeverity.MEDIUM
    else:
        assert alert.severity == AlertSeverity.LOW


# ---------------------------------------------------------------------------
# Property 60: Attack Path Alert Severity Mapping
# ---------------------------------------------------------------------------
@given(
    path_id=st.uuids(version=4),
    agent_id=valid_id_strategy,
    risk_score=st.floats(min_value=0.0, max_value=1.0),
    correlation_score=st.floats(min_value=0.0, max_value=1.0),
)
@settings(max_examples=100)
def test_property_60_attack_path_alert_severity_mapping_valid(
    path_id: uuid.UUID,
    agent_id: str,
    risk_score: float,
    correlation_score: float,
):
    """Feature: blackwall-advanced-threat-detection, Property 60: Attack Path Alert Severity Mapping

    For any correlated multi-stage attack path, the published alert severity SHALL be based on the risk_score.
    """
    bus = AlertBus()
    now = datetime.now(UTC)
    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="exec",
        target="/bin/bash",
        risk_score=risk_score,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now + timedelta(seconds=1),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="connect",
        target="10.0.0.1",
        risk_score=risk_score,
    )
    node1 = AttackNode(node_id=uuid.uuid4(), event=ev1)
    node2 = AttackNode(node_id=uuid.uuid4(), event=ev2)

    path = AttackPath(
        path_id=path_id,
        agent_id=agent_id,
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=1),
        risk_score=risk_score,
        attack_stages=["T1059.004"],
        correlation_score=correlation_score,
    )

    alert = bus.generate_attack_path_alert(path)
    if risk_score >= 0.8:
        assert alert.severity == AlertSeverity.CRITICAL
    elif risk_score >= 0.5:
        assert alert.severity == AlertSeverity.HIGH
    elif risk_score >= 0.3:
        assert alert.severity == AlertSeverity.MEDIUM
    else:
        assert alert.severity == AlertSeverity.LOW


# ---------------------------------------------------------------------------
# Property 61: C2 Detection Alert Generation
# ---------------------------------------------------------------------------
@given(
    agent_id=valid_id_strategy,
    endpoints=st.lists(valid_id_strategy, min_size=1, max_size=5),
    pattern=st.sampled_from(["beaconing", "polling", "webhook", "dns_tunnel"]),
)
@settings(max_examples=100)
def test_property_61_c2_detection_alert_generation_valid(
    agent_id: str,
    endpoints: list,
    pattern: str,
):
    """Feature: blackwall-advanced-threat-detection, Property 61: C2 Detection Alert Generation

    For any detected C2 infrastructure, an alert with CRITICAL severity SHALL be published to the Alert Bus.
    """
    bus = AlertBus()
    c2 = C2Evidence(
        agent_id=agent_id,
        c2_endpoints=endpoints,
        communication_pattern=pattern,
        persistence_indicators=["cron"],
    )

    alert = bus.generate_c2_alert(c2)
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.threat_type == "c2_infrastructure"
    assert alert.agent_id == agent_id


# ---------------------------------------------------------------------------
# Property 62: K8s Threat Alert Severity Mapping
# ---------------------------------------------------------------------------
@given(
    threat_type=st.sampled_from(
        [
            "pod_token_theft",
            "fleet_spawning",
            "secrets_exfiltration",
            "self_respawning_pod",
            "unknown_k8s_threat",
        ]
    ),
    namespace=valid_id_strategy,
    pod_name=valid_id_strategy,
    service_account=valid_id_strategy,
)
@settings(max_examples=100)
def test_property_62_k8s_threat_alert_severity_mapping_valid(
    threat_type: str,
    namespace: str,
    pod_name: str,
    service_account: str,
):
    """Feature: blackwall-advanced-threat-detection, Property 62: K8s Threat Alert Severity Mapping

    For any detected Kubernetes threat, the published alert severity SHALL be based on the threat_type.
    """
    bus = AlertBus()
    k8s = K8sThreatEvidence(
        threat_type=threat_type,
        namespace=namespace,
        pod_name=pod_name,
        service_account=service_account,
        evidence={},
    )

    alert = bus.generate_k8s_alert(k8s)
    if threat_type in {"pod_token_theft", "fleet_spawning"}:
        assert alert.severity == AlertSeverity.CRITICAL
    elif threat_type in {"secrets_exfiltration", "self_respawning_pod"}:
        assert alert.severity == AlertSeverity.HIGH
    else:
        assert alert.severity in {AlertSeverity.MEDIUM, AlertSeverity.LOW}


# ---------------------------------------------------------------------------
# Property 63: Registry Threat Alert Severity Mapping
# ---------------------------------------------------------------------------
@given(
    registry_type=st.sampled_from(["npm", "PyPI", "Artifactory"]),
    package_name=valid_id_strategy,
    exploit_confidence=st.floats(min_value=0.0, max_value=1.0),
    has_cve=st.booleans(),
)
@settings(max_examples=100)
def test_property_63_registry_threat_alert_severity_mapping_valid(
    registry_type: str,
    package_name: str,
    exploit_confidence: float,
    has_cve: bool,
):
    """Feature: blackwall-advanced-threat-detection, Property 63: Registry Threat Alert Severity Mapping

    For any detected registry threat, the published alert severity SHALL be based on the exploit confidence level.
    """
    bus = AlertBus()
    registry = RegistryThreatEvidence(
        registry_type=registry_type,
        package_name=package_name,
        exploit_indicators=["malformed_package"] if has_cve else [],
        cve_candidates=["CVE-2026-9999"] if has_cve else [],
    )

    alert = bus.generate_registry_alert(registry, exploit_confidence=exploit_confidence)
    if exploit_confidence >= 0.8:
        assert alert.severity == AlertSeverity.CRITICAL
    elif exploit_confidence >= 0.5:
        assert alert.severity == AlertSeverity.HIGH
    elif exploit_confidence >= 0.3:
        assert alert.severity == AlertSeverity.MEDIUM
    else:
        assert alert.severity == AlertSeverity.LOW


# ---------------------------------------------------------------------------
# Rejection Testing for Alert Model Invariants (Rule 17)
# ---------------------------------------------------------------------------
@given(
    empty_str=st.text().filter(lambda s: not s.strip()),
)
@settings(max_examples=50)
def test_alert_rejection_empty_strings(empty_str: str):
    """Verify Alert model rejects empty or whitespace-only title, threat_type, or description."""
    now = datetime.now(UTC)
    with pytest.raises((ValidationError, ValueError)):
        Alert(
            alert_id=uuid.uuid4(),
            timestamp=now,
            severity=AlertSeverity.HIGH,
            threat_type=empty_str,
            title="Valid Title",
            description="Valid Description",
        )

    with pytest.raises((ValidationError, ValueError)):
        Alert(
            alert_id=uuid.uuid4(),
            timestamp=now,
            severity=AlertSeverity.HIGH,
            threat_type="valid_type",
            title=empty_str,
            description="Valid Description",
        )

    with pytest.raises((ValidationError, ValueError)):
        Alert(
            alert_id=uuid.uuid4(),
            timestamp=now,
            severity=AlertSeverity.HIGH,
            threat_type="valid_type",
            title="Valid Title",
            description=empty_str,
        )
