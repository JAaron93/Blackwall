"""Unit tests for Alert Generation across all threat types (Blackwall Pillar 6 Task 15.2, 15.3, 15.4)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    AILMEvidence,
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


def create_normalized_event(
    agent_id: str = "agent-01",
    action: str = "exec",
    target: str = "/bin/bash",
    risk_score: float = 0.8,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"detail": "test"},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_swarm_alerts():
    """Verify alert generation and publication for swarm detection (Requirement 10.1, Task 15.2)."""
    bus = AlertBus()
    now = datetime.now(UTC)

    swarm = SwarmEvidence(
        swarm_id=uuid.uuid4(),
        agent_ids={"agent-1", "agent-2"},
        shared_patterns=["ip:10.0.0.1"],
        temporal_correlation=0.85,
        coordination_score=0.90,
        first_seen=now,
        last_seen=now + timedelta(seconds=100),
    )

    alert = bus.generate_swarm_alert(swarm)
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.threat_type == "swarm_detection"
    assert alert.evidence_id == swarm.swarm_id
    assert set(alert.agent_ids) == {"agent-1", "agent-2"}
    assert alert.evidence["coordination_score"] == 0.90

    success = await bus.publish_swarm_alert(swarm)
    assert success is True
    assert len(bus.get_alerts(severity=AlertSeverity.CRITICAL)) == 1


@pytest.mark.asyncio
async def test_ailm_alerts():
    """Verify alert generation for AILM events mapping risk_level (Requirement 10.2, Task 15.3)."""
    bus = AlertBus()

    # CRITICAL risk level
    ailm_crit = AILMEvidence(
        agent_id="agent-ailm-01",
        composed_permissions={"db_read", "s3_write", "iam_passrole"},
        boundary_crossings=["boundary_a", "boundary_b", "boundary_c"],
        risk_level="CRITICAL",
    )
    alert_crit = bus.generate_ailm_alert(ailm_crit)
    assert alert_crit.severity == AlertSeverity.CRITICAL
    assert alert_crit.agent_id == "agent-ailm-01"
    assert "agent-ailm-01" in alert_crit.agent_ids
    assert "db_read" in alert_crit.evidence["composed_permissions"]

    # HIGH risk level
    ailm_high = AILMEvidence(
        agent_id="agent-ailm-02",
        composed_permissions={"db_read", "s3_write"},
        boundary_crossings=["boundary_a", "boundary_b"],
        risk_level="HIGH",
    )
    alert_high = bus.generate_ailm_alert(ailm_high)
    assert alert_high.severity == AlertSeverity.HIGH

    # MEDIUM risk level
    ailm_med = AILMEvidence(
        agent_id="agent-ailm-03",
        composed_permissions={"db_read"},
        boundary_crossings=["boundary_a"],
        risk_level="MEDIUM",
    )
    alert_med = bus.generate_ailm_alert(ailm_med)
    assert alert_med.severity == AlertSeverity.MEDIUM

    success = await bus.publish_ailm_alert(ailm_crit)
    assert success is True
    assert len(bus.get_alerts()) == 1


@pytest.mark.asyncio
async def test_all_alert_types():
    """Verify alert generation for exploit chains, attack paths, C2, K8s, and registry threats (Requirement 10.3-10.7, Task 15.4)."""
    bus = AlertBus()
    now = datetime.now(UTC)

    # 1. Exploit Chains (novelty_score mapping - Requirement 10.3)
    chain_crit = ExploitChainEvidence(
        chain_id=uuid.uuid4(),
        exploits=[("RCE", ExploitCategory.RCE), ("PrivEsc", ExploitCategory.PRIVILEGE_ESCALATION)],
        novelty_score=0.90,
        chaining_confidence=0.85,
    )
    alert_chain_crit = bus.generate_exploit_chain_alert(chain_crit)
    assert alert_chain_crit.severity == AlertSeverity.CRITICAL
    assert alert_chain_crit.threat_type == "exploit_chain"

    chain_high = ExploitChainEvidence(
        chain_id=uuid.uuid4(),
        exploits=[("RCE", ExploitCategory.RCE)],
        novelty_score=0.60,
        chaining_confidence=0.70,
    )
    alert_chain_high = bus.generate_exploit_chain_alert(chain_high)
    assert alert_chain_high.severity == AlertSeverity.HIGH

    chain_med = ExploitChainEvidence(
        chain_id=uuid.uuid4(),
        exploits=[("CredTheft", ExploitCategory.CREDENTIAL_THEFT)],
        novelty_score=0.40,
        chaining_confidence=0.60,
    )
    alert_chain_med = bus.generate_exploit_chain_alert(chain_med)
    assert alert_chain_med.severity == AlertSeverity.MEDIUM

    chain_low = ExploitChainEvidence(
        chain_id=uuid.uuid4(),
        exploits=[],
        novelty_score=0.10,
        chaining_confidence=0.30,
    )
    alert_chain_low = bus.generate_exploit_chain_alert(chain_low)
    assert alert_chain_low.severity == AlertSeverity.LOW

    # 2. Multi-Stage Attack Paths (risk_score mapping - Requirement 10.4)
    ev1 = create_normalized_event(agent_id="agent-path-01", risk_score=0.85)
    ev2 = create_normalized_event(agent_id="agent-path-01", risk_score=0.90)
    node1 = AttackNode(node_id=uuid.uuid4(), event=ev1)
    node2 = AttackNode(node_id=uuid.uuid4(), event=ev2)

    path_crit = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-path-01",
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=60),
        risk_score=0.88,
        attack_stages=["T1059.004", "T1068"],
        correlation_score=0.90,
    )
    alert_path_crit = bus.generate_attack_path_alert(path_crit)
    assert alert_path_crit.severity == AlertSeverity.CRITICAL
    assert alert_path_crit.agent_id == "agent-path-01"

    path_high = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-path-01",
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=60),
        risk_score=0.65,
        attack_stages=["T1059.004"],
        correlation_score=0.70,
    )
    assert bus.generate_attack_path_alert(path_high).severity == AlertSeverity.HIGH

    path_med = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-path-01",
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=60),
        risk_score=0.35,
        attack_stages=[],
        correlation_score=0.40,
    )
    assert bus.generate_attack_path_alert(path_med).severity == AlertSeverity.MEDIUM

    # 3. C2 Infrastructure Detection (CRITICAL severity - Requirement 10.5)
    c2 = C2Evidence(
        agent_id="agent-c2-01",
        c2_endpoints=["https://pastebin.com/raw/malicious"],
        communication_pattern="beaconing",
        persistence_indicators=["cron"],
    )
    alert_c2 = bus.generate_c2_alert(c2)
    assert alert_c2.severity == AlertSeverity.CRITICAL
    assert alert_c2.threat_type == "c2_infrastructure"
    assert alert_c2.agent_id == "agent-c2-01"

    # 4. Kubernetes Threats (threat_type mapping - Requirement 10.6)
    k8s_token = K8sThreatEvidence(
        threat_type="pod_token_theft",
        namespace="default",
        pod_name="victim-pod",
        service_account="victim-sa",
        evidence={"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
    )
    alert_k8s_token = bus.generate_k8s_alert(k8s_token)
    assert alert_k8s_token.severity == AlertSeverity.CRITICAL

    k8s_fleet = K8sThreatEvidence(
        threat_type="fleet_spawning",
        namespace="kube-system",
        pod_name="miner-01",
        service_account="default",
        evidence={"pod_count": 10},
    )
    assert bus.generate_k8s_alert(k8s_fleet).severity == AlertSeverity.CRITICAL

    k8s_secrets = K8sThreatEvidence(
        threat_type="secrets_exfiltration",
        namespace="production",
        pod_name="app-pod",
        service_account="app-sa",
        evidence={"count": 50},
    )
    assert bus.generate_k8s_alert(k8s_secrets).severity == AlertSeverity.HIGH

    k8s_respawn = K8sThreatEvidence(
        threat_type="self_respawning_pod",
        namespace="default",
        pod_name="backdoor-pod",
        service_account="default",
        evidence={"restarts": 5},
    )
    assert bus.generate_k8s_alert(k8s_respawn).severity == AlertSeverity.HIGH

    # 5. Registry Threats (exploit confidence mapping - Requirement 10.7)
    reg_high_conf = RegistryThreatEvidence(
        registry_type="npm",
        package_name="express-malicious",
        exploit_indicators=["malformed_tarball"],
        cve_candidates=["CVE-2026-1234"],
    )
    alert_reg_crit = bus.generate_registry_alert(reg_high_conf, exploit_confidence=0.85)
    assert alert_reg_crit.severity == AlertSeverity.CRITICAL

    alert_reg_high = bus.generate_registry_alert(reg_high_conf, exploit_confidence=0.60)
    assert alert_reg_high.severity == AlertSeverity.HIGH

    reg_low_conf = RegistryThreatEvidence(
        registry_type="PyPI",
        package_name="requests-typo",
        exploit_indicators=["unusual_headers"],
        cve_candidates=[],
    )
    alert_reg_med = bus.generate_registry_alert(reg_low_conf, exploit_confidence=0.35)
    assert alert_reg_med.severity == AlertSeverity.MEDIUM

    alert_reg_low = bus.generate_registry_alert(reg_low_conf, exploit_confidence=0.10)
    assert alert_reg_low.severity == AlertSeverity.LOW

    # Verify publishing all types
    assert await bus.publish_exploit_chain_alert(chain_crit) is True
    assert await bus.publish_attack_path_alert(path_crit) is True
    assert await bus.publish_c2_alert(c2) is True
    assert await bus.publish_k8s_alert(k8s_token) is True
    assert await bus.publish_registry_alert(reg_high_conf, exploit_confidence=0.85) is True
    assert len(bus.get_alerts()) == 5
