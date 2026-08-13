"""BDD Step Definitions for Alert Generation (`tests/features/alert_generation.feature`)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

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
from tests.step_defs.async_utils import run_async

scenarios("../features/alert_generation.feature")


class AlertBDDState:
    def __init__(self):
        self.bus = AlertBus(retry_delay=0.001)
        self.received_alerts = []
        self.swarm_evidence = None
        self.ailm_evidence = None
        self.exploit_evidence = None
        self.c2_evidence = None
        self.attack_path = None
        self.k8s_evidence = None
        self.registry_evidence = None
        self.registry_confidence = 0.0
        self.failing_attempts = 0
        self.publish_result = None

        self.bus.subscribe(lambda a: self.received_alerts.append(a))


@pytest.fixture
def alert_state():
    return AlertBDDState()


# Scenario 1: detected swarm publishes a CRITICAL alert to the AlertBus
@given(parsers.parse('a detected agent swarm with agents "{agents_str}" and coordination_score {score:f}'))
def given_detected_swarm(alert_state, agents_str, score):
    agents = set(agents_str.split(","))
    now = datetime.now(UTC)
    alert_state.swarm_evidence = SwarmEvidence(
        swarm_id=uuid.uuid4(),
        agent_ids=agents,
        shared_patterns=["pattern1"],
        temporal_correlation=0.88,
        coordination_score=score,
        first_seen=now,
        last_seen=now + timedelta(seconds=30),
    )


@when("the AlertBus generates and publishes an alert for the swarm")
def when_publish_swarm_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_swarm_alert(alert_state.swarm_evidence)
    )


# Scenario 2: AILM evidence with HIGH risk_level publishes a HIGH severity alert
@given(parsers.parse('an AILM evidence for agent "{agent_id}" with risk_level "{risk_level}"'))
def given_ailm_evidence(alert_state, agent_id, risk_level):
    alert_state.ailm_evidence = AILMEvidence(
        agent_id=agent_id,
        composed_permissions={"perm_a", "perm_b"},
        boundary_crossings=["boundary_1"],
        risk_level=risk_level,
    )


@when("the AlertBus generates and publishes an alert for the AILM evidence")
def when_publish_ailm_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_ailm_alert(alert_state.ailm_evidence)
    )


# Scenario 3: exploit chain with novelty_score 0.9 publishes a CRITICAL alert
@given(parsers.parse("an exploit chain evidence with novelty_score {score:f}"))
def given_exploit_evidence(alert_state, score):
    alert_state.exploit_evidence = ExploitChainEvidence(
        chain_id=uuid.uuid4(),
        exploits=[("exploit_rce", ExploitCategory.RCE)],
        novelty_score=score,
        chaining_confidence=0.90,
    )


@when("the AlertBus generates and publishes an alert for the exploit chain")
def when_publish_exploit_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_exploit_chain_alert(alert_state.exploit_evidence)
    )


# Scenario 4: detected C2 infrastructure publishes a CRITICAL alert
@given(parsers.parse('a C2 evidence for agent "{agent_id}" with endpoint "{endpoint}"'))
def given_c2_evidence(alert_state, agent_id, endpoint):
    alert_state.c2_evidence = C2Evidence(
        agent_id=agent_id,
        c2_endpoints=[endpoint],
        communication_pattern="beaconing",
        persistence_indicators=["cron_job"],
    )


@when("the AlertBus generates and publishes an alert for the C2 evidence")
def when_publish_c2_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_c2_alert(alert_state.c2_evidence)
    )


# Scenario 5: alert delivery failure retries up to 5 times before logging a persistent failure
@given(parsers.parse("an AlertBus configured with {retries:d} max retries and a subscriber that always fails"))
def given_failing_bus(alert_state, retries):
    alert_state.bus = AlertBus(max_retries=retries, retry_delay=0.001)

    async def failing_subscriber(alert):
        alert_state.failing_attempts += 1
        raise ConnectionResetError("Sink connection dropped")

    alert_state.bus.subscribe(failing_subscriber)


@when("a threat alert is published to the AlertBus")
def when_publish_threat_alert(alert_state):
    alert = Alert(
        alert_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        severity=AlertSeverity.HIGH,
        threat_type="test_failing",
        title="Test Failing Delivery",
        description="Delivery failure test description",
    )
    alert_state.publish_result = run_async(alert_state.bus.publish(alert))


@then(parsers.parse("the delivery should be attempted {expected_attempts:d} times and recorded as a persistent failure"))
def then_delivery_attempted_and_recorded(alert_state, expected_attempts):
    assert alert_state.failing_attempts == expected_attempts
    assert alert_state.publish_result is False
    assert len(alert_state.bus.persistent_failures) == 1


# Scenario 6: correlated attack path with high risk publishes a CRITICAL alert
@given(parsers.parse('a correlated attack path for agent "{agent_id}" with risk_score {score:f}'))
def given_correlated_attack_path(alert_state, agent_id, score):
    now = datetime.now(UTC)
    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="exec",
        target="/bin/curl",
        risk_score=score,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now + timedelta(seconds=5),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=agent_id,
        action="read_token",
        target="/var/run/secrets",
        risk_score=score,
    )
    node1 = AttackNode(node_id=uuid.uuid4(), event=ev1)
    node2 = AttackNode(node_id=uuid.uuid4(), event=ev2)

    alert_state.attack_path = AttackPath(
        path_id=uuid.uuid4(),
        agent_id=agent_id,
        nodes=[node1, node2],
        start_time=now,
        end_time=now + timedelta(seconds=5),
        risk_score=score,
        attack_stages=["T1059.004", "T1003.008"],
        correlation_score=0.85,
    )


@when("the AlertBus generates and publishes an alert for the attack path")
def when_publish_attack_path_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_attack_path_alert(alert_state.attack_path)
    )


# Scenario 7: Kubernetes pod token theft publishes a CRITICAL alert
@given(parsers.parse('a Kubernetes threat evidence with threat_type "{threat_type}" in namespace "{namespace}"'))
def given_k8s_threat(alert_state, threat_type, namespace):
    alert_state.k8s_evidence = K8sThreatEvidence(
        threat_type=threat_type,
        namespace=namespace,
        pod_name="victim-pod-01",
        service_account="sa-compromised",
        evidence={"target": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
    )


@when("the AlertBus generates and publishes an alert for the Kubernetes threat")
def when_publish_k8s_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_k8s_alert(alert_state.k8s_evidence)
    )


# Scenario 8: package registry threat with high confidence publishes a CRITICAL alert
@given(parsers.parse('a package registry threat evidence for "{reg_type}" package "{pkg_name}" with exploit confidence {score:f}'))
def given_registry_threat(alert_state, reg_type, pkg_name, score):
    alert_state.registry_evidence = RegistryThreatEvidence(
        registry_type=reg_type,
        package_name=pkg_name,
        exploit_indicators=["malformed_tarball"],
        cve_candidates=["CVE-2026-9999"],
    )
    alert_state.registry_confidence = score


@when("the AlertBus generates and publishes an alert for the registry threat")
def when_publish_registry_alert(alert_state):
    alert_state.publish_result = run_async(
        alert_state.bus.publish_registry_alert(
            alert_state.registry_evidence,
            exploit_confidence=alert_state.registry_confidence,
        )
    )


# Generic Then for published alert
@then(parsers.parse('a published alert with severity "{expected_sev}" and threat_type "{expected_type}" should be received'))
def then_alert_received(alert_state, expected_sev, expected_type):
    assert alert_state.publish_result is True
    assert len(alert_state.received_alerts) >= 1
    last_alert = alert_state.received_alerts[-1]
    assert str(last_alert.severity.value) == expected_sev or str(last_alert.severity) == expected_sev
    assert last_alert.threat_type == expected_type
