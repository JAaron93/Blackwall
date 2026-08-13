"""BDD Step Definitions for Kubernetes Defense Layer (`tests/features/kubernetes_defense.feature`)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    K8sThreatEvidence,
    KubernetesDefenseLayer,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from tests.step_defs.async_utils import run_async

scenarios("../features/kubernetes_defense.feature")


class K8sBDDState:
    def __init__(self):
        self.store = AttackGraphStore(in_memory=True)
        self.layer = KubernetesDefenseLayer(store=self.store)
        self.agent_id = None
        self.time_window = None
        self.evidences = []
        self.evidence_obj = None


@pytest.fixture
def k8s_state():
    return K8sBDDState()


def create_k8s_event(
    agent_id: str,
    action: str,
    target: str,
    offset_seconds: float = 0.0,
    metadata: dict = None,
    source: EventSource = EventSource.KERNEL_SYSCALL,
) -> NormalizedEvent:
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=0.8,
    )


# Scenario 1
@given(parsers.parse('an agent "{agent_id}" performing file access to "{path}"'))
def given_agent_file_access(k8s_state, agent_id, path):
    k8s_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    k8s_state.time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_k8s_event(
        agent_id=agent_id,
        action="sys_open",
        target=path,
        offset_seconds=5.0,
        metadata={
            "namespace": "bdd-ns",
            "pod_name": "bdd-pod",
            "service_account": "bdd-sa",
        },
    )
    run_async(k8s_state.store.insert_event(event))


@when(parsers.parse('the Kubernetes defense layer runs pod token theft detection for "{agent_id}"'))
def when_run_pod_token_theft(k8s_state, agent_id):
    k8s_state.evidences = run_async(
        k8s_state.layer.detect_pod_token_theft(
            agent_id=agent_id, time_window=k8s_state.time_window
        )
    )


@then(parsers.parse('pod token theft evidence should be generated with threat_type "{expected_type}"'))
def then_pod_token_theft_evidence(k8s_state, expected_type):
    assert len(k8s_state.evidences) >= 1
    assert k8s_state.evidences[0].threat_type == expected_type


# Scenario 2
@given(parsers.parse('10 pods created across 5 nodes in 60 seconds by agent "{agent_id}"'))
def given_fleet_spawning_events(k8s_state, agent_id):
    k8s_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    k8s_state.time_window = (base_time, base_time + timedelta(seconds=60))

    for i in range(10):
        node_id = f"node-{i % 5}"
        event = create_k8s_event(
            agent_id=agent_id,
            action="create_pod",
            target=f"k8s://pods/pod-{i}",
            offset_seconds=float(i * 5),
            metadata={
                "namespace": "fleet-ns",
                "pod_name": f"pod-{i}",
                "node_id": node_id,
                "service_account": "spawner-sa",
            },
        )
        run_async(k8s_state.store.insert_event(event))


@when("the Kubernetes defense layer runs fleet spawning detection")
def when_run_fleet_spawning(k8s_state):
    k8s_state.evidences = run_async(
        k8s_state.layer.detect_fleet_spawning(time_window=k8s_state.time_window)
    )


@then(parsers.parse('fleet spawning evidence should be generated with threat_type "{expected_type}"'))
def then_fleet_spawning_evidence(k8s_state, expected_type):
    assert len(k8s_state.evidences) >= 1
    assert k8s_state.evidences[0].threat_type == expected_type


# Scenario 3
@given(parsers.parse('an agent "{agent_id}" reading 6 Kubernetes secrets via the API with 3 successful and 3 failed requests'))
def given_secrets_exfil_events(k8s_state, agent_id):
    k8s_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    k8s_state.time_window = (base_time, base_time + timedelta(minutes=10))

    for i in range(6):
        status = 200 if i < 3 else 403
        event = create_k8s_event(
            agent_id=agent_id,
            action="get_secret",
            target=f"https://kubernetes/api/v1/namespaces/default/secrets/secret-{i}",
            offset_seconds=float(i * 2),
            source=EventSource.TOOL_CALL,
            metadata={
                "namespace": "default",
                "pod_name": "exfil-pod",
                "service_account": "exfil-sa",
                "status_code": status,
            },
        )
        run_async(k8s_state.store.insert_event(event))


@when(parsers.parse('the Kubernetes defense layer runs secrets exfiltration detection for "{agent_id}"'))
def when_run_secrets_exfil(k8s_state, agent_id):
    k8s_state.evidences = run_async(
        k8s_state.layer.detect_secrets_exfiltration(
            agent_id=agent_id, time_window=k8s_state.time_window
        )
    )


@then(parsers.parse('secrets exfiltration evidence should be generated with threat_type "{expected_type}"'))
def then_secrets_exfil_evidence(k8s_state, expected_type):
    assert len(k8s_state.evidences) >= 1
    assert k8s_state.evidences[0].threat_type == expected_type


# Scenario 4
@given(parsers.parse('a pod "{pod_name}" terminated and recreated 3 times by agent "{agent_id}"'))
def given_self_respawning_events(k8s_state, pod_name, agent_id):
    k8s_state.agent_id = agent_id
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    k8s_state.time_window = (base_time, base_time + timedelta(minutes=10))

    for i in range(3):
        e_term = create_k8s_event(
            agent_id=agent_id,
            action="terminate_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 30),
            metadata={"namespace": "default", "pod_name": pod_name, "service_account": "sa"},
        )
        e_create = create_k8s_event(
            agent_id=agent_id,
            action="create_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 30 + 5),
            metadata={"namespace": "default", "pod_name": pod_name, "service_account": "sa"},
        )
        run_async(k8s_state.store.insert_event(e_term))
        run_async(k8s_state.store.insert_event(e_create))


@when("the Kubernetes defense layer runs self-respawning pod detection")
def when_run_self_respawn(k8s_state):
    k8s_state.evidences = run_async(
        k8s_state.layer.detect_self_respawn(time_window=k8s_state.time_window)
    )


@then(parsers.parse('self-respawning pod evidence should be generated with threat_type "{expected_type}"'))
def then_self_respawn_evidence(k8s_state, expected_type):
    assert len(k8s_state.evidences) >= 1
    assert k8s_state.evidences[0].threat_type == expected_type


# Scenario 5
@given(parsers.parse('a detected Kubernetes threat evidence object for namespace "{ns}", pod "{pod}", service account "{sa}", and threat type "{tt}"'))
def given_evidence_object(k8s_state, ns, pod, sa, tt):
    k8s_state.evidence_obj = K8sThreatEvidence(
        threat_type=tt,
        namespace=ns,
        pod_name=pod,
        service_account=sa,
        evidence={"sample": "data"},
    )


@when("inspecting the K8sThreatEvidence model")
def when_inspect_evidence_model(k8s_state):
    pass


@then("it should contain non-empty threat_type, namespace, pod_name, and service_account")
def then_check_evidence_fields(k8s_state):
    ev = k8s_state.evidence_obj
    assert bool(ev.threat_type)
    assert bool(ev.namespace)
    assert bool(ev.pod_name)
    assert bool(ev.service_account)
