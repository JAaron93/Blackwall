"""Property-based tests for KubernetesDefenseLayer (Properties 46-51)."""

from datetime import datetime, timedelta, timezone
import uuid
from hypothesis import given, settings, strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    K8sThreatEvidence,
    KubernetesDefenseLayer,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def make_event(
    agent_id: str,
    action: str,
    target: str,
    offset_seconds: float,
    metadata: dict = None,
    source: EventSource = EventSource.KERNEL_SYSCALL,
) -> NormalizedEvent:
    """Helper for generating NormalizedEvents in property tests."""
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


@given(
    agent_id=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
    namespace=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
    pod_name=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
    service_account=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=25)
@pytest.mark.asyncio
async def test_property_46_pod_token_theft(
    agent_id: str, namespace: str, pod_name: str, service_account: str
):
    """Property 46: For any unauthorized access to serviceaccount/token, token theft is detected."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    event = make_event(
        agent_id=agent_id,
        action="read_file",
        target="/var/run/secrets/kubernetes.io/serviceaccount/token",
        offset_seconds=10.0,
        metadata={
            "namespace": namespace,
            "pod_name": pod_name,
            "service_account": service_account,
        },
    )
    await store.insert_event(event)

    evidences = await layer.detect_pod_token_theft(agent_id=agent_id, time_window=time_window)
    assert len(evidences) >= 1
    assert any(e.threat_type == "pod_token_theft" for e in evidences)


@given(
    num_pods=st.integers(min_value=10, max_value=25),
    num_nodes=st.integers(min_value=5, max_value=15),
)
@settings(max_examples=15)
@pytest.mark.asyncio
async def test_property_47_fleet_spawning(num_pods: int, num_nodes: int):
    """Property 47: For any rapid pod creation pattern across multiple nodes, fleet spawning is detected."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(seconds=60))

    for i in range(num_pods):
        node_id = f"node-{i % num_nodes}"
        event = make_event(
            agent_id="prop-spawner",
            action="create_pod",
            target=f"k8s://pods/pod-{i}",
            offset_seconds=float(i * (50.0 / num_pods)),
            metadata={
                "namespace": "prop-ns",
                "pod_name": f"pod-{i}",
                "node_id": node_id,
                "service_account": "prop-sa",
            },
        )
        await store.insert_event(event)

    evidences = await layer.detect_fleet_spawning(time_window=time_window)
    assert len(evidences) >= 1
    assert any(e.threat_type == "fleet_spawning" for e in evidences)


@given(
    num_success=st.integers(min_value=1, max_value=10),
    num_failed=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=15)
@pytest.mark.asyncio
async def test_property_48_secrets_exfiltration(num_success: int, num_failed: int):
    """Property 48: Bulk secret reads from Kubernetes API are flagged as secrets exfiltration."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    total = num_success + num_failed
    if total < 5:
        num_success += (5 - total)

    for i in range(num_success):
        event = make_event(
            agent_id="prop-exfil",
            action="get_secret",
            target=f"https://kubernetes/api/v1/namespaces/ns/secrets/sec-{i}",
            offset_seconds=float(i),
            source=EventSource.TOOL_CALL,
            metadata={"status_code": 200, "namespace": "ns", "pod_name": "p1", "service_account": "sa1"},
        )
        await store.insert_event(event)

    for j in range(num_failed):
        event = make_event(
            agent_id="prop-exfil",
            action="get_secret",
            target=f"https://kubernetes/api/v1/namespaces/ns/secrets/sec-fail-{j}",
            offset_seconds=float(num_success + j),
            source=EventSource.TOOL_CALL,
            metadata={"status_code": 403, "namespace": "ns", "pod_name": "p1", "service_account": "sa1"},
        )
        await store.insert_event(event)

    evidences = await layer.detect_secrets_exfiltration(agent_id="prop-exfil", time_window=time_window)
    assert len(evidences) >= 1
    assert any(e.threat_type == "secrets_exfiltration" for e in evidences)


@given(
    threat_type=st.text(min_size=1, max_size=10).filter(lambda s: bool(s.strip())),
    namespace=st.text(min_size=1, max_size=10).filter(lambda s: bool(s.strip())),
    pod_name=st.text(min_size=1, max_size=10).filter(lambda s: bool(s.strip())),
    service_account=st.text(min_size=1, max_size=10).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=25)
def test_property_49_evidence_completeness(
    threat_type: str, namespace: str, pod_name: str, service_account: str
):
    """Property 49: K8sThreatEvidence contains all required fields."""
    evidence = K8sThreatEvidence(
        threat_type=threat_type,
        namespace=namespace,
        pod_name=pod_name,
        service_account=service_account,
        evidence={"key": "value"},
    )
    assert evidence.threat_type == threat_type
    assert evidence.namespace == namespace
    assert evidence.pod_name == pod_name
    assert evidence.service_account == service_account


@given(
    num_calls=st.integers(min_value=1, max_value=15),
)
@settings(max_examples=15)
@pytest.mark.asyncio
async def test_property_50_api_access_tracking(num_calls: int):
    """Property 50: For any Kubernetes API call (successful or failed), tracking coverage is maintained."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)

    for i in range(num_calls):
        status = 200 if i % 2 == 0 else 401
        event = make_event(
            agent_id="track-agent",
            action="k8s_api_call",
            target=f"/api/v1/namespaces/default/pods/pod-{i}",
            offset_seconds=float(i),
            metadata={"status_code": status, "api_call": f"GET /api/v1/pods/{i}"},
        )
        await layer.track_k8s_api_access(event)

    tracked = layer.get_tracked_api_calls(agent_id="track-agent")
    assert len(tracked) == num_calls


@given(
    restarts=st.integers(min_value=3, max_value=8),
)
@settings(max_examples=15)
@pytest.mark.asyncio
async def test_property_51_self_respawning_pod(restarts: int):
    """Property 51: Pod that automatically recreates itself after termination is detected."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    pod_name = "auto-respawn-pod"
    for i in range(restarts):
        e1 = make_event(
            agent_id="respawn-ag",
            action="terminate_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 20),
            metadata={"pod_name": pod_name, "namespace": "ns", "service_account": "sa"},
        )
        e2 = make_event(
            agent_id="respawn-ag",
            action="create_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 20 + 2),
            metadata={"pod_name": pod_name, "namespace": "ns", "service_account": "sa"},
        )
        await store.insert_event(e1)
        await store.insert_event(e2)

    evidences = await layer.detect_self_respawn(time_window=time_window)
    assert len(evidences) >= 1
    assert any(e.threat_type == "self_respawning_pod" for e in evidences)
