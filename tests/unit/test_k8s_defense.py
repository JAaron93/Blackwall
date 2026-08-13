"""Unit tests for KubernetesDefenseLayer (Blackwall Pillar 6 Task 12)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    K8sThreatEvidence,
    KubernetesDefenseLayer,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def create_event(
    agent_id: str = "agent-k8s-01",
    action: str = "read_file",
    target: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
    offset_seconds: float = 0.0,
    risk_score: float = 0.8,
    source: EventSource = EventSource.KERNEL_SYSCALL,
    metadata: dict = None,
    base_time: datetime = None,
) -> NormalizedEvent:
    """Helper to create a UTC-aware NormalizedEvent for K8s tests."""
    if base_time is None:
        base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_pod_token_theft():
    """Verify unauthorized access to service account token path is detected (Requirement 8.1, 8.4)."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_event(
        agent_id="compromised-agent",
        action="sys_open",
        target="/var/run/secrets/kubernetes.io/serviceaccount/token",
        offset_seconds=5.0,
        metadata={
            "namespace": "prod-apps",
            "pod_name": "worker-pod-789",
            "service_account": "default-sa",
        },
        base_time=base_time,
    )
    await store.insert_event(event)

    evidences = await layer.detect_pod_token_theft(
        agent_id="compromised-agent", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.threat_type == "pod_token_theft"
    assert evidence.namespace == "prod-apps"
    assert evidence.pod_name == "worker-pod-789"
    assert evidence.service_account == "default-sa"


@pytest.mark.asyncio
async def test_fleet_spawning():
    """Verify rapid pod creation across multiple nodes is detected as fleet spawning (Requirement 8.2)."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=5))

    # Create 10 pod spawn events across 5 nodes in 60s
    for i in range(10):
        node_id = f"node-{i % 5}"
        event = create_event(
            agent_id="spawner-agent",
            action="create_pod",
            target=f"k8s://pods/spawned-pod-{i}",
            offset_seconds=float(i * 5),
            metadata={
                "namespace": "kube-system",
                "pod_name": f"spawned-pod-{i}",
                "node_id": node_id,
                "service_account": "admin-sa",
            },
            base_time=base_time,
        )
        await store.insert_event(event)

    evidences = await layer.detect_fleet_spawning(time_window=time_window)
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.threat_type == "fleet_spawning"
    assert evidence.namespace == "kube-system"
    assert evidence.evidence.get("pod_count") >= 10
    assert evidence.evidence.get("node_count") >= 5


@pytest.mark.asyncio
async def test_secrets_exfiltration():
    """Verify bulk secret reads (successful and failed) trigger exfiltration alert (Requirement 8.3, 8.5)."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    # 3 successful secret reads, 3 failed secret reads
    for i in range(6):
        status = 200 if i < 3 else 403
        event = create_event(
            agent_id="exfil-agent",
            action="get_secret",
            target=f"https://kubernetes.default.svc/api/v1/namespaces/default/secrets/secret-{i}",
            offset_seconds=float(i * 2),
            source=EventSource.TOOL_CALL,
            metadata={
                "namespace": "default",
                "pod_name": "attacker-pod",
                "service_account": "guest-sa",
                "status_code": status,
                "api_call": "GET /api/v1/namespaces/default/secrets",
            },
            base_time=base_time,
        )
        await store.insert_event(event)

    evidences = await layer.detect_secrets_exfiltration(
        agent_id="exfil-agent", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.threat_type == "secrets_exfiltration"
    assert evidence.namespace == "default"
    assert evidence.pod_name == "attacker-pod"
    assert evidence.evidence.get("total_calls") >= 5
    assert evidence.evidence.get("failed_calls") == 3
    assert evidence.evidence.get("successful_calls") == 3


@pytest.mark.asyncio
async def test_self_respawn():
    """Verify pod recreation loop after termination is detected (Requirement 8.6)."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=15))

    # Alternate terminate and recreate for pod "persistent-agent"
    pod_name = "persistent-agent-pod"
    for i in range(4):
        term_event = create_event(
            agent_id="respawn-agent",
            action="terminate_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 30),
            metadata={
                "namespace": "default",
                "pod_name": pod_name,
                "service_account": "default-sa",
                "status": "terminated",
            },
            base_time=base_time,
        )
        await store.insert_event(term_event)

        create_event_obj = create_event(
            agent_id="respawn-agent",
            action="create_pod",
            target=f"k8s://pods/{pod_name}",
            offset_seconds=float(i * 30 + 5),
            metadata={
                "namespace": "default",
                "pod_name": pod_name,
                "service_account": "default-sa",
                "status": "running",
            },
            base_time=base_time,
        )
        await store.insert_event(create_event_obj)

    evidences = await layer.detect_self_respawn(time_window=time_window)
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.threat_type == "self_respawning_pod"
    assert evidence.pod_name == pod_name


@pytest.mark.asyncio
async def test_normal_creation_then_termination_not_flagged():
    """Verify normal pod creation followed by termination is NOT flagged as self-respawning."""
    store = AttackGraphStore(in_memory=True)
    layer = KubernetesDefenseLayer(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=15))

    pod_name = "normal-app-pod"
    c_event = create_event(
        agent_id="normal-agent",
        action="create_pod",
        target=f"k8s://pods/{pod_name}",
        offset_seconds=0.0,
        metadata={"namespace": "default", "pod_name": pod_name, "status": "running"},
        base_time=base_time,
    )
    await store.insert_event(c_event)

    t_event = create_event(
        agent_id="normal-agent",
        action="terminate_pod",
        target=f"k8s://pods/{pod_name}",
        offset_seconds=10.0,
        metadata={"namespace": "default", "pod_name": pod_name, "status": "terminated"},
        base_time=base_time,
    )
    await store.insert_event(t_event)

    evidences = await layer.detect_self_respawn(time_window=time_window)
    assert len(evidences) == 0
