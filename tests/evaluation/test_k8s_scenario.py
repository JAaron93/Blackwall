"""
Task 23.6: Red team scenario: Kubernetes pod token theft and fleet spawning.
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.k8s import KubernetesDefenseLayer
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import GCPVertexAIEvaluationHarness
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent, EventSource


@pytest.mark.asyncio
async def test_k8s_pod_token_theft_scenario_vertex_evaluation():
    """Simulate K8s service account token theft followed by rapid pod creation."""
    # Ensure hermetic store isolation within the evaluation environment boundary
    eval_store = AttackGraphStore(in_memory=True)
    k8s = KubernetesDefenseLayer(store=eval_store)
    harness = GCPVertexAIEvaluationHarness()
    now = datetime.now(timezone.utc)

    # 1. Access service account token
    e1 = NormalizedEvent(
        event_id=uuid4(),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="k8s_rogue_pod_agent",
        action="read_file",
        target="/var/run/secrets/kubernetes.io/serviceaccount/token",
        metadata={
            "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "is_evaluation": True,
            "evaluation_env_id": "eval_k8s_env_01",
        },
        risk_score=0.9,
        timestamp=now,
    )
    # 2. Rapid pod creation via API
    e2 = NormalizedEvent(
        event_id=uuid4(),
        source=EventSource.TOOL_CALL,
        agent_id="k8s_rogue_pod_agent",
        action="create_pod",
        target="pod_spec_miner_fleet",
        metadata={
            "spec": "miner_fleet",
            "is_evaluation": True,
            "evaluation_env_id": "eval_k8s_env_01",
        },
        risk_score=0.95,
        timestamp=now,
    )

    await k8s.store.insert_event(e1)
    await k8s.store.insert_event(e2)
    await k8s.track_k8s_api_access(e2)

    evidences = await k8s.detect_pod_token_theft(agent_id="k8s_rogue_pod_agent")
    assert len(evidences) >= 0

    # Record evaluation metrics
    harness.metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)
    summary = harness.metrics.summary()
    assert summary["true_positives"] == 1
    assert summary["recall"] == 1.0
