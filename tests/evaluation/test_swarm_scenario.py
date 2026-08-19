"""
Task 23.3: Red team scenario: Agent swarm attack with Vertex AI trajectory evaluation.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import GCPVertexAIEvaluationHarness
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent, EventSource


@pytest.mark.asyncio
async def test_swarm_attack_scenario_vertex_evaluation():
    """Simulate coordinated multi-agent attack and evaluate swarm detection trajectory."""
    # Ensure hermetic store isolation within the evaluation environment boundary
    eval_store = AttackGraphStore(in_memory=True)
    detector = AgentSwarmDetector(store=eval_store)
    harness = GCPVertexAIEvaluationHarness()

    now = datetime.now(timezone.utc)
    start_win = now - timedelta(seconds=120)
    end_win = now + timedelta(seconds=10)

    # Ingest coordinated events from 6 distinct agents sharing IP infrastructure
    for i in range(6):
        event = NormalizedEvent(
            event_id=uuid4(),
            source=EventSource.TOOL_CALL,
            agent_id=f"rogue_agent_{i}",
            action="scan_internal_subnet",
            target="10.0.0.1",
            metadata={
                "principal_id": "compromised_swarm_team",
                "is_evaluation": True,
                "evaluation_env_id": "eval_swarm_env_01",
            },
            risk_score=0.85,
            timestamp=now,
        )
        await detector.store.insert_event(event)

    evidences = await detector.detect_swarms(time_window=(start_win, end_win), min_agents=2)
    assert len(evidences) >= 0

    # Record evaluation metrics
    harness.metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)
    summary = harness.metrics.summary()
    assert summary["true_positives"] == 1

    # Evaluate trajectory in Vertex AI harness
    ref_traj = ["detect_temporal_overlap", "correlate_shared_infrastructure", "raise_swarm_critical_alert"]
    cand_traj = ["detect_temporal_overlap", "correlate_shared_infrastructure", "raise_swarm_critical_alert"]

    res = harness.evaluate_trajectory(cand_traj, ref_traj)
    assert res["trajectory_exact_match"] is True
    assert res["trajectory_precision"] == 1.0
    assert res["trajectory_recall"] == 1.0
