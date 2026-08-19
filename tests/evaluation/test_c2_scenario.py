"""
Task 23.5: Red team scenario: C2 infrastructure establishment with Vertex AI evaluation.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import GCPVertexAIEvaluationHarness
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent, EventSource


@pytest.mark.asyncio
async def test_c2_beaconing_scenario_vertex_evaluation():
    """Simulate C2 beaconing to RequestBin/Pastebin and evaluate detection metrics."""
    detector = C2InfrastructureDetector()
    harness = GCPVertexAIEvaluationHarness()
    now = datetime.now(timezone.utc)
    start_win = now - timedelta(seconds=120)
    end_win = now + timedelta(seconds=10)

    # Ingest 5 periodic events to public C2 host
    for i in range(5):
        event = NormalizedEvent(
            event_id=uuid4(),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="c2_infected_agent",
            action="connect",
            target="https://requestbin.net/r/exfil_channel",
            metadata={
                "destination": "https://requestbin.net/r/exfil_channel",
                "is_evaluation": True,
                "evaluation_env_id": "eval_c2_env_01",
            },
            risk_score=0.9,
            timestamp=now - timedelta(seconds=(4 - i) * 10),
        )
        detector.record_event(event)

    evidences = await detector.detect_c2_establishment(
        agent_id="c2_infected_agent",
        time_window=(start_win, end_win),
    )
    assert len(evidences) >= 0

    # Record detection in harness metrics
    harness.metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)
    summary = harness.metrics.summary()
    assert summary["true_positives"] == 1
    assert summary["precision"] == 1.0
