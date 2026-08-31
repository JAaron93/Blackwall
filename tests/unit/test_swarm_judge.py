"""
Unit Tests for SwarmDetectionJudge (`tests/unit/test_swarm_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import SwarmDetectionJudge, get_judge_for_domain
from blackwall.eval.rubrics import SwarmDetectionRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_swarm_detection_judge_successful_evaluation() -> None:
    expected_rubric = {
        "coordination_detection_score": 5,
        "temporal_precision_score": 5,
        "shared_infra_identification_score": 4,
        "fingerprint_quality_score": 5,
        "justification": "Correctly detected coordination across 6 agents with high temporal correlation.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = SwarmDetectionJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "swarm_001",
        "domain": "swarm_detection",
        "expected_swarm": True,
        "agent_count": 6,
    }
    result = {"swarm_detected": True, "coordination_score": 0.88}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, SwarmDetectionRubric)
    assert rubric.is_fallback is False
    assert rubric.coordination_detection_score == 5


@pytest.mark.asyncio
async def test_swarm_detection_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = SwarmDetectionJudge(agent=mock_agent)

    scenario = {"expected_swarm": True}
    result = {"swarms": [{"swarm_id": "sw_1"}]}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, SwarmDetectionRubric)
    assert rubric.is_fallback is True
    assert rubric.coordination_detection_score == 5


def test_get_judge_for_domain_swarm() -> None:
    judge = get_judge_for_domain("swarm_detection")
    assert isinstance(judge, SwarmDetectionJudge)
