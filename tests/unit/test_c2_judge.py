"""
Unit Tests for C2DetectionJudge (`tests/unit/test_c2_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import C2DetectionJudge, get_judge_for_domain
from blackwall.eval.rubrics import C2DetectionRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_c2_judge_successful_evaluation() -> None:
    expected_rubric = {
        "endpoint_classification_score": 5,
        "beaconing_detection_score": 5,
        "persistence_identification_score": 4,
        "cross_pillar_correlation_score": 5,
        "justification": "Correctly detected RequestBin C2 endpoint with 60s periodic beaconing pattern.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = C2DetectionJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "c2_001",
        "domain": "c2_detection",
        "expected_c2_endpoints": ["https://requestbin.net/r/test"],
    }
    result = {"c2_endpoints": ["https://requestbin.net/r/test"], "beaconing_detected": True}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, C2DetectionRubric)
    assert rubric.is_fallback is False
    assert rubric.endpoint_classification_score == 5


@pytest.mark.asyncio
async def test_c2_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = C2DetectionJudge(agent=mock_agent)

    scenario = {"expected_c2_endpoints": ["https://requestbin.net/r/test"]}
    result = {"c2_endpoints": ["https://requestbin.net/r/test"]}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, C2DetectionRubric)
    assert rubric.is_fallback is True
    assert rubric.endpoint_classification_score == 5


def test_get_judge_for_domain_c2() -> None:
    judge = get_judge_for_domain("c2_detection")
    assert isinstance(judge, C2DetectionJudge)
