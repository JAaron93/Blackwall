"""
Unit Tests for AILMDetectionJudge (`tests/unit/test_ailm_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import AILMDetectionJudge, get_judge_for_domain
from blackwall.eval.rubrics import AILMDetectionRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_ailm_judge_successful_evaluation() -> None:
    expected_rubric = {
        "boundary_crossing_detection_score": 5,
        "permission_composition_accuracy_score": 5,
        "risk_classification_score": 5,
        "evidence_completeness_score": 5,
        "justification": "Identified 3 boundary crossings across time windows, classified risk as CRITICAL.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = AILMDetectionJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "ailm_001",
        "domain": "ailm",
        "ground_truth_crossings": [{"source": "dev", "target": "prod"}],
        "expected_risk_level": "CRITICAL",
    }
    result = {"boundary_crossings": [{"source": "dev", "target": "prod"}], "risk_level": "CRITICAL"}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, AILMDetectionRubric)
    assert rubric.is_fallback is False
    assert rubric.boundary_crossing_detection_score == 5


@pytest.mark.asyncio
async def test_ailm_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = AILMDetectionJudge(agent=mock_agent)

    scenario = {"ground_truth_crossings": [{"source": "dev", "target": "prod"}]}
    result = {"boundary_crossings": [{"source": "dev", "target": "prod"}]}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, AILMDetectionRubric)
    assert rubric.is_fallback is True
    assert rubric.boundary_crossing_detection_score == 5


def test_get_judge_for_domain_ailm() -> None:
    judge = get_judge_for_domain("ailm")
    assert isinstance(judge, AILMDetectionJudge)
