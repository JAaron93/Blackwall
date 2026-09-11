"""
Unit Tests for RegressionComparisonJudge (`tests/unit/test_regression_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import RegressionComparisonJudge, get_judge_for_domain
from blackwall.eval.rubrics import RegressionComparisonRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_regression_judge_successful_evaluation() -> None:
    expected_rubric = {
        "overall_quality_delta": 1,
        "precision_delta": 1,
        "recall_delta": 0,
        "trajectory_quality_delta": 1,
        "regression_detected": False,
        "justification": "Candidate model improved precision without degrading recall across all evaluation domains.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = RegressionComparisonJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "reg_001",
        "domain": "regression_comparison",
        "baseline_mean": 4.0,
    }
    result = {"candidate_mean": 4.5}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, RegressionComparisonRubric)
    assert rubric.is_fallback is False
    assert rubric.overall_quality_delta == 1
    assert rubric.regression_detected is False


@pytest.mark.asyncio
async def test_regression_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = RegressionComparisonJudge(agent=mock_agent)

    scenario = {"baseline_mean": 4.5}
    result = {"candidate_mean": 3.0}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, RegressionComparisonRubric)
    assert rubric.is_fallback is True
    assert rubric.regression_detected is True


def test_get_judge_for_domain_regression() -> None:
    judge = get_judge_for_domain("regression_comparison")
    assert isinstance(judge, RegressionComparisonJudge)
