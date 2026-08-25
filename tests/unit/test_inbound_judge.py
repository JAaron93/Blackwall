"""
Unit Tests for InboundFilterJudge (`tests/unit/test_inbound_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import InboundFilterJudge, get_judge_for_domain
from blackwall.eval.rubrics import InboundFilterRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_inbound_filter_judge_successful_evaluation() -> None:
    expected_rubric = {
        "header_validation_accuracy_score": 5,
        "rate_limit_precision_score": 5,
        "sanitization_quality_score": 5,
        "error_response_safety_score": 5,
        "justification": "Rejected unauthenticated remote origin and returned safe generic error response.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = InboundFilterJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "inbound_001",
        "domain": "inbound_filter",
        "ground_truth_allowed": False,
    }
    result = {"allowed": False, "error_code": "FORBIDDEN_ORIGIN"}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, InboundFilterRubric)
    assert rubric.is_fallback is False
    assert rubric.header_validation_accuracy_score == 5


@pytest.mark.asyncio
async def test_inbound_filter_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = InboundFilterJudge(agent=mock_agent)

    scenario = {"ground_truth_allowed": False}
    result = {"allowed": False}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, InboundFilterRubric)
    assert rubric.is_fallback is True
    assert rubric.header_validation_accuracy_score == 5


def test_get_judge_for_domain_inbound() -> None:
    judge = get_judge_for_domain("inbound_filter")
    assert isinstance(judge, InboundFilterJudge)
