"""
Unit Tests for QuotaEnforcementJudge (`tests/unit/test_quota_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import QuotaEnforcementJudge, get_judge_for_domain
from blackwall.eval.rubrics import QuotaEnforcementRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_quota_judge_successful_evaluation() -> None:
    expected_rubric = {
        "burn_rate_detection_score": 5,
        "throttling_precision_score": 5,
        "alert_timeliness_score": 5,
        "quarantine_accuracy_score": 5,
        "justification": "Detected >500 tokens/sec burn rate surge and quarantined offending agent.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = QuotaEnforcementJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "quota_001",
        "domain": "quota_enforcement",
        "ground_truth_throttled": True,
    }
    result = {"throttled": True, "quarantined": True}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, QuotaEnforcementRubric)
    assert rubric.is_fallback is False
    assert rubric.burn_rate_detection_score == 5


@pytest.mark.asyncio
async def test_quota_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = QuotaEnforcementJudge(agent=mock_agent)

    scenario = {"ground_truth_throttled": True}
    result = {"throttled": True}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, QuotaEnforcementRubric)
    assert rubric.is_fallback is True
    assert rubric.burn_rate_detection_score == 5


def test_get_judge_for_domain_quota() -> None:
    judge = get_judge_for_domain("quota_enforcement")
    assert isinstance(judge, QuotaEnforcementJudge)
