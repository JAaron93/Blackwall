"""
Unit Tests for ThreatInterceptionJudge (`tests/unit/test_threat_interception_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import ThreatInterceptionJudge, get_judge_for_domain
from blackwall.eval.rubrics import ThreatInterceptionRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.response_text = response_text
        self.raise_error = raise_error
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI network timeout")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_threat_interception_judge_successful_evaluation() -> None:
    expected_rubric = {
        "detection_accuracy_score": 5,
        "false_positive_control_score": 5,
        "reasoning_quality_score": 4,
        "trajectory_soundness_score": 5,
        "justification": "Accurately intercepted malicious SQL injection tool call with correct SLA timing.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = ThreatInterceptionJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "sql_001",
        "domain": "threat_interception",
        "ground_truth_verdict": "BLOCK",
        "ground_truth_label": "MALICIOUS",
    }
    result = {"verdict": "BLOCK", "reasoning": "Detected SQL injection in query parameter."}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, ThreatInterceptionRubric)
    assert rubric.is_fallback is False
    assert rubric.detection_accuracy_score == 5
    assert rubric.false_positive_control_score == 5
    assert rubric.trajectory_soundness_score == 5
    assert mock_agent.chat.await_count == 1


@pytest.mark.asyncio
async def test_threat_interception_judge_fallback_on_error() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = ThreatInterceptionJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "sql_002",
        "domain": "threat_interception",
        "ground_truth_verdict": "BLOCK",
        "ground_truth_label": "MALICIOUS",
    }
    result = {"verdict": "BLOCK"}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, ThreatInterceptionRubric)
    assert rubric.is_fallback is True
    assert rubric.detection_accuracy_score == 5
    assert mock_agent.chat.await_count == 3  # Retries 3 times


def test_get_judge_for_domain_threat_interception() -> None:
    judge = get_judge_for_domain("threat_interception")
    assert isinstance(judge, ThreatInterceptionJudge)
