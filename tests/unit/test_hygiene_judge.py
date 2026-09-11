"""
Unit Tests for ContextHygieneJudge (`tests/unit/test_hygiene_judge.py`).
"""

import json
from unittest.mock import AsyncMock

import pytest

from blackwall.eval.judges import ContextHygieneJudge, get_judge_for_domain
from blackwall.eval.rubrics import ContextHygieneRubric


class MockAgent:
    def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
        self.chat = AsyncMock()
        if raise_error:
            self.chat.side_effect = RuntimeError("Vertex AI unavailable")
        else:
            self.chat.return_value = response_text or ""


@pytest.mark.asyncio
async def test_hygiene_judge_successful_evaluation() -> None:
    expected_rubric = {
        "redaction_completeness_score": 5,
        "placeholder_format_compliance_score": 5,
        "metadata_preservation_score": 5,
        "non_sensitive_passthrough_score": 5,
        "justification": "All credentials redacted to [[VARIABLE_NAME]] format while preserving payload structure.",
        "is_fallback": False,
    }
    mock_agent = MockAgent(response_text=json.dumps(expected_rubric))
    judge = ContextHygieneJudge(agent=mock_agent)

    scenario = {
        "scenario_id": "hygiene_001",
        "domain": "context_hygiene",
        "expected_sanitized": "Bearer [[AUTH_TOKEN]]",
    }
    result = {"sanitized_output": "Bearer [[AUTH_TOKEN]]"}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, ContextHygieneRubric)
    assert rubric.is_fallback is False
    assert rubric.redaction_completeness_score == 5


@pytest.mark.asyncio
async def test_hygiene_judge_fallback() -> None:
    mock_agent = MockAgent(raise_error=True)
    judge = ContextHygieneJudge(agent=mock_agent)

    scenario = {}
    result = {"sanitized_output": "Clean payload with [[KEY]]."}

    rubric = await judge.evaluate(scenario, result)

    assert isinstance(rubric, ContextHygieneRubric)
    assert rubric.is_fallback is True
    assert rubric.redaction_completeness_score == 5


def test_get_judge_for_domain_hygiene() -> None:
    judge = get_judge_for_domain("context_hygiene")
    assert isinstance(judge, ContextHygieneJudge)
