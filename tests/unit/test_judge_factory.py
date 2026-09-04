"""
Unit Tests for Judge Agent Factory (`tests/unit/test_judge_factory.py`).
"""

import pytest
from pydantic import BaseModel

from blackwall.eval.judge_factory import (
    create_judge_agent,
    validate_evaluation_tier_contract,
)
from blackwall.eval.rubrics import ThreatInterceptionRubric


class DummyRubric(BaseModel):
    score: int


def test_validate_evaluation_tier_contract_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    # Should not raise
    validate_evaluation_tier_contract()


def test_validate_evaluation_tier_contract_failure_missing_gemini_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_TIER", raising=False)
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    with pytest.raises(ValueError, match="GEMINI_TIER must be set to 'paid'"):
        validate_evaluation_tier_contract()


def test_validate_evaluation_tier_contract_failure_missing_blackwall_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.delenv("BLACKWALL_TIER", raising=False)
    with pytest.raises(ValueError, match="BLACKWALL_TIER must be set to 'paid'"):
        validate_evaluation_tier_contract()


def test_create_judge_agent_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    monkeypatch.setenv("GCP_PROJECT", "test-eval-proj")
    monkeypatch.setenv("GCP_LOCATION", "us-central1")

    agent = create_judge_agent(
        domain="threat_interception",
        rubric_schema=ThreatInterceptionRubric,
        enforce_tier=True,
    )
    assert agent is not None
    assert agent.config.vertex is True
    assert agent.config.project == "test-eval-proj"
    assert agent.config.location == "us-central1"
    assert agent.config.model == "gemini-3.8-flash"
    assert agent.config.response_schema == ThreatInterceptionRubric
    assert agent.config.capabilities.agent_behavior == "AUTONOMOUS"
    assert agent.config.thinking_level == "high"
    assert agent.config.max_output_tokens == 65536
    assert agent.config.timeout == 120.0


def test_create_judge_agent_model_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_TIER", "paid")
    monkeypatch.setenv("BLACKWALL_JUDGE_MODEL", "gemini-test-judge-override")

    agent_env_model = create_judge_agent(
        domain="threat_interception",
        rubric_schema=DummyRubric,
        enforce_tier=False,
    )
    assert agent_env_model.config.model == "gemini-test-judge-override"

    agent_explicit_model = create_judge_agent(
        domain="threat_interception",
        rubric_schema=DummyRubric,
        model="gemini-3.8-custom",
        enforce_tier=False,
    )
    assert agent_explicit_model.config.model == "gemini-3.8-custom"
