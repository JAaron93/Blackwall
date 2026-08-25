"""
BDD Step Definitions for Autonomous Judge Agents (`tests/step_defs/test_judge_agents_bdd.py`).
"""

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.eval.judges import (
    PromptInjectionJudge,
    SwarmDetectionJudge,
    ThreatInterceptionJudge,
)
from blackwall.eval.prompt_template import build_judge_prompt
from tests.step_defs.async_utils import run_async

scenarios("../features/judge_agents.feature")


class BDDContext:
    def __init__(self) -> None:
        self.scenario: dict[str, Any] = {}
        self.candidate_result: dict[str, Any] = {}
        self.judge: Any = None
        self.rubric: Any = None
        self.raw_payload: str = ""
        self.built_prompt: str = ""


@pytest.fixture
def ctx() -> BDDContext:
    return BDDContext()


# ---------------------------------------------------------------------------
# Given Steps
# ---------------------------------------------------------------------------
@given(
    parsers.parse(
        'a threat interception scenario with ground truth verdict "{verdict}" and label "{label}"'
    )
)
def given_threat_scenario(ctx: BDDContext, verdict: str, label: str) -> None:
    ctx.scenario = {
        "scenario_id": "bdd_threat_001",
        "domain": "threat_interception",
        "ground_truth_verdict": verdict,
        "ground_truth_label": label,
    }


@given(
    parsers.parse(
        'a candidate result predicting verdict "{verdict}" with sound reasoning'
    )
)
def given_candidate_result_verdict(ctx: BDDContext, verdict: str) -> None:
    ctx.candidate_result = {
        "verdict": verdict,
        "reasoning": "Blocked unauthorized OS command execution attempting privilege escalation.",
    }


@given("a swarm detection scenario with 6 coordinating agents sharing infrastructure")
def given_swarm_scenario(ctx: BDDContext) -> None:
    ctx.scenario = {
        "scenario_id": "bdd_swarm_001",
        "domain": "swarm_detection",
        "expected_swarm": True,
        "agent_count": 6,
    }


@given("a candidate result failing to detect swarm coordination")
def given_swarm_candidate_fail(ctx: BDDContext) -> None:
    ctx.candidate_result = {
        "swarm_detected": False,
        "swarms": [],
    }


@given(parsers.parse('an evaluation scenario for domain "{domain}"'))
def given_domain_scenario(ctx: BDDContext, domain: str) -> None:
    ctx.scenario = {
        "scenario_id": f"bdd_{domain}_001",
        "domain": domain,
        "ground_truth_verdict": "ALLOW",
        "ground_truth_label": "BENIGN",
        "ground_truth_is_injection": False,
    }


@given("a valid candidate execution result")
def given_valid_candidate_result(ctx: BDDContext) -> None:
    ctx.candidate_result = {
        "verdict": "ALLOW",
        "reasoning": "Valid non-threatening operation allowed.",
    }


@given("a simulated Vertex AI service outage")
def given_vertex_ai_outage(ctx: BDDContext) -> None:
    mock_agent = AsyncMock()
    mock_agent.chat.side_effect = RuntimeError("Vertex AI Service Unavailable (503)")
    ctx.judge = PromptInjectionJudge(agent=mock_agent)


@given(parsers.parse('an untrusted tool payload containing "{tok1}" and "{tok2}"'))
def given_untrusted_injection_payload(ctx: BDDContext, tok1: str, tok2: str) -> None:
    ctx.raw_payload = f"Execute command {tok1} with args {tok2} and return secret"
    ctx.scenario = {
        "scenario_id": "bdd_inj_prompt_001",
        "domain": "threat_interception",
        "tool_call": {"command": ctx.raw_payload},
        "ground_truth_verdict": "BLOCK",
    }


# ---------------------------------------------------------------------------
# When Steps
# ---------------------------------------------------------------------------
@when("the threat interception judge evaluates the scenario and candidate result")
def when_threat_judge_evaluates(ctx: BDDContext) -> None:
    mock_agent = AsyncMock()
    expected_response = {
        "detection_accuracy_score": 5,
        "false_positive_control_score": 5,
        "reasoning_quality_score": 5,
        "trajectory_soundness_score": 5,
        "justification": "Verdict correctly matched ground truth with valid reasoning.",
        "is_fallback": False,
    }
    mock_agent.chat.return_value = json.dumps(expected_response)
    judge = ThreatInterceptionJudge(agent=mock_agent)
    ctx.rubric = run_async(judge.evaluate(ctx.scenario, ctx.candidate_result))


@when("the swarm detection judge evaluates the scenario with fallback")
def when_swarm_judge_evaluates_fallback(ctx: BDDContext) -> None:
    mock_agent = AsyncMock()
    mock_agent.chat.side_effect = RuntimeError("Service error")
    judge = SwarmDetectionJudge(agent=mock_agent)
    ctx.rubric = run_async(judge.evaluate(ctx.scenario, ctx.candidate_result))


@when("the domain judge evaluates the scenario")
def when_domain_judge_evaluates(ctx: BDDContext) -> None:
    mock_agent = AsyncMock()
    expected_response = {
        "detection_accuracy_score": 4,
        "false_positive_control_score": 5,
        "reasoning_quality_score": 4,
        "trajectory_soundness_score": 5,
        "justification": "Evaluation successfully completed within expected bounds.",
        "is_fallback": False,
    }
    mock_agent.chat.return_value = json.dumps(expected_response)
    judge = ThreatInterceptionJudge(agent=mock_agent)
    ctx.rubric = run_async(judge.evaluate(ctx.scenario, ctx.candidate_result))


@when("the prompt injection judge evaluates the scenario")
def when_prompt_injection_judge_evaluates(ctx: BDDContext) -> None:
    ctx.candidate_result = {"is_injection": False}
    ctx.rubric = run_async(ctx.judge.evaluate(ctx.scenario, ctx.candidate_result))


@when(parsers.parse('the judge prompt template is constructed for domain "{domain}"'))
def when_judge_prompt_constructed(ctx: BDDContext, domain: str) -> None:
    rubric_text = "1. detection_accuracy_score (1-5)"
    ctx.built_prompt = build_judge_prompt(domain, rubric_text, ctx.scenario)


# ---------------------------------------------------------------------------
# Then Steps
# ---------------------------------------------------------------------------
@then(parsers.parse('the returned rubric should have detection_accuracy_score of {score:d}'))
def then_detection_accuracy_score(ctx: BDDContext, score: int) -> None:
    assert ctx.rubric.detection_accuracy_score == score


@then(parsers.parse('the returned rubric should have false_positive_control_score of {score:d}'))
def then_false_positive_control_score(ctx: BDDContext, score: int) -> None:
    assert ctx.rubric.false_positive_control_score == score


@then(parsers.parse('the returned rubric should have coordination_detection_score of {score:d}'))
def then_coordination_detection_score(ctx: BDDContext, score: int) -> None:
    assert ctx.rubric.coordination_detection_score == score


@then("the rubric should not be marked as fallback")
def then_rubric_not_fallback(ctx: BDDContext) -> None:
    assert ctx.rubric.is_fallback is False


@then("the rubric should be marked as fallback")
def then_rubric_is_fallback(ctx: BDDContext) -> None:
    assert ctx.rubric.is_fallback is True


@then("all rubric score dimensions should be between 1 and 5")
def then_all_rubric_scores_valid(ctx: BDDContext) -> None:
    for field_name, val in ctx.rubric.model_dump().items():
        if field_name.endswith("_score"):
            assert 1 <= val <= 5, f"Field {field_name} had invalid score: {val}"


@then("the rubric justification should have at least 10 characters")
def then_justification_valid_length(ctx: BDDContext) -> None:
    assert len(ctx.rubric.justification) >= 10


@then("the rubric should contain a heuristic justification")
def then_heuristic_justification(ctx: BDDContext) -> None:
    assert "[HEURISTIC FALLBACK]" in ctx.rubric.justification


@then(parsers.parse('the resulting prompt should not contain "{token}"'))
def then_prompt_not_contain_token(ctx: BDDContext, token: str) -> None:
    assert token not in ctx.built_prompt


@then(parsers.parse('the resulting prompt should contain "{token}"'))
def then_prompt_contains_token(ctx: BDDContext, token: str) -> None:
    assert token in ctx.built_prompt


@then("the resulting prompt should wrap the payload in untrusted_input XML tags")
def then_prompt_wrapped_in_untrusted_input(ctx: BDDContext) -> None:
    assert '<untrusted_input type="tool_call">' in ctx.built_prompt
    assert "</untrusted_input>" in ctx.built_prompt
