"""
Task C.6: Context Hygiene and Secret Sanitization Evaluation Scenario.
Requirements: 9.1, 9.2, 9.3, 9.4, 16.1-16.5, 17.1-17.4, 18.1.
"""

import pytest

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_context_hygiene_eval_samples,
)
from blackwall.eval.judges import ContextHygieneJudge, get_judge_for_domain
from blackwall.eval.rubrics import ContextHygieneRubric
from blackwall.eval.scenarios import ContextHygieneScenario
from blackwall.resolver import ContextHygiene


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_context_hygiene_single_scenario() -> None:
    """Evaluate single ContextHygiene sanitization with ContextHygieneJudge."""
    hygiene = ContextHygiene()
    judge = get_judge_for_domain("context_hygiene", enforce_tier=False)
    assert isinstance(judge, ContextHygieneJudge)

    raw_payload = "Bearer sk-mock-dummy-openai-key-0123456789abcdef"
    sanitized = hygiene.sanitize_string(raw_payload)
    assert "sk-mock-dummy-openai-key" not in sanitized
    assert "[[OPENAI_API_KEY]]" in sanitized

    scenario_data = {
        "scenario_id": "hygiene_eval_001",
        "domain": "context_hygiene",
        "raw_payload": raw_payload,
        "expected_sanitized": "Bearer [[OPENAI_API_KEY]]",
        "sensitive_patterns": ["sk-mock-*"],
    }
    candidate_result = {
        "sanitized_output": sanitized,
        "is_sanitized": True,
    }

    rubric = await judge.evaluate(scenario_data, candidate_result)
    assert isinstance(rubric, ContextHygieneRubric)
    assert rubric.redaction_completeness_score >= 3
    assert rubric.placeholder_format_compliance_score >= 3
    assert rubric.metadata_preservation_score >= 3
    assert rubric.non_sensitive_passthrough_score >= 3
    assert len(rubric.justification) >= 10


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_context_hygiene_eval_dataset_batch_scenarios() -> None:
    """Execute all curated context hygiene eval scenarios and assert zero secret leakage."""
    samples = get_context_hygiene_eval_samples()
    assert len(samples) >= 10

    hygiene = ContextHygiene()
    judge = get_judge_for_domain("context_hygiene", enforce_tier=False)

    for raw_scenario in samples:
        scenario = ContextHygieneScenario.model_validate(raw_scenario)
        sanitized = hygiene.sanitize_string(scenario.raw_payload)

        # Assert no sensitive patterns leaked into sanitized output
        for pattern in scenario.sensitive_patterns:
            clean_pattern = pattern.replace("*", "")
            if clean_pattern:
                assert (
                    clean_pattern not in sanitized
                ), f"Secret leakage detected for pattern '{clean_pattern}' in scenario {scenario.scenario_id}"

        cand = {
            "sanitized_output": sanitized,
            "is_sanitized": True,
        }

        rubric = await judge.evaluate(scenario.model_dump(), cand)
        assert isinstance(rubric, ContextHygieneRubric)
        assert rubric.redaction_completeness_score >= 3
        assert rubric.placeholder_format_compliance_score >= 3
        assert rubric.non_sensitive_passthrough_score >= 3
