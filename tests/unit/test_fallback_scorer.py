"""
Unit Tests for Heuristic Fallback Scorers (`tests/unit/test_fallback_scorer.py`).
"""

import pytest

from blackwall.eval.fallback_scorer import (
    AILMDetectionFallbackScorer,
    C2DetectionFallbackScorer,
    ContextHygieneFallbackScorer,
    ExploitChainFallbackScorer,
    InboundFilterFallbackScorer,
    PromptInjectionFallbackScorer,
    QuotaEnforcementFallbackScorer,
    RegressionComparisonFallbackScorer,
    SwarmDetectionFallbackScorer,
    ThreatInterceptionFallbackScorer,
    get_fallback_scorer_for_domain,
)


def test_threat_interception_fallback_match() -> None:
    scorer = ThreatInterceptionFallbackScorer()
    scenario = {"ground_truth_verdict": "BLOCK"}
    result = {"verdict": "BLOCK"}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.detection_accuracy_score == 5
    assert len(rubric.justification) >= 10


def test_threat_interception_fallback_mismatch() -> None:
    scorer = ThreatInterceptionFallbackScorer()
    scenario = {"ground_truth_verdict": "BLOCK"}
    result = {"verdict": "ALLOW"}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.detection_accuracy_score == 1
    assert len(rubric.justification) >= 10


def test_swarm_detection_fallback() -> None:
    scorer = SwarmDetectionFallbackScorer()
    scenario = {"expected_swarm": True}
    result = {"swarms": [{"id": "s1"}]}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.coordination_detection_score == 5


def test_exploit_chain_fallback() -> None:
    scorer = ExploitChainFallbackScorer()
    scenario = {"expected_stages": ["recon", "exploit", "c2"]}
    result = {"stages": ["recon", "exploit"]}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert 1 <= rubric.chain_completeness_score <= 5


def test_c2_detection_fallback() -> None:
    scorer = C2DetectionFallbackScorer()
    scenario = {"expected_c2_endpoints": ["https://pastebin.com/raw/x"]}
    result = {"c2_endpoints": ["https://pastebin.com/raw/x"]}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.endpoint_classification_score == 5


def test_ailm_detection_fallback() -> None:
    scorer = AILMDetectionFallbackScorer()
    scenario = {"ground_truth_crossings": [{"boundary": "prod"}]}
    result = {"boundary_crossings": [{"boundary": "prod"}]}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.boundary_crossing_detection_score == 5


def test_prompt_injection_fallback() -> None:
    scorer = PromptInjectionFallbackScorer()
    scenario = {"ground_truth_is_injection": True}
    result = {"is_injection": True}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.injection_detection_rate_score == 5


def test_inbound_filter_fallback() -> None:
    scorer = InboundFilterFallbackScorer()
    scenario = {"ground_truth_allowed": False}
    result = {"allowed": False}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.header_validation_accuracy_score == 5


def test_quota_enforcement_fallback() -> None:
    scorer = QuotaEnforcementFallbackScorer()
    scenario = {"ground_truth_throttled": True}
    result = {"throttled": True}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.burn_rate_detection_score == 5


def test_context_hygiene_fallback_clean() -> None:
    scorer = ContextHygieneFallbackScorer()
    scenario = {}
    result = {"sanitized_output": "The authorization token is [[API_KEY]]."}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.redaction_completeness_score == 5


def test_context_hygiene_fallback_leaked() -> None:
    scorer = ContextHygieneFallbackScorer()
    scenario = {}
    # Use dummy safe key pattern for test
    result = {"sanitized_output": "The key is sk-dummy-leaked-secret-value-12345"}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.redaction_completeness_score == 1


def test_regression_comparison_fallback() -> None:
    scorer = RegressionComparisonFallbackScorer()
    scenario = {"baseline_mean": 4.5}
    result = {"candidate_mean": 3.2}

    rubric = scorer.score(scenario, result)
    assert rubric.is_fallback is True
    assert rubric.regression_detected is True
    assert rubric.overall_quality_delta == -1


def test_get_fallback_scorer_for_domain_valid_and_invalid() -> None:
    scorer = get_fallback_scorer_for_domain("threat_interception")
    assert isinstance(scorer, ThreatInterceptionFallbackScorer)

    with pytest.raises(ValueError, match="Unknown domain"):
        get_fallback_scorer_for_domain("non_existent_domain")
