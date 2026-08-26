"""
Unit Tests for Pydantic Rubric Models (`tests/unit/test_rubric_models.py`).
"""

import pytest
from pydantic import ValidationError

from blackwall.eval.rubrics import (
    AILMDetectionRubric,
    C2DetectionRubric,
    ContextHygieneRubric,
    ExploitChainRubric,
    InboundFilterRubric,
    PromptInjectionRubric,
    QuotaEnforcementRubric,
    RegressionComparisonRubric,
    SwarmDetectionRubric,
    ThreatInterceptionRubric,
    get_rubric_for_domain,
)


def test_threat_interception_rubric_valid() -> None:
    rubric = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=5,
        reasoning_quality_score=4,
        trajectory_soundness_score=5,
        justification="The model blocked malicious command and permitted benign tool calls accurately.",
    )
    assert rubric.is_fallback is False
    assert rubric.detection_accuracy_score == 5


def test_rubrics_reject_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ThreatInterceptionRubric(
            detection_accuracy_score=5,
            false_positive_control_score=5,
            reasoning_quality_score=4,
            trajectory_soundness_score=5,
            justification="Detailed justification here",
            unknown_extra_field=123,  # type: ignore[call-arg]
        )


def test_rubrics_reject_invalid_score_bounds() -> None:
    with pytest.raises(ValidationError):
        ThreatInterceptionRubric(
            detection_accuracy_score=6,  # Invalid > 5
            false_positive_control_score=5,
            reasoning_quality_score=4,
            trajectory_soundness_score=5,
            justification="Detailed justification here",
        )

    with pytest.raises(ValidationError):
        ThreatInterceptionRubric(
            detection_accuracy_score=0,  # Invalid < 1
            false_positive_control_score=5,
            reasoning_quality_score=4,
            trajectory_soundness_score=5,
            justification="Detailed justification here",
        )


def test_rubrics_reject_short_justification() -> None:
    with pytest.raises(ValidationError):
        ThreatInterceptionRubric(
            detection_accuracy_score=5,
            false_positive_control_score=5,
            reasoning_quality_score=4,
            trajectory_soundness_score=5,
            justification="Too short",  # < 10 chars
        )


def test_all_rubric_classes_valid_instantiation() -> None:
    just = "Valid justification exceeding ten characters."
    
    r_swarm = SwarmDetectionRubric(
        coordination_detection_score=5,
        temporal_precision_score=4,
        shared_infra_identification_score=5,
        fingerprint_quality_score=4,
        justification=just,
    )
    assert r_swarm.coordination_detection_score == 5

    r_exploit = ExploitChainRubric(
        chain_completeness_score=5,
        novelty_calibration_score=4,
        mitre_mapping_accuracy_score=5,
        chaining_confidence_score=4,
        justification=just,
    )
    assert r_exploit.chain_completeness_score == 5

    r_c2 = C2DetectionRubric(
        endpoint_classification_score=5,
        beaconing_detection_score=4,
        persistence_identification_score=5,
        cross_pillar_correlation_score=4,
        justification=just,
    )
    assert r_c2.endpoint_classification_score == 5

    r_ailm = AILMDetectionRubric(
        boundary_crossing_detection_score=5,
        permission_composition_accuracy_score=4,
        risk_classification_score=5,
        evidence_completeness_score=4,
        justification=just,
    )
    assert r_ailm.boundary_crossing_detection_score == 5

    r_prompt = PromptInjectionRubric(
        injection_detection_rate_score=5,
        redaction_completeness_score=5,
        false_positive_control_score=4,
        alert_severity_accuracy_score=5,
        justification=just,
    )
    assert r_prompt.injection_detection_rate_score == 5

    r_inbound = InboundFilterRubric(
        header_validation_accuracy_score=5,
        rate_limit_precision_score=4,
        sanitization_quality_score=5,
        error_response_safety_score=5,
        justification=just,
    )
    assert r_inbound.header_validation_accuracy_score == 5

    r_quota = QuotaEnforcementRubric(
        burn_rate_detection_score=5,
        throttling_precision_score=4,
        alert_timeliness_score=5,
        quarantine_accuracy_score=5,
        justification=just,
    )
    assert r_quota.burn_rate_detection_score == 5

    r_hygiene = ContextHygieneRubric(
        redaction_completeness_score=5,
        placeholder_format_compliance_score=5,
        metadata_preservation_score=4,
        non_sensitive_passthrough_score=5,
        justification=just,
    )
    assert r_hygiene.redaction_completeness_score == 5

    r_reg = RegressionComparisonRubric(
        overall_quality_delta=-1,
        precision_delta=0,
        recall_delta=-1,
        trajectory_quality_delta=0,
        regression_detected=False,
        justification=just,
    )
    assert r_reg.overall_quality_delta == -1


def test_get_rubric_for_domain_mapping() -> None:
    assert get_rubric_for_domain("threat_interception") == ThreatInterceptionRubric
    assert get_rubric_for_domain("ailm") == AILMDetectionRubric
    assert get_rubric_for_domain("pairwise_regression") == RegressionComparisonRubric

    with pytest.raises(ValueError, match="Unknown evaluation domain"):
        get_rubric_for_domain("unsupported_domain_name")
