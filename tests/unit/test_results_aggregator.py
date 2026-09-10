"""
Unit tests for Evaluation Results Aggregator with Fallback Isolation (Track D.1 / Task D.1.2).

Verifies:
- Filtering is_fallback=True rows from quality mean computations.
- Reporting None for domains with 100% fallback rows.
- Calculation of fallback_count and fallback_rate per domain and overall.
- Pass/fail gating against configurable threshold.
"""

import pytest
from blackwall.eval.aggregator import (
    DomainSummary,
    EvaluationAggregator,
    EvaluationResultRecord,
)
from blackwall.eval.rubrics import ThreatInterceptionRubric, C2DetectionRubric


def test_aggregator_clean_evaluation():
    """Verify aggregation when all results are non-fallback judge evaluations."""
    aggregator = EvaluationAggregator(threshold=3.5)

    r1 = ThreatInterceptionRubric(
        detection_accuracy_score=5,
        false_positive_control_score=4,
        reasoning_quality_score=5,
        trajectory_soundness_score=4,
        justification="Accurate blocking of SQL injection",
        is_fallback=False,
    )
    r2 = ThreatInterceptionRubric(
        detection_accuracy_score=4,
        false_positive_control_score=4,
        reasoning_quality_score=4,
        trajectory_soundness_score=4,
        justification="Accurate detection with minor reasoning delay",
        is_fallback=False,
    )

    aggregator.add_record(EvaluationResultRecord(scenario_id="s1", domain="threat_interception", rubric=r1))
    aggregator.add_record(EvaluationResultRecord(scenario_id="s2", domain="threat_interception", rubric=r2))

    summary = aggregator.summarize()
    domain_summary = summary.domain_summaries["threat_interception"]

    assert domain_summary.total_scenarios == 2
    assert domain_summary.fallback_count == 0
    assert domain_summary.fallback_rate == 0.0
    assert domain_summary.valid_count == 2
    assert domain_summary.overall_mean == pytest.approx(4.25)
    assert domain_summary.dimension_means["detection_accuracy_score"] == 4.5
    assert domain_summary.dimension_means["false_positive_control_score"] == 4.0
    assert domain_summary.passed is True
    assert summary.all_passed is True


def test_aggregator_fallback_isolation():
    """Verify is_fallback=True rows are excluded from quality score averages."""
    aggregator = EvaluationAggregator(threshold=3.5)

    # Valid judge rubric (average score = 4.0)
    r_valid = ThreatInterceptionRubric(
        detection_accuracy_score=4,
        false_positive_control_score=4,
        reasoning_quality_score=4,
        trajectory_soundness_score=4,
        justification="Standard valid judge evaluation",
        is_fallback=False,
    )
    # Heuristic fallback rubric (average score = 1.0, should be isolated)
    r_fallback = ThreatInterceptionRubric(
        detection_accuracy_score=1,
        false_positive_control_score=1,
        reasoning_quality_score=1,
        trajectory_soundness_score=1,
        justification="Heuristic fallback due to timeout",
        is_fallback=True,
    )

    aggregator.add_record(EvaluationResultRecord(scenario_id="s1", domain="threat_interception", rubric=r_valid))
    aggregator.add_record(EvaluationResultRecord(scenario_id="s2", domain="threat_interception", rubric=r_fallback))

    summary = aggregator.summarize()
    domain_summary = summary.domain_summaries["threat_interception"]

    assert domain_summary.total_scenarios == 2
    assert domain_summary.fallback_count == 1
    assert domain_summary.fallback_rate == 0.5
    assert domain_summary.valid_count == 1
    # Mean MUST be computed only from the valid rubric (4.0), not averaged with fallback (2.5)
    assert domain_summary.overall_mean == pytest.approx(4.0)
    assert domain_summary.passed is True


def test_aggregator_100_percent_fallback():
    """Verify domains with 100% fallback return None for judge mean scores and fail gating."""
    aggregator = EvaluationAggregator(threshold=3.5)

    r_fallback = C2DetectionRubric(
        endpoint_classification_score=5,
        beaconing_detection_score=5,
        persistence_identification_score=5,
        cross_pillar_correlation_score=5,
        justification="Heuristic fallback scoring",
        is_fallback=True,
    )

    aggregator.add_record(EvaluationResultRecord(scenario_id="c2_1", domain="c2_detection", rubric=r_fallback))
    summary = aggregator.summarize()
    domain_summary = summary.domain_summaries["c2_detection"]

    assert domain_summary.total_scenarios == 1
    assert domain_summary.fallback_count == 1
    assert domain_summary.fallback_rate == 1.0
    assert domain_summary.valid_count == 0
    assert domain_summary.overall_mean is None
    assert domain_summary.passed is False
    assert summary.all_passed is False


def test_aggregator_threshold_gating():
    """Verify failure when a domain mean is below configured threshold."""
    aggregator = EvaluationAggregator(threshold=4.0)

    r_low = ThreatInterceptionRubric(
        detection_accuracy_score=3,
        false_positive_control_score=3,
        reasoning_quality_score=3,
        trajectory_soundness_score=3,
        justification="Below threshold performance",
        is_fallback=False,
    )

    aggregator.add_record(EvaluationResultRecord(scenario_id="s1", domain="threat_interception", rubric=r_low))
    summary = aggregator.summarize()

    assert summary.domain_summaries["threat_interception"].overall_mean == pytest.approx(3.0)
    assert summary.domain_summaries["threat_interception"].passed is False
    assert summary.all_passed is False
