"""
Unit tests for AILM Evaluation Scenarios (Task A.2.1 / Requirements 5.1, 5.2, 5.3, 5.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_ailm_eval_samples,
)
from blackwall.eval.scenarios import AILMScenario


def test_ailm_eval_dataset_quantity_and_schema():
    """Verify at least 10 scenarios exist and all conform to AILMScenario schema."""
    samples = get_ailm_eval_samples()
    assert len(samples) >= 10

    for s in samples:
        scenario = AILMScenario.model_validate(s)
        assert scenario.domain == "ailm"
        assert len(scenario.permission_grants) >= 1
        assert scenario.expected_risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_ailm_eval_dataset_boundary_crossing_critical_risk():
    """Verify scenarios with 3+ crossings have CRITICAL risk level (Requirement 5.3)."""
    samples = get_ailm_eval_samples()
    critical_cases = [s for s in samples if len(s["ground_truth_crossings"]) >= 3]
    assert len(critical_cases) >= 3

    for s in critical_cases:
        assert s["expected_risk_level"] == "CRITICAL"


def test_ailm_eval_dataset_risk_distribution():
    """Verify presence of LOW, MEDIUM, HIGH, and CRITICAL risk levels."""
    samples = get_ailm_eval_samples()
    levels = {s["expected_risk_level"] for s in samples}
    assert "LOW" in levels
    assert "MEDIUM" in levels
    assert "HIGH" in levels
    assert "CRITICAL" in levels
