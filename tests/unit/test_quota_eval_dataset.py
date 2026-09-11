"""
Unit tests for Agent Quota Enforcer Evaluation Scenarios (Task A.2.4 / Requirements 8.1, 8.2, 8.3, 8.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_quota_enforcement_eval_samples,
)
from blackwall.eval.scenarios import QuotaEnforcementScenario


def test_quota_enforcement_eval_dataset_quantity_and_schema():
    """Verify at least 10 scenarios exist and all satisfy QuotaEnforcementScenario schema."""
    samples = get_quota_enforcement_eval_samples()
    assert len(samples) >= 10

    for s in samples:
        scenario = QuotaEnforcementScenario.model_validate(s)
        assert scenario.domain == "quota_enforcement"
        assert len(scenario.activity_stream) >= 1
        assert isinstance(scenario.ground_truth_throttled, bool)
        assert len(scenario.expected_alert_type) > 0


def test_quota_enforcement_eval_dataset_boundary_conditions():
    """Verify threshold boundary cases (499 vs 501 tokens/sec)."""
    samples = get_quota_enforcement_eval_samples()
    boundary_cases = [s for s in samples if s.get("metadata", {}).get("boundary_type")]
    assert len(boundary_cases) >= 2

    below_cases = [s for s in boundary_cases if s["metadata"]["boundary_type"] == "BELOW_THRESHOLD"]
    above_cases = [s for s in boundary_cases if s["metadata"]["boundary_type"] == "ABOVE_THRESHOLD"]

    assert len(below_cases) >= 1
    assert below_cases[0]["ground_truth_throttled"] is False

    assert len(above_cases) >= 1
    assert above_cases[0]["ground_truth_throttled"] is True
