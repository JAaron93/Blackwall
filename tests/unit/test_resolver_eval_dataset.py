"""
Unit tests for SyncResolver Threat Interception Evaluation Scenarios (Task A.2.6 / Requirements 1.1, 1.2, 1.3, 1.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_sync_resolver_eval_samples,
)
from blackwall.eval.scenarios import ThreatInterceptionScenario


def test_resolver_eval_dataset_quantity_and_schema():
    """Verify at least 20 scenarios exist and all satisfy ThreatInterceptionScenario schema."""
    samples = get_sync_resolver_eval_samples()
    assert len(samples) >= 20

    for s in samples:
        scenario = ThreatInterceptionScenario.model_validate(s)
        assert scenario.domain == "threat_interception"
        assert scenario.ground_truth_verdict in ("ALLOW", "BLOCK", "QUARANTINE")
        assert scenario.ground_truth_label in ("BENIGN", "MALICIOUS")


def test_resolver_eval_dataset_verdict_distribution():
    """Verify presence of ALLOW, BLOCK, and QUARANTINE verdicts."""
    samples = get_sync_resolver_eval_samples()
    verdicts = {s["ground_truth_verdict"] for s in samples}

    assert "ALLOW" in verdicts
    assert "BLOCK" in verdicts
    assert "QUARANTINE" in verdicts

    allow_count = sum(1 for s in samples if s["ground_truth_verdict"] == "ALLOW")
    block_count = sum(1 for s in samples if s["ground_truth_verdict"] == "BLOCK")

    assert allow_count >= 8
    assert block_count >= 8
