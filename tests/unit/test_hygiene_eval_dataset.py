"""
Unit tests for Context Hygiene Evaluation Scenarios (Task A.2.5 / Requirements 9.1, 9.2, 9.3, 9.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_context_hygiene_eval_samples,
)
from blackwall.eval.scenarios import ContextHygieneScenario


def test_context_hygiene_eval_dataset_quantity_and_schema():
    """Verify at least 12 scenarios exist and all satisfy ContextHygieneScenario schema."""
    samples = get_context_hygiene_eval_samples()
    assert len(samples) >= 12

    for s in samples:
        scenario = ContextHygieneScenario.model_validate(s)
        assert scenario.domain == "context_hygiene"
        assert len(scenario.raw_payload) > 0
        assert len(scenario.expected_sanitized) > 0


def test_context_hygiene_eval_dataset_secret_types():
    """Verify coverage of diverse secret types (API keys, AWS, JWT, GCP, Slack, RSA)."""
    samples = get_context_hygiene_eval_samples()
    secret_types = {s.get("metadata", {}).get("secret_type") for s in samples}

    assert "OPENAI_API_KEY" in secret_types
    assert "AWS_CREDENTIALS" in secret_types
    assert "JWT_TOKEN" in secret_types
    assert "GCP_API_KEY" in secret_types
    assert "BENIGN_PASSTHROUGH" in secret_types


def test_context_hygiene_eval_dataset_placeholder_format():
    """Verify sensitive replacements use [[VARIABLE_NAME]] format (Requirement 9.3)."""
    samples = get_context_hygiene_eval_samples()
    sensitive_cases = [s for s in samples if s["sensitive_patterns"]]

    assert len(sensitive_cases) >= 6
    for s in sensitive_cases:
        assert "[[" in s["expected_sanitized"] and "]]" in s["expected_sanitized"]
