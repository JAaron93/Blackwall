"""
Unit tests for Prompt Injection Evaluation Scenarios (Task A.2.2 / Requirements 6.1, 6.2, 6.3, 6.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_prompt_injection_eval_samples,
)
from blackwall.eval.scenarios import PromptInjectionScenario


def test_prompt_injection_eval_dataset_quantity_and_schema():
    """Verify at least 15 scenarios exist and all satisfy PromptInjectionScenario schema."""
    samples = get_prompt_injection_eval_samples()
    assert len(samples) >= 15

    for s in samples:
        scenario = PromptInjectionScenario.model_validate(s)
        assert scenario.domain == "prompt_injection"
        assert len(scenario.payload) > 0
        assert isinstance(scenario.ground_truth_is_injection, bool)


def test_prompt_injection_eval_dataset_distribution():
    """Verify presence of both true positives (jailbreaks) and true negatives (benign)."""
    samples = get_prompt_injection_eval_samples()
    true_positives = [s for s in samples if s["ground_truth_is_injection"] is True]
    true_negatives = [s for s in samples if s["ground_truth_is_injection"] is False]

    assert len(true_positives) >= 8
    assert len(true_negatives) >= 6


def test_prompt_injection_eval_dataset_structural_tags():
    """Verify structural jailbreaks contain tags like [INST], <<SYS>>, <|im_start|>."""
    samples = get_prompt_injection_eval_samples()
    structural = [
        s
        for s in samples
        if "[INST]" in s["payload"] or "<|im_start|>" in s["payload"] or "<<SYS>>" in s["payload"]
    ]
    assert len(structural) >= 2
    for s in structural:
        assert s["ground_truth_is_injection"] is True
        assert s["expected_severity"] == "CRITICAL"
