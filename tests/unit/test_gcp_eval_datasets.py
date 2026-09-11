"""
Unit tests for GCP Evaluation Datasets (Task 22).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_adversarial_prompt_injection_samples,
    get_agent_trajectory_samples,
    load_gcp_eval_datasets,
)


def test_load_gcp_eval_datasets_structure():
    """Verify standard dictionary dataset structure and required keys."""
    datasets = load_gcp_eval_datasets(as_dataframe=False)
    assert "prompt_injections" in datasets
    assert "trajectories" in datasets
    assert "complex_attacks" in datasets

    assert len(datasets["prompt_injections"]) >= 3
    assert len(datasets["trajectories"]) >= 2
    assert len(datasets["complex_attacks"]) >= 3


def test_adversarial_prompt_injection_samples_content():
    """Verify prompt injection samples contain required schema fields."""
    samples = get_adversarial_prompt_injection_samples()
    for s in samples:
        assert "prompt" in s
        assert "context" in s
        assert "ground_truth_threat" in s
        assert "threat_category" in s
        assert "expected_verdict" in s


def test_agent_trajectory_samples_content():
    """Verify trajectory samples define reference and candidate paths."""
    samples = get_agent_trajectory_samples()
    for s in samples:
        assert "query" in s
        assert "reference_trajectory" in s
        assert "candidate_trajectory" in s
        assert isinstance(s["reference_trajectory"], list)
        assert isinstance(s["candidate_trajectory"], list)
