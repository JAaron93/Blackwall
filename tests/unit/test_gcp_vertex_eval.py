"""
Unit tests for GCP Vertex AI Evaluation Engine (Task 22).
"""

import pytest
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexEvalConfig,
    GCPVertexEvalMetrics,
    GCPVertexAIEvaluationHarness,
)


def test_gcp_vertex_eval_config_defaults():
    """Verify default configuration parameters for GCP Vertex AI Evaluation."""
    config = GCPVertexEvalConfig(
        project_id="test-eval-project",
        location="us-central1",
    )
    assert config.project_id == "test-eval-project"
    assert config.location == "us-central1"
    assert config.main_model == "gemini-3.5-flash-lite"
    assert config.reasoner_model == "gemini-3.7-flash"
    assert config.flip_enabled is True
    assert config.sampling_count == 4


def test_gcp_vertex_eval_config_validation():
    """Verify validation on empty or whitespace configuration values."""
    with pytest.raises(ValueError):
        GCPVertexEvalConfig(project_id="  ")
    with pytest.raises(ValueError):
        GCPVertexEvalConfig(main_model="")


def test_gcp_vertex_eval_metrics_calculations():
    """Verify accurate calculation of TP, FP, TN, FN, precision, recall, F1, and FPR."""
    metrics = GCPVertexEvalMetrics()
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0

    # Record 8 TP, 2 FP, 88 TN, 2 FN
    for _ in range(8):
        metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)
    for _ in range(2):
        metrics.record_verdict(predicted_blocked=True, is_actual_threat=False)
    for _ in range(88):
        metrics.record_verdict(predicted_blocked=False, is_actual_threat=False)
    for _ in range(2):
        metrics.record_verdict(predicted_blocked=False, is_actual_threat=True)

    assert metrics.total_events == 100
    assert metrics.true_positives == 8
    assert metrics.false_positives == 2
    assert metrics.true_negatives == 88
    assert metrics.false_negatives == 2

    # Precision = 8 / 10 = 0.8
    assert pytest.approx(metrics.precision, 0.001) == 0.8
    # Recall = 8 / 10 = 0.8
    assert pytest.approx(metrics.recall, 0.001) == 0.8
    # F1 Score = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.8
    assert pytest.approx(metrics.f1_score, 0.001) == 0.8
    # FPR = 2 / (2 + 88) = 2 / 90 ≈ 0.0222
    assert pytest.approx(metrics.false_positive_rate, 0.001) == 2.0 / 90.0

    summary = metrics.summary()
    assert summary["precision"] == 0.8
    assert summary["recall"] == 0.8
    assert summary["f1_score"] == 0.8


def test_gcp_vertex_eval_trajectory_evaluation():
    """Verify agent trajectory step evaluation precision, recall, and ordering."""
    harness = GCPVertexAIEvaluationHarness(
        config=GCPVertexEvalConfig(project_id="test-proj")
    )
    
    ref = ["query_db", "format_data", "send_email"]
    cand = ["query_db", "dump_tables", "format_data", "send_email"]

    res = harness.evaluate_trajectory(predicted_steps=cand, reference_steps=ref)
    assert res["trajectory_exact_match"] is False
    assert res["trajectory_in_order_match"] is True
    assert res["trajectory_precision"] == 0.75  # 3 valid steps out of 4 executed
    assert res["trajectory_recall"] == 1.0      # All 3 required steps captured

    summary = harness.metrics.summary()
    assert summary["avg_trajectory_precision"] == 0.75
    assert summary["avg_trajectory_recall"] == 1.0


def test_gcp_vertex_eval_autorater_builders():
    """Verify creation of Pointwise and Pairwise autorater rubrics."""
    harness = GCPVertexAIEvaluationHarness()
    threat_autorater = harness.build_threat_accuracy_autorater()
    assert threat_autorater is not None

    hygiene_autorater = harness.build_context_hygiene_autorater()
    assert hygiene_autorater is not None

    pairwise_autorater = harness.create_pairwise_autorater(
        metric_name="threat_reasoning_comparison",
        prompt_template="Compare Model A and Model B on threat explanation.",
    )
    assert pairwise_autorater is not None


def test_gcp_vertex_eval_run_eval_task_local_fallback():
    """Verify EvalTask execution handles local fallback gracefully."""
    harness = GCPVertexAIEvaluationHarness()
    dataset = [{"prompt": "test", "response": "test"}]
    metrics = ["threat_interception_accuracy"]
    result = harness.run_eval_task(dataset=dataset, metrics=metrics)
    assert result["status"] in ("COMPLETED", "LOCAL_FALLBACK")
    assert result["model"] == "gemini-3.7-flash"
