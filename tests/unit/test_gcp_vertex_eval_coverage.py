import pytest

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_adversarial_prompt_injection_samples,
    get_agent_trajectory_samples,
    get_swarm_and_exploit_chain_samples,
    load_gcp_eval_datasets,
)
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import (
    GCPCloudTraceExporter,
)
from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexAIEvaluationHarness,
    GCPVertexEvalConfig,
    GCPVertexEvalMetrics,
)

# =========================================================================
# Task 7.3: GCP Vertex AI Evaluation & Telemetry Coverage Tests
# =========================================================================

# --- GCPVertexEvalConfig & GCPVertexEvalMetrics ---

def test_gcp_vertex_eval_config_validation():
    config = GCPVertexEvalConfig(
        project_id="test-proj-eval",
        location="us-central1",
        main_model="gemini-3.5-flash-lite",
        reasoner_model="gemini-3.8-flash",
        sampling_count=8,
    )
    assert config.project_id == "test-proj-eval"
    assert config.location == "us-central1"
    assert config.sampling_count == 8

    with pytest.raises(ValueError, match="Configuration fields must not be empty"):
        GCPVertexEvalConfig(project_id="")

    with pytest.raises(ValueError, match="Configuration fields must not be empty"):
        GCPVertexEvalConfig(location="   ")


def test_gcp_vertex_eval_metrics_calculations():
    metrics = GCPVertexEvalMetrics()

    # Initial state
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.average_trajectory_precision == 1.0
    assert metrics.average_trajectory_recall == 1.0

    # Record verdicts
    metrics.record_verdict(predicted_blocked=True, is_actual_threat=True)   # TP
    metrics.record_verdict(predicted_blocked=True, is_actual_threat=False)  # FP
    metrics.record_verdict(predicted_blocked=False, is_actual_threat=False) # TN
    metrics.record_verdict(predicted_blocked=False, is_actual_threat=True)  # FN

    assert metrics.total_events == 4
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 1

    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1_score == 0.5
    assert metrics.false_positive_rate == 0.5

    # Record trajectories
    metrics.record_trajectory(precision=0.8, recall=1.0)
    metrics.record_trajectory(precision=0.6, recall=0.8)

    assert metrics.trajectory_eval_count == 2
    assert round(metrics.average_trajectory_precision, 2) == 0.7
    assert round(metrics.average_trajectory_recall, 2) == 0.9

    summary = metrics.summary()
    assert summary["total_events"] == 4
    assert summary["f1_score"] == 0.5
    assert summary["avg_trajectory_precision"] == 0.7


# --- GCPVertexAIEvaluationHarness ---

def test_harness_init_and_autoraters():
    config = GCPVertexEvalConfig(project_id="test-eval-proj", allow_fallback=True)
    harness = GCPVertexAIEvaluationHarness(config=config)

    assert harness.metrics is not None
    assert harness.trace_exporter is not None

    threat_autorater = harness.build_threat_accuracy_autorater()
    if isinstance(threat_autorater, dict):
        assert threat_autorater["metric"] == "threat_interception_accuracy"
        assert "accuracy" in threat_autorater["criteria"]
    else:
        assert getattr(threat_autorater, "metric", getattr(threat_autorater, "metric_name", None)) == "threat_interception_accuracy"

    hygiene_autorater = harness.build_context_hygiene_autorater()
    if isinstance(hygiene_autorater, dict):
        assert hygiene_autorater["metric"] == "context_hygiene_sanitization"
        assert "redaction" in hygiene_autorater["criteria"]
    else:
        assert getattr(hygiene_autorater, "metric", getattr(hygiene_autorater, "metric_name", None)) == "context_hygiene_sanitization"

    pairwise = harness.create_pairwise_autorater(
        metric_name="pairwise_test",
        prompt_template="Compare {baseline} vs {candidate}",
    )
    if isinstance(pairwise, dict):
        assert pairwise["metric"] == "pairwise_test"
        assert pairwise["flip_enabled"] is True
    else:
        assert getattr(pairwise, "metric", getattr(pairwise, "metric_name", None)) == "pairwise_test"


def test_evaluate_trajectory():
    harness = GCPVertexAIEvaluationHarness(config=GCPVertexEvalConfig(allow_fallback=True))

    # Exact match
    res_exact = harness.evaluate_trajectory(
        predicted_steps=["step1", "step2", "step3"],
        reference_steps=["step1", "step2", "step3"],
    )
    assert res_exact["trajectory_exact_match"] is True
    assert res_exact["trajectory_in_order_match"] is True
    assert res_exact["trajectory_precision"] == 1.0
    assert res_exact["trajectory_recall"] == 1.0

    # Partial / Out-of-order
    res_partial = harness.evaluate_trajectory(
        predicted_steps=["step1", "step3", "step2"],
        reference_steps=["step1", "step2", "step3"],
    )
    assert res_partial["trajectory_exact_match"] is False
    assert res_partial["trajectory_in_order_match"] is False
    assert res_partial["trajectory_precision"] == 1.0
    assert res_partial["trajectory_recall"] == 1.0

    # Empty cases
    res_empty = harness.evaluate_trajectory(predicted_steps=[], reference_steps=[])
    assert res_empty["trajectory_exact_match"] is True

    res_empty_pred = harness.evaluate_trajectory(predicted_steps=[], reference_steps=["step1"])
    assert res_empty_pred["trajectory_exact_match"] is False
    assert res_empty_pred["trajectory_precision"] == 0.0


def test_run_eval_task_local_fallback():
    config = GCPVertexEvalConfig(project_id="test-proj", allow_fallback=True)
    harness = GCPVertexAIEvaluationHarness(config=config)

    dataset = [{"prompt": "test prompt", "response": "test response"}]
    metrics = ["threat_accuracy"]

    res = harness.run_eval_task(dataset=dataset, metrics=metrics)
    assert res["status"] == "LOCAL_FALLBACK"
    assert res["total_items"] == 1
    assert "threat_accuracy" in res["metrics"]
    assert res["thinking_level"] == "high"
    assert res["max_output_tokens"] == 65536
    assert res["http_timeout"] == 120.0


def test_run_eval_task_capabilities_forwarded_to_vertex():
    from unittest.mock import MagicMock, patch

    config = GCPVertexEvalConfig(
        project_id="test-proj",
        thinking_level="high",
        max_output_tokens=65536,
        http_timeout=90.0,
        allow_fallback=False,
    )
    harness = GCPVertexAIEvaluationHarness(config=config)
    harness._vertex_eval_available = True
    harness._init_error = None

    dataset = [{"prompt": "test prompt"}]
    metrics = ["threat_accuracy"]

    mock_eval_task_cls = MagicMock()
    mock_eval_task_instance = MagicMock()
    mock_eval_task_cls.return_value = mock_eval_task_instance
    mock_eval_result = MagicMock()
    mock_eval_result.metrics_table = "table"
    mock_eval_result.summary_metrics = {"accuracy": 1.0}
    mock_eval_task_instance.evaluate.return_value = mock_eval_result

    with patch("vertexai.preview.evaluation.EvalTask", mock_eval_task_cls):
        res = harness.run_eval_task(dataset=dataset, metrics=metrics)

    assert res["status"] == "COMPLETED"
    assert res["thinking_level"] == "high"
    assert res["max_output_tokens"] == 65536
    assert res["http_timeout"] == 90.0

    mock_eval_task_instance.evaluate.assert_called_once()
    call_kwargs = mock_eval_task_instance.evaluate.call_args[1]
    assert call_kwargs["retry_timeout"] == 90.0
    passed_model = call_kwargs["model"]
    assert hasattr(passed_model, "_generation_config")
    assert passed_model._generation_config.to_dict()["max_output_tokens"] == 65536
    raw_cfg = getattr(passed_model._generation_config, "_raw_generation_config", None)
    assert raw_cfg is not None
    assert raw_cfg.thinking_config.include_thoughts is True
    assert raw_cfg.thinking_config.thinking_budget == -1


def test_run_eval_task_failure_when_fallback_disabled():
    config = GCPVertexEvalConfig(project_id="test-proj", allow_fallback=False)
    harness = GCPVertexAIEvaluationHarness(config=config)
    harness._init_error = "ADC unconfigured"

    dataset = [{"prompt": "test prompt"}]
    metrics = ["accuracy"]

    res = harness.run_eval_task(dataset=dataset, metrics=metrics, raise_on_error=False)
    assert res["status"] == "FAILED"
    assert "ADC unconfigured" in res["error"]

    with pytest.raises(RuntimeError, match="Vertex AI Evaluation Service unavailable"):
        harness.run_eval_task(dataset=dataset, metrics=metrics, raise_on_error=True)


# --- GCP Eval Datasets ---

def test_eval_datasets():
    injections = get_adversarial_prompt_injection_samples()
    assert len(injections) >= 3
    assert all("prompt" in s and "ground_truth_threat" in s for s in injections)

    trajectories = get_agent_trajectory_samples()
    assert len(trajectories) >= 2
    assert all("reference_trajectory" in s and "candidate_trajectory" in s for s in trajectories)

    attacks = get_swarm_and_exploit_chain_samples()
    assert len(attacks) >= 3
    assert any(a["threat_type"] == "SWARM_COORDINATION" for a in attacks)
    assert any(a["threat_type"] == "RCE_TO_PRIVESC_CHAIN" for a in attacks)
    assert any(a["threat_type"] == "C2_INFRASTRUCTURE" for a in attacks)

    all_datasets = load_gcp_eval_datasets(as_dataframe=False)
    assert "prompt_injections" in all_datasets
    assert "trajectories" in all_datasets
    assert "complex_attacks" in all_datasets

    # Test as_dataframe (if pandas is available or returns dict)
    df_datasets = load_gcp_eval_datasets(as_dataframe=True)
    assert df_datasets is not None


# --- GCP Cloud Trace Exporter ---

def test_gcp_cloud_trace_exporter():
    exporter = GCPCloudTraceExporter(project_id="test-trace-project", export_to_cloud=False)

    span = exporter.start_span(
        name="test.eval.span",
        model="gemini-3.5-flash-lite",
        metric_name="interception_accuracy",
        attributes={"scenario": "prompt_injection"},
    )
    assert span.name == "test.eval.span"
    assert span.attributes["gen_ai.system"] == "vertex_ai"
    assert span.attributes["scenario"] == "prompt_injection"
    assert span.duration_ms >= 0.0

    exporter.record_evaluation_result(
        span=span,
        score=0.95,
        verdict="BLOCK",
        input_tokens=150,
        output_tokens=30,
    )
    assert span.attributes["gen_ai.evaluation.score"] == 0.95
    assert span.attributes["blackwall.verdict"] == "BLOCK"
    assert span.attributes["gen_ai.usage.input_tokens"] == 150
    assert span.status_code == "OK"
    assert len(exporter.exported_spans) == 1
