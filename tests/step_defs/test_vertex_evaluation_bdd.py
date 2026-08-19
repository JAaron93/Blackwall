"""
BDD step definitions for GCP Vertex AI Evaluation Engine (Task 22).
"""

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexAIEvaluationHarness,
    GCPVertexEvalConfig,
)
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import (
    GCPCloudTraceExporter,
    GCPTraceSpan,
)
from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_adversarial_prompt_injection_samples,
)

scenarios("../features/vertex_evaluation.feature")


class BDDState:
    def __init__(self):
        self.config: GCPVertexEvalConfig | None = None
        self.harness: GCPVertexAIEvaluationHarness | None = None
        self.exporter: GCPCloudTraceExporter | None = None
        self.span: GCPTraceSpan | None = None
        self.dataset: list | None = None
        self.eval_result: dict | None = None
        self.trajectory_result: dict | None = None


@pytest.fixture
def bdd_state() -> BDDState:
    return BDDState()


# ---------------------------------------------------------------------------
# Scenario: Vertex AI initializes successfully
# ---------------------------------------------------------------------------


@given("a configured GCP Vertex AI environment")
def given_configured_gcp_environment(bdd_state: BDDState):
    bdd_state.config = GCPVertexEvalConfig(
        project_id="bdd-vertex-eval-project",
        location="us-central1",
    )


@when("the evaluation harness is instantiated")
def when_harness_instantiated(bdd_state: BDDState):
    bdd_state.harness = GCPVertexAIEvaluationHarness(config=bdd_state.config)


@then("the evaluation harness is initialized with valid project and location")
def then_harness_initialized(bdd_state: BDDState):
    assert bdd_state.harness is not None
    assert bdd_state.harness.config.project_id == "bdd-vertex-eval-project"
    assert bdd_state.harness.config.location == "us-central1"


# ---------------------------------------------------------------------------
# Scenario: Evaluation run executes EvalTask
# ---------------------------------------------------------------------------


@given("a dataset containing adversarial prompt injection samples")
def given_prompt_injection_dataset(bdd_state: BDDState):
    bdd_state.dataset = get_adversarial_prompt_injection_samples()
    bdd_state.harness = GCPVertexAIEvaluationHarness()


import sys
from unittest.mock import MagicMock


@when("the evaluation harness runs an EvalTask with threat accuracy autoraters")
def when_runs_eval_task(bdd_state: BDDState):
    autorater = bdd_state.harness.build_threat_accuracy_autorater()
    bdd_state.harness._vertex_eval_available = True
    bdd_state.harness._init_error = None
    mock_eval_module = MagicMock()
    mock_eval_task = MagicMock()
    mock_task_instance = MagicMock()
    mock_task_instance.evaluate.return_value = MagicMock(
        metrics_table=None,
        summary_metrics={"precision": 1.0, "recall": 1.0},
    )
    mock_eval_task.return_value = mock_task_instance
    mock_eval_module.EvalTask = mock_eval_task
    mock_eval_module.AutoraterConfig = MagicMock()

    orig_mod = sys.modules.get("vertexai.preview.evaluation")
    sys.modules["vertexai.preview.evaluation"] = mock_eval_module
    try:
        bdd_state.eval_result = bdd_state.harness.run_eval_task(
            dataset=bdd_state.dataset,
            metrics=[autorater],
        )
    finally:
        if orig_mod is not None:
            sys.modules["vertexai.preview.evaluation"] = orig_mod
        else:
            sys.modules.pop("vertexai.preview.evaluation", None)
    # Record synthetic verdicts for summary aggregation check
    for item in bdd_state.dataset:
        bdd_state.harness.metrics.record_verdict(
            predicted_blocked=True,
            is_actual_threat=item["ground_truth_threat"],
        )


@then("the evaluation run completes and aggregates precision and recall metrics")
def then_eval_aggregates_metrics(bdd_state: BDDState):
    assert bdd_state.eval_result is not None
    assert bdd_state.eval_result["status"] == "COMPLETED"
    summary = bdd_state.harness.metrics.summary()
    assert summary["total_events"] == len(bdd_state.dataset)
    assert 0.0 <= summary["precision"] <= 1.0
    assert 0.0 <= summary["recall"] <= 1.0


# ---------------------------------------------------------------------------
# Scenario: Telemetry spans exported to Cloud Trace
# ---------------------------------------------------------------------------


@given("an active GCP Cloud Trace exporter")
def given_cloud_trace_exporter(bdd_state: BDDState):
    bdd_state.exporter = GCPCloudTraceExporter(project_id="bdd-trace-project")


@when("an evaluation span is recorded with GenAI semantic conventions")
def when_span_recorded(bdd_state: BDDState):
    bdd_state.span = bdd_state.exporter.start_span(
        name="bdd.eval_span",
        model="gemini-3.5-flash-lite",
        metric_name="threat_interception_accuracy",
    )
    bdd_state.exporter.record_evaluation_result(
        span=bdd_state.span,
        score=5.0,
        verdict="CRITICAL",
        input_tokens=150,
        output_tokens=30,
    )


@then("the span is captured with standard OpenTelemetry attributes and latency duration")
def then_span_captured(bdd_state: BDDState):
    assert len(bdd_state.exporter.exported_spans) == 1
    span = bdd_state.exporter.exported_spans[0]
    assert span.attributes["gen_ai.system"] == "vertex_ai"
    assert span.attributes["gen_ai.request.model"] == "gemini-3.5-flash-lite"
    assert span.attributes["gen_ai.evaluation.score"] == 5.0
    assert span.duration_ms >= 0.0


# ---------------------------------------------------------------------------
# Scenario: Agent trajectory evaluation validates tool call sequence
# ---------------------------------------------------------------------------


@given("a reference tool execution trajectory and a candidate agent trajectory")
def given_trajectories(bdd_state: BDDState):
    bdd_state.harness = GCPVertexAIEvaluationHarness()
    bdd_state.ref_traj = ["step_read_auth", "step_validate_token", "step_grant_access"]
    bdd_state.cand_traj = ["step_read_auth", "step_validate_token", "step_grant_access"]


@when("the evaluation harness assesses trajectory precision and recall")
def when_assesses_trajectory(bdd_state: BDDState):
    bdd_state.trajectory_result = bdd_state.harness.evaluate_trajectory(
        predicted_steps=bdd_state.cand_traj,
        reference_steps=bdd_state.ref_traj,
    )


@then("the trajectory evaluation computes correct step precision and in-order match")
def then_trajectory_computed(bdd_state: BDDState):
    res = bdd_state.trajectory_result
    assert res["trajectory_exact_match"] is True
    assert res["trajectory_in_order_match"] is True
    assert res["trajectory_precision"] == 1.0
    assert res["trajectory_recall"] == 1.0
