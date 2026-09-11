"""
Unit tests for Cloud Trace evaluation-specific attributes (Track D.4 / Task D.4.1).

Verifies that GCPCloudTraceExporter supports:
- gen_ai.evaluation.domain
- gen_ai.evaluation.judge_model
- gen_ai.evaluation.rubric_scores
- gen_ai.evaluation.is_fallback
- gen_ai.evaluation.mean_score
"""

import json
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import (
    GCPCloudTraceExporter,
    GCPTraceSpan,
)


def test_eval_trace_export_judge_attributes():
    """Verify recording of domain, judge_model, rubric_scores, is_fallback, and mean_score."""
    exporter = GCPCloudTraceExporter(project_id="eval-test-proj")
    span = exporter.start_span(
        name="vertex_eval.judge.threat_interception",
        model="gemini-3.8-flash",
        domain="threat_interception",
        judge_model="gemini-3.8-flash",
    )

    assert span.attributes["gen_ai.evaluation.domain"] == "threat_interception"
    assert span.attributes["gen_ai.evaluation.judge_model"] == "gemini-3.8-flash"

    rubric_scores = {
        "detection_accuracy_score": 5,
        "false_positive_control_score": 4,
        "reasoning_quality_score": 5,
        "trajectory_soundness_score": 4,
    }

    exporter.record_evaluation_result(
        span=span,
        score=4.5,
        verdict="BLOCK",
        domain="threat_interception",
        judge_model="gemini-3.8-flash",
        rubric_scores=rubric_scores,
        is_fallback=False,
        mean_score=4.5,
        input_tokens=250,
        output_tokens=60,
    )

    assert span.attributes["gen_ai.evaluation.domain"] == "threat_interception"
    assert span.attributes["gen_ai.evaluation.judge_model"] == "gemini-3.8-flash"
    assert span.attributes["gen_ai.evaluation.rubric_scores"] == json.dumps(rubric_scores)
    assert span.attributes["gen_ai.evaluation.is_fallback"] is False
    assert span.attributes["gen_ai.evaluation.mean_score"] == 4.5
    assert span.attributes["gen_ai.evaluation.score"] == 4.5
    assert span.attributes["blackwall.verdict"] == "BLOCK"
    assert span.attributes["gen_ai.usage.input_tokens"] == 250
    assert span.attributes["gen_ai.usage.output_tokens"] == 60
    assert span.end_time_ns is not None


def test_eval_trace_export_fallback_attributes():
    """Verify fallback evaluation span attributes are properly captured."""
    exporter = GCPCloudTraceExporter(project_id="eval-test-proj")
    span = exporter.start_span(
        name="vertex_eval.judge.c2_detection",
        model="heuristic_fallback",
    )

    exporter.record_evaluation_result(
        span=span,
        score=3.0,
        verdict="QUARANTINE",
        domain="c2_detection",
        judge_model="heuristic_fallback",
        is_fallback=True,
        mean_score=3.0,
    )

    assert span.attributes["gen_ai.evaluation.domain"] == "c2_detection"
    assert span.attributes["gen_ai.evaluation.judge_model"] == "heuristic_fallback"
    assert span.attributes["gen_ai.evaluation.is_fallback"] is True
    assert span.attributes["gen_ai.evaluation.mean_score"] == 3.0
    assert span.attributes["gen_ai.evaluation.score"] == 3.0
