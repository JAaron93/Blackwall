"""
Unit tests for GCP Cloud Trace Exporter (Task 22).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import (
    GCPCloudTraceExporter,
    GCPTraceSpan,
)


def test_gcp_trace_span_lifecycle():
    """Verify trace span duration calculation and status completion."""
    span = GCPTraceSpan(name="test_span", attributes={"test.attr": "val"})
    assert span.name == "test_span"
    assert span.status_code == "OK"
    assert span.end_time_ns is None

    span.finish(status="OK")
    assert span.end_time_ns is not None
    assert span.duration_ms >= 0.0


def test_gcp_cloud_trace_exporter_span_creation_and_recording():
    """Verify trace exporter records OpenTelemetry GenAI semantic attributes."""
    exporter = GCPCloudTraceExporter(project_id="unit-test-proj")
    span = exporter.start_span(
        name="vertex_eval.threat_interception",
        model="gemini-3.5-flash-lite",
        metric_name="threat_interception_accuracy",
        attributes={"scenario.id": "prompt_injection_01"},
    )
    assert span.attributes["gen_ai.system"] == "vertex_ai"
    assert span.attributes["gen_ai.request.model"] == "gemini-3.5-flash-lite"
    assert span.attributes["gen_ai.evaluation.metric_name"] == "threat_interception_accuracy"
    assert span.attributes["scenario.id"] == "prompt_injection_01"

    exporter.record_evaluation_result(
        span=span,
        score=5.0,
        verdict="CRITICAL",
        input_tokens=120,
        output_tokens=45,
    )
    assert span.attributes["gen_ai.evaluation.score"] == 5.0
    assert span.attributes["blackwall.verdict"] == "CRITICAL"
    assert span.attributes["gen_ai.usage.input_tokens"] == 120
    assert span.attributes["gen_ai.usage.output_tokens"] == 45
    assert span.end_time_ns is not None

    assert len(exporter.exported_spans) == 1
    exporter.clear()
    assert len(exporter.exported_spans) == 0


def test_gcp_cloud_trace_exporter_error_recording():
    """Verify trace exporter records error telemetry and OpenTelemetry exception status."""
    exporter = GCPCloudTraceExporter(project_id="unit-test-proj")
    span = exporter.start_span(
        name="vertex_eval.failed_task",
        model="gemini-3.7-flash",
    )
    exporter.record_evaluation_error(
        span=span,
        error="Vertex AI Quota Exceeded",
        status="ERROR",
    )
    assert span.attributes["error"] == "Vertex AI Quota Exceeded"
    assert span.attributes["blackwall.status"] == "ERROR"
    assert span.status_code == "ERROR"
    assert span.end_time_ns is not None
    assert len(exporter.exported_spans) == 1


def test_gcp_cloud_trace_exporter_disable_flag(monkeypatch):
    """Verify trace exporter respects BLACKWALL_DISABLE_CLOUD_TRACE environment variable."""
    monkeypatch.setenv("BLACKWALL_DISABLE_CLOUD_TRACE", "true")
    exporter = GCPCloudTraceExporter(project_id="unit-test-proj")
    assert exporter._export_to_cloud is False
    assert exporter.is_cloud_trace_available is False
