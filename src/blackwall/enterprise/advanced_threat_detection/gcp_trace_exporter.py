"""
Google Cloud Trace OpenTelemetry Telemetry Exporter (`blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter`).

Exports OpenTelemetry GenAI semantic convention spans and security evaluation telemetry
directly to Google Cloud Trace (`opentelemetry-exporter-gcp-trace`).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, PrivateAttr

logger = logging.getLogger(__name__)


class GCPTraceSpan(BaseModel):
    """Structured representation of an OpenTelemetry GenAI evaluation span."""

    name: str = Field(description="Span operation name (e.g. vertex_eval.interception).")
    start_time_ns: int = Field(default_factory=lambda: time.time_ns())
    end_time_ns: Optional[int] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    status_code: str = Field(default="OK")
    _otel_span: Any = PrivateAttr(default=None)

    def finish(self, status: str = "OK") -> None:
        """Mark span as finished with timestamp and status."""
        self.end_time_ns = time.time_ns()
        self.status_code = status

    @property
    def duration_ms(self) -> float:
        """Calculate span duration in milliseconds."""
        if self.end_time_ns is None:
            return (time.time_ns() - self.start_time_ns) / 1_000_000.0
        return (self.end_time_ns - self.start_time_ns) / 1_000_000.0


class GCPCloudTraceExporter:
    """
    OpenTelemetry telemetry manager configuring Google Cloud Trace
    and exporting GenAI evaluation spans using standard semantic conventions.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        export_to_cloud: Optional[bool] = None,
    ) -> None:
        self.project_id = (
            project_id
            or os.getenv("GCP_PROJECT")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or os.getenv("PROJECT_ID")
            or "blackwall-security-eval"
        )
        disable_cloud_trace = os.getenv("BLACKWALL_DISABLE_CLOUD_TRACE", "false").lower() in ("true", "1", "yes")
        export_env = os.getenv("BLACKWALL_EXPORT_CLOUD_TRACE")
        if disable_cloud_trace:
            self._export_to_cloud = False
        elif export_to_cloud is not None:
            self._export_to_cloud = export_to_cloud
        elif export_env is not None:
            self._export_to_cloud = export_env.lower() in ("true", "1", "yes")
        else:
            self._export_to_cloud = True
        self._exported_spans: List[GCPTraceSpan] = []
        self._is_cloud_trace_available = False
        self._tracer_provider = None
        self._cloud_trace_exporter = None
        self._span_processor = None
        self._tracer = None

        self._init_cloud_trace()

    def _init_cloud_trace(self) -> bool:
        """Initialize Google Cloud Trace OpenTelemetry exporter if installed."""
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            self._tracer_provider = TracerProvider()
            if self._export_to_cloud:
                self._cloud_trace_exporter = CloudTraceSpanExporter(project_id=self.project_id)
                self._span_processor = BatchSpanProcessor(self._cloud_trace_exporter)
                self._tracer_provider.add_span_processor(self._span_processor)
                self._is_cloud_trace_available = True
                logger.info("Google Cloud Trace OpenTelemetry exporter available and configured for project %s", self.project_id)
            else:
                self._is_cloud_trace_available = False
                logger.info("Google Cloud Trace export disabled; operating in in-memory mode")
            self._tracer = self._tracer_provider.get_tracer("blackwall.evaluation")
            return self._is_cloud_trace_available
        except (ImportError, Exception) as exc:
            self._is_cloud_trace_available = False
            self._tracer_provider = None
            self._cloud_trace_exporter = None
            self._span_processor = None
            self._tracer = None
            logger.debug("Google Cloud Trace SDK not initialized (%s); operating in buffered in-memory mode", exc)
            return False

    @property
    def is_cloud_trace_available(self) -> bool:
        return self._is_cloud_trace_available

    @property
    def exported_spans(self) -> List[GCPTraceSpan]:
        """Return all recorded spans in memory."""
        return list(self._exported_spans)

    def start_span(
        self,
        name: str,
        model: str = "gemini-3.5-flash-lite",
        metric_name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> GCPTraceSpan:
        """
        Start a new evaluation span with OpenTelemetry GenAI semantic conventions.
        """
        span_attrs: Dict[str, Any] = {
            "gen_ai.system": "vertex_ai",
            "gen_ai.request.model": model,
            "gcp.project_id": self.project_id,
        }
        if metric_name:
            span_attrs["gen_ai.evaluation.metric_name"] = metric_name
        if attributes:
            span_attrs.update(attributes)

        span = GCPTraceSpan(name=name, attributes=span_attrs)

        if self._tracer is not None:
            try:
                otel_span = self._tracer.start_span(
                    name=name,
                    start_time=span.start_time_ns,
                )
                for k, v in span.attributes.items():
                    if isinstance(v, (str, bool, int, float)):
                        otel_span.set_attribute(k, v)
                span._otel_span = otel_span
            except Exception as exc:
                logger.debug("Failed to start OpenTelemetry span: %s", exc)

        self._exported_spans.append(span)
        return span

    def record_evaluation_result(
        self,
        span: GCPTraceSpan,
        score: float,
        verdict: str,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> None:
        """Record evaluation score and token metrics on an active span and stream to Cloud Trace."""
        span.attributes["gen_ai.evaluation.score"] = score
        span.attributes["blackwall.verdict"] = verdict
        if input_tokens is not None:
            span.attributes["gen_ai.usage.input_tokens"] = input_tokens
        if output_tokens is not None:
            span.attributes["gen_ai.usage.output_tokens"] = output_tokens
        span.finish(status="OK")

        otel_span = getattr(span, "_otel_span", None)
        if otel_span is not None:
            try:
                from opentelemetry.trace import Status, StatusCode

                otel_span.set_attribute("gen_ai.evaluation.score", score)
                otel_span.set_attribute("blackwall.verdict", verdict)
                if input_tokens is not None:
                    otel_span.set_attribute("gen_ai.usage.input_tokens", input_tokens)
                if output_tokens is not None:
                    otel_span.set_attribute("gen_ai.usage.output_tokens", output_tokens)
                otel_span.set_status(Status(StatusCode.OK))
                otel_span.end(end_time=span.end_time_ns)
            except Exception as exc:
                logger.debug("Failed to end OpenTelemetry span: %s", exc)
        elif self._tracer is not None:
            try:
                from opentelemetry.trace import Status, StatusCode

                with self._tracer.start_as_current_span(
                    span.name,
                    start_time=span.start_time_ns,
                ) as otel_span_fallback:
                    for k, v in span.attributes.items():
                        if isinstance(v, (str, bool, int, float)):
                            otel_span_fallback.set_attribute(k, v)
                    otel_span_fallback.set_status(Status(StatusCode.OK))
            except Exception as exc:
                logger.debug("Failed to stream span to CloudTraceSpanExporter: %s", exc)

    def record_evaluation_error(
        self,
        span: GCPTraceSpan,
        error: Any,
        status: str = "ERROR",
    ) -> None:
        """Record evaluation error on an active span and stream error telemetry to Cloud Trace."""
        err_msg = str(error)
        span.attributes["error"] = err_msg
        span.attributes["blackwall.status"] = status
        span.finish(status=status)

        otel_span = getattr(span, "_otel_span", None)
        if otel_span is not None:
            try:
                from opentelemetry.trace import Status, StatusCode

                otel_span.set_attribute("error", err_msg)
                otel_span.set_attribute("blackwall.status", status)
                otel_span.set_status(Status(StatusCode.ERROR, description=err_msg))
                if isinstance(error, Exception):
                    otel_span.record_exception(error)
                otel_span.end(end_time=span.end_time_ns)
            except Exception as exc:
                logger.debug("Failed to end OpenTelemetry error span: %s", exc)
        elif self._tracer is not None:
            try:
                from opentelemetry.trace import Status, StatusCode

                with self._tracer.start_as_current_span(
                    span.name,
                    start_time=span.start_time_ns,
                ) as otel_span_fallback:
                    for k, v in span.attributes.items():
                        if isinstance(v, (str, bool, int, float)):
                            otel_span_fallback.set_attribute(k, v)
                    otel_span_fallback.set_status(Status(StatusCode.ERROR, description=err_msg))
                    if isinstance(error, Exception):
                        otel_span_fallback.record_exception(error)
            except Exception as exc:
                logger.debug("Failed to stream error span to CloudTraceSpanExporter: %s", exc)

    def flush(self) -> None:
        """Flush the span processor to send pending spans to Cloud Trace."""
        if self._span_processor is not None:
            try:
                self._span_processor.force_flush()
            except Exception as exc:
                logger.debug("Failed to flush Cloud Trace span processor: %s", exc)

    def clear(self) -> None:
        """Clear all in-memory spans."""
        self._exported_spans.clear()
