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

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GCPTraceSpan(BaseModel):
    """Structured representation of an OpenTelemetry GenAI evaluation span."""

    name: str = Field(description="Span operation name (e.g. vertex_eval.interception).")
    start_time_ns: int = Field(default_factory=lambda: time.time_ns())
    end_time_ns: Optional[int] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    status_code: str = Field(default="OK")

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
        self.project_id = project_id or os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "blackwall-cloud-project"
        if export_to_cloud is not None:
            self._export_to_cloud = export_to_cloud
        else:
            self._export_to_cloud = os.getenv("BLACKWALL_DISABLE_CLOUD_TRACE", "false").lower() != "true"
        self._exported_spans: List[GCPTraceSpan] = []
        self._is_cloud_trace_available = False
        self._tracer_provider: Any = None
        self._cloud_trace_exporter: Any = None
        self._span_processor: Any = None
        self._tracer: Any = None
        self._init_cloud_trace()

    def _init_cloud_trace(self) -> bool:
        """Initialize Google Cloud Trace OpenTelemetry exporter if installed."""
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            self._tracer_provider = TracerProvider()
            if self._export_to_cloud:
                try:
                    self._cloud_trace_exporter = CloudTraceSpanExporter(project_id=self.project_id)
                    self._span_processor = BatchSpanProcessor(self._cloud_trace_exporter)
                    self._tracer_provider.add_span_processor(self._span_processor)
                except Exception as exc:
                    logger.debug("Could not attach CloudTraceSpanExporter (%s); using in-memory tracer", exc)
            self._tracer = self._tracer_provider.get_tracer("blackwall.evaluation")

            self._is_cloud_trace_available = True
            logger.info("Google Cloud Trace OpenTelemetry exporter available and configured for project %s", self.project_id)
            return True
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

        if self._tracer is not None:
            try:
                with self._tracer.start_as_current_span(span.name) as otel_span:
                    for k, v in span.attributes.items():
                        if isinstance(v, (str, bool, int, float)):
                            otel_span.set_attribute(k, v)
            except Exception as exc:
                logger.debug("Failed to stream span to CloudTraceSpanExporter: %s", exc)

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
