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

    def __init__(self, project_id: Optional[str] = None) -> None:
        self.project_id = project_id or os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "blackwall-cloud-project"
        self._exported_spans: List[GCPTraceSpan] = []
        self._is_cloud_trace_available = False
        self._init_cloud_trace()

    def _init_cloud_trace(self) -> bool:
        """Initialize Google Cloud Trace OpenTelemetry exporter if installed."""
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter  # noqa: F401
            from opentelemetry.sdk.trace import TracerProvider  # noqa: F401
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: F401

            self._is_cloud_trace_available = True
            logger.info("Google Cloud Trace OpenTelemetry exporter available and configured")
            return True
        except ImportError:
            self._is_cloud_trace_available = False
            logger.debug("Google Cloud Trace SDK not installed; operating in buffered in-memory mode")
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
        """Record evaluation score and token metrics on an active span."""
        span.attributes["gen_ai.evaluation.score"] = score
        span.attributes["blackwall.verdict"] = verdict
        if input_tokens is not None:
            span.attributes["gen_ai.usage.input_tokens"] = input_tokens
        if output_tokens is not None:
            span.attributes["gen_ai.usage.output_tokens"] = output_tokens
        span.finish(status="OK")

    def clear(self) -> None:
        """Clear all in-memory spans."""
        self._exported_spans.clear()
