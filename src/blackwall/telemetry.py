import logging
import os
from typing import Any, Dict

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import start_http_server

logger = logging.getLogger(__name__)

_telemetry_initialized = False
_metrics: Dict[str, Any] = {}

# Resource attributes
resource = Resource.create({"service.name": "blackwall-agentic-firewall"})

def setup_telemetry(metrics_port: int = 8000) -> bool:
    """Initialize OpenTelemetry tracing and Prometheus metrics."""
    global _telemetry_initialized
    if _telemetry_initialized:
        return True

    # 1. Tracing Setup (OTLP)
    trace_provider = TracerProvider(resource=resource)
    
    # Configure OTLP Exporter with gzip compression
    # We explicitly set compression="gzip" here to meet the requirement.
    # Note: grpc compression options are passed differently depending on version.
    # Passing no arguments relies on environment variables like OTEL_EXPORTER_OTLP_COMPRESSION=gzip.
    # To be explicit, we set it in the environment if not already set.
    if "OTEL_EXPORTER_OTLP_COMPRESSION" not in os.environ:
        os.environ["OTEL_EXPORTER_OTLP_COMPRESSION"] = "gzip"
        
    otlp_exporter = OTLPSpanExporter()
    
    span_processor = BatchSpanProcessor(otlp_exporter)
    trace_provider.add_span_processor(span_processor)
    trace.set_tracer_provider(trace_provider)

    # 2. Metrics Setup (Prometheus)
    # Start Prometheus metrics server in a background thread
    start_http_server(metrics_port)
    
    metric_reader = PrometheusMetricReader()
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    
    # Initialize metric instruments
    meter = metrics.get_meter("blackwall.metrics")
    
    _metrics["interceptions_total"] = meter.create_counter(
        "blackwall_interceptions_total",
        description="Total number of tool calls intercepted",
    )
    
    _metrics["verdicts_total"] = meter.create_counter(
        "blackwall_verdicts_total",
        description="Total verdicts assigned by type",
    )
    
    _metrics["threat_score"] = meter.create_histogram(
        "blackwall_threat_score",
        description="Distribution of threat scores",
    )
    
    _metrics["api_latency_seconds"] = meter.create_histogram(
        "blackwall_api_latency_seconds",
        description="API latency in seconds for resolving batches",
    )
    
    _metrics["batch_size"] = meter.create_histogram(
        "blackwall_batch_size",
        description="Number of callbacks in a resolved batch",
    )
    
    _metrics["cache_hits_total"] = meter.create_counter(
        "blackwall_cache_hits_total",
        description="Total number of cache hits",
    )
    
    _metrics["cache_misses_total"] = meter.create_counter(
        "blackwall_cache_misses_total",
        description="Total number of cache misses",
    )
    
    _metrics["errors_total"] = meter.create_counter(
        "blackwall_errors_total",
        description="Total number of errors encountered",
    )
    
    _telemetry_initialized = True
    logger.info("Telemetry initialized with Prometheus endpoint on port %d", metrics_port)
    return True


def get_tracer(name: str = "blackwall") -> trace.Tracer:
    """Get an OpenTelemetry tracer."""
    return trace.get_tracer(name)


def get_metric(name: str):
    """Retrieve an initialized metric instrument."""
    return _metrics.get(name)
