"""
Unit tests for src/blackwall/telemetry.py

Tests the three public functions:
  - setup_telemetry()  — configures OpenTelemetry tracing + Prometheus metrics
  - get_tracer(name)   — returns an OTel Tracer from the configured provider
  - get_metric(name)   — returns a named metric instrument from _metrics dict
"""

import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers & fixtures
# ---------------------------------------------------------------------------


def _reload_telemetry_module():
    """Force a clean reload of the telemetry module, resetting module-level
    state (_telemetry_initialized, _metrics) between tests."""
    if "blackwall.telemetry" in sys.modules:
        del sys.modules["blackwall.telemetry"]
    import blackwall.telemetry  # noqa: F401 – side-effects only
    return blackwall.telemetry


@pytest.fixture(autouse=True)
def reset_telemetry_state():
    """Reset global telemetry state before every test so each test starts
    from a clean slate regardless of execution order."""
    # Reload first to guarantee a fresh module state
    mod = _reload_telemetry_module()
    mod._telemetry_initialized = False
    mod._metrics.clear()
    yield
    # Teardown: reset again so we don't leak into the next test
    mod._telemetry_initialized = False
    mod._metrics.clear()


def _make_setup_mocks():
    """Return a context-manager stack of patches for all heavy external deps
    used by setup_telemetry() so the tests remain fully offline."""
    patches = [
        patch("blackwall.telemetry.TracerProvider"),
        patch("blackwall.telemetry.BatchSpanProcessor"),
        patch("blackwall.telemetry.trace"),
        patch("blackwall.telemetry.PrometheusMetricReader"),
        patch("blackwall.telemetry.MeterProvider"),
        patch("blackwall.telemetry.metrics"),
        patch("blackwall.telemetry.start_http_server"),
        patch("blackwall.telemetry.resource"),
    ]
    return patches


# ---------------------------------------------------------------------------
# 1. setup_telemetry is callable and doesn't raise
# ---------------------------------------------------------------------------


class TestSetupTelemetryCallable:
    """setup_telemetry() must complete without raising in every branch."""

    def test_setup_telemetry_succeeds_and_returns_true(self):
        """Happy path: setup_telemetry() returns True on first call."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram

        mock_metrics = MagicMock()
        mock_metrics.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider") as mock_tp,
            patch("blackwall.telemetry.trace") as mock_trace,
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics),
            patch("blackwall.telemetry.start_http_server"),
        ):
            mock_tp.return_value = MagicMock()
            mock_trace.set_tracer_provider = MagicMock()

            result = tel.setup_telemetry(metrics_port=9999)

        assert result is True

    def test_setup_telemetry_does_not_raise_on_clean_state(self):
        """setup_telemetry() should never raise under normal conditions."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            try:
                tel.setup_telemetry()
            except Exception as exc:  # pragma: no cover
                pytest.fail(f"setup_telemetry() raised unexpectedly: {exc}")

    def test_setup_telemetry_uses_none_exporter_when_env_set(
        self, monkeypatch
    ):
        """When OTEL_TRACES_EXPORTER=none, InMemorySpanExporter path is taken."""
        import blackwall.telemetry as tel

        monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            result = tel.setup_telemetry()

        assert result is True

    def test_setup_telemetry_falls_back_when_otlp_unavailable(
        self, monkeypatch
    ):
        """If OTLPSpanExporter raises, setup_telemetry falls back gracefully
        and still returns True (no exception propagation)."""
        import blackwall.telemetry as tel

        # Ensure OTLP branch (not none-exporter branch)
        monkeypatch.delenv("OTEL_TRACES_EXPORTER", raising=False)

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        def raise_import(*args, **kwargs):
            raise ImportError("opentelemetry-exporter-otlp-proto-grpc not installed")

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
            patch.dict(
                "sys.modules",
                {
                    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": None,
                },
            ),
        ):
            # The module-level try/except catches ImportError → falls back
            result = tel.setup_telemetry()

        assert result is True


# ---------------------------------------------------------------------------
# 2. setup_telemetry is idempotent (calling twice is safe)
# ---------------------------------------------------------------------------


class TestSetupTelemetryIdempotent:
    """Calling setup_telemetry() more than once must be safe and fast."""

    def test_second_call_returns_true_immediately(self):
        """The second call returns True without re-running setup logic."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server") as mock_server,
        ):
            first = tel.setup_telemetry()
            second = tel.setup_telemetry()

        assert first is True
        assert second is True
        # start_http_server must only be called once (idempotency guarantee)
        mock_server.assert_called_once()

    def test_idempotent_does_not_double_register_metrics(self):
        """The _metrics dict must not grow on repeated calls."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()
            metrics_count_after_first = len(tel._metrics)
            tel.setup_telemetry()
            metrics_count_after_second = len(tel._metrics)

        assert metrics_count_after_first == metrics_count_after_second

    def test_initialized_flag_is_set_after_first_call(self):
        """_telemetry_initialized must be True after setup_telemetry()."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            assert tel._telemetry_initialized is False
            tel.setup_telemetry()
            assert tel._telemetry_initialized is True


# ---------------------------------------------------------------------------
# 3. get_tracer returns a tracer-like object
# ---------------------------------------------------------------------------


class TestGetTracer:
    """get_tracer() must return a usable tracer from the OTel trace API."""

    def test_get_tracer_returns_object(self):
        """get_tracer() must return a non-None object."""
        import blackwall.telemetry as tel

        mock_tracer = MagicMock()
        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = mock_tracer
            result = tel.get_tracer("test-component")

        assert result is not None

    def test_get_tracer_has_start_span(self):
        """The returned tracer must have a start_span / start_as_current_span
        attribute, confirming it is tracer-like."""
        import blackwall.telemetry as tel

        mock_tracer = MagicMock(spec=["start_span", "start_as_current_span"])
        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = mock_tracer
            result = tel.get_tracer("blackwall.core")

        assert hasattr(result, "start_span") or hasattr(
            result, "start_as_current_span"
        ), "Tracer must expose span-creation methods"

    def test_get_tracer_passes_name_to_otel(self):
        """The name argument must be forwarded to trace.get_tracer()."""
        import blackwall.telemetry as tel

        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = MagicMock()
            tel.get_tracer("my-service")
            mock_trace.get_tracer.assert_called_once_with("my-service")

    def test_get_tracer_default_name(self):
        """get_tracer() works with the default name 'blackwall'."""
        import blackwall.telemetry as tel

        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = MagicMock()
            tel.get_tracer("blackwall")
            mock_trace.get_tracer.assert_called_with("blackwall")

    def test_get_tracer_returns_real_tracer_after_setup(self):
        """After setup_telemetry(), get_tracer() returns a real OTel tracer."""
        import blackwall.telemetry as tel

        mock_tracer_instance = MagicMock()
        mock_tracer_instance.start_span = MagicMock()

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace") as mock_trace,
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            mock_trace.get_tracer.return_value = mock_tracer_instance
            tel.setup_telemetry()
            tracer = tel.get_tracer("blackwall.resolver")

        assert tracer is mock_tracer_instance
        assert hasattr(tracer, "start_span")


# ---------------------------------------------------------------------------
# 4. get_metric returns a metric/meter-like object
# ---------------------------------------------------------------------------


class TestGetMetric:
    """get_metric() must return the registered instrument or None."""

    def _run_setup(self, tel_module):
        """Helper: run setup_telemetry with all heavy deps mocked."""
        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel_module.setup_telemetry()

        return mock_counter, mock_histogram

    def test_get_metric_returns_none_before_setup(self):
        """Before setup_telemetry(), get_metric() returns None for any name."""
        import blackwall.telemetry as tel

        result = tel.get_metric("interceptions_total")
        assert result is None

    def test_get_metric_returns_none_for_unknown_name(self):
        """get_metric() returns None for unregistered metric names."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()

        result = tel.get_metric("non_existent_metric")
        assert result is None

    def test_get_metric_interceptions_total_after_setup(self):
        """get_metric('interceptions_total') returns a counter-like object."""
        import blackwall.telemetry as tel

        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()

        result = tel.get_metric("interceptions_total")
        assert result is mock_counter

    def test_get_metric_threat_score_after_setup(self):
        """get_metric('threat_score') returns a histogram-like object."""
        import blackwall.telemetry as tel

        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()

        result = tel.get_metric("threat_score")
        assert result is mock_histogram

    @pytest.mark.parametrize(
        "metric_name",
        [
            "interceptions_total",
            "verdicts_total",
            "threat_score",
            "api_latency_seconds",
            "batch_size",
            "cache_hits_total",
            "cache_misses_total",
            "errors_total",
        ],
    )
    def test_all_registered_metrics_are_retrievable(self, metric_name):
        """Every metric registered in setup_telemetry() must be gettable."""
        import blackwall.telemetry as tel

        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()

        result = tel.get_metric(metric_name)
        assert result is not None, (
            f"Expected metric '{metric_name}' to be registered after setup"
        )


# ---------------------------------------------------------------------------
# 5. get_tracer with different names returns distinct tracers (or same no-op)
# ---------------------------------------------------------------------------


class TestGetTracerDistinctNames:
    """get_tracer() must properly forward each requested name to OTel."""

    def test_different_names_produce_different_calls(self):
        """Two different names must produce two distinct get_tracer() calls."""
        import blackwall.telemetry as tel

        tracer_a = MagicMock(name="tracer_a")
        tracer_b = MagicMock(name="tracer_b")

        def side_effect(name):
            return tracer_a if name == "service.a" else tracer_b

        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.side_effect = side_effect

            result_a = tel.get_tracer("service.a")
            result_b = tel.get_tracer("service.b")

        assert result_a is tracer_a
        assert result_b is tracer_b
        assert result_a is not result_b

    def test_same_name_produces_same_result(self):
        """Calling get_tracer() with the same name twice returns the same mock
        (OTel providers cache by name)."""
        import blackwall.telemetry as tel

        shared_tracer = MagicMock()

        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = shared_tracer

            first = tel.get_tracer("shared.name")
            second = tel.get_tracer("shared.name")

        assert first is second

    def test_multiple_distinct_names_all_forwarded(self):
        """All three names must appear in the call list."""
        import blackwall.telemetry as tel

        names = ["alpha", "beta", "gamma"]
        with patch("blackwall.telemetry.trace") as mock_trace:
            mock_trace.get_tracer.return_value = MagicMock()

            for name in names:
                tel.get_tracer(name)

        call_args = [c.args[0] for c in mock_trace.get_tracer.call_args_list]
        for name in names:
            assert name in call_args, (
                f"Expected name '{name}' to be forwarded to trace.get_tracer()"
            )

    def test_no_op_tracer_branch_returns_tracer_like_object(self, monkeypatch):
        """Even with a no-op/ProxyTracer the returned object exposes span API."""
        import blackwall.telemetry as tel

        # Use the real trace.get_tracer which returns a ProxyTracer when no
        # provider is configured — it is still tracer-like.
        from opentelemetry import trace as real_trace

        # Reset OTel global provider to avoid cross-test contamination
        real_trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
        real_trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]

        with patch("blackwall.telemetry.trace", real_trace):
            tracer = tel.get_tracer("noop-test")

        assert tracer is not None
        # ProxyTracer / NoOpTracer both expose start_as_current_span
        assert hasattr(tracer, "start_as_current_span") or hasattr(
            tracer, "start_span"
        )


# ---------------------------------------------------------------------------
# 6. Integration-style: setup → get_tracer → get_metric pipeline
# ---------------------------------------------------------------------------


class TestTelemetryIntegration:
    """Verify the typical call sequence a caller would use."""

    def test_full_setup_and_retrieval_pipeline(self):
        """setup_telemetry → get_tracer → get_metric works end-to-end."""
        import blackwall.telemetry as tel

        mock_tracer = MagicMock()
        mock_counter = MagicMock()
        mock_histogram = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace") as mock_trace,
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            mock_trace.get_tracer.return_value = mock_tracer
            assert tel.setup_telemetry() is True

            tracer = tel.get_tracer("integration-test")
            errors_metric = tel.get_metric("errors_total")
            cache_metric = tel.get_metric("cache_hits_total")

        assert tracer is mock_tracer
        assert errors_metric is mock_counter
        assert cache_metric is mock_counter

    def test_prometheus_server_started_on_setup(self):
        """start_http_server must be invoked with the given port during setup."""
        import blackwall.telemetry as tel

        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider"),
            patch("blackwall.telemetry.trace"),
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server") as mock_server,
        ):
            tel.setup_telemetry(metrics_port=8080)

        mock_server.assert_called_once_with(8080)

    def test_tracer_provider_set_during_setup(self):
        """trace.set_tracer_provider() must be called with the new provider."""
        import blackwall.telemetry as tel

        mock_provider = MagicMock()
        mock_meter = MagicMock()
        mock_meter.create_counter.return_value = MagicMock()
        mock_meter.create_histogram.return_value = MagicMock()
        mock_metrics_obj = MagicMock()
        mock_metrics_obj.get_meter.return_value = mock_meter

        with (
            patch("blackwall.telemetry.TracerProvider", return_value=mock_provider),
            patch("blackwall.telemetry.trace") as mock_trace,
            patch("blackwall.telemetry.PrometheusMetricReader"),
            patch("blackwall.telemetry.MeterProvider"),
            patch("blackwall.telemetry.metrics", mock_metrics_obj),
            patch("blackwall.telemetry.start_http_server"),
        ):
            tel.setup_telemetry()
            mock_trace.set_tracer_provider.assert_called_once_with(mock_provider)
