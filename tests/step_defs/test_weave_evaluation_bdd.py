"""BDD Step definitions for Weave evaluation tracking features."""

import uuid
from datetime import UTC, datetime

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.enterprise.advanced_threat_detection.weave_config import (
    should_enable_weave,
)
from blackwall.enterprise.advanced_threat_detection.weave_metrics import (
    ThreatDetectionMetrics,
    WeaveMetricsCollector,
)
from blackwall.enterprise.advanced_threat_detection.weave_serializer import (
    WeaveTraceSerializer,
)

scenarios("../features/weave_evaluation_tracking.feature")


@pytest.fixture
def bdd_context() -> dict:
    return {}


@given(parsers.parse('the environment variable "{name}" is set to "{val}"'))
def set_env_var(monkeypatch: pytest.MonkeyPatch, name: str, val: str) -> None:
    monkeypatch.setenv(name, val)


@given(parsers.parse('the environment variable "{name}" is not set'))
def unset_env_var(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.delenv(name, raising=False)


@when("checking if Weave should be enabled")
def check_weave_enabled(bdd_context: dict) -> None:
    bdd_context["weave_enabled"] = should_enable_weave()


@then("Weave is enabled")
def assert_weave_enabled(bdd_context: dict) -> None:
    assert bdd_context["weave_enabled"] is True


@then("Weave is disabled")
def assert_weave_disabled(bdd_context: dict) -> None:
    assert bdd_context["weave_enabled"] is False


@given("a normalized security event with secret tokens and raw actions")
def make_security_event(bdd_context: dict) -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    bdd_context["event"] = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.PIPELINE_EXECUTION,
        agent_id="eval-agent-1",
        action="cat /etc/shadow",
        target="/etc/shadow",
        risk_score=0.9,
        metadata={"auth_token": "secret123", "normal": "ok"},
    )


@when("the event is serialized for Weave tracing")
def serialize_event_for_weave(bdd_context: dict) -> None:
    event = bdd_context["event"]
    bdd_context["serialized"] = WeaveTraceSerializer.serialize_event(event)
    bdd_context["masked_meta"] = WeaveTraceSerializer.mask_metadata(event.metadata)


@then("raw action and target fields are excluded")
def assert_action_target_excluded(bdd_context: dict) -> None:
    serialized = bdd_context["serialized"]
    assert "action" not in serialized
    assert "target" not in serialized
    assert "metadata" not in serialized


@then("the event ID and timestamp are preserved")
def assert_id_ts_preserved(bdd_context: dict) -> None:
    serialized = bdd_context["serialized"]
    assert serialized["event_id"] == str(bdd_context["event"].event_id)
    assert "timestamp" in serialized


@then("sensitive metadata keys are redacted")
def assert_metadata_redacted(bdd_context: dict) -> None:
    masked = bdd_context["masked_meta"]
    assert masked["auth_token"] == "**REDACTED**"
    assert masked["normal"] == "ok"


@given(parsers.parse("a scenario evaluation with {tp:d} true positives {fp:d} false positives and {fn:d} false negatives"))
def record_evaluation_confusion_matrix(bdd_context: dict, tp: int, fp: int, fn: int) -> None:
    collector = WeaveMetricsCollector()
    scenario = "bdd-scenario"
    for _ in range(tp):
        collector.record_result(scenario, "det", True, True, 10.0)
    for _ in range(fp):
        collector.record_result(scenario, "det", False, True, 10.0)
    for _ in range(fn):
        collector.record_result(scenario, "det", True, False, 10.0)
    bdd_context["collector"] = collector
    bdd_context["scenario"] = scenario


@when("detection metrics are computed")
def compute_bdd_metrics(bdd_context: dict) -> None:
    collector: WeaveMetricsCollector = bdd_context["collector"]
    bdd_context["metrics"] = collector.compute_metrics(bdd_context["scenario"])


@then(parsers.parse("the precision is approximately {prec:f}"))
def assert_precision_approx(bdd_context: dict, prec: float) -> None:
    metrics: ThreatDetectionMetrics = bdd_context["metrics"]
    assert abs(metrics.precision - prec) < 0.01


@then(parsers.parse("the recall is approximately {rec:f}"))
def assert_recall_approx(bdd_context: dict, rec: float) -> None:
    metrics: ThreatDetectionMetrics = bdd_context["metrics"]
    assert abs(metrics.recall - rec) < 0.01


@then(parsers.parse("the F1 score is approximately {f1:f}"))
def assert_f1_approx(bdd_context: dict, f1: float) -> None:
    metrics: ThreatDetectionMetrics = bdd_context["metrics"]
    assert abs(metrics.f1_score - f1) < 0.01
