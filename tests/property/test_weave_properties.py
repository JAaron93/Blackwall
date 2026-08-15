"""Property-based tests for Weave Evaluation Tracking (Properties 82 - 88).

Validates: Requirements 16.2, 16.4, 16.5, 16.13, 17.2, 17.3, 17.4, 17.5.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.weave_config import (
    WeaveConfig,
    init_weave,
    should_enable_weave,
)
from blackwall.enterprise.advanced_threat_detection.weave_metrics import (
    WeaveMetricsCollector,
)
from blackwall.enterprise.advanced_threat_detection.weave_serializer import (
    WeaveTraceSerializer,
)


# ---------------------------------------------------------------------------
# Property 82: Weave Initialization Fallback
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    project_name=st.text(min_size=1, max_size=50).filter(lambda s: bool(s.strip())),
    disabled=st.booleans(),
)
def test_property_82_weave_initialization_fallback(
    project_name: str, disabled: bool
) -> None:
    """Property 82: init_weave gracefully returns False or True without raising exceptions."""
    with patch(
        "blackwall.enterprise.advanced_threat_detection.weave_config.should_enable_weave",
        return_value=not disabled,
    ):
        config = WeaveConfig(project_name=project_name)
        result = init_weave(config)
        assert isinstance(result, bool)
        if disabled:
            assert result is False


# ---------------------------------------------------------------------------
# Property 83: Weave Offline Mode Compliance
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    has_api_key=st.booleans(),
)
def test_property_83_weave_offline_mode_compliance(has_api_key: bool) -> None:
    """Property 83: WEAVE_OFFLINE=true enables Weave without API key, but WEAVE_DISABLED=true overrides it."""
    import os

    # When WEAVE_DISABLED is true, should_enable_weave() is always False
    with patch.dict(
        os.environ, {"WEAVE_DISABLED": "true", "WEAVE_OFFLINE": "true"}, clear=False
    ):
        assert should_enable_weave() is False

    # When WEAVE_DISABLED is unset and WEAVE_OFFLINE is true
    with patch.dict(os.environ, {"WEAVE_OFFLINE": "true"}, clear=False):
        os.environ.pop("WEAVE_DISABLED", None)
        if has_api_key:
            os.environ["WANDB_API_KEY"] = "dummy-key"
        else:
            os.environ.pop("WANDB_API_KEY", None)
        assert should_enable_weave() is True


# ---------------------------------------------------------------------------
# Property 84: Weave Metric Precision Calculation
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
)
def test_property_84_weave_precision_calculation(tp: int, fp: int) -> None:
    """Property 84: Precision = TP / (TP + FP) or 1.0 when no threats exist, 0.0 when threats exist but TP=0."""
    collector = WeaveMetricsCollector()
    scenario = f"sc-{uuid.uuid4()}"
    # Feed TP instances
    for _ in range(tp):
        collector.record_result(scenario, "det", True, True, 10.0)
    # Feed FP instances
    for _ in range(fp):
        collector.record_result(scenario, "det", False, True, 10.0)

    metrics = collector.compute_metrics(scenario)
    if tp + fp > 0:
        expected_prec = tp / (tp + fp)
    else:
        expected_prec = 1.0
    assert abs(metrics.precision - expected_prec) < 1e-6


# ---------------------------------------------------------------------------
# Property 85: Weave Metric Recall Calculation
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    tp=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
def test_property_85_weave_recall_calculation(tp: int, fn: int) -> None:
    """Property 85: Recall = TP / (TP + FN) or 1.0 when denominator is 0."""
    collector = WeaveMetricsCollector()
    scenario = f"sc-{uuid.uuid4()}"
    # Feed TP instances
    for _ in range(tp):
        collector.record_result(scenario, "det", True, True, 10.0)
    # Feed FN instances
    for _ in range(fn):
        collector.record_result(scenario, "det", True, False, 10.0)

    metrics = collector.compute_metrics(scenario)
    expected_recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    assert abs(metrics.recall - expected_recall) < 1e-6


# ---------------------------------------------------------------------------
# Property 86: Weave Metric F1 Score Calculation
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
def test_property_86_weave_f1_score_calculation(tp: int, fp: int, fn: int) -> None:
    """Property 86: F1 = 2 * (P * R) / (P + R) or 0.0 when P + R == 0."""
    collector = WeaveMetricsCollector()
    scenario = f"sc-{uuid.uuid4()}"
    for _ in range(tp):
        collector.record_result(scenario, "det", True, True, 10.0)
    for _ in range(fp):
        collector.record_result(scenario, "det", False, True, 10.0)
    for _ in range(fn):
        collector.record_result(scenario, "det", True, False, 10.0)

    metrics = collector.compute_metrics(scenario)
    if tp + fp > 0:
        p = tp / (tp + fp)
    else:
        p = 1.0 if tp + fn == 0 else 0.0

    r = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    expected_f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
    assert abs(metrics.f1_score - expected_f1) < 1e-6


# ---------------------------------------------------------------------------
# Property 87: Weave Metric FPR Calculation
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    fp=st.integers(min_value=0, max_value=500),
    tn=st.integers(min_value=0, max_value=500),
)
def test_property_87_weave_fpr_calculation(fp: int, tn: int) -> None:
    """Property 87: False Positive Rate (FPR) = FP / (FP + TN) or 0.0."""
    collector = WeaveMetricsCollector()
    scenario = f"sc-{uuid.uuid4()}"
    for _ in range(fp):
        collector.record_result(scenario, "det", False, True, 10.0)
    for _ in range(tn):
        collector.record_result(scenario, "det", False, False, 10.0)

    metrics = collector.compute_metrics(scenario)
    expected_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    assert abs(metrics.false_positive_rate - expected_fpr) < 1e-6


# ---------------------------------------------------------------------------
# Property 88: Weave Trace Parameter Logging & Sanitization
# ---------------------------------------------------------------------------
@settings(max_examples=50)
@given(
    agent_id=st.text(min_size=1, max_size=30).filter(lambda s: bool(s.strip())),
    action=st.text(min_size=1, max_size=30),
    target=st.text(min_size=1, max_size=30),
    secret_val=st.text(min_size=1, max_size=30),
)
def test_property_88_weave_trace_parameter_logging(
    agent_id: str, action: str, target: str, secret_val: str
) -> None:
    """Property 88: WeaveTraceSerializer drops action/target/raw metadata and redacts secret keys."""
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.PIPELINE_EXECUTION,
        agent_id=agent_id,
        action=action,
        target=target,
        risk_score=0.75,
        metadata={"api_key": secret_val, "safe_tag": "public"},
    )
    serialized = WeaveTraceSerializer.serialize_event(event)

    # Safe fields present
    assert "event_id" in serialized
    assert "timestamp" in serialized
    assert "source" in serialized
    assert "risk_score" in serialized

    # Unsafe / dropped fields strictly absent
    assert "action" not in serialized
    assert "target" not in serialized
    assert "metadata" not in serialized
    assert "prompt" not in serialized

    # Metadata masking verification
    masked = WeaveTraceSerializer.mask_metadata(event.metadata)
    assert masked["api_key"] == "**REDACTED**"
    assert masked["safe_tag"] == "public"
