"""
Property-based tests for GCP Vertex AI Evaluation Engine (Task 22).

Properties tested:
- Property 82: Vertex Evaluation Metric Precision Calculation
- Property 83: Vertex Evaluation Metric Recall Calculation
- Property 84: Vertex Evaluation Metric F1 Score Calculation
- Property 85: Vertex Evaluation Metric FPR Calculation
"""

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexEvalConfig,
    GCPVertexEvalMetrics,
)


# ---------------------------------------------------------------------------
# Property 82: Precision Calculation
# ---------------------------------------------------------------------------


@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
    tn=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
@settings(max_examples=100)
def test_property_82_precision_calculation(tp: int, fp: int, tn: int, fn: int):
    """Property 82: Precision calculation is bounded [0.0, 1.0] and matches formula."""
    metrics = GCPVertexEvalMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        total_events=tp + fp + tn + fn,
    )
    p = metrics.precision
    assert 0.0 <= p <= 1.0
    if tp + fp > 0:
        assert pytest.approx(p, 0.0001) == tp / (tp + fp)
    else:
        assert p == 1.0


# ---------------------------------------------------------------------------
# Property 83: Recall Calculation
# ---------------------------------------------------------------------------


@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
    tn=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
@settings(max_examples=100)
def test_property_83_recall_calculation(tp: int, fp: int, tn: int, fn: int):
    """Property 83: Recall calculation is bounded [0.0, 1.0] and matches formula."""
    metrics = GCPVertexEvalMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        total_events=tp + fp + tn + fn,
    )
    r = metrics.recall
    assert 0.0 <= r <= 1.0
    if tp + fn > 0:
        assert pytest.approx(r, 0.0001) == tp / (tp + fn)
    else:
        assert r == 1.0


# ---------------------------------------------------------------------------
# Property 84: F1 Score Calculation
# ---------------------------------------------------------------------------


@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
    tn=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
@settings(max_examples=100)
def test_property_84_f1_score_calculation(tp: int, fp: int, tn: int, fn: int):
    """Property 84: F1 score is bounded [0.0, 1.0] and matches harmonic mean."""
    metrics = GCPVertexEvalMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        total_events=tp + fp + tn + fn,
    )
    f1 = metrics.f1_score
    assert 0.0 <= f1 <= 1.0
    p = metrics.precision
    r = metrics.recall
    if p + r > 0:
        expected = 2.0 * (p * r) / (p + r)
        assert pytest.approx(f1, 0.0001) == expected


# ---------------------------------------------------------------------------
# Property 85: False Positive Rate (FPR) Calculation
# ---------------------------------------------------------------------------


@given(
    tp=st.integers(min_value=0, max_value=500),
    fp=st.integers(min_value=0, max_value=500),
    tn=st.integers(min_value=0, max_value=500),
    fn=st.integers(min_value=0, max_value=500),
)
@settings(max_examples=100)
def test_property_85_fpr_calculation(tp: int, fp: int, tn: int, fn: int):
    """Property 85: FPR calculation is bounded [0.0, 1.0] and matches formula."""
    metrics = GCPVertexEvalMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        total_events=tp + fp + tn + fn,
    )
    fpr = metrics.false_positive_rate
    assert 0.0 <= fpr <= 1.0
    if fp + tn > 0:
        assert pytest.approx(fpr, 0.0001) == fp / (fp + tn)
    else:
        assert fpr == 0.0


# ---------------------------------------------------------------------------
# Model Validation & Rejection Testing
# ---------------------------------------------------------------------------


@given(invalid_str=st.text().filter(lambda s: not s.strip()))
def test_property_config_rejection(invalid_str: str):
    """Verify invalid whitespace strings are rejected by GCPVertexEvalConfig."""
    with pytest.raises((ValidationError, ValueError)):
        GCPVertexEvalConfig(project_id=invalid_str)
