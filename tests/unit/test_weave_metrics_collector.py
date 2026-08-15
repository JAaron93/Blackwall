"""Unit tests for ThreatDetectionMetrics and WeaveMetricsCollector (Subtask 22.4, Requirement 19)."""

from unittest.mock import MagicMock

import pytest

from blackwall.enterprise.advanced_threat_detection.weave_metrics import (
    WeaveMetricsCollector,
)


def test_metrics_collector_empty() -> None:
    collector = WeaveMetricsCollector()
    metrics = collector.compute_metrics("empty-scenario")
    assert metrics.scenario_id == "empty-scenario"
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.detection_latency_ms == 0.0
    assert metrics.per_detector_accuracy == {}


def test_metrics_collector_confusion_matrix() -> None:
    collector = WeaveMetricsCollector()
    # 2 TP
    collector.record_result(
        "sc-1", "detector_a", actual_threat=True, predicted_threat=True, latency_ms=10.0
    )
    collector.record_result(
        "sc-1", "detector_a", actual_threat=True, predicted_threat=True, latency_ms=20.0
    )
    # 1 FP
    collector.record_result(
        "sc-1",
        "detector_a",
        actual_threat=False,
        predicted_threat=True,
        latency_ms=15.0,
    )
    # 1 FN
    collector.record_result(
        "sc-1",
        "detector_b",
        actual_threat=True,
        predicted_threat=False,
        latency_ms=25.0,
    )
    # 1 TN
    collector.record_result(
        "sc-1",
        "detector_b",
        actual_threat=False,
        predicted_threat=False,
        latency_ms=30.0,
    )

    metrics = collector.compute_metrics("sc-1")
    # TP=2, FP=1, FN=1, TN=1
    # Precision = 2 / (2 + 1) = 2/3 ~ 0.6667
    assert pytest.approx(metrics.precision, 0.01) == 2 / 3
    # Recall = 2 / (2 + 1) = 2/3 ~ 0.6667
    assert pytest.approx(metrics.recall, 0.01) == 2 / 3
    # F1 = 2 * (2/3 * 2/3) / (4/3) = 2/3
    assert pytest.approx(metrics.f1_score, 0.01) == 2 / 3
    # FPR = FP / (FP + TN) = 1 / (1 + 1) = 0.5
    assert pytest.approx(metrics.false_positive_rate, 0.01) == 0.5
    # Avg latency = (10 + 20 + 15 + 25 + 30) / 5 = 20.0
    assert pytest.approx(metrics.detection_latency_ms, 0.01) == 20.0

    # Per detector accuracy
    # detector_a: 3 total, 2 correct (2 TP) -> 2/3 ~ 0.6667
    assert pytest.approx(metrics.per_detector_accuracy["detector_a"], 0.01) == 2 / 3
    # detector_b: 2 total, 1 correct (1 TN) -> 0.5
    assert pytest.approx(metrics.per_detector_accuracy["detector_b"], 0.01) == 0.5


def test_publish_metrics_with_harness() -> None:
    collector = WeaveMetricsCollector()
    collector.record_result(
        "sc-pub", "det_1", actual_threat=True, predicted_threat=True, latency_ms=5.0
    )

    mock_harness = MagicMock()
    res = collector.publish_metrics("sc-pub", harness=mock_harness)

    assert isinstance(res, dict)
    assert res["scenario_id"] == "sc-pub"
    mock_harness.track_detection_metrics.assert_called_once_with("sc-pub", res)
