"""Threat Detection Metrics computation and Weave Metrics Collector.

Subtask 22.4: WeaveMetricsCollector for Aggregated Metrics.
Requirement 19.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

try:
    import weave
except ImportError:  # pragma: no cover
    weave = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class ThreatDetectionMetrics:
    """Aggregated metrics for threat detection quality and latency."""

    scenario_id: str
    precision: float = 1.0
    recall: float = 1.0
    f1_score: float = 1.0
    false_positive_rate: float = 0.0
    detection_latency_ms: float = 0.0
    per_detector_accuracy: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary representation."""
        return asdict(self)


@dataclass
class _Record:
    detector: str
    actual: bool
    predicted: bool
    latency_ms: float


class WeaveMetricsCollector:
    """Collector aggregating threat detection evaluation records into metrics."""

    def __init__(self) -> None:
        self._records: dict[str, list[_Record]] = {}

    def record_result(
        self,
        scenario_id: str,
        detector: str,
        actual_threat: bool,
        predicted_threat: bool,
        latency_ms: float = 0.0,
    ) -> None:
        """Record an individual detector outcome for a scenario."""
        if scenario_id not in self._records:
            self._records[scenario_id] = []
        self._records[scenario_id].append(
            _Record(
                detector=detector,
                actual=bool(actual_threat),
                predicted=bool(predicted_threat),
                latency_ms=float(latency_ms),
            )
        )

    def compute_metrics(self, scenario_id: str) -> ThreatDetectionMetrics:
        """Compute aggregated precision, recall, f1, FPR, latency, and per-detector accuracy."""
        records = self._records.get(scenario_id, [])
        if not records:
            return ThreatDetectionMetrics(scenario_id=scenario_id)

        tp = sum(1 for r in records if r.actual and r.predicted)
        fp = sum(1 for r in records if not r.actual and r.predicted)
        fn = sum(1 for r in records if r.actual and not r.predicted)
        tn = sum(1 for r in records if not r.actual and not r.predicted)

        # Precision = TP / (TP + FP)
        if tp + fp > 0:
            precision = tp / (tp + fp)
        else:
            precision = 1.0 if tp + fn == 0 else 0.0

        # Recall = TP / (TP + FN)
        if tp + fn > 0:
            recall = tp / (tp + fn)
        else:
            recall = 1.0

        # F1 Score = 2 * (precision * recall) / (precision + recall)
        if precision + recall > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
        else:
            f1_score = 0.0

        # False Positive Rate = FP / (FP + TN)
        if fp + tn > 0:
            fpr = fp / (fp + tn)
        else:
            fpr = 0.0

        # Latency
        avg_latency = sum(r.latency_ms for r in records) / len(records)

        # Per-detector accuracy
        per_detector: dict[str, list[_Record]] = {}
        for r in records:
            per_detector.setdefault(r.detector, []).append(r)

        per_detector_acc: dict[str, float] = {}
        for det_name, det_records in per_detector.items():
            correct = sum(1 for r in det_records if r.actual == r.predicted)
            per_detector_acc[det_name] = correct / len(det_records) if det_records else 0.0

        return ThreatDetectionMetrics(
            scenario_id=scenario_id,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            false_positive_rate=fpr,
            detection_latency_ms=avg_latency,
            per_detector_accuracy=per_detector_acc,
        )

    def publish_metrics(
        self,
        scenario_id: str,
        harness: Any | None = None,
    ) -> dict[str, Any]:
        """Compute metrics for scenario and publish to Weave / harness."""
        metrics = self.compute_metrics(scenario_id)
        data = metrics.to_dict()

        if harness is not None and hasattr(harness, "track_detection_metrics"):
            harness.track_detection_metrics(scenario_id, data)
        elif weave is not None:
            try:
                if hasattr(weave, "publish"):
                    weave.publish(data)
                elif hasattr(weave, "log"):
                    weave.log(data)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to publish metrics to Weave: %s", exc)

        return data
