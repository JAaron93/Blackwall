"""
Unit tests for Historical Regression Tracker (Track D.3 / Task D.3.1).

Verifies:
- Persistence of evaluation run summaries to JSONL file.
- Loading of latest run as comparison baseline.
- Regression detection when any domain mean drops > 0.5.
- Querying last N runs via get_history(n).
"""

import json
from pathlib import Path
import pytest
from blackwall.eval.regression_tracker import (
    EvalRunSummary,
    HistoricalRegressionTracker,
    RegressionReport,
)


def test_first_run_stores_baseline(tmp_path: Path):
    """Verify first evaluation run is recorded as baseline without regression."""
    history_file = tmp_path / "history.jsonl"
    tracker = HistoricalRegressionTracker(history_path=history_file)

    run1 = EvalRunSummary(
        run_id="run-001",
        domain_means={"threat_interception": 4.5, "c2_detection": 4.0},
        overall_mean=4.25,
    )

    report = tracker.record_and_compare(run1)
    assert report.is_baseline is True
    assert report.regression_detected is False
    assert report.baseline_run_id is None
    assert len(tracker.get_history()) == 1


def test_improved_run_reports_no_regression(tmp_path: Path):
    """Verify second run with equal or higher scores reports no regression."""
    history_file = tmp_path / "history.jsonl"
    tracker = HistoricalRegressionTracker(history_path=history_file)

    run1 = EvalRunSummary(
        run_id="run-001",
        domain_means={"threat_interception": 4.0, "c2_detection": 4.0},
        overall_mean=4.0,
    )
    tracker.record_and_compare(run1)

    run2 = EvalRunSummary(
        run_id="run-002",
        domain_means={"threat_interception": 4.5, "c2_detection": 4.2},
        overall_mean=4.35,
    )
    report = tracker.record_and_compare(run2)

    assert report.is_baseline is False
    assert report.baseline_run_id == "run-001"
    assert report.regression_detected is False
    assert report.domain_deltas["threat_interception"] == pytest.approx(0.5)
    assert report.domain_deltas["c2_detection"] == pytest.approx(0.2)


def test_regressed_run_flags_regression(tmp_path: Path):
    """Verify run with domain mean drop > 0.5 flags regression."""
    history_file = tmp_path / "history.jsonl"
    tracker = HistoricalRegressionTracker(history_path=history_file)

    run1 = EvalRunSummary(
        run_id="run-001",
        domain_means={"threat_interception": 4.8, "c2_detection": 4.5},
        overall_mean=4.65,
    )
    tracker.record_and_compare(run1)

    # threat_interception drops from 4.8 to 4.2 (drop = 0.6 > 0.5)
    run2 = EvalRunSummary(
        run_id="run-002",
        domain_means={"threat_interception": 4.2, "c2_detection": 4.5},
        overall_mean=4.35,
    )
    report = tracker.record_and_compare(run2)

    assert report.is_baseline is False
    assert report.regression_detected is True
    assert "threat_interception" in report.regressed_domains
    assert report.regressed_domains["threat_interception"] == pytest.approx(-0.6)


def test_get_history_limit(tmp_path: Path):
    """Verify get_history(n) returns last N runs in chronological order."""
    history_file = tmp_path / "history.jsonl"
    tracker = HistoricalRegressionTracker(history_path=history_file)

    for i in range(5):
        run = EvalRunSummary(
            run_id=f"run-{i:03d}",
            domain_means={"threat_interception": 4.0 + i * 0.1},
            overall_mean=4.0 + i * 0.1,
        )
        tracker.record_and_compare(run)

    assert len(tracker.get_history()) == 5
    last_3 = tracker.get_history(3)
    assert len(last_3) == 3
    assert [r.run_id for r in last_3] == ["run-002", "run-003", "run-004"]


def test_partial_baseline_does_not_hide_regression(tmp_path: Path):
    """Verify that an intermediate partial baseline does not hide regressions for absent domains."""
    history_file = tmp_path / "history.jsonl"
    tracker = HistoricalRegressionTracker(history_path=history_file)

    # Run 1: evaluates threat_interception=4.9 and c2_detection=4.5
    run1 = EvalRunSummary(
        run_id="run-001",
        domain_means={"threat_interception": 4.9, "c2_detection": 4.5},
        overall_mean=4.7,
    )
    tracker.record_and_compare(run1)

    # Run 2: partial selective run evaluating ONLY c2_detection=4.6
    run2 = EvalRunSummary(
        run_id="run-002",
        domain_means={"c2_detection": 4.6},
        overall_mean=4.6,
    )
    tracker.record_and_compare(run2)

    # Run 3: evaluates threat_interception=4.2 (drop = 0.7 from run-001)
    run3 = EvalRunSummary(
        run_id="run-003",
        domain_means={"threat_interception": 4.2},
        overall_mean=4.2,
    )
    report = tracker.record_and_compare(run3)

    assert report.is_baseline is False
    assert report.regression_detected is True
    assert "threat_interception" in report.regressed_domains
    assert report.regressed_domains["threat_interception"] == pytest.approx(-0.7)
