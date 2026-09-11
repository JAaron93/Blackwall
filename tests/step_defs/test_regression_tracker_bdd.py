"""
BDD step definitions for Historical Regression Tracker (`tests/features/regression_tracker.feature`).
"""

from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.eval.regression_tracker import (
    EvalRunSummary,
    HistoricalRegressionTracker,
    RegressionReport,
)

scenarios("../features/regression_tracker.feature")


class TrackerBDDState:
    def __init__(self, tmp_path: Path) -> None:
        self.history_file = tmp_path / "history.jsonl"
        self.tracker = HistoricalRegressionTracker(history_path=self.history_file)
        self.last_report: RegressionReport | None = None
        self.queried_history: list[EvalRunSummary] = []


@pytest.fixture
def bdd_state(tmp_path: Path) -> TrackerBDDState:
    return TrackerBDDState(tmp_path)


# ---------------------------------------------------------------------------
# Given Steps
# ---------------------------------------------------------------------------


@given("an empty evaluation history repository")
def given_empty_history(bdd_state: TrackerBDDState) -> None:
    if bdd_state.history_file.exists():
        bdd_state.history_file.unlink()
    bdd_state.tracker = HistoricalRegressionTracker(history_path=bdd_state.history_file)


@given(
    parsers.parse(
        'a historical evaluation baseline "{run_id}" with threat_interception {score1:f} and c2_detection {score2:f}'
    )
)
def given_baseline_scores(bdd_state: TrackerBDDState, run_id: str, score1: float, score2: float) -> None:
    domain_means = {
        "threat_interception": score1,
        "c2_detection": score2,
    }
    overall = (score1 + score2) / 2.0
    run = EvalRunSummary(run_id=run_id, domain_means=domain_means, overall_mean=overall)
    bdd_state.tracker.record_and_compare(run)


@given("a history containing 5 evaluation runs")
def given_five_runs_in_history(bdd_state: TrackerBDDState) -> None:
    for i in range(5):
        run = EvalRunSummary(
            run_id=f"run-{i:03d}",
            domain_means={"threat_interception": 4.0 + i * 0.1},
            overall_mean=4.0 + i * 0.1,
        )
        bdd_state.tracker.record_and_compare(run)


# ---------------------------------------------------------------------------
# When Steps
# ---------------------------------------------------------------------------


@when(
    parsers.parse(
        'an evaluation run "{run_id}" with threat_interception {score1:f} and c2_detection {score2:f} completes'
    )
)
def when_run_completes(bdd_state: TrackerBDDState, run_id: str, score1: float, score2: float) -> None:
    domain_means = {
        "threat_interception": score1,
        "c2_detection": score2,
    }
    overall = (score1 + score2) / 2.0
    run = EvalRunSummary(run_id=run_id, domain_means=domain_means, overall_mean=overall)
    bdd_state.last_report = bdd_state.tracker.record_and_compare(run)


@when("querying the last 3 runs")
def when_query_last_three_runs(bdd_state: TrackerBDDState) -> None:
    bdd_state.queried_history = bdd_state.tracker.get_history(limit=3)


# ---------------------------------------------------------------------------
# Then Steps
# ---------------------------------------------------------------------------


@then("the run should be recorded as a baseline")
def then_recorded_as_baseline(bdd_state: TrackerBDDState) -> None:
    assert bdd_state.last_report is not None
    assert bdd_state.last_report.is_baseline is True


@then("no regression should be detected")
def then_no_regression_detected(bdd_state: TrackerBDDState) -> None:
    assert bdd_state.last_report is not None
    assert bdd_state.last_report.regression_detected is False


@then(parsers.parse('the domain delta for "{domain}" should be {expected_delta:f}'))
def then_domain_delta_matches(bdd_state: TrackerBDDState, domain: str, expected_delta: float) -> None:
    assert bdd_state.last_report is not None
    assert domain in bdd_state.last_report.domain_deltas
    assert bdd_state.last_report.domain_deltas[domain] == pytest.approx(expected_delta)


@then("a regression should be detected")
def then_regression_detected(bdd_state: TrackerBDDState) -> None:
    assert bdd_state.last_report is not None
    assert bdd_state.last_report.regression_detected is True


@then(parsers.parse('"{domain}" should be in the regressed domains list'))
def then_domain_in_regressed_list(bdd_state: TrackerBDDState, domain: str) -> None:
    assert bdd_state.last_report is not None
    assert domain in bdd_state.last_report.regressed_domains


@then("exactly 3 runs should be returned in chronological order")
def then_three_runs_returned(bdd_state: TrackerBDDState) -> None:
    assert len(bdd_state.queried_history) == 3
    assert [r.run_id for r in bdd_state.queried_history] == ["run-002", "run-003", "run-004"]
