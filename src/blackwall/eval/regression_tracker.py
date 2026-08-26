"""
Historical Regression Tracker for Blackwall Security Evaluations (`blackwall.eval.regression_tracker`).

Persists evaluation runs to JSON Lines format (history.jsonl), compares current run
results against the most recent baseline run, and flags performance regressions
when domain mean scores drop > 0.5 points.
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

DEFAULT_HISTORY_PATH = Path("tests/eval/regression/history.jsonl")
REGRESSION_DROP_THRESHOLD = 0.5


class EvalRunSummary(BaseModel):
    """Structured summary of a completed evaluation run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(description="Unique evaluation run identifier")
    timestamp_iso: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        description="ISO 8601 timestamp of the evaluation run",
    )
    domain_means: dict[str, float] = Field(
        description="Mean quality score per evaluated security domain"
    )
    overall_mean: float = Field(
        description="Overall mean quality score across all evaluated domains"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Run metadata such as model, commit SHA, environment, or CLI flags",
    )


class RegressionReport(BaseModel):
    """Structured comparison report between current run and baseline."""

    model_config = ConfigDict(extra="forbid")

    is_baseline: bool = Field(description="True if this run is the first recorded baseline")
    baseline_run_id: str | None = Field(default=None, description="Run ID of the baseline comparison")
    current_run_id: str = Field(description="Run ID of the evaluated candidate")
    regression_detected: bool = Field(description="True if any domain mean dropped > 0.5 from baseline")
    regressed_domains: dict[str, float] = Field(
        default_factory=dict,
        description="Domains with regressions mapped to their negative delta",
    )
    domain_deltas: dict[str, float] = Field(
        default_factory=dict,
        description="Score differences (candidate - baseline) across all shared domains",
    )
    overall_delta: float = Field(default=0.0, description="Overall score delta across shared domains")
    details: str = Field(default="", description="Human-readable explanation of comparison results")


class HistoricalRegressionTracker:
    """
    Manages evaluation history persistence and detects score regressions across runs.
    """

    def __init__(self, history_path: str | Path | None = None) -> None:
        self.history_path = Path(history_path) if history_path else DEFAULT_HISTORY_PATH
        self._ensure_history_dir()

    def _ensure_history_dir(self) -> None:
        """Ensure parent directory for history file exists."""
        self.history_path.parent.mkdir(parents=True, exist_ok=True)

    def get_history(self, limit: int | None = None) -> list[EvalRunSummary]:
        """
        Load historical evaluation runs in chronological order.
        If limit is specified, returns the last N runs.
        """
        if not self.history_path.exists():
            return []

        runs: list[EvalRunSummary] = []
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        data = json.loads(stripped)
                        runs.append(EvalRunSummary.model_validate(data))
                    except Exception as exc:
                        logger.warning("Skipping corrupted line in history: %s (%s)", stripped, exc)
        except OSError as exc:
            logger.error("Failed to read evaluation history file %s: %s", self.history_path, exc)
            return []

        if limit is not None and limit > 0:
            return runs[-limit:]
        return runs

    def get_latest_run(self) -> EvalRunSummary | None:
        """Retrieve the most recent historical evaluation run, or None if history is empty."""
        history = self.get_history()
        return history[-1] if history else None

    def record_run(self, run: EvalRunSummary) -> None:
        """Append an evaluation run summary to the history JSONL file."""
        self._ensure_history_dir()
        try:
            with open(self.history_path, "a", encoding="utf-8") as f:
                f.write(run.model_dump_json() + "\n")
        except OSError as exc:
            logger.error("Failed to append run to history file %s: %s", self.history_path, exc)

    def compare_against_baseline(
        self,
        current_run: EvalRunSummary,
        threshold_drop: float = REGRESSION_DROP_THRESHOLD,
    ) -> RegressionReport:
        """
        Compare current evaluation run against the latest historical baselines.
        Iterates backwards through history so selective/partial baseline runs
        do not hide regressions for domains evaluated in prior runs.
        """
        history = self.get_history()
        if not history:
            return RegressionReport(
                is_baseline=True,
                baseline_run_id=None,
                current_run_id=current_run.run_id,
                regression_detected=False,
                details=f"Run {current_run.run_id} established as initial baseline.",
            )

        latest_run = history[-1]
        domain_deltas: dict[str, float] = {}
        regressed_domains: dict[str, float] = {}
        compared_baseline_runs: set[str] = set()

        for domain, current_mean in current_run.domain_means.items():
            if current_mean is None:
                continue
            # Search history in reverse for the most recent run containing this domain
            for prior_run in reversed(history):
                if domain in prior_run.domain_means and prior_run.domain_means[domain] is not None:
                    base_mean = prior_run.domain_means[domain]
                    delta = round(current_mean - base_mean, 4)
                    domain_deltas[domain] = delta
                    compared_baseline_runs.add(prior_run.run_id)
                    # If delta is negative and drop > threshold_drop (i.e. delta < -threshold_drop)
                    if delta < -threshold_drop:
                        regressed_domains[domain] = delta
                    break

        if not domain_deltas:
            return RegressionReport(
                is_baseline=True,
                baseline_run_id=latest_run.run_id,
                current_run_id=current_run.run_id,
                regression_detected=False,
                details=f"No prior history found for current domains. Run {current_run.run_id} established as baseline.",
            )

        # Compute overall delta across all compared domain baselines
        overall_delta = (
            round(sum(domain_deltas.values()) / len(domain_deltas), 4)
            if domain_deltas
            else 0.0
        )
        regression_detected = len(regressed_domains) > 0
        primary_baseline_id = latest_run.run_id

        if regression_detected:
            reg_list = ", ".join(f"{d} ({delta:+0.2f})" for d, delta in regressed_domains.items())
            details = (
                f"Regression detected against historical baselines ({', '.join(sorted(compared_baseline_runs))})! "
                f"Domains with drop > {threshold_drop}: {reg_list}"
            )
        else:
            details = (
                f"No regression detected against historical baselines ({', '.join(sorted(compared_baseline_runs))}). "
                f"Average domain delta: {overall_delta:+0.2f}."
            )

        return RegressionReport(
            is_baseline=False,
            baseline_run_id=primary_baseline_id,
            current_run_id=current_run.run_id,
            regression_detected=regression_detected,
            regressed_domains=regressed_domains,
            domain_deltas=domain_deltas,
            overall_delta=overall_delta,
            details=details,
        )

    def record_and_compare(
        self,
        current_run: EvalRunSummary,
        threshold_drop: float = REGRESSION_DROP_THRESHOLD,
    ) -> RegressionReport:
        """
        Compare current run against baseline, then persist current run to history.
        """
        report = self.compare_against_baseline(current_run, threshold_drop=threshold_drop)
        self.record_run(current_run)
        return report
