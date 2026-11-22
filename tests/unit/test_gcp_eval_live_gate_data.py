"""Hermetic recomputation for the TASK-D03 live Vertex EvalTask gate evidence.

No network calls: every published gate figure is re-derived from the committed
result JSONs. The recording wrapper captured the REAL managed EvalTask result;
no mocked run_eval_task stands in for a live pass.
"""

from __future__ import annotations

import json
import re
import statistics
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from blackwall.eval.aggregator import EvaluationAggregator, EvaluationResultRecord

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "gcp_eval_live_gate"
RUN_FILES = ("live_gate_rows_run1.json", "live_gate_rows_run2.json")
MANIFEST = RUNS_DIR / "manifest.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runs() -> dict[str, dict[str, Any]]:
    return {name: _load(RUNS_DIR / name) for name in RUN_FILES}


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return _load(MANIFEST)


def test_schema_and_timestamps(runs, manifest):
    assert manifest["schema_version"] == 1
    for name, artifact in runs.items():
        assert artifact["schema_version"] == 1
        assert artifact["script"] == "scripts/gcp_eval_live_gate.py"
        assert artifact["method"]["allow_fallback"] is False
        stamp = datetime.fromisoformat(artifact["generated_at"])
        assert stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)
        assert stamp.date() >= date(2026, 11, 22)
        assert name in manifest["runs"]


def test_no_credentials_in_artifacts():
    for path in (MANIFEST, *[RUNS_DIR / n for n in RUN_FILES],
                 RUNS_DIR / "live_gate_discarded_missing_sdk.json"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(
            r"TYPESAFE_API_KEY|GCP_PROJECT|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY",
            text, re.IGNORECASE,
        ), path.name


@pytest.mark.parametrize("name,expected_exit,expected_pass,expected_regression", [
    ("live_gate_rows_run1.json", 0, True, False),
    ("live_gate_rows_run2.json", 1, False, True),
])
def test_live_eval_task_gate_recomputed(runs, manifest, name, expected_exit, expected_pass, expected_regression):
    artifact = runs[name]
    result = artifact["eval_task"]
    assert result["status"] == "COMPLETED", result
    assert isinstance(result.get("model"), str) and result["model"]
    assert artifact["gate"]["eval_task_completed"] is True
    # Recompute the whole CI summary from the committed per-scenario rows using
    # the production aggregator; saved summary flags are never trusted alone.
    rows = artifact["scenario_records"]
    assert len(rows) == artifact["summary"]["total_scenarios"] - len(artifact["failed_scenarios"])
    assert all(isinstance(r["execution_time_ms"], (int, float)) for r in rows)
    assert all(isinstance(r["is_fallback"], bool) for r in rows)
    assert all(any(isinstance(v, (int, float)) for k, v in r["rubric"].items()
                   if k not in ("justification", "is_fallback", "regression_detected")) for r in rows)
    rebuilt = EvaluationAggregator(threshold=artifact["method"]["threshold"])
    for row in rows:
        rebuilt.add_record(EvaluationResultRecord(**row))
    for error in artifact["failed_scenarios"]:
        rebuilt.record_error(**error)
    assert rebuilt.summarize().model_dump(mode="json") == artifact["summary"]
    assert artifact["gate"]["fallback_free"] is True
    assert artifact["summary"]["total_fallbacks"] == 0
    assert artifact["regression"]["regression_detected"] is expected_regression
    assert artifact["gate"]["no_regression"] is (not expected_regression)
    assert artifact["exit_code"] == expected_exit
    assert artifact["gate"]["ci_passed"] is (expected_exit == 0)
    assert artifact["summary"]["all_passed"] is expected_pass
    published = manifest["runs"][name]
    for key in ("exit_code", "all_passed", "overall_mean", "eval_task_status"):
        actual = (result["status"] if key == "eval_task_status"
                  else artifact["exit_code"] if key == "exit_code"
                  else artifact["summary"]["all_passed"] if key == "all_passed"
                  else artifact["summary"]["overall_mean"])
        assert actual == published[key], (name, key)


def test_managed_scores_not_usable_and_scope_explicitly_narrowed(runs, manifest):
    for artifact in runs.values():
        stats = {k: v for k, v in artifact["eval_task"].get("summary_metrics", {}).items()
                 if str(k).endswith(("/mean", "/std"))}
        assert stats, "managed metric statistics missing"
        assert all(not isinstance(v, (int, float)) for v in stats.values())
        assert artifact["gate"]["managed_scores_usable"] is False
    assert manifest["scope"] == "managed Vertex EvalTask service invocation only; usable managed scores NOT verified"
    tasks = (REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md").read_text()
    block = " ".join(tasks.split("TASK-D03 [hybrid]")[1].split("TASK-D04 [C1]")[0]
                     .replace(">", " ").split())
    assert "service invocation" in block
    assert "NaN" in block
    assert "usable managed scores" in block


def test_run_to_run_spread_recomputed_and_pinned(runs, manifest):
    r1 = runs["live_gate_rows_run1.json"]["summary"]["domain_summaries"]
    r2 = runs["live_gate_rows_run2.json"]["summary"]["domain_summaries"]
    assert set(r1) == set(r2)
    diffs = [r2[k]["overall_mean"] - r1[k]["overall_mean"] for k in r1]
    pinned = manifest["spread"]
    assert round(statistics.fmean(abs(d) for d in diffs), 4) == pinned["mean_abs_domain_delta"]
    assert round(max(abs(d) for d in diffs), 4) == pinned["max_abs_domain_delta"]
    # The run-1 CI failure was a genuine 1-scenario domain score, not an outage:
    assert r1["exploit_chain"]["overall_mean"] == pinned["run1_exploit_chain_mean"]
    assert r2["exploit_chain"]["overall_mean"] == pinned["run2_exploit_chain_mean"]


def test_discarded_run_is_recorded(manifest):
    discarded = manifest["discarded"]
    assert len(discarded) == 1
    entry = discarded[0]
    assert entry["file"] == "live_gate_discarded_missing_sdk.json"
    assert "vertexai" in entry["cause"]
    assert "google-cloud-aiplatform[evaluation]" in entry["fix"]
    assert _load(RUNS_DIR / entry["file"])["eval_task"]["status"] == "FAILED"


def test_superseded_runs_recorded(manifest):
    superseded = manifest["superseded"]
    assert {entry["file"] for entry in superseded} == {
        "live_gate_run1.json", "live_gate_run2.json"
    }
    for entry in superseded:
        assert "scenario_records" not in _load(RUNS_DIR / entry["file"])
        assert "per-scenario rows" in entry["why"]


def test_pointer_chain_is_documented():
    tasks = (REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md").read_text()
    adr = (REPO_ROOT / "docs" / "adr" / "0008-jev-transport-vercel-gateway-to-typesafe-api.md").read_text()
    for label, text in (("tasks", tasks), ("ADR 0008", adr)):
        assert "gcp_eval_live_gate" in text, label
        assert "test_gcp_eval_live_gate_data" in text, label
