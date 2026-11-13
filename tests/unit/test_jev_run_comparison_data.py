"""Data-integrity tests for the Jev release-comparison runs and the notebook
cell that plots them (notebooks/benchmark_analytics.py).

Governing spec: .kiro/specs/tier-1-jev-addition/ (transport: ADR 0008).

A per-case comparison of two Jev releases is only meaningful when every run
scored the SAME states, so these tests pin: identical case ids and states across
runs, error-free rows, the served release recorded in each run's own ``model``
field, that the headline runs asked for their release by name and got it, and
that the comparison separates the two things that changed (the Jev release and
the transport) instead of mixing them. They read committed files only and never
touch the network.
"""

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "tests" / "eval" / "results"
RUNS_DIR = RESULTS_DIR / "jev_runs"
MANIFEST = RUNS_DIR / "manifest.json"
MAIN_ARTIFACT = RESULTS_DIR / "jev_triage_results.json"
NOTEBOOK = REPO_ROOT / "notebooks" / "benchmark_analytics.py"

HEADLINE_KEYS = {
    "pinned_1_13_run1",
    "pinned_1_13_run2",
    "pinned_1_14_run1",
    "pinned_1_14_run2",
}
HISTORY_KEYS = {"gateway_1_13", "latest_alias_run1", "latest_alias_run2"}


def _runs() -> list[dict[str, Any]]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["runs"]


def _records(run: dict[str, Any]) -> list[dict[str, Any]]:
    return json.loads((RUNS_DIR / run["file"]).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runs() -> list[dict[str, Any]]:
    return _runs()


def test_manifest_lists_the_headline_and_history_runs(runs):
    assert {r["key"] for r in runs} == HEADLINE_KEYS | HISTORY_KEYS
    for run in runs:
        for field in (
            "label", "short_label", "file", "group", "transport", "plan", "release",
            "requested_model", "served_model", "date",
        ):
            assert run.get(field), f"{run['key']} is missing {field!r}"


def test_the_headline_runs_are_exactly_the_pinned_ones(runs):
    headline = {r["key"] for r in runs if r["group"] == "headline"}
    assert headline == HEADLINE_KEYS
    assert {r["group"] for r in runs} == {"headline", "history"}


def test_the_committed_artifact_is_one_of_the_runs(runs):
    """The dashboard's main artifact must be the TASK-D02 run the ADR cites, not a copy."""
    run = next(r for r in runs if r["key"] == "latest_alias_run1")
    assert (RUNS_DIR / run["file"]).resolve() == MAIN_ARTIFACT.resolve()


def test_every_run_scores_the_same_cases_and_states(runs):
    base = {r["eval_case_id"]: r["state"] for r in json.loads(MAIN_ARTIFACT.read_text())}
    assert len(base) == 167
    for run in runs:
        rows = {r["eval_case_id"]: r["state"] for r in _records(run)}
        assert rows.keys() == base.keys(), f"{run['key']} covers different cases"
        changed = [i for i in base if rows[i] != base[i]]
        assert not changed, f"{run['key']} scored different states for {changed[:3]}"


def test_every_run_is_error_free_with_valid_probabilities(runs):
    for run in runs:
        for r in _records(run):
            assert r["error"] is None, (run["key"], r["eval_case_id"])
            assert not r["is_fallback"], (run["key"], r["eval_case_id"])
            assert 0.0 <= r["p_threat"] <= 1.0, (run["key"], r["eval_case_id"])


def test_served_release_matches_each_runs_own_model_field(runs):
    """The ``model`` field is what the API reported as having answered; the
    manifest must agree with it rather than with the requested alias."""
    for run in runs:
        assert {r["model"] for r in _records(run)} == {run["served_model"]}, run["key"]


def test_headline_runs_asked_for_their_release_by_name_and_got_it(runs):
    for run in (r for r in runs if r["group"] == "headline"):
        assert run["requested_model"] == run["served_model"], run["key"]
        assert run["requested_model"].startswith("jev-1."), run["key"]
        assert run["release"] == run["requested_model"], run["key"]


def test_each_release_has_two_pinned_runs_on_one_transport(runs):
    """Two runs per release give a within-release noise to read the
    between-release difference against, with no transport difference."""
    for release in ("jev-1.13.0", "jev-1.14.0"):
        group = [r for r in runs if r["group"] == "headline" and r["release"] == release]
        assert len(group) == 2, release
        assert {r["transport"] for r in group} == {"typesafe-api"}, release


def test_transport_effect_is_isolated_on_one_release(runs):
    """The Gateway-era run and the pinned 1.13 runs differ only in transport.

    The Gateway slug (``typesafe-ai/jev``) never recorded the version, so the
    manifest must say the 1.13 attribution is maintainer-reported, not measured.
    """
    gateway = next(r for r in runs if r["key"] == "gateway_1_13")
    assert gateway["group"] == "history"
    assert gateway["transport"] == "vercel-gateway"
    assert gateway["release"] == "jev-1.13.0"
    assert gateway["release_evidence"] == "maintainer-reported"


def test_latest_alias_runs_are_history_served_by_1_14(runs):
    for key in ("latest_alias_run1", "latest_alias_run2"):
        run = next(r for r in runs if r["key"] == key)
        assert run["group"] == "history"
        assert run["requested_model"] == "jev-latest"
        assert run["served_model"] == "jev-1.14.0"


def test_notebook_plots_the_release_comparison_from_the_manifest():
    source = NOTEBOOK.read_text(encoding="utf-8")
    assert "jev_runs" in source and "manifest.json" in source
    assert "Jev release comparison" in source
    # Pinned (headline) runs are shown by default; history runs are opt-in.
    assert '"headline"' in source
    # The fixed acceptance band is shaded, not recomputed from the exploratory sliders.
    assert "add_hrect" in source
    assert "y0=0.35, y1=0.75" in source
