"""Recomputation tests for the G03 live atomic probe. Hermetic: committed rows only."""

import hashlib
import json
import re
import statistics
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from blackwall.policy.jev_questions import JEV_ATOMIC_QUESTIONS

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_atomic_probe"
MANIFEST = RUNS_DIR / "manifest.json"
RUN_FILES = ("probe_2026-11-20.json", "probe_refined_heldout_2026-11-20.json")


def _load(name: str) -> Any:
    return json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest():
    return _load(MANIFEST.name)


def _split(case_id: str) -> str:
    return "dev" if hashlib.sha256(case_id.encode()).digest()[0] & 1 else "heldout"


def _recomputed_band(data: dict[str, Any], row: dict[str, Any]) -> tuple[float, str]:
    """Derive score+band from the raw answers using THIS run's recorded thresholds.

    This is the whole point of the recomputation test: a stored ``threat_score``
    or ``band`` string is never trusted. Any drift in an answer or in the
    max-combination / band logic is caught before a detection count is computed.
    """
    score = max(row["answers"].values())  # combine_answers() is a fail-closed max
    assert row["threat_score"] == score, (row["id"], "threat_score")
    low = data["band"]["clear_low"]
    high = data["band"]["clear_high"]
    band = "clear_low" if score < low else "clear_high" if score > high else "escalate"
    assert row["band"] == band, (row["id"], "band")
    return score, band


def _bands(data: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {b: 0 for b in ("clear_low", "escalate", "clear_high")}
    for row in rows:
        _, band = _recomputed_band(data, row)
        counts[band] += 1
    return counts


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {r["file"] for r in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1


@pytest.mark.parametrize("name", ["manifest.json", *RUN_FILES])
def test_no_credentials_and_question_shape(name):
    text = (RUNS_DIR / name).read_text(encoding="utf-8")
    assert not re.search(r"TYPESAFE_API_KEY|gen-lang-client-|AIza", text, re.IGNORECASE)
    if name != "manifest.json":
        data = json.loads(text)
        assert data["question_keys"] == list(JEV_ATOMIC_QUESTIONS)
        assert data["served_models"] == {"jev-1.14.0": len(data["cases"])}
        assert all(not c.get("error") for c in data["cases"])
        assert all(set(c["answers"]) == set(JEV_ATOMIC_QUESTIONS) for c in data["cases"])
        assert all(isinstance(c["state"], dict) for c in data["cases"])


@pytest.mark.parametrize("name", RUN_FILES)
def test_split_integrity(name):
    data = _load(name)
    assert all(c["split"] == _split(c["id"]) for c in data["cases"])
    if data.get("split_requested", "all") == "heldout":
        assert {c["split"] for c in data["cases"]} == {"heldout"}


@pytest.mark.parametrize("name", RUN_FILES)
def test_generated_at_is_utc_and_matches_manifest(manifest, name):
    """Testing rule 80: every measurement export records when the run happened."""
    recorded = {r["file"]: r["generated_at"] for r in manifest["runs"]}
    assert "timestamp_provenance" in manifest
    value = _load(name)["generated_at"]
    assert value == recorded[name]
    assert value.endswith("Z")
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)
    # These two runs both happened on 2026-11-21 UTC (local filenames are 11-20).
    assert parsed.date() == date(2026, 11, 21)
    assert parsed.time() == datetime.fromisoformat(recorded[name]).time()


@pytest.mark.parametrize("name", RUN_FILES)
def test_every_row_score_and_band_recomputed_from_answers(name):
    """Guard the source of truth: no published count rests on a stored band string."""
    data = _load(name)
    assert data["band"] == {"clear_low": 0.08, "clear_high": 0.40}
    for row in data["cases"]:
        _recomputed_band(data, row)


@pytest.mark.parametrize("run", ["baseline_heldout", "refined_heldout", "baseline_dev"])
def test_published_class_bands_recomputed_and_pinned(manifest, run):
    source = _load("probe_2026-11-20.json") if run != "refined_heldout" else _load("probe_refined_heldout_2026-11-20.json")
    split = "dev" if run == "baseline_dev" else "heldout"
    for klass, pinned in manifest["results"][run].items():
        rows = [c for c in source["cases"] if c["split"] == split and c["klass"] == klass]
        assert len(rows) == pinned["n"]
        assert _bands(source, rows) == pinned["bands"]
        if "unauth_mean" in pinned:
            mean = statistics.fmean(c["answers"]["unauthorized_access"] for c in rows)
            assert round(mean, 3) == pinned["unauth_mean"]


def test_refinement_direction_on_heldout(manifest):
    base = manifest["results"]["baseline_heldout"]
    refined = manifest["results"]["refined_heldout"]
    assert refined["benign"]["bands"]["clear_high"] < base["benign"]["bands"]["clear_high"]
    assert refined["benign"]["unauth_mean"] < base["benign"]["unauth_mean"]
    assert refined["ioc"]["bands"] == base["ioc"]["bands"]
    assert refined["other_malicious"]["bands"] == base["other_malicious"]["bands"]
    # Disclosed caveat: no clear-low anywhere, so the band needs re-validation.
    for run in ("baseline_heldout", "refined_heldout"):
        for klass in manifest["results"][run]:
            assert manifest["results"][run][klass]["bands"]["clear_low"] == 0


def test_pointer_chain_is_documented():
    tasks = (REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md").read_text(encoding="utf-8")
    design = (REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "design.md").read_text(encoding="utf-8")
    for label, text in (("tasks", tasks), ("design", design)):
        assert "jev_atomic_probe" in text, label
        assert "test_jev_atomic_probe_data" in text, label
