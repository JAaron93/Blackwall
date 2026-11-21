"""Recomputation tests for the G03 live atomic probe. Hermetic: committed rows only."""

import hashlib
import json
import re
import statistics
from pathlib import Path
from typing import Any

import pytest

from blackwall.policy.jev_questions import JEV_ATOMIC_QUESTIONS

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_atomic_probe"
MANIFEST = RUNS_DIR / "manifest.json"


def _load(name: str) -> Any:
    return json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest():
    return _load(MANIFEST.name)


def _split(case_id: str) -> str:
    return "dev" if hashlib.sha256(case_id.encode()).digest()[0] & 1 else "heldout"


def _bands(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {b: sum(1 for r in rows if r["band"] == b) for b in ("clear_low", "escalate", "clear_high")}


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {r["file"] for r in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1


@pytest.mark.parametrize("name", ["manifest.json", "probe_2026-11-20.json",
                                  "probe_refined_heldout_2026-11-20.json"])
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


@pytest.mark.parametrize("name", ["probe_2026-11-20.json", "probe_refined_heldout_2026-11-20.json"])
def test_split_integrity(name):
    data = _load(name)
    assert all(c["split"] == _split(c["id"]) for c in data["cases"])
    if data.get("split_requested", "all") == "heldout":
        assert {c["split"] for c in data["cases"]} == {"heldout"}


@pytest.mark.parametrize("run", ["baseline_heldout", "refined_heldout", "baseline_dev"])
def test_published_class_bands_recomputed_and_pinned(manifest, run):
    source = _load("probe_2026-11-20.json") if run != "refined_heldout" else _load("probe_refined_heldout_2026-11-20.json")
    split = "dev" if run == "baseline_dev" else "heldout"
    for klass, pinned in manifest["results"][run].items():
        rows = [c for c in source["cases"] if c["split"] == split and c["klass"] == klass]
        assert len(rows) == pinned["n"]
        assert _bands(rows) == pinned["bands"]
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
