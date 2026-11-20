"""Data-integrity tests for the F10 band-decision evidence.

Recomputes the sweep, selection and held-out figures from the committed balanced-corpus
rows and the current evalset, pins the manifest headline, and checks the pointer chain.
Hermetic: no network, no model calls, no credentials.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_band_sweep.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_runs_balanced"
SWEEP_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_band_sweep"
MANIFEST = SWEEP_DIR / "manifest.json"
ARTIFACT = SWEEP_DIR / "band_sweep_2026-11-20.json"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sweep_module():
    spec = importlib.util.spec_from_file_location("jev_band_sweep_data", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def artifact():
    return _load(ARTIFACT)


@pytest.fixture(scope="module")
def manifest():
    return _load(MANIFEST)


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {r["file"] for r in manifest["runs"]}
    on_disk = {p.name for p in SWEEP_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1


@pytest.mark.parametrize("name", ["manifest.json", "band_sweep_2026-11-20.json"])
def test_no_credentials_in_artifacts(name):
    forbidden = re.compile(
        r"TYPESAFE_API_KEY|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY", re.IGNORECASE
    )
    assert not forbidden.search((SWEEP_DIR / name).read_text(encoding="utf-8")), name


def test_split_is_deterministic_and_disjoint(sweep_module, artifact):
    ids = [r["eval_case_id"] for r in _load(RUNS_DIR / "jev-1.14.0_2026-11-20_run1.json")]
    halves = {cid: sweep_module.stable_split(cid) for cid in ids}
    assert len(halves) == len(ids)
    assert {halves[cid] for cid in ids} == {0, 1}
    assert all(sweep_module.stable_split(cid) == halves[cid] for cid in ids)
    assert abs(sum(halves.values()) - len(ids) / 2) <= 20  # roughly balanced


def test_baseline_recomputed_and_pinned(sweep_module, artifact, manifest):
    runs, attack_types = sweep_module.load_inputs()
    got = sweep_module.metrics(runs[0], 0.35, 0.75, attack_types)
    assert got == artifact["baseline"]
    head = manifest["headline"]["baseline_0.35_0.75"]
    assert got["accuracy"] == head["accuracy"]
    assert got["below_low_attacks"] == head["below_low_attacks"]
    assert got["below_low_ioc_type_attacks"] == head["below_low_ioc_type_attacks"]


def test_tune_selection_recomputed(sweep_module, artifact):
    runs, attack_types = sweep_module.load_inputs()
    tune = sweep_module.sweep(runs[0], 0, attack_types)
    assert tune == artifact["tune_sweep"]
    assert len(tune) == len(sweep_module.LOW_EDGES) * len(sweep_module.HIGH_EDGES)
    eligible = [m for m in tune if m["fp"] == 0]
    chosen = max(
        eligible,
        key=lambda m: (m["accuracy"], -m["escalation_rate"],
                       -(m["low"] - 0.35) ** 2 - (m["high"] - 0.75) ** 2),
    )
    assert chosen == artifact["selected"]
    assert (chosen["low"], chosen["high"]) == (0.08, 0.40)


@pytest.mark.parametrize("run_index,key", [(0, "run1"), (1, "run2")])
def test_holdout_recomputed_and_replicated(sweep_module, artifact, manifest, run_index, key):
    runs, attack_types = sweep_module.load_inputs()
    sel = artifact["selected"]
    got = sweep_module.metrics(
        [r for r in runs[run_index] if sweep_module.stable_split(r["eval_case_id"]) == 1],
        sel["low"], sel["high"], attack_types,
    )
    assert got == artifact["holdout"][key]
    head = manifest["headline"]["selected_0.08_0.40_holdout"]
    assert got["accuracy"] == head["accuracy"]
    assert got["below_low_attacks"] == head["below_low_attacks"]
    assert got["fp"] == head["false_positives"]
    assert artifact["holdout"]["run1"] == artifact["holdout"]["run2"]


def test_tradeoff_direction(manifest):
    base = manifest["headline"]["baseline_0.35_0.75"]
    hold = manifest["headline"]["selected_0.08_0.40_holdout"]
    assert hold["accuracy"] > base["accuracy"]
    assert hold["below_low_attacks"] < base["below_low_attacks"]
    assert hold["escalation_rate"] > base["escalation_rate"]
    assert hold["false_positives"] == base["false_positives"] == 0


def test_evidence_is_not_a_band_change(manifest, artifact):
    text = json.dumps(manifest) + json.dumps(artifact)
    assert "NOT a band change" in text or "not a band change" in text
    assert "Track G" in text
    assert "same-change sync" in text


def test_pointer_chain_is_documented():
    tasks = (
        REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md"
    ).read_text(encoding="utf-8")
    assert "jev_band_sweep" in tasks
    assert "test_jev_band_sweep_data" in tasks
