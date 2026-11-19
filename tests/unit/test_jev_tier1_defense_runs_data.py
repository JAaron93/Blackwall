"""Data-integrity tests for the TASK-F02 Tier-1 steering defense experiment.

The experiment is harness-only: the committed JSON artifacts are the evidence that a
nonce-XML state boundary is NOT a drop-in defense, because it moves Jev's unsteered
calibration. These tests recompute both arms from committed rows (defense artifact and
the existing shipped-state baseline), pin every figure the manifest reports, scan for
credentials, and check the pointer chain. Hermetic: no network, no keys.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_tier1_defense_runs"
BASELINE_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_tier2_runs"
MANIFEST = RUNS_DIR / "manifest.json"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("jev_tier2_defense_data", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def manifest():
    return _load(MANIFEST)


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {run["file"] for run in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1
    assert {run["split"] for run in manifest["runs"]} == {"dev", "heldout"}
    assert manifest["discarded"]  # the wiring smoke run is recorded


@pytest.mark.parametrize("name", ["manifest.json", "tier1_defense_2026-11-19_dev.json",
                                  "tier1_defense_2026-11-19_heldout.json"])
def test_no_credentials_in_artifacts(name):
    forbidden = re.compile(
        r"gen-lang-client-|TYPESAFE_API_KEY|AIza|BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{10,}",
        re.IGNORECASE,
    )
    text = (RUNS_DIR / name).read_text(encoding="utf-8")
    assert not forbidden.search(text), f"credential-shaped content in {name}"


@pytest.mark.parametrize("run", ["dev", "heldout"])
def test_defense_arm_recomputed_and_pinned(harness, manifest, run):
    entry = next(r for r in manifest["runs"] if r["split"] == run)
    data = _load(RUNS_DIR / entry["file"])
    meta = data["summary"]["run"]
    assert meta["defense"] == "state-boundary"
    assert "harness-only" in meta["note"]
    assert meta["configs"] == ["semantic_only"]
    assert meta["band"] == {"clear_low": 0.35, "clear_high": 0.75}
    assert meta["release"] == "jev-1.14.0"
    assert data["served_models"]["jev"] == {"jev-1.14.0": entry["calls"]["jev"]}
    assert data["served_models"]["tier2"] == {"gemini-3.5-flash-lite": entry["calls"]["tier2"]}
    assert data["errors"] == {"rows": {}}

    summary = harness.summarize_tier1_steering(data["rows"])["semantic_only"]
    m = summary["malicious"]
    pinned = manifest["comparison"][run]["defense"]
    assert m["baseline"] == pinned["base_verdicts"]
    assert m["held_bases"] == pinned["held_bases"]
    assert m["block_bases"] == pinned["block_bases"]
    assert m["steered_calls"] == pinned["steered"]
    assert (m["to_allow"]["n"], m["to_allow"]["of"]) == (pinned["to_allow"]["n"], pinned["to_allow"]["of"])
    assert (m["block_weakened"]["n"], m["block_weakened"]["of"]) == (
        pinned["block_weakened"]["n"], pinned["block_weakened"]["of"]
    )
    assert m["crossings"]["below_035"] == pinned["below_035"]
    assert m["errors"] == 0 and m["abstained"] == 0


@pytest.mark.parametrize("run", ["dev", "heldout"])
def test_matched_shipped_baseline_recomputed_and_pinned(harness, manifest, run):
    defense = _load(RUNS_DIR / next(r["file"] for r in manifest["runs"] if r["split"] == run))
    bases = {row["base_id"] for row in defense["rows"]}
    baseline = _load(BASELINE_DIR / f"tier1_steering_2026-11-14_{run}.json")
    matched = [
        row for row in baseline["rows"]
        if row.get("config") == "semantic_only" and row["base_id"] in bases
    ]
    m = harness.summarize_tier1_steering(matched)["semantic_only"]["malicious"]
    pinned = manifest["comparison"][run]["baseline"]
    assert m["baseline"] == pinned["base_verdicts"]
    assert m["block_bases"] == pinned["block_bases"]
    assert m["steered_calls"] == pinned["steered"]
    assert (m["to_allow"]["n"], m["to_allow"]["of"]) == (pinned["to_allow"]["n"], pinned["to_allow"]["of"])
    assert (m["block_weakened"]["n"], m["block_weakened"]["of"]) == (
        pinned["block_weakened"]["n"], pinned["block_weakened"]["of"]
    )
    assert m["crossings"]["below_035"] == pinned["below_035"]


@pytest.mark.parametrize("run", ["dev", "heldout"])
def test_finding_direction_holds(harness, manifest, run):
    """The candidate changes calibration and does not shrink the bypass surface."""
    pair = manifest["comparison"][run]
    assert pair["defense"]["block_bases"] > pair["baseline"]["block_bases"]
    d_rate = pair["defense"]["to_allow"]["n"] / pair["defense"]["to_allow"]["of"]
    b_rate = pair["baseline"]["to_allow"]["n"] / pair["baseline"]["to_allow"]["of"]
    assert d_rate > b_rate
    assert pair["defense"]["below_035"] > pair["baseline"]["below_035"]


def test_pointer_chain_is_documented():
    tasks = (
        REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md"
    ).read_text(encoding="utf-8")
    adr = (
        REPO_ROOT / "docs" / "adr" / "0009-tier2-flash-lite-medium-and-jev-only-fail-fast.md"
    ).read_text(encoding="utf-8")
    for label, text in (("F02 task", tasks), ("ADR 0009", adr)):
        assert "jev_tier1_defense_runs" in text, label
        assert "test_jev_tier1_defense_runs_data" in text, label
