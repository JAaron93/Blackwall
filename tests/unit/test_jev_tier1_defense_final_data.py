"""Data-integrity tests for the TASK-F02 final defense validation.

Recomputes every published figure from committed rows on the CURRENT corpus,
including the matched malicious comparison, benign false alarms with Tier-2
outages excluded, crossing counts, P-shift statistics and Wilson upper bounds.
Hermetic: no network, no credentials.
"""

import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_tier1_defense_final"
MANIFEST = RUNS_DIR / "manifest.json"


def _load(name):
    return json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("jev_tier2_f02_final", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def manifest():
    return _load(MANIFEST)


def _rows(entry):
    return _load(entry["file"])["rows"]


def _held(rows):
    return {
        r["base_id"] for r in rows
        if r["kind"] == "baseline" and r.get("verdict") in ("BLOCK", "QUARANTINE")
        and not r.get("error")
    }


def _outage(r):
    """Tier-2 was called but produced no verdict — a service hold, not a model answer."""
    return bool(r.get("tier2_called")) and not r.get("tier2_decision")


def _flips(rows, bases):
    sel = [r for r in rows if r["kind"] == "steered" and r["base_id"] in bases
           and not r.get("error") and r.get("verdict")]
    return sum(1 for r in sel if r["verdict"] == "ALLOW"), len(sel)


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {r["file"] for r in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert {r["arm"] for r in manifest["runs"]} == {"shipped state", "nonce-XML boundary"}
    assert manifest["discarded"]  # the four wrong-corpus runs are recorded, not dropped


@pytest.mark.parametrize("entry", _load(MANIFEST)["runs"], ids=lambda e: e["file"])
def test_called_counts_recomputed_from_rows(entry):
    """PR #218 review: tier2_calls must describe the saved rows, not a placeholder."""
    rows = _rows(entry)
    assert sum(1 for r in rows if r.get("jev_p") is not None) == entry["jev_calls"]
    assert sum(1 for r in rows if r.get("tier2_called")) == entry["tier2_calls"]


@pytest.mark.parametrize("name", ["manifest.json", "final_baseline_malicious.json",
                                  "final_defense_malicious.json", "final_baseline_benign.json",
                                  "final_defense_benign.json"])
def test_no_credentials_and_band_provenance(name):
    text = (RUNS_DIR / name).read_text(encoding="utf-8")
    assert not re.search(
        r"TYPESAFE_API_KEY|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY", text, re.IGNORECASE
    ), name
    if name != "manifest.json":
        run = json.loads(text)["summary"]["run"]
        assert run["band"] == {"clear_low": 0.08, "clear_high": 0.40}
        assert run["configs"] == ["semantic_only"]


@pytest.mark.parametrize("name", ["final_baseline_malicious.json", "final_defense_malicious.json",
                                  "final_baseline_benign.json", "final_defense_benign.json"])
def test_rows_come_from_the_current_corpus_without_placeholders(harness, name):
    """PR #218 review: the old [[VALUE]] ablation corpus must never be used here."""
    current = {c.id: (c.tool, c.args) for c in harness.load_current_cases()}
    for row in _load(name)["rows"]:
        if row["id"] in current:
            tool, args = current[row["id"]]
            base_id = row["id"].split("::")[0]
            if base_id in current and "::" in row["id"]:
                base_tool, _ = current[base_id]
                assert row["tool"] == base_tool
                # Steered rows carry payload-injected arguments; the base row is exact.
                continue
            assert row["tool"] == tool
            assert row["args"] == args
        assert "[[" not in json.dumps(row.get("args")), row["id"]


def test_matched_malicious_figures_recomputed_and_pinned(harness, manifest):
    entries = {r["arm"]: r for r in manifest["runs"] if r["class_subset"] != "benign"}
    base, defense = _rows(entries["shipped state"]), _rows(entries["nonce-XML boundary"])
    common = _held(base) & _held(defense)
    pinned = manifest["matched_results"]["malicious"]
    assert len(common) == pinned["common_held_bases"] == 25
    for rows, key in ((base, "baseline_to_allow"), (defense, "defense_to_allow")):
        n, of = _flips(rows, common)
        rec = pinned[key]
        assert (n, of) == (rec["n"], rec["of"])
        assert round(n / of, 4) == rec["rate"]
        summary = harness.summarize_tier1_steering(rows)["semantic_only"]["malicious"]
        assert summary["to_allow"]["upper95"] == pytest.approx(rec["upper95"], abs=0.0001)
    assert pinned["defense_to_allow"]["of"] == pinned["baseline_to_allow"]["of"]
    assert pinned["defense_to_allow"]["n"] < pinned["baseline_to_allow"]["n"]

    for rows, key in ((base, "baseline"), (defense, "defense")):
        summary = harness.summarize_tier1_steering(rows)["semantic_only"]["malicious"]
        assert summary["crossings"]["below_035"] == pinned["below_edge_crossings"][key]


def test_benign_figures_recomputed_with_outages_excluded(harness, manifest):
    entries = {r["arm"]: r for r in manifest["runs"] if r["class_subset"] == "benign"}
    for arm, key in (("shipped state", "baseline"), ("nonce-XML boundary", "defense")):
        all_rows = _rows(entries[arm])
        baselines = {r["base_id"]: r for r in all_rows if r["kind"] == "baseline"}
        deltas = [d for r in all_rows if r["kind"] == "steered"
                  if (d := harness._shift(r, baselines)) is not None]
        rows = [r for r in all_rows
                if r["kind"] == "steered" and r.get("verdict") and not _outage(r)]
        counts = Counter(r["verdict"] for r in rows)
        flagged = counts["BLOCK"] + counts["QUARANTINE"]
        pinned = manifest["matched_results"]["benign"][key]
        assert (len(rows), counts["ALLOW"], counts["BLOCK"], counts["QUARANTINE"]) == (
            pinned["steered_answered"], pinned["allow"], pinned["block"], pinned["quarantine"]
        )
        assert flagged == pinned["flagged"]
        assert round(flagged / len(rows), 4) == pinned["flagged_rate"]
        # Published P-shift figures recomputed exactly as the harness does.
        assert round(sum(deltas) / len(deltas), 4) == pinned["p_shift_mean"]
        assert sum(1 for d in deltas if round(d, 6) >= 0.05) == pinned["rise_ge_0_05"]
    benign = manifest["matched_results"]["benign"]
    assert benign["defense"]["flagged_rate"] > benign["baseline"]["flagged_rate"]
    # Outage rows are tracked separately, never counted as model false alarms.
    for entry in manifest["runs"]:
        rows = _rows(entry)
        assert sum(1 for r in rows if r["kind"] == "steered" and _outage(r)) == entry["outage_rows"]


def test_finding_says_not_validated_and_no_guard(manifest):
    text = json.dumps(manifest)
    assert "NOT validated for shipping" in text
    assert "No guard was shipped" in text
    assert "raised_above_035" in text


def test_pointer_chain_is_documented():
    tasks = (
        REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md"
    ).read_text(encoding="utf-8")
    adr = (
        REPO_ROOT / "docs" / "adr" / "0009-tier2-flash-lite-medium-and-jev-only-fail-fast.md"
    ).read_text(encoding="utf-8")
    for label, text in (("F02 task", tasks), ("ADR 0009", adr)):
        assert "jev_tier1_defense_final" in text, label
        assert "test_jev_tier1_defense_final_data" in text, label
