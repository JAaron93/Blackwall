"""Hermetic recomputation for the full Tier-1/Tier-2 structured-state validation.

Reads committed JSON only. Recomputes matched malicious flips/crossings, benign
flags with Tier-2 outages excluded, and pins every saved input against a
network-free rebuild of the current corpus and steering payloads.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_f02_full_defense"
MANIFEST = RUNS_DIR / "manifest.json"


def _load(name: str) -> Any:
    return json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def harness() -> Any:
    spec = importlib.util.spec_from_file_location("jev_tier2_f02_full", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return _load("manifest.json")


def _rows(entry: dict[str, Any]) -> list[dict[str, Any]]:
    return _load(entry["file"])["rows"]


def _outage(row: dict[str, Any]) -> bool:
    return bool(row.get("tier2_called")) and not row.get("tier2_decision")


def _held(rows: list[dict[str, Any]]) -> set[str]:
    return {r["base_id"] for r in rows if r["kind"] == "baseline"
            and r.get("verdict") in ("BLOCK", "QUARANTINE") and not r.get("error")}


def _flips(rows: list[dict[str, Any]], bases: set[str]) -> tuple[int, int]:
    sel = [r for r in rows if r["kind"] == "steered" and r["base_id"] in bases
           and not r.get("error") and r.get("verdict")]
    return sum(1 for r in sel if r["verdict"] == "ALLOW"), len(sel)


def test_manifest_names_every_artifact_and_no_other(manifest):
    listed = {r["file"] for r in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert {r["arm"] for r in manifest["runs"]} == {"shipped state", "structured state"}
    assert {r["class_subset"] for r in manifest["runs"]} == {"malicious", "benign"}


@pytest.mark.parametrize("entry", _load("manifest.json")["runs"], ids=lambda e: e["file"])
def test_called_counts_recomputed_from_rows(entry):
    rows = _rows(entry)
    assert sum(1 for r in rows if r.get("jev_p") is not None) == entry["jev_calls"]
    assert sum(1 for r in rows if r.get("tier2_called")) == entry["tier2_calls"]


@pytest.mark.parametrize("name", ["manifest.json", "full_baseline_malicious.json",
                                  "full_structured_malicious.json", "full_baseline_benign.json",
                                  "full_structured_benign.json"])
def test_no_credentials_and_band_provenance(name):
    text = (RUNS_DIR / name).read_text(encoding="utf-8")
    # Benign eval cases carry synthetic "Bearer <fake>" header values; only
    # real credential shapes are banned (same pattern as the prior F02 test).
    assert not re.search(r"TYPESAFE_API_KEY|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY", text, re.IGNORECASE)
    if name != "manifest.json":
        run = json.loads(text)["summary"]["run"]
        assert run["band"] == {"clear_low": 0.08, "clear_high": 0.40}
        assert run["configs"] == ["semantic_only"]
        assert run["defense"] in ("none", "structured")
        assert run["corpus"] == "current" if "corpus" in run else True


def test_saved_inputs_match_current_corpus_payloads_and_builders(harness, manifest):
    from blackwall.models import ToolCallContext
    from blackwall.policy.semantic import (
        JEV_IS_THREAT_QUESTION,
        JevTriageBackend,
    )
    from blackwall.resolver import ContextHygiene

    expected_question_sha = hashlib.sha256(json.dumps(
        {"is_threat": JEV_IS_THREAT_QUESTION}, sort_keys=True
    ).encode()).hexdigest()
    hygiene = ContextHygiene(preserve_iocs=True)
    for subset in ("malicious", "benign"):
        entries = {e["arm"]: e for e in manifest["runs"] if e["class_subset"] == subset}
        old, new = _rows(entries["shipped state"]), _rows(entries["structured state"])
        keys = {(r["base_id"], r["payload_id"]) for r in old}
        assert keys == {(r["base_id"], r["payload_id"]) for r in new}
        assert len(old) == len(new) == len(keys)
        for arm, rows in (("shipped state", old), ("structured state", new)):
            for row in rows:
                egress = row.get("egress")
                assert egress and egress["questions_sha"] == expected_question_sha, row["id"]
                assert egress["keys"] == ["model", "questions", "state"]
                ctx = hygiene.sanitize_context(ToolCallContext(
                    tool_name=row["tool"], arguments=row["args"], metadata=row.get("metadata")
                ))
                try:
                    expected = (JevTriageBackend.build_legacy_state(ctx) if arm == "shipped state"
                                else JevTriageBackend.build_state(ctx))
                except Exception:  # noqa: BLE001 - fail-closed builder: the row must record the failure
                    assert row.get("error"), (arm, row["id"])
                    continue
                assert egress["state"] == expected, (arm, row["id"], "state drift")
                assert isinstance(egress["state"], (str if arm == "shipped state" else dict))


def test_matched_malicious_figures_recomputed_and_pinned(harness, manifest):
    entries = {r["arm"]: r for r in manifest["runs"] if r["class_subset"] == "malicious"}
    base, defense = _rows(entries["shipped state"]), _rows(entries["structured state"])
    common = _held(base) & _held(defense)
    pinned = manifest["matched_results"]["malicious"]
    assert len(common) == pinned["common_held_bases"]
    for rows, key in ((base, "baseline_to_allow"), (defense, "structured_to_allow")):
        n, of = _flips(rows, common)
        rec = pinned[key]
        assert (n, of) == (rec["n"], rec["of"])
        assert round(n / of, 4) == rec["rate"]
        summary = harness.summarize_tier1_steering(rows)["semantic_only"]["malicious"]
        assert summary["to_allow"]["upper95"] == pytest.approx(rec["upper95"], abs=0.0001)
    assert pinned["structured_to_allow"]["of"] == pinned["baseline_to_allow"]["of"]
    for rows, key in ((base, "baseline"), (defense, "structured")):
        summary = harness.summarize_tier1_steering(rows)["semantic_only"]["malicious"]
        assert summary["crossings"]["below_035"] == pinned["below_edge_crossings"][key]


def test_benign_figures_recomputed_with_outages_excluded(harness, manifest):
    entries = {r["arm"]: r for r in manifest["runs"] if r["class_subset"] == "benign"}
    for arm, key in (("shipped state", "baseline"), ("structured state", "structured")):
        all_rows = _rows(entries[arm])
        baselines = {r["base_id"]: r for r in all_rows if r["kind"] == "baseline"}
        deltas = [d for r in all_rows if r["kind"] == "steered"
                  if (d := harness._shift(r, baselines)) is not None]
        answered = [r for r in all_rows if r["kind"] == "steered" and r.get("verdict") and not _outage(r)]
        counts = Counter(r["verdict"] for r in answered)
        flagged = counts["BLOCK"] + counts["QUARANTINE"]
        pinned = manifest["matched_results"]["benign"][key]
        assert (len(answered), counts["ALLOW"], counts["BLOCK"], counts["QUARANTINE"]) == (
            pinned["steered_answered"], pinned["allow"], pinned["block"], pinned["quarantine"]
        )
        assert flagged == pinned["flagged"]
        assert round(flagged / len(answered), 4) == pinned["flagged_rate"]
        assert round(sum(deltas) / len(deltas), 4) == pinned["p_shift_mean"]
        assert sum(1 for d in deltas if round(d, 6) >= 0.05) == pinned["rise_ge_0_05"]
    for entry in manifest["runs"]:
        rows = _rows(entry)
        assert sum(1 for r in rows if r["kind"] == "steered" and _outage(r)) == entry["outage_rows"]


def test_finding_records_no_guard_and_no_overclaim(manifest):
    text = json.dumps(manifest)
    assert "NOT validated" in text
    assert "No guard was shipped" in text
    assert manifest["decision"]["ship"] is False


def test_pointer_chain_is_documented():
    for rel in (".kiro/specs/tier-1-jev-addition/tasks.md",
                "docs/adr/0009-tier2-flash-lite-medium-and-jev-only-fail-fast.md",
                "docs/evaluation_guide.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "jev_f02_full_defense" in text, rel
        assert "test_jev_f02_full_defense_data" in text, rel
