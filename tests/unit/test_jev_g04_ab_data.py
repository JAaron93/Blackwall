"""Hermetic recomputation of the TASK-G04 golden A/B evidence.

Reads committed JSON only; never calls the network. Every published figure is
re-derived from per-case answers, never trusted from a stored score/band field.
The gate set is the F10 re-baselined one (accuracy >=0.85, recall >=0.75,
AUROC >=0.97, ECE <=0.27, in-band escalation <=20%) on held-out cases.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_g04_ab"
ARTIFACT = RUNS_DIR / "ab.json"
MANIFEST = RUNS_DIR / "manifest.json"
LO, HI = 0.08, 0.40
GATES = {"accuracy": 0.85, "recall": 0.75, "auroc": 0.97, "ece": 0.27, "escalation_rate": 0.20}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def artifact() -> dict[str, Any]:
    return _load(ARTIFACT)


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return _load(MANIFEST)


def _split(case_id: str) -> str:
    return "heldout" if hashlib.sha256(case_id.encode()).digest()[0] & 1 else "dev"


def _recompute(row: dict[str, Any]) -> tuple[float, str]:
    answers = row["answers"]
    score = max(answers.values()) if len(answers) == 6 else answers["is_threat"]
    assert row["threat_score"] == score, (row["id"], row["arm"], "score")
    band = "clear_low" if score < LO else "clear_high" if score > HI else "escalate"
    assert row["band"] == band, (row["id"], row["arm"], "band")
    return score, band


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fn = fp = tn = esc = 0
    for row in rows:
        _, band = _recompute(row)
        malicious = row["label"] == 1
        if band == "escalate":
            esc += 1
        elif malicious:
            tp, fn = (tp + 1, fn) if band == "clear_high" else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if band == "clear_high" else (fp, tn + 1)
    decided = tp + fn + fp + tn
    scores = [(row["threat_score"], row["label"]) for row in rows]
    pos = [p for p, y in scores if y == 1]
    neg = [p for p, y in scores if y == 0]
    auroc = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))
    ece = 0.0
    for b in range(10):
        lo, hi = b / 10, (b + 1) / 10
        sel = [(p, y) for p, y in scores if lo <= p < hi or (b == 9 and p == 1.0)]
        if sel:
            ece += len(sel) / len(scores) * abs(
                sum(p for p, _ in sel) / len(sel) - sum(y for _, y in sel) / len(sel)
            )
    return {
        "n": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn, "escalated": esc,
        "accuracy": decided and (tp + tn) / decided or 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "frr": fp / (fp + tn) if fp + tn else 0.0,
        "auroc": auroc, "ece": ece,
        "escalation_rate": esc / len(rows),
    }


def _run(artifact: dict[str, Any], release: str, arm: str, pass_no: int) -> dict[str, Any]:
    matches = [r for r in artifact["runs"]
               if r["release"] == release and r["arm"] == arm and r["pass"] == pass_no]
    assert len(matches) == 1, (release, arm, pass_no)
    return matches[0]


def test_artifact_shape_and_timestamp(artifact, manifest):
    assert artifact["schema_version"] == 1
    assert manifest["schema_version"] == 1
    assert artifact["releases_requested"] == ["jev-1.13.0", "jev-1.14.0"]
    assert artifact["band"] == {"clear_low": LO, "clear_high": HI}
    assert sorted(artifact["question_sets"]) == ["atomic", "legacy"]
    assert len(artifact["question_sets"]["atomic"]) == 6
    stamp = datetime.fromisoformat(artifact["generated_at"])
    assert stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)
    assert stamp.date() >= date(2026, 11, 21)
    assert len(artifact["runs"]) == 8
    for release in artifact["releases_requested"]:
        for arm in ("legacy", "atomic"):
            for pass_no in (1, 2):
                _run(artifact, release, arm, pass_no)


def test_no_credentials_in_committed_evidence():
    for path in (ARTIFACT, MANIFEST):
        text = path.read_text(encoding="utf-8")
        # ContextHygiene deliberately leaves "Bearer [[API_KEY]]" placeholders in
        # saved states; only an unredacted token is a credential leak.
        assert not re.search(r"TYPESAFE_API_KEY|AIza|gen-lang-client-|Bearer\s+(?!\[\[)\S+", text, re.IGNORECASE)


def test_legacy_states_match_canonical_scorer(artifact):
    spec = importlib.util.spec_from_file_location("ab_driver", REPO_ROOT / "scripts" / "jev_g04_ab.py")
    driver = importlib.util.module_from_spec(spec)
    sys.modules["ab_driver"] = driver
    spec.loader.exec_module(driver)
    from jev_triage_eval import build_cases

    canonical = {c["id"]: c["state"] for c in build_cases(["security", "evasion_proof"])}
    seen = set()
    for run in artifact["runs"]:
        for row in run["rows"]:
            if row["arm"] == "legacy":
                assert row["state"] == canonical[row["id"]], (row["id"], "state drift")
                seen.add(row["id"])
    assert seen == set(canonical)


def test_every_row_score_band_and_served_model_recomputed(artifact):
    for run in artifact["runs"]:
        assert run["errors"] == 0, (run["release"], run["arm"], run["pass"])
        assert run["cases"] == len(run["rows"]) == artifact["corpus"]["cases"]
        served: dict[str, int] = {}
        for row in run["rows"]:
            _recompute(row)
            name = row["served_model"]
            assert isinstance(name, str) and name.startswith("jev-")
            served[name] = served.get(name, 0) + 1
        assert served == run["served_models"]
        assert list(served) == [run["release"]], (run["release"], served)


def test_split_integrity(artifact, manifest):
    for run in artifact["runs"]:
        for row in run["rows"]:
            assert row["suite"] in ("security", "evasion_proof")
            assert row["label"] in (0, 1)
            assert ("heldout" if hashlib.sha256(row["id"].encode()).digest()[0] & 1 else "dev") == _split(row["id"])
    assert manifest["method"]["split"] == artifact["split"]


@pytest.mark.parametrize("release", ["jev-1.13.0", "jev-1.14.0"])
@pytest.mark.parametrize("arm", ["legacy", "atomic"])
@pytest.mark.parametrize("pass_no", [1, 2])
def test_published_heldout_gates_recomputed_and_pinned(artifact, manifest, release, arm, pass_no):
    run = _run(artifact, release, arm, pass_no)
    heldout = [row for row in run["rows"] if _split(row["id"]) == "heldout"]
    metrics = _metrics(heldout)
    pinned = manifest["gates"][release][arm][f"run{pass_no}"]
    for key, value in pinned.items():
        assert round(metrics[key], 4) == value, (release, arm, pass_no, key, metrics[key], value)
    # Pin the measured outcome, do not assume a particular one: a NO-GO arm
    # must still fail its gates in the test, or the evidence could be silently
    # "fixed" by editing the manifest instead of re-running the experiment.
    passes = all(
        (metrics[k] >= floor) if k in ("accuracy", "recall", "auroc") else (metrics[k] <= floor)
        for k, floor in GATES.items()
    ) and metrics["frr"] < 0.05
    assert passes is manifest["decision"]["gates_pass"][release][arm]
    assert metrics["n"] >= 90


def test_within_release_spread_recomputed_and_pinned(artifact, manifest):
    for release in artifact["releases_requested"]:
        for arm in ("legacy", "atomic"):
            r1 = _run(artifact, release, arm, 1)
            r2 = _run(artifact, release, arm, 2)
            by_id = {row["id"]: row for row in r2["rows"]}
            diffs = [abs(row["threat_score"] - by_id[row["id"]]["threat_score"]) for row in r1["rows"]]
            zones = sum(row["band"] != by_id[row["id"]]["band"] for row in r1["rows"])
            pinned = manifest["spread"][release][arm]
            assert round(sum(diffs) / len(diffs), 4) == pinned["mean_abs_diff"]
            assert round(max(diffs), 4) == pinned["max_diff"]
            assert zones == pinned["zone_changes"]


def test_ab_decision_is_derived_from_pinned_gates(manifest):
    decision = manifest["decision"]
    for release in manifest["gates"]:
        for arm in ("legacy", "atomic"):
            passes = all(
                all(
                    (v >= GATES[k]) if k in ("accuracy", "recall", "auroc") else (v <= GATES[k])
                    for k, v in manifest["gates"][release][arm][f"run{p}"].items()
                    if k in GATES
                )
                for p in (1, 2)
            )
            assert decision["gates_pass"][release][arm] is passes
    assert decision["flip"] is (decision["gates_pass"]["jev-1.14.0"]["atomic"]
                                and not decision["regressed_vs_legacy"])
    assert decision["production_still_legacy"] is True


def test_production_flip_not_shipped_in_this_evidence_pr():
    from blackwall.policy.semantic import JevTriageBackend
    assert JevTriageBackend.build_request_state.__doc__.find("legacy until G04") >= 0
    assert hasattr(JevTriageBackend, "_build_atomic_payload")


def test_pointer_chain_is_documented():
    for rel in (".kiro/specs/tier-1-jev-addition/tasks.md",
                ".kiro/specs/tier-1-jev-addition/design.md",
                "docs/adr/0009-tier2-flash-lite-medium-and-jev-only-fail-fast.md",
                "docs/evaluation_guide.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "jev_g04_ab" in text or "jev_g04_ab_data" in text, rel
