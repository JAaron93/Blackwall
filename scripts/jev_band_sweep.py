"""F10 evidence prep: sweep candidate band edges over committed Tier-1 P values.

Offline only — reads the balanced-corpus runs from ``tests/eval/results/`` and
never calls a model. Cases are split deterministically by a hash of the case id:
the sweep selects a candidate on the tune half, and the selection is reported on
the held-out half of BOTH runs as a replicate check.

This is EVIDENCE FOR A DECISION, not a band change. FR-02 requires a spec
amendment with fresh labeled evidence and a same-change sync before any edge moves.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_runs_balanced"
EVALSET = REPO_ROOT / "tests" / "eval" / "evalsets" / "blackwall_security.evalset.json"
LOW_EDGES = (0.35, 0.30, 0.25, 0.20, 0.15, 0.10, 0.08)
HIGH_EDGES = (0.75, 0.65, 0.60, 0.55, 0.50, 0.45, 0.40)
IOC_TYPES = {"C2_IOC", "REVERSE_SHELL", "CREDENTIAL_EXFILTRATION", "COVERT_CHANNEL"}


def stable_split(case_id: str) -> int:
    """Deterministic 0/1 half assignment from the case id (no RNG, no labels)."""
    digest = hashlib.sha256(case_id.encode("utf-8")).digest()
    return digest[0] & 1


def load_inputs() -> tuple[list[list[dict[str, Any]]], dict[str, str]]:
    runs = [
        json.loads((RUNS_DIR / f"jev-1.14.0_2026-11-20_run{i}.json").read_text(encoding="utf-8"))
        for i in (1, 2)
    ]
    cases = json.loads(EVALSET.read_text(encoding="utf-8"))["eval_cases"]
    attack_types = {
        c["eval_case_id"]: c.get("metadata", {}).get("attack_type", "") for c in cases
    }
    return runs, attack_types


def metrics(rows: list[dict[str, Any]], low: float, high: float,
            attack_types: dict[str, str]) -> dict[str, Any]:
    """Repo confusion at a candidate band, plus below-edge attack composition."""
    tp = fn = fp = tn = esc = 0
    below_low: list[str] = []
    for r in rows:
        p = float(r["p_threat"])
        malicious = r["ground_truth"] == "MALICIOUS"
        if p < low:
            if malicious:
                fn += 1
                below_low.append(r["eval_case_id"])
            else:
                tn += 1
        elif p > high:
            if malicious:
                tp += 1
            else:
                fp += 1
        else:
            esc += 1
    decided = tp + fn + fp + tn
    return {
        "low": low, "high": high,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn, "escalate": esc,
        "accuracy": round((tp + tn) / decided, 4) if decided else None,
        "escalation_rate": round(esc / len(rows), 4),
        "below_low_attacks": len(below_low),
        "below_low_ioc_type_attacks": sum(
            1 for cid in below_low if attack_types.get(cid) in IOC_TYPES
        ),
    }


def sweep(run: list[dict[str, Any]], half: int,
          attack_types: dict[str, str]) -> list[dict[str, Any]]:
    selected = [r for r in run if stable_split(r["eval_case_id"]) == half]
    return [
        metrics(selected, low, high, attack_types)
        for low in LOW_EDGES for high in HIGH_EDGES
    ]


def build_artifact() -> dict[str, Any]:
    runs, attack_types = load_inputs()
    base = metrics(runs[0], 0.35, 0.75, attack_types)
    tune = sweep(runs[0], 0, attack_types)
    # Selection rule: no new benign blocks (fp == 0), highest tune accuracy,
    # then lowest escalation, then closest to the shipped edges.
    eligible = [m for m in tune if m["fp"] == 0]
    assert eligible, "no candidate with zero false positives"
    chosen = max(
        eligible,
        key=lambda m: (m["accuracy"], -m["escalation_rate"],
                       -(m["low"] - 0.35) ** 2 - (m["high"] - 0.75) ** 2),
    )
    holdout_run1 = metrics(
        [r for r in runs[0] if stable_split(r["eval_case_id"]) == 1],
        chosen["low"], chosen["high"], attack_types,
    )
    holdout_run2 = metrics(
        [r for r in runs[1] if stable_split(r["eval_case_id"]) == 1],
        chosen["low"], chosen["high"], attack_types,
    )
    # Baseline on the SAME held-out cases — the headline must compare matched sets.
    holdout_baseline = {
        f"run{i}": metrics(
            [r for r in runs[i - 1] if stable_split(r["eval_case_id"]) == 1],
            0.35, 0.75, attack_types,
        )
        for i in (1, 2)
    }
    return {
        "schema_version": 1,
        "purpose": "F10 band-decision evidence only; NOT a band change (FR-02 still requires a spec amendment).",
        "inputs": {
            "runs": [f"jev-1.14.0_2026-11-20_run{i}.json" for i in (1, 2)],
            "corpus": "tests/eval/results/jev_runs_balanced/ (TASK-F09, 197 scored cases)",
            "split": "sha256(eval_case_id).digest()[0] & 1; tune=0, hold-out=1 (deterministic, label-blind)",
            "model": "jev-1.14.0",
            "grid": {"low_edges": list(LOW_EDGES), "high_edges": list(HIGH_EDGES)},
            "ioc_types": sorted(IOC_TYPES),
        },
        "baseline": base,
        "tune_sweep": tune,
        "selected": chosen,
        "holdout_baseline": holdout_baseline,
        "holdout": {"run1": holdout_run1, "run2": holdout_run2},
        "metric_definitions": {
            "escalation_rate": (
                "IN-BAND Tier-2 share only: P inside [low, high]. It excludes the separate "
                "disagreement route (argument novelty >= 0.4 with P < 0.2), which also calls "
                "Tier-2 in SyncResolver (FR-03). Treat it as an in-band escalation share, not "
                "the total Tier-2 call rate."
            ),
            "accuracy": "Decided accuracy (tp+tn)/(tp+tn+fp+fn); in-band cases are excluded from the denominator.",
        },
        "options": [
            "Lower the clear-low edge toward the selected value (captures more below-edge attacks, may raise escalation).",
            "Add threat-intelligence backing for IOC-type calls (8 C2_IOC in the corpus) instead of moving the edge.",
            "Accept the remaining misses and leave the fixed 0.35/0.75 band unchanged.",
        ],
        "caveats": [
            "The tune/held-out split is EXPLORATORY on previously inspected data: the original 167 cases were already used in the indicative sweep in ADR 0009, and the balanced corpus retains them (adding only 30). Hashing them now does not make them independent; do not read this as fresh held-out confirmation.",
            "escalation_rate is the in-band share only; the disagreement route (novelty >= 0.4 with P < 0.2) also calls Tier-2 and is not counted here.",
            "Tier-1 Jev scores only; no full-firewall verdicts and no end-to-end catch-rate claim.",
            "The sweep is tuned on one half and reported on the other, but it is still a single corpus and release.",
            "Track G (question/state redesign, FR-09) is PLANNED and would invalidate this evidence if it lands first.",
            "Any band change needs fresh labeled evidence and a same-change sync of AGENTS.md, .agents/rules/ and .greptile/.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="Write the sweep artifact JSON here")
    args = parser.parse_args(argv)
    artifact = build_artifact()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.out} — selected {artifact['selected']['low']}/{artifact['selected']['high']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
