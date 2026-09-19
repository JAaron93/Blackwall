#!/usr/bin/env python3
"""Run the Tier-1 Jev triage backend over Blackwall golden evalsets.

Produces tests/eval/results/jev_triage_results.json — per-case Jev P(threat)
records consumed by notebooks/benchmark_analytics.py and the Track-D
acceptance gate (.kiro/specs/tier-1-jev-addition/).

Live Vercel AI Gateway calls; requires AI_GATEWAY_API_KEY in the
environment (paid credits recommended — the free tier is rate-capped to
~20-call bursts). Every call sets disallowPromptTraining=true and all
states are ContextHygiene-sanitized before egress. Nothing secret is
written to disk: only sanitized states, probabilities, and usage.

Usage:
  AI_GATEWAY_API_KEY=... .venv/bin/python scripts/jev_triage_eval.py
  AI_GATEWAY_API_KEY=... .venv/bin/python scripts/jev_triage_eval.py --limit 10
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

INSTALL_DIR = Path.home() / ".cache" / "blackwall" / "jev-eval"
NODE_RUNNER = REPO_ROOT / "scripts" / "jev_evaluate.mjs"


# Ground-truth-bearing harness scaffolding that never appears in production
# Tool/Arguments/Metadata states. Two precise patterns, nothing broader:
# (1) standalone label words; (2) parent-case-ID references
# (label_category_digits, e.g. malicious_sql_001). Payload placeholders
# such as [[MALICIOUS_COMMAND]] match NEITHER pattern and are preserved —
# erasing them would destroy the attack signal being measured.
LABEL_STANDALONE_RE = re.compile(
    r"\b(benign|malicious|evasion|evasive|evade|evading)\b", re.IGNORECASE
)
LABEL_CASEID_RE = re.compile(
    r"\b(?:benign|malicious|evasion)(?:_[a-z]+)+_\d+\b", re.IGNORECASE
)
PROOF_TOOL_RE = re.compile(r"tool '([^']+)'")


def neutralize(text: str) -> str:
    scrubbed = LABEL_CASEID_RE.sub("", LABEL_STANDALONE_RE.sub("", text))
    return re.sub(r"\s+", " ", scrubbed).strip()


def user_text(case: dict) -> str:
    for msg in case.get("conversation") or []:
        for part in msg.get("parts") or []:
            if isinstance(part, dict) and part.get("text"):
                return part["text"]
        uc = msg.get("user_content") or {}
        for part in uc.get("parts", []):
            if isinstance(part, dict) and part.get("text"):
                return part["text"]
    for part in (case.get("prompt") or {}).get("parts", []):
        if isinstance(part, dict) and part.get("text"):
            return part["text"]
    return ""


def tool_name(case: dict) -> str:
    md = case.get("metadata") or {}
    if md.get("tool_name"):
        return str(md["tool_name"])
    for tu in case.get("expected_tool_use") or []:
        ti = (tu.get("tool_use") or {}).get("tool_input") or {}
        if ti.get("tool_name"):
            return str(ti["tool_name"])
    return "unknown"


def build_cases(suites: list[str]) -> list[dict]:
    from blackwall.resolver import ContextHygiene

    # Production semantic triage preserves IOCs (URLs, IPs, paths) while
    # redacting secrets — the eval MUST use the same mode.
    hygiene = ContextHygiene(preserve_iocs=True)

    def finalize(case_id: str, suite: str, tool: str, text: str,
                 label: int, expected: str, scenario: str) -> dict:
        # Production-shaped state: Tool + payload only. No Scenario line
        # and no ground-truth-bearing words (neutralize()).
        raw = f"Tool: {tool}\nRequest: {neutralize(text)}"
        state = hygiene.sanitize_string(raw)
        return {
            "id": case_id,
            "suite": suite,
            "state": state,
            "h": hashlib.sha256(state.encode()).hexdigest()[:16],
            "label": label,
            "expected": expected,
            "scenario": scenario,
            "tool": tool,
        }

    cases: list[dict] = []
    if "security" in suites:
        sec = json.loads(
            (REPO_ROOT / "tests/eval/evalsets/blackwall_security.evalset.json").read_text()
        )
        for c in sec["eval_cases"]:
            md = c.get("metadata", {})
            label = 1 if md.get("ground_truth") == "MALICIOUS" else 0
            cases.append(finalize(
                c["eval_case_id"], "security", tool_name(c), user_text(c), label,
                c.get("expected_verdict", "BLOCK" if label else "ALLOW"),
                md.get("scenario_type", ""),
            ))
    if "evasion_proof" in suites:
        proof = json.loads(
            (REPO_ROOT / "tests/eval/evalsets/blackwall_evasion_proof.evalset.json").read_text()
        )
        for c in proof["eval_cases"]:
            text = user_text(c)
            m = PROOF_TOOL_RE.search(text)
            tool = m.group(1) if m else "database_query"
            cases.append(finalize(
                c.get("eval_id", "proof"), "evasion_proof", tool, text,
                1, "BLOCK", "evasion",
            ))
    return cases


def ensure_node_env() -> None:
    if (INSTALL_DIR / "node_modules" / "ai" / "package.json").exists():
        return
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    if not (INSTALL_DIR / "package.json").exists():
        subprocess.run(
            ["npm", "init", "-y"], cwd=INSTALL_DIR, check=True, capture_output=True
        )
    subprocess.run(
        ["npm", "install", "ai@latest"], cwd=INSTALL_DIR, check=True, capture_output=True
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Jev triage eval over golden evalsets")
    ap.add_argument("--out", default="tests/eval/results/jev_triage_results.json")
    ap.add_argument("--pace-ms", type=int, default=2000)
    ap.add_argument("--limit", type=int, default=0, help="0 = all cases")
    ap.add_argument("--suites", nargs="+", default=["security", "evasion_proof"])
    args = ap.parse_args()

    if not os.environ.get("AI_GATEWAY_API_KEY"):
        print("AI_GATEWAY_API_KEY is not set", file=sys.stderr)
        return 2

    ensure_node_env()
    cases = build_cases(args.suites)
    if args.limit:
        cases = cases[: args.limit]
    print(f"cases={len(cases)}", file=sys.stderr)

    work = INSTALL_DIR / "cases.json"
    raw_out = INSTALL_DIR / "jev_raw.json"
    work.write_text(json.dumps(cases, indent=1))

    env = dict(os.environ, JEV_PACE_MS=str(args.pace_ms))
    proc = subprocess.run(
        ["node", str(NODE_RUNNER), "batch", str(work), str(raw_out)],
        cwd=INSTALL_DIR,
        env=env,
    )
    if proc.returncode != 0 and not raw_out.exists():
        return proc.returncode

    raw = json.loads(raw_out.read_text())
    states = {c["id"]: (c["state"], c["h"]) for c in cases}
    records = []
    for r in raw:
        # Drop rows that are out of scope for this run (different suite
        # selection, --limit) or stale (state content changed since).
        current = states.get(r["id"])
        if current is None or r.get("h") != current[1]:
            continue
        records.append(
            {
                "eval_case_id": r["id"],
                "suite": r["suite"],
                "ground_truth": "MALICIOUS" if r["label"] == 1 else "BENIGN",
                "scenario": r["scenario"],
                "expected_verdict": r["expected"],
                "tool_name": r.get("tool", "unknown"),
                "backend": "jev",
                "model": "typesafe-ai/jev",
                "state": current[0],
                "p_threat": r["p"],
                "confidence": r["confidence"],
                "latency_ms": r["latency_ms"],
                "input_tokens": (r.get("usage") or {}).get("inputTokens"),
                "output_tokens": (r.get("usage") or {}).get("outputTokens"),
                "tier2_disposition": None,
                "error": r["error"],
            }
        )
    out_path = REPO_ROOT / args.out
    out_path.write_text(json.dumps(records, indent=1))
    ok = sum(1 for r in records if not r["error"])
    print(f"wrote {out_path} n={len(records)} ok={ok}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
