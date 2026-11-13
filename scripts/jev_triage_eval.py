#!/usr/bin/env python3
"""Run the Tier-1 Jev triage backend over Blackwall golden evalsets.

Produces tests/eval/results/jev_triage_results_class_blind.json — per-case Jev
P(threat) records for the class-blind corpus (TASK-F05b, ADR 0009): one shared
prompt template, real attack text and real benign values, and states built the
way production builds them (ContextHygiene, then JevTriageBackend.build_state).
The committed jev_triage_results.json and tests/eval/results/jev_runs/ are the
TASK-D02 evidence behind ADR 0008, scored on the earlier corpus, and are left
alone; pass --out explicitly if you really mean to replace one.

Live calls to the official TypeSafe AI API (System One, ADR 0008); requires
TYPESAFE_API_KEY in the environment (paid per-token billing) and Node 18+ for
the zero-dependency scripts/jev_evaluate.mjs helper. All states are
ContextHygiene-sanitized before egress. Nothing secret is written to disk:
only sanitized states, probabilities, and usage.

Each record carries the Jev release that actually answered (``model``), so
evidence stays attributable even though JEV_MODEL defaults to the moving
``jev-latest`` alias (deliberately unpinned, ADR 0008). Calls run back to back;
a throttled call is retried once, and any row that still fails is recorded as a
fallback — re-running the script fills in just those rows.

Usage:
  TYPESAFE_API_KEY=... .venv/bin/python scripts/jev_triage_eval.py
  TYPESAFE_API_KEY=... .venv/bin/python scripts/jev_triage_eval.py --limit 10
  # after TypeSafe ships a release behind jev-latest (resume would replay old rows):
  TYPESAFE_API_KEY=... .venv/bin/python scripts/jev_triage_eval.py --fresh
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


# The evasion-proof suite stores its prompt as "Execute tool 'X' with arguments:
# {json}"; the security suite stores the same shape plus ``metadata.tool_arguments``.
# Both are scored as production builds the state (TASK-F05b, ADR 0009): sanitize
# the context, then ``JevTriageBackend.build_state``. No harness wrapper, no
# label words and no ground-truth fields ever reach Jev.
PROOF_PROMPT_RE = re.compile(r"^Execute tool '([^']+)' with arguments: (\{.*\})$", re.S)


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
    from blackwall.models import ToolCallContext
    from blackwall.policy.semantic import JevTriageBackend
    from blackwall.resolver import ContextHygiene

    # Production semantic triage preserves IOCs (URLs, IPs, paths) while
    # redacting secrets - the eval MUST use the same mode.
    hygiene = ContextHygiene(preserve_iocs=True)

    def finalize(case_id: str, suite: str, tool: str, arguments: dict,
                 label: int, expected: str, scenario: str) -> dict:
        ctx = hygiene.sanitize_context(
            ToolCallContext(tool_name=tool, arguments=arguments)
        )
        state = JevTriageBackend.build_state(ctx)
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
                c["eval_case_id"], "security", tool_name(c), md["tool_arguments"], label,
                c.get("expected_verdict", "BLOCK" if label else "ALLOW"),
                md.get("scenario_type", ""),
            ))
    if "evasion_proof" in suites:
        proof = json.loads(
            (REPO_ROOT / "tests/eval/evalsets/blackwall_evasion_proof.evalset.json").read_text()
        )
        for c in proof["eval_cases"]:
            m = PROOF_PROMPT_RE.match(user_text(c))
            if m is None:
                raise ValueError(f"unrecognised evasion-proof prompt: {c.get('eval_id')}")
            cases.append(finalize(
                c.get("eval_id", "proof"), "evasion_proof", m.group(1),
                json.loads(m.group(2)), 1, "BLOCK", "evasion",
            ))
    return cases


def build_records(raw: list[dict], cases: list[dict]) -> list[dict]:
    """Map raw helper rows onto the committed per-case artifact shape.

    Rows that are out of scope for this run (different suite selection,
    ``--limit``) or stale (state content changed since) are dropped.
    """
    states = {c["id"]: (c["state"], c["h"]) for c in cases}
    records = []
    for r in raw:
        current = states.get(r["id"])
        if current is None or r.get("h") != current[1]:
            continue
        usage = r.get("usage") or {}
        records.append(
            {
                "eval_case_id": r["id"],
                "suite": r["suite"],
                "ground_truth": "MALICIOUS" if r["label"] == 1 else "BENIGN",
                "scenario": r["scenario"],
                "expected_verdict": r["expected"],
                "tool_name": r.get("tool", "unknown"),
                "backend": "jev",
                # The release that answered, not the alias that was requested.
                "model": r.get("served_model") or r.get("model"),
                "state": current[0],
                "p_threat": r["p"],
                # A noul answer carries no separate confidence (ADR 0008).
                "confidence": r.get("confidence"),
                "latency_ms": r["latency_ms"],
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "tier2_disposition": None,
                "is_fallback": bool(r.get("is_fallback", r.get("error") is not None)),
                "error": r["error"],
            }
        )
    return records


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Jev triage eval over golden evalsets")
    # NOT jev_triage_results.json: that file is the committed TASK-D02 artifact behind
    # ADR 0008 (scored on the earlier corpus). This scorer builds the class-blind
    # corpus, so its default output is a different file (TASK-F05b, ADR 0009).
    ap.add_argument("--out", default="tests/eval/results/jev_triage_results_class_blind.json")
    ap.add_argument("--limit", type=int, default=0, help="0 = all cases")
    ap.add_argument("--suites", nargs="+", default=["security", "evasion_proof"])
    ap.add_argument(
        "--fresh",
        action="store_true",
        help=(
            "discard the cached raw rows and call the API for every case. Use it "
            "after TypeSafe ships a release behind jev-latest: resume is keyed on "
            "the requested model, and the alias name does not change, so without "
            "this flag the old release's rows are replayed and nothing is called"
        ),
    )
    return ap


def main() -> int:
    ap = _parser()
    args = ap.parse_args()

    # The legacy AI_GATEWAY_API_KEY is deliberately not honored: a Vercel
    # credential must never be presented to a different vendor (ADR 0008).
    if not os.environ.get("TYPESAFE_API_KEY"):
        print("TYPESAFE_API_KEY is not set", file=sys.stderr)
        return 2

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    cases = build_cases(args.suites)
    if args.limit:
        cases = cases[: args.limit]
    print(f"cases={len(cases)}", file=sys.stderr)

    work = INSTALL_DIR / "cases.json"
    # New filename for the new transport: any pre-ADR-0008 ``jev_raw.json`` is
    # the only copy of the raw Vercel-Gateway A/B rows, so it is left untouched
    # rather than overwritten by a first-party-API run.
    raw_out = INSTALL_DIR / "jev_raw_systemone.json"
    work.write_text(json.dumps(cases, indent=1))
    if args.fresh:
        raw_out.unlink(missing_ok=True)
        print("fresh run: cached raw rows discarded", file=sys.stderr)

    proc = subprocess.run(
        ["node", str(NODE_RUNNER), "batch", str(work), str(raw_out)],
        cwd=INSTALL_DIR,
    )
    if proc.returncode != 0 and not raw_out.exists():
        return proc.returncode

    records = build_records(json.loads(raw_out.read_text()), cases)
    out_path = REPO_ROOT / args.out
    out_path.write_text(json.dumps(records, indent=1))
    ok = sum(1 for r in records if not r["error"])
    print(f"wrote {out_path} n={len(records)} ok={ok}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
