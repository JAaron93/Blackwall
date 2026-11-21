"""TASK-G04 golden A/B: score the current class-blind corpus with the shipped
single-question payload and the G02 atomic six-question payload, two interleaved
passes per named Jev release. Evidence only — production stays on _build_payload
until the held-out gate passes (G04 decision / G05 same-change sync).

Usage:
  TYPESAFE_API_KEY=... .venv/bin/python scripts/jev_g04_ab.py --out <file>.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from jev_triage_eval import (
    PROOF_PROMPT_RE,
    build_cases,
    tool_name,
    user_text,
)
from jev_triage_eval import (
    REPO_ROOT as EVAL_ROOT,
)

from blackwall.models import ToolCallContext
from blackwall.policy.jev_questions import (
    JEV_ATOMIC_QUESTIONS,
    combine_answers,
    parse_atomic_answers,
)
from blackwall.policy.semantic import (
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JEV_IS_THREAT_QUESTION,
    JevTriageBackend,
)
from blackwall.resolver import ContextHygiene

SUITES = ("security", "evasion_proof")
RELEASES = ("jev-1.13.0", "jev-1.14.0")  # named releases, never the alias
ARMS = ("legacy", "atomic")
PASSES = (1, 2)


def build_contexts() -> list[dict[str, Any]]:
    """Same sanitized contexts as jev_triage_eval.build_cases, with args retained
    so the atomic builder can use them. Canonical-state equality is asserted in
    main(); the legacy arm must be byte-identical to every stored run's state."""
    hygiene = ContextHygiene(preserve_iocs=True)
    rows: list[dict[str, Any]] = []

    def finalize(case_id: str, suite: str, tool: str, arguments: dict,
                 label: int, scenario: str) -> None:
        rows.append({
            "id": case_id,
            "suite": suite,
            "label": label,
            "scenario": scenario,
            "context": hygiene.sanitize_context(
                ToolCallContext(tool_name=tool, arguments=arguments)
            ),
        })

    sec = json.loads((EVAL_ROOT / "tests/eval/evalsets/blackwall_security.evalset.json").read_text())
    for case in sec["eval_cases"]:
        md = case["metadata"]
        finalize(
            case["eval_case_id"], "security", tool_name(case), md["tool_arguments"],
            1 if md.get("ground_truth") == "MALICIOUS" else 0,
            md.get("scenario_type", ""),
        )

    proof = json.loads((EVAL_ROOT / "tests/eval/evalsets/blackwall_evasion_proof.evalset.json").read_text())
    for case in proof["eval_cases"]:
        match = PROOF_PROMPT_RE.match(user_text(case))
        if match is None:
            raise ValueError(f"unrecognised evasion-proof prompt: {case.get('eval_id')}")
        finalize(
            case.get("eval_id", "proof"), "evasion_proof", match.group(1),
            json.loads(match.group(2)), 1, "evasion",
        )
    return rows


def band_for(score: float) -> str:
    if score < JEV_CLEAR_LOW_THRESHOLD:
        return "clear_low"
    if score > JEV_CLEAR_HIGH_THRESHOLD:
        return "clear_high"
    return "escalate"


async def score_arm(backend: JevTriageBackend, arm: str, release: str,
                    pass_no: int, contexts: list[dict[str, Any]],
                    concurrency: int) -> dict[str, Any]:
    sem = asyncio.Semaphore(concurrency)
    rows: list[dict[str, Any] | None] = [None] * len(contexts)

    async def one(index: int, case: dict[str, Any]) -> None:
        ctx = case["context"]
        if arm == "legacy":
            payload = {
                "model": release,
                "state": JevTriageBackend.build_legacy_state(ctx),
                "questions": {"is_threat": JEV_IS_THREAT_QUESTION},
            }
        else:
            payload = backend._build_atomic_payload(ctx)
            payload["model"] = release  # pin the named release, never the alias
        row: dict[str, Any] = {
            "id": case["id"], "suite": case["suite"], "label": case["label"],
            "scenario": case["scenario"], "arm": arm, "release": release,
            "pass": pass_no, "state": payload["state"],
            "question_keys": sorted(payload["questions"]),
        }
        async with sem:
            try:
                response = await backend._post_with_one_retry(payload)
                if response.status_code != 200:
                    row["error"] = f"HTTP {response.status_code}"
                else:
                    data = response.json()
                    row["served_model"] = data.get("model")
                    row["usage"] = data.get("usage")
                    if arm == "legacy":
                        score = backend._read_noul((data.get("answers") or {}).get("is_threat"))
                        if score is None:
                            row["error"] = "invalid legacy noul"
                        else:
                            row["answers"] = {"is_threat": score}
                    else:
                        answers = parse_atomic_answers(data)
                        row["answers"] = answers
                        score = combine_answers(answers)
                    if score is not None:
                        row["threat_score"] = score
                        row["band"] = band_for(score)
            except Exception as exc:  # noqa: BLE001 - record, never silently drop
                row["error"] = type(exc).__name__
        rows[index] = row

    await asyncio.gather(*(one(i, c) for i, c in enumerate(contexts)))
    resolved = [r for r in rows if r is not None]
    served: dict[str, int] = {}
    for row in resolved:
        name = row.get("served_model")
        if isinstance(name, str):
            served[name] = served.get(name, 0) + 1
    return {
        "pass": pass_no, "release": release, "arm": arm,
        "cases": len(resolved),
        "errors": sum(1 for r in resolved if r.get("error")),
        "served_models": served,
        "rows": resolved,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()

    contexts = build_contexts()
    canonical = {c["id"]: c["state"] for c in build_cases(list(SUITES))}
    assert [c["id"] for c in contexts] == [c["id"] for c in build_cases(list(SUITES))]
    for case in contexts:
        assert JevTriageBackend.build_legacy_state(case["context"]) == canonical[case["id"]], case["id"]

    runs: list[dict[str, Any]] = []
    for pass_no in PASSES:
        for release in RELEASES:
            for arm in ARMS:
                backend = JevTriageBackend(
                    api_key=os.environ["TYPESAFE_API_KEY"], model=release
                )
                try:
                    runs.append(await score_arm(backend, arm, release, pass_no, contexts, args.concurrency))
                finally:
                    await backend.aclose()
                print(
                    f"pass {pass_no} {release} {arm}: errors={runs[-1]['errors']} "
                    f"served={runs[-1]['served_models']}", flush=True,
                )

    artifact = {
        "schema_version": 1,
        "purpose": "TASK-G04 golden A/B evidence only; production stays legacy until the held-out gate passes.",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "question_sets": {"legacy": ["is_threat"], "atomic": sorted(JEV_ATOMIC_QUESTIONS)},
        "band": {"clear_low": JEV_CLEAR_LOW_THRESHOLD, "clear_high": JEV_CLEAR_HIGH_THRESHOLD},
        "releases_requested": list(RELEASES),
        "order": "pass 1/2 -> release 1.13/1.14 -> arm legacy/atomic (releases and arms interleaved within each pass)",
        "split": "sha256(eval_case_id).digest()[0] & 1; dev=0, heldout=1 (label-blind, matches jev_band_sweep)",
        "corpus": {"suites": list(SUITES), "cases": len(contexts)},
        "runs": runs,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    errors = sum(run["errors"] for run in runs)
    print(f"wrote {args.out} runs={len(runs)} cases={len(contexts)} errors={errors}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
