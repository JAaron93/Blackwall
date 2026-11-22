"""TASK-F02 follow-up: test native-object state as a Tier-1 steering defense.

Two harness-only arms, both using the SHIPPED single `is_threat` question and the
0.08/0.40 band: legacy dict-repr state vs G01's native JSON object state. No
question redesign (G04 rejected that), no Tier-2 calls, no production change.
The dev payloads are used to design; the heldout payloads are a one-pass check.

Usage:
  TYPESAFE_API_KEY=... .venv/bin/python scripts/jev_f02_structured_state.py --out <file>.json
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

from jev_tier2_eval import (
    apply_steering,
    load_cases,
    tier1_payloads,
)

from blackwall.models import ToolCallContext
from blackwall.policy.semantic import (
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JEV_IS_THREAT_QUESTION,
    JevTriageBackend,
)
from blackwall.resolver import ContextHygiene

RELEASE = "jev-1.14.0"
ARMS = ("legacy", "structured")
PASSES = (1, 2)
DEV_BASES = 20
HELDOUT_BASES = 10


def select_bases() -> dict[str, list[Any]]:
    cases = load_cases(RELEASE, "current")
    malicious = sorted((c for c in cases if c.label == "MALICIOUS"), key=lambda c: c.id)[:DEV_BASES + HELDOUT_BASES]
    benign = sorted((c for c in cases if c.label == "BENIGN"), key=lambda c: c.id)[:DEV_BASES + HELDOUT_BASES]
    return {"malicious": malicious, "benign": benign}


def band_for(p: float) -> str:
    if p < JEV_CLEAR_LOW_THRESHOLD:
        return "clear_low"
    if p > JEV_CLEAR_HIGH_THRESHOLD:
        return "clear_high"
    return "escalate"


async def run_arm(backend: JevTriageBackend, arm: str, pass_no: int,
                  jobs: list[dict[str, Any]], concurrency: int) -> dict[str, Any]:
    sem = asyncio.Semaphore(concurrency)
    rows: list[dict[str, Any] | None] = [None] * len(jobs)
    hygiene = ContextHygiene(preserve_iocs=True)

    async def one(index: int, job: dict[str, Any]) -> None:
        case = job["case"]
        ctx = hygiene.sanitize_context(
            ToolCallContext(tool_name=case.tool, arguments=case.args,
                            metadata=getattr(case, "metadata", None))
        )
        state = (JevTriageBackend.build_legacy_state(ctx) if arm == "legacy"
                 else JevTriageBackend.build_state(ctx))
        payload = {"model": RELEASE, "state": state,
                   "questions": {"is_threat": JEV_IS_THREAT_QUESTION}}
        row: dict[str, Any] = {
            "id": case.id, "base_id": job["base_id"], "klass": job["klass"],
            "payload_id": job["payload_id"], "split": job["split"],
            "carrier": job["carrier"], "arm": arm, "pass": pass_no,
            "label": 1 if case.label == "MALICIOUS" else 0,
            "unsteered_p": float(case.jev_p), "state": state,
            "is_fallback": False,
        }
        async with sem:
            try:
                response = await backend._post_with_one_retry(payload)
                if response.status_code != 200:
                    row.update(error=f"HTTP {response.status_code}", is_fallback=True)
                else:
                    data = response.json()
                    p = backend._read_noul((data.get("answers") or {}).get("is_threat"))
                    if p is None:
                        row.update(error="invalid noul", is_fallback=True)
                    else:
                        row.update(served_model=data.get("model"), usage=data.get("usage"),
                                   threat_score=p, band=band_for(p))
            except Exception as exc:  # noqa: BLE001 - recorded, never dropped
                row.update(error=type(exc).__name__, is_fallback=True)
        rows[index] = row

    await asyncio.gather(*(one(i, j) for i, j in enumerate(jobs)))
    resolved = [r for r in rows if r is not None]
    served: dict[str, int] = {}
    for row in resolved:
        name = row.get("served_model")
        if isinstance(name, str):
            served[name] = served.get(name, 0) + 1
    return {
        "arm": arm, "pass": pass_no, "split_jobs": sorted({j["split"] for j in jobs}),
        "calls": len(resolved), "errors": sum(1 for r in resolved if r.get("error")),
        "served_models": served, "rows": resolved,
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()

    bases = select_bases()
    dev_payloads = [p for p in tier1_payloads("dev")]
    heldout_payloads = [p for p in tier1_payloads("heldout")]

    def jobs_for(split: str, n_bases: int) -> list[dict[str, Any]]:
        payloads = dev_payloads if split == "dev" else heldout_payloads
        out: list[dict[str, Any]] = []
        for klass, cases in bases.items():
            for base in cases[:n_bases]:
                out.append({
                    "base_id": base.id, "klass": klass, "case": base,
                    "payload_id": "baseline", "split": split, "carrier": "none",
                })
                for payload in payloads:
                    out.append({
                        "base_id": base.id, "klass": klass,
                        "case": apply_steering(base, payload),
                        "payload_id": payload.id, "split": split, "carrier": payload.carrier,
                    })
        return out

    runs: list[dict[str, Any]] = []
    for pass_no in PASSES:
        for arm in ARMS:
            backend = JevTriageBackend(api_key=os.environ["TYPESAFE_API_KEY"], model=RELEASE)
            try:
                runs.append(await run_arm(backend, arm, pass_no, jobs_for("dev", DEV_BASES), args.concurrency))
            finally:
                await backend.aclose()
            print(f"dev pass {pass_no} {arm}: errors={runs[-1]['errors']} served={runs[-1]['served_models']}", flush=True)

    # Heldout one-pass check (different payload text, different base cases where possible).
    for arm in ARMS:
        backend = JevTriageBackend(api_key=os.environ["TYPESAFE_API_KEY"], model=RELEASE)
        try:
            runs.append(await run_arm(backend, arm, 3, jobs_for("heldout", HELDOUT_BASES), args.concurrency))
        finally:
            await backend.aclose()
        print(f"heldout {arm}: errors={runs[-1]['errors']} served={runs[-1]['served_models']}", flush=True)

    artifact = {
        "schema_version": 1,
        "purpose": "TASK-F02 follow-up evidence: native-object state vs legacy state under Tier-1 steering. Harness-only; no production change.",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "release_requested": RELEASE,
        "band": {"clear_low": JEV_CLEAR_LOW_THRESHOLD, "clear_high": JEV_CLEAR_HIGH_THRESHOLD},
        "question": "is_threat (unchanged shipped single noul)",
        "arms": {"legacy": "build_legacy_state dict-repr string", "structured": "build_state native JSON object"},
        "selection": f"dev: {DEV_BASES} malicious + {DEV_BASES} benign bases, {len(dev_payloads)} dev payloads + baseline, 2 interleaved passes; heldout: {HELDOUT_BASES} per class, {len(heldout_payloads)} heldout payloads + baseline, one pass",
        "caveat": "Tier-1 signals only; no Tier-2 verdicts, so to-ALLOW flips are not measured. Below-edge crossings, benign clear-high holds and P shift are.",
        "question_definition": JEV_IS_THREAT_QUESTION,
        "runs": runs,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} runs={len(runs)} errors={sum(r['errors'] for r in runs)}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
