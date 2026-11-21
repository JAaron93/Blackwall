"""TASK-G03 live probe: read individual atomic Jev answers on a bounded corpus.

Probes representative C2/IOC, other-malicious and benign cases with the G02
atomic payload (six noul questions over one native-object state), keeps the exact
payload and every category answer, and exposes a deterministic dev/held-out
split for wording refinement. No production flip; no verdict claims.

Usage:
  TYPESAFE_API_KEY=... python scripts/jev_atomic_probe.py --out <file>.json
"""
import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from blackwall.models import ToolCallContext
from blackwall.policy.jev_questions import (
    JEV_ATOMIC_QUESTIONS,
    parse_atomic_answers,
)
from blackwall.policy.semantic import (
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    JevTriageBackend,
)
from blackwall.resolver import ContextHygiene

EVALSET = REPO_ROOT / "tests" / "eval" / "evalsets" / "blackwall_security.evalset.json"
IOC_TYPES = {"C2_IOC", "REVERSE_SHELL", "CREDENTIAL_EXFILTRATION", "COVERT_CHANNEL"}
DEFAULT_MODEL = "jev-1.14.0"  # request a named release, never the moving alias


def split_for(case_id: str) -> str:
    return "dev" if hashlib.sha256(case_id.encode("utf-8")).digest()[0] & 1 else "heldout"


def select_cases(per_class: int) -> list[dict[str, Any]]:
    cases = json.loads(EVALSET.read_text(encoding="utf-8"))["eval_cases"]
    buckets: dict[str, list[dict[str, Any]]] = {"ioc": [], "other_malicious": [], "benign": []}
    for case in sorted(cases, key=lambda c: c["eval_case_id"]):
        md = case["metadata"]
        label = md["ground_truth"]
        attack = md.get("attack_type") or ""
        if label == "BENIGN":
            key = "benign"
        elif attack in IOC_TYPES:
            key = "ioc"
        elif label == "MALICIOUS":
            key = "other_malicious"
        else:
            continue
        buckets[key].append(case)
    selected = []
    for key, rows in buckets.items():
        for case in rows[:per_class]:
            md = case["metadata"]
            selected.append({
                "id": case["eval_case_id"],
                "klass": key,
                "label": md["ground_truth"],
                "attack_type": md.get("attack_type"),
                "tool": md["tool_name"],
                "args": dict(md["tool_arguments"]),
                "split": split_for(case["eval_case_id"]),
            })
    return selected


async def probe(selected: list[dict[str, Any]], concurrency: int, model: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    backend = JevTriageBackend(api_key=os.environ["TYPESAFE_API_KEY"], model=model)
    hygiene = ContextHygiene(preserve_iocs=True)
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any] | None] = [None] * len(selected)

    async def one(index: int, case: dict[str, Any]) -> None:
        ctx = hygiene.sanitize_context(
            ToolCallContext(tool_name=case["tool"], arguments=case["args"])
        )
        payload = backend._build_atomic_payload(ctx)
        row: dict[str, Any] = {**case, "state": payload["state"], "questions": payload["questions"]}
        async with sem:
            try:
                response = await backend._post_with_one_retry(payload)
                if response.status_code != 200:
                    row["error"] = f"HTTP {response.status_code}"
                else:
                    data = response.json()
                    row["answers"] = parse_atomic_answers(data)
                    row["served_model"] = data.get("model")
                    row["usage"] = data.get("usage")
                    result = backend._parse_atomic_response(data)
                    row["threat_score"] = result.threat_score
                    score = result.threat_score
                    row["band"] = (
                        "clear_low" if score < JEV_CLEAR_LOW_THRESHOLD
                        else "clear_high" if score > JEV_CLEAR_HIGH_THRESHOLD
                        else "escalate"
                    )
            except Exception as exc:  # noqa: BLE001 - failed calls are recorded, never silently dropped
                row["error"] = type(exc).__name__
        results[index] = row

    try:
        await asyncio.gather(*(one(i, c) for i, c in enumerate(selected)))
    finally:
        await backend.aclose()
    served: dict[str, int] = {}
    for row in results:
        name = (row or {}).get("served_model")
        if name:
            served[name] = served.get(name, 0) + 1
    return [r for r in results if r is not None], served


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--split", choices=("all", "dev", "heldout"), default="all",
                        help="probe a single split for wording refinement checks")
    args = parser.parse_args()
    selected = select_cases(args.per_class)
    if args.split != "all":
        selected = [c for c in selected if c["split"] == args.split]
    rows, served = await probe(selected, args.concurrency, args.model)
    artifact = {
        "schema_version": 1,
        "purpose": "TASK-G03 live probe of atomic Jev questions; evidence only, no production flip.",
        "model_requested": args.model,
        "split_requested": args.split,
        "served_models": served,
        "question_keys": list(JEV_ATOMIC_QUESTIONS),
        "band": {"clear_low": JEV_CLEAR_LOW_THRESHOLD, "clear_high": JEV_CLEAR_HIGH_THRESHOLD},
        "split": "sha256(eval_case_id).digest()[0] & 1; dev=1, heldout=0",
        "cases": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    errors = sum(1 for r in rows if r.get("error"))
    print(f"wrote {args.out} cases={len(rows)} errors={errors} served={served}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
