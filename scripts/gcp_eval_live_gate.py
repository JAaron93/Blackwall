"""TASK-D03 evidence: run the full live GCP eval pipeline and export the managed
Vertex AI EvalTask gate result as a machine-readable artifact.

Harness-only: wraps the REAL GCPVertexAIEvaluationHarness.run_eval_task to capture
its result, never substitutes a canned response. No --allow-fallback, no mocked
judges, no cached rows. Requires the maintainer's .env and ADC.

Usage:
  .venv/bin/python scripts/gcp_eval_live_gate.py --out <file>.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import dotenv_values


def load_env(path: Path) -> None:
    """Read only variable names/values from the operator's env file into this
    process; real environment wins. Values are never printed or committed."""
    for key, value in dotenv_values(path).items():
        if value is not None and key not in os.environ:
            os.environ[key] = value


from run_gcp_eval import run_evaluation_pipeline

from blackwall.enterprise.advanced_threat_detection.gcp_vertex_eval import (
    GCPVertexAIEvaluationHarness,
)
from blackwall.eval.aggregator import EvaluationAggregator


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return str(value)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    captured: dict[str, Any] = {"records": [], "errors": []}
    original = GCPVertexAIEvaluationHarness.run_eval_task
    original_add = EvaluationAggregator.add_record
    original_error = EvaluationAggregator.record_error

    def recording(self: Any, *a: Any, **kw: Any) -> dict[str, Any]:
        result = original(self, *a, **kw)
        captured["result"] = result
        return result

    def recording_add(self: Any, record: Any, *a: Any, **kw: Any) -> None:
        captured["records"].append(json_safe(record.model_dump(mode="json")))
        return original_add(self, record, *a, **kw)

    def recording_error(self: Any, **kw: Any) -> None:
        captured["errors"].append(json_safe(kw))
        return original_error(self, **kw)

    GCPVertexAIEvaluationHarness.run_eval_task = recording  # type: ignore[assignment]
    EvaluationAggregator.add_record = recording_add  # type: ignore[assignment]
    EvaluationAggregator.record_error = recording_error  # type: ignore[assignment]
    try:
        exit_code, summary, regression = await run_evaluation_pipeline(
            domains=[d.strip() for d in args.domains.split(",") if d.strip()] or None,
            threshold=args.eval_threshold,
            scenarios_dir=REPO_ROOT / args.scenarios_dir,
            history_path=args.history_path,
            model=args.model,
            export_trace=not args.no_trace,
            allow_fallback=False,
        )
    finally:
        GCPVertexAIEvaluationHarness.run_eval_task = original  # type: ignore[assignment]
        EvaluationAggregator.add_record = original_add  # type: ignore[assignment]
        EvaluationAggregator.record_error = original_error  # type: ignore[assignment]

    assert "result" in captured, "managed EvalTask was never called"
    result = json_safe(captured["result"])
    score_stats = {
        k: v for k, v in (result.get("summary_metrics") or {}).items()
        if str(k).endswith(("/mean", "/std"))
    }
    managed_scores_usable = bool(score_stats) and all(
        isinstance(v, (int, float)) for v in score_stats.values()
    )
    return {
        "schema_version": 1,
        "purpose": "TASK-D03 live managed Vertex EvalTask gate evidence; real paid calls, no mocks or fallback.",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "script": "scripts/gcp_eval_live_gate.py",
        "method": {
            "pipeline": "scripts/run_gcp_eval.py::run_evaluation_pipeline via a recording wrapper on run_eval_task",
            "domains": args.domains or "all canonical domains",
            "threshold": args.eval_threshold,
            "allow_fallback": False,
            "export_trace": not args.no_trace,
            "history_path": str(args.history_path),
            "authentication": "ADC; GCP settings read from the maintainer's .env via dotenv_values, values never printed or committed",
        },
        "billed": {
            "project": "GCP project from .env (value withheld from the artifact)",
            "judge_and_autorater_model": args.model or "gemini-3.5-flash-lite",
        },
        "eval_task": result,
        "scenario_records": captured["records"],
        "failed_scenarios": captured["errors"],
        "summary": json_safe(summary.model_dump(mode="json")),
        "regression": json_safe(regression.model_dump(mode="json")),
        "exit_code": exit_code,
        "gate": {
            "eval_task_completed": result.get("status") == "COMPLETED",
            "managed_scores_usable": managed_scores_usable,
            "ci_passed": exit_code == 0,
            "fallback_free": summary.total_fallbacks == 0,
            "no_regression": not regression.regression_detected,
        },
        "discarded": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=REPO_ROOT / ".env",
                        help="operator env file (values are loaded, never printed or committed)")
    parser.add_argument("--domains", default="", help="comma-filter; empty = full canonical suite")
    parser.add_argument("--eval-threshold", type=float, default=3.5)
    parser.add_argument("--scenarios-dir", default="tests/eval/judge_scenarios")
    parser.add_argument("--history-path", type=Path,
                        default=Path(tempfile.gettempdir()) / "blackwall_d03_eval_history.jsonl",
                        help="portable scratch ledger (defaults to the OS temp dir)")
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-trace", action="store_true")
    args = parser.parse_args()
    load_env(args.env_file)
    artifact = asyncio.run(run(args))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"wrote {args.out} status={artifact['eval_task'].get('status')} "
        f"exit={artifact['exit_code']} gate={artifact['gate']}", flush=True,
    )


if __name__ == "__main__":
    main()
