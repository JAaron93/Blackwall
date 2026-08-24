#!/usr/bin/env python3
"""
ADK-to-EvalTask Dataset Bridge (`scripts/bridge_adk_to_eval.py`).

Transforms ADK evalset JSON files (from build_evalset.py) into
judge-consumable scenario format for Blackwall Vertex AI / Antigravity evaluation.

Usage:
    python scripts/bridge_adk_to_eval.py [--workspace <path>] [--input <path>] [--output <path>]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from blackwall.eval.scenarios import ThreatInterceptionScenario

logger = logging.getLogger(__name__)


def transform_adk_case(case: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a single ADK EvalCase dictionary into a judge-consumable scenario dictionary.

    Mapping:
      - eval_case_id -> scenario_id
      - domain -> "threat_interception"
      - conversation text -> prompt
      - reference -> ground_truth_verdict (ALLOW, BLOCK, QUARANTINE)
      - metadata.ground_truth -> ground_truth_label (BENIGN, MALICIOUS)
      - expected_tool_use tool_names -> reference_trajectory
      - metadata -> preserved dict
    """
    scenario_id = case.get("eval_case_id") or case.get("id") or case.get("scenario_id")
    if not scenario_id:
        raise ValueError(f"ADK case missing required identifier ('eval_case_id' or 'id'): {case}")

    # Extract prompt from conversation
    prompt = ""
    conversation = case.get("conversation", [])
    if conversation and isinstance(conversation, list):
        first_turn = conversation[0]
        if isinstance(first_turn, dict):
            parts = first_turn.get("parts", [])
            if parts and isinstance(parts, list) and isinstance(parts[0], dict):
                prompt = parts[0].get("text", "")
            elif "content" in first_turn:
                prompt = str(first_turn["content"])
            elif "text" in first_turn:
                prompt = str(first_turn["text"])
    elif "prompt" in case:
        prompt = str(case["prompt"])

    # Extract verdicts and labels
    reference_verdict = case.get("reference") or case.get("expected_verdict") or "ALLOW"
    ground_truth_verdict = str(reference_verdict).upper()

    metadata = dict(case.get("metadata", {}))
    ground_truth_label = metadata.get("ground_truth")
    if not ground_truth_label:
        ground_truth_label = "MALICIOUS" if ground_truth_verdict in ("BLOCK", "QUARANTINE") else "BENIGN"
    ground_truth_label = str(ground_truth_label).upper()

    # Extract reference trajectory
    expected_tool_use = case.get("expected_tool_use", [])
    reference_trajectory: list[str] = []
    if isinstance(expected_tool_use, list):
        for step in expected_tool_use:
            if isinstance(step, dict):
                tool_use = step.get("tool_use", {})
                if isinstance(tool_use, dict) and "tool_name" in tool_use:
                    reference_trajectory.append(str(tool_use["tool_name"]))
                elif "tool_name" in step:
                    reference_trajectory.append(str(step["tool_name"]))

    if not reference_trajectory:
        reference_trajectory = ["before_tool_callback"]

    # Extract tool_call if available
    tool_call: dict[str, Any] | None = None
    if "tool_call_context" in case:
        tool_call = case["tool_call_context"]
    elif expected_tool_use and isinstance(expected_tool_use[0], dict):
        tool_input = expected_tool_use[0].get("tool_use", {}).get("tool_input")
        if tool_input:
            tool_call = {"tool_input": tool_input}

    scenario_dict: dict[str, Any] = {
        "scenario_id": str(scenario_id),
        "domain": "threat_interception",
        "prompt": prompt,
        "ground_truth_verdict": ground_truth_verdict,
        "ground_truth_label": ground_truth_label,
        "reference_trajectory": reference_trajectory,
        "metadata": metadata,
    }
    if tool_call is not None:
        scenario_dict["tool_call"] = tool_call

    # Validate output schema compliance
    ThreatInterceptionScenario.model_validate(scenario_dict)

    return scenario_dict


def bridge_adk_evalset(adk_data: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Transform an entire ADK evalset structure into a list of judge-consumable scenarios.

    Accepts either:
      - {"eval_cases": [...]}
      - {"cases": [...]}
      - [...]
    """
    if isinstance(adk_data, dict):
        raw_cases = adk_data.get("eval_cases") or adk_data.get("cases") or []
    elif isinstance(adk_data, list):
        raw_cases = adk_data
    else:
        raise TypeError(f"Invalid ADK evalset data type: {type(adk_data).__name__}")

    scenarios = []
    for raw_case in raw_cases:
        scenarios.append(transform_adk_case(raw_case))

    return scenarios


def bridge_file(input_path: Path, output_path: Path) -> list[dict[str, Any]]:
    """Read ADK evalset from input_path, transform, and write judge scenarios to output_path."""
    if not input_path.exists():
        raise FileNotFoundError(f"ADK evalset file not found at {input_path}")

    raw_text = input_path.read_text(encoding="utf-8")
    data = json.loads(raw_text)
    scenarios = bridge_adk_evalset(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"scenarios": scenarios}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return scenarios


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Root workspace directory",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Input ADK evalset JSON path (default: tests/eval/evalsets/blackwall_security.evalset.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output judge scenarios JSON path (default: tests/eval/judge_scenarios/adk_bridged_scenarios.json)",
    )

    args = parser.parse_args(argv)
    workspace = args.workspace
    input_path = args.input or (workspace / "tests" / "eval" / "evalsets" / "blackwall_security.evalset.json")
    output_path = args.output or (workspace / "tests" / "eval" / "judge_scenarios" / "adk_bridged_scenarios.json")

    try:
        scenarios = bridge_file(input_path, output_path)
        print(f"✅ Successfully bridged {len(scenarios)} ADK cases to {output_path}")
        return 0
    except Exception as e:
        logger.exception("Error bridging ADK evalset")
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
