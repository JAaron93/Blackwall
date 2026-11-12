"""Unit tests for the Jev eval producer (scripts/jev_triage_eval.py).

Governing spec: .kiro/specs/tier-1-jev-addition/ (transport: ADR 0008).

The producer turns raw rows from the Node helper (scripts/jev_evaluate.mjs)
into the committed per-case artifact consumed by notebooks/benchmark_analytics.py.
These tests pin the first-party API row shape and the drift guards that keep the
two language implementations of the calibrated question identical. They never
execute ``node`` or touch the network (testing rule 61).
"""

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from blackwall.policy.semantic import JEV_IS_THREAT_QUESTION

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_triage_eval.py"
HELPER = REPO_ROOT / "scripts" / "jev_evaluate.mjs"


@pytest.fixture(scope="module")
def eval_module():
    spec = importlib.util.spec_from_file_location("jev_triage_eval", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def _case(case_id: str = "case-1", state_hash: str = "h1") -> dict[str, Any]:
    return {"id": case_id, "state": "Tool: t\nRequest: hi", "h": state_hash}


def _raw_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "case-1",
        "suite": "security",
        "h": "h1",
        "label": 1,
        "expected": "BLOCK",
        "scenario": "sqli",
        "tool": "database_query",
        "model": "jev-latest",
        "served_model": "jev-1.14.0",
        "p": 0.93,
        "confidence": None,
        "latency_ms": 812,
        "usage": {"input_tokens": 120, "output_tokens": 8},
        "error": None,
        "is_fallback": False,
    }
    row.update(overrides)
    return row


def test_record_maps_noul_row_to_artifact_shape(eval_module):
    records = eval_module.build_records([_raw_row()], [_case()])
    assert len(records) == 1
    record = records[0]
    assert record["eval_case_id"] == "case-1"
    assert record["ground_truth"] == "MALICIOUS"
    assert record["backend"] == "jev"
    assert record["p_threat"] == pytest.approx(0.93)
    assert record["confidence"] is None
    assert record["input_tokens"] == 120
    assert record["output_tokens"] == 8
    assert record["is_fallback"] is False
    assert record["error"] is None


def test_record_model_is_the_served_release_not_the_alias(eval_module):
    """Provenance: the artifact must say which Jev release answered, because
    the fixed 0.35/0.75 band is only valid for the release it was calibrated on."""
    record = eval_module.build_records([_raw_row()], [_case()])[0]
    assert record["model"] == "jev-1.14.0"


def test_record_model_falls_back_to_requested_model(eval_module):
    row = _raw_row(served_model=None, p=None, error="HTTP 401", is_fallback=True)
    record = eval_module.build_records([row], [_case()])[0]
    assert record["model"] == "jev-latest"
    assert record["is_fallback"] is True
    assert record["error"] == "HTTP 401"


def test_legacy_camel_case_usage_is_not_read(eval_module):
    """Vercel-era ``inputTokens`` keys are not part of the first-party contract."""
    row = _raw_row(usage={"inputTokens": 99, "outputTokens": 9})
    record = eval_module.build_records([row], [_case()])[0]
    assert record["input_tokens"] is None
    assert record["output_tokens"] is None


def test_stale_and_out_of_scope_rows_are_dropped(eval_module):
    rows = [
        _raw_row(id="case-1", h="old-hash"),  # state changed since the row was made
        _raw_row(id="not-in-this-run"),  # different suite selection / --limit
    ]
    assert eval_module.build_records(rows, [_case("case-1", "h1")]) == []


def test_producer_requires_typesafe_key_and_ignores_legacy(
    eval_module, monkeypatch, tmp_path, capsys
):
    # Hermetic by construction: main() writes the committed A/B artifact and a
    # per-user cache and shells out to node. Redirect every path and make any
    # subprocess call fail loudly, so a regression can never touch real state.
    monkeypatch.setattr(eval_module, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(eval_module, "INSTALL_DIR", tmp_path / "cache")

    def _forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("main() must not spawn a process without a key")

    monkeypatch.setattr(eval_module.subprocess, "run", _forbidden)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "legacy-vercel-credential")
    monkeypatch.setattr(sys, "argv", ["jev_triage_eval.py"])
    assert eval_module.main() == 2
    assert "TYPESAFE_API_KEY is not set" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []  # nothing written anywhere


def test_pacing_flag_is_gone(eval_module, monkeypatch, tmp_path):
    """The 2s inter-call pacing existed for the Gateway free tier's ~20-call burst
    cap. On the paid API calls run back to back (ADR 0008)."""
    monkeypatch.setattr(eval_module, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(eval_module, "INSTALL_DIR", tmp_path / "cache")
    # Hermetic even in a regression: no key, and no process may be spawned.
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)

    def _forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("must not spawn a process")

    monkeypatch.setattr(eval_module.subprocess, "run", _forbidden)
    monkeypatch.setattr(sys, "argv", ["jev_triage_eval.py", "--pace-ms", "1"])
    with pytest.raises(SystemExit) as exc:
        eval_module.main()
    assert exc.value.code == 2  # argparse: unrecognized arguments
    assert "pace" not in SCRIPT.read_text(encoding="utf-8").lower()


def test_producer_has_no_npm_bootstrap(eval_module):
    """The helper uses Node's built-in fetch; the `npm install ai` bootstrap
    (Vercel AI SDK) must be gone."""
    assert not hasattr(eval_module, "ensure_node_env")
    assert "npm" not in SCRIPT.read_text(encoding="utf-8")


def test_question_wording_is_identical_in_python_and_node():
    """Drift guard: the calibrated instructions are duplicated in the dev-only
    Node helper (NFR-06 forbids a Node runtime path). Text-only comparison."""
    source = HELPER.read_text(encoding="utf-8")
    match = re.search(r"IS_THREAT_INSTRUCTIONS =\s*\n?\s*'((?:[^'\\]|\\.)*)'", source)
    assert match is not None, "IS_THREAT_INSTRUCTIONS constant not found"
    assert match.group(1) == JEV_IS_THREAT_QUESTION["instructions"]
    assert JEV_IS_THREAT_QUESTION["type"] == "noul"
