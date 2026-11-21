"""TASK-G02: atomic questions, strict multi-answer parsing, fail-closed max.

Wording parity is checked statically here (no Node execution); executable JS
checks live in ``scripts/jev_questions_export.test.mjs`` under ``node --test``.
"""

from pathlib import Path

import pytest

from blackwall.models import ToolCallContext
from blackwall.policy.jev_questions import (
    JEV_ATOMIC_QUESTIONS,
    combine_answers,
    parse_atomic_answers,
)
from blackwall.policy.semantic import JevTriageBackend

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_six_atomic_questions_each_carry_criteria():
    assert len(JEV_ATOMIC_QUESTIONS) == 6
    for name, question in JEV_ATOMIC_QUESTIONS.items():
        assert question["type"] == "noul", name
        assert question["instructions"].strip(), name
        assert question["criteria"]["true"].strip(), name
        assert question["criteria"]["false"].strip(), name


def test_refined_unauthorized_criteria_name_the_dev_confusers():
    """G03 refinement: audit-log reads and declared internal fetches are not attacks."""
    false_criteria = JEV_ATOMIC_QUESTIONS["unauthorized_access"]["criteria"]["false"].lower()
    assert "audit" in false_criteria
    assert "internal" in false_criteria


def test_parse_atomic_answers_is_strict_and_fail_closed():
    payload = {
        "answers": {
            name: {"type": "noul", "noul": 0.1 + i / 10}
            for i, name in enumerate(JEV_ATOMIC_QUESTIONS)
        }
    }
    got = parse_atomic_answers(payload)
    assert set(got) == set(JEV_ATOMIC_QUESTIONS)
    assert all(isinstance(v, float) and 0.0 <= v <= 1.0 for v in got.values())

    for bad in (
        {"answers": {}},
        {"answers": {"injection": {"type": "noul", "noul": 1.5}}},
        {"answers": {"injection": {"type": "choice", "noul": 0.5}}},
        {"answers": None},
    ):
        with pytest.raises(ValueError, match="answer"):
            parse_atomic_answers(bad)


def test_combine_answers_is_fail_closed_max_and_total():
    assert combine_answers({"a": 0.1, "b": 0.73, "c": 0.4}) == pytest.approx(0.73)
    assert combine_answers({"a": 0.0}) == 0.0
    assert combine_answers({"a": 1.0}) == 1.0
    for bad in ({}, {"a": -0.1}, {"a": 1.2}, {"a": float("nan")}, {"a": True}):
        with pytest.raises(ValueError):
            combine_answers(bad)


def test_build_state_returns_native_json_object():
    ctx = ToolCallContext(tool_name="query_db", arguments={"sql": "SELECT 1"}, metadata={})
    state = JevTriageBackend.build_state(ctx)
    assert isinstance(state, dict)
    assert state["tool"]["name"] == "query_db"
    assert state["arguments"] == {"sql": "SELECT 1"}


def test_dev_mjs_helper_reads_shared_wording_without_duplicating_it():
    """Static guard: no Node execution, no second copy of the calibrated wording."""
    script = (REPO_ROOT / "scripts" / "jev_questions_export.mjs").read_text(encoding="utf-8")
    assert "jev_questions.json" in script
    assert "readFileSync" in script
    for question in JEV_ATOMIC_QUESTIONS.values():
        assert question["instructions"] not in script
        assert question["criteria"]["true"] not in script
        assert question["criteria"]["false"] not in script
