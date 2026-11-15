"""Wording-parity guard between the dev Node helper and the production backend.

typesafe-ai skill audit F9: ``scripts/jev_evaluate.mjs`` (dev-only eval tooling)
duplicates the calibrated ``is_threat`` question wording. The fixed 0.35/0.75
band is only valid for that wording, so the two copies MUST stay identical —
the .mjs comment already states this invariant. This static guard fails if
either side drifts (no Node execution; rule 61 keeps ``node --test`` separate).
Track G updates both copies together when the question set is redesigned.
"""

from __future__ import annotations

import re
from pathlib import Path

from blackwall.policy.semantic import JEV_IS_THREAT_QUESTION

_MJS = Path(__file__).resolve().parents[2] / "scripts" / "jev_evaluate.mjs"


def _mjs_instructions() -> str:
    text = _MJS.read_text(encoding="utf-8")
    match = re.search(
        r"export const IS_THREAT_INSTRUCTIONS =\s*'([^']*)';", text
    )
    assert match is not None, "IS_THREAT_INSTRUCTIONS not found in jev_evaluate.mjs"
    return match.group(1)


def test_question_wording_matches_between_mjs_and_backend() -> None:
    assert _mjs_instructions() == JEV_IS_THREAT_QUESTION["instructions"]


def test_question_type_is_noul_in_both() -> None:
    text = _MJS.read_text(encoding="utf-8")
    assert "type: 'noul'" in text
    assert JEV_IS_THREAT_QUESTION["type"] == "noul"