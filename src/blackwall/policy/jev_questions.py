"""Atomic Tier-1 questions for Track G (FR-09): one judgment per category.

The wording has a single source of truth, ``jev_questions.json``, shared with the
dev ``.mjs`` probe helper so calibration and production ask identical questions.
Question names are descriptive content, not opaque IDs (per the TypeSafe skill).
"""

import json
import math
from pathlib import Path
from typing import Any

JEV_ATOMIC_QUESTIONS: dict[str, dict[str, Any]] = json.loads(
    Path(__file__).with_name("jev_questions.json").read_text(encoding="utf-8")
)


def parse_atomic_answers(data: dict[str, Any]) -> dict[str, float]:
    """Read answers.<name>.noul for every atomic question; fail closed on malformed data."""
    answers = data.get("answers")
    if not isinstance(answers, dict):
        raise ValueError("Jev response has no answers object")  # noqa: TRY004
    result: dict[str, float] = {}
    for name in JEV_ATOMIC_QUESTIONS:
        answer = answers.get(name)
        if not isinstance(answer, dict) or answer.get("type") != "noul":
            raise ValueError(f"Jev answer for {name} is not a noul answer")
        probability = answer.get("noul")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)):
            # Fail closed with one uniform error type for all malformed answers.
            raise ValueError(f"Jev answer for {name} has no numeric noul probability")  # noqa: TRY004
        if not math.isfinite(probability) or not 0.0 <= float(probability) <= 1.0:
            raise ValueError(f"Jev answer for {name} is out of range")
        result[name] = float(probability)
    return result


def combine_answers(probabilities: dict[str, float]) -> float:
    """Fail-closed ``max`` over category probabilities (total over [0, 1]).

    A strong signal in any one category raises the single Tier-1 ``threat_score``
    signal. Invalid inputs raise rather than being clamped to a plausible score.
    """
    if not probabilities:
        raise ValueError("no category probabilities to combine")
    values = list(probabilities.values())
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("category probability is not numeric")  # noqa: TRY004
        if not math.isfinite(value) or not 0.0 <= float(value) <= 1.0:
            raise ValueError("category probability is out of range")
    return max(float(v) for v in values)
