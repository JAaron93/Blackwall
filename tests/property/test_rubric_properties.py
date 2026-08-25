"""
Property-based Tests for Pydantic Rubric Models (`tests/property/test_rubric_properties.py`).

Validates:
- Property E-8: All score fields reject values outside [1, 5] (and [-5, 5] for deltas).
- Property E-9: Justification rejects strings shorter than 10 characters.
- Property E-10: extra="forbid" rejects unknown fields.
- Property E-11: is_fallback defaults to False.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from blackwall.eval.rubrics import (
    AILMDetectionRubric,
    C2DetectionRubric,
    ContextHygieneRubric,
    ExploitChainRubric,
    InboundFilterRubric,
    PromptInjectionRubric,
    QuotaEnforcementRubric,
    RegressionComparisonRubric,
    SwarmDetectionRubric,
    ThreatInterceptionRubric,
)

RUBRIC_CLASSES = [
    ThreatInterceptionRubric,
    SwarmDetectionRubric,
    ExploitChainRubric,
    C2DetectionRubric,
    AILMDetectionRubric,
    PromptInjectionRubric,
    InboundFilterRubric,
    QuotaEnforcementRubric,
    ContextHygieneRubric,
]


# ---------------------------------------------------------------------------
# Property E-8: All score fields reject values outside [1, 5]
# ---------------------------------------------------------------------------
@settings(max_examples=50, deadline=None)
@given(
    rubric_cls=st.sampled_from(RUBRIC_CLASSES),
    invalid_score=st.one_of(st.integers(max_value=0), st.integers(min_value=6)),
    justification=st.text(min_size=10, max_size=50).filter(lambda s: len(s.strip()) >= 10),
)
def test_property_e8_score_bounds_rejection(
    rubric_cls: type, invalid_score: int, justification: str
) -> None:
    # First field in the model is a score field
    score_fields = [k for k in rubric_cls.model_fields if k.endswith("_score")]
    target_field = score_fields[0]

    valid_kwargs = {f: 3 for f in score_fields}
    valid_kwargs["justification"] = justification

    # Invalid score must raise ValidationError
    invalid_kwargs = dict(valid_kwargs)
    invalid_kwargs[target_field] = invalid_score

    with pytest.raises(ValidationError):
        rubric_cls(**invalid_kwargs)


# ---------------------------------------------------------------------------
# Property E-9: Justification rejects strings shorter than 10 characters
# ---------------------------------------------------------------------------
@settings(max_examples=50, deadline=None)
@given(
    rubric_cls=st.sampled_from(RUBRIC_CLASSES),
    short_justification=st.text(min_size=0, max_size=9),
)
def test_property_e9_justification_short_rejection(
    rubric_cls: type, short_justification: str
) -> None:
    score_fields = [k for k in rubric_cls.model_fields if k.endswith("_score")]
    valid_kwargs = {f: 3 for f in score_fields}
    valid_kwargs["justification"] = short_justification

    with pytest.raises(ValidationError):
        rubric_cls(**valid_kwargs)


# ---------------------------------------------------------------------------
# Property E-10: extra="forbid" rejects unknown fields
# ---------------------------------------------------------------------------
@settings(max_examples=50, deadline=None)
@given(
    rubric_cls=st.sampled_from(RUBRIC_CLASSES + [RegressionComparisonRubric]),
    extra_field=st.from_regex(r"[a-z_]{5,15}", fullmatch=True),
    justification=st.text(min_size=10, max_size=50).filter(lambda s: len(s.strip()) >= 10),
)
def test_property_e10_extra_fields_forbid(
    rubric_cls: type, extra_field: str, justification: str
) -> None:
    if extra_field in rubric_cls.model_fields:
        extra_field = f"extra_{extra_field}"

    score_fields = [k for k in rubric_cls.model_fields if k.endswith(("_score", "_delta"))]
    valid_kwargs = {f: 3 if f.endswith("_score") else 0 for f in score_fields}
    valid_kwargs["justification"] = justification
    valid_kwargs[extra_field] = "unexpected_data"

    with pytest.raises(ValidationError):
        rubric_cls(**valid_kwargs)


# ---------------------------------------------------------------------------
# Property E-11: is_fallback defaults to False
# ---------------------------------------------------------------------------
@settings(max_examples=50, deadline=None)
@given(
    rubric_cls=st.sampled_from(RUBRIC_CLASSES),
    justification=st.text(min_size=10, max_size=50).filter(lambda s: len(s.strip()) >= 10),
)
def test_property_e11_is_fallback_defaults_to_false(
    rubric_cls: type, justification: str
) -> None:
    score_fields = [k for k in rubric_cls.model_fields if k.endswith("_score")]
    valid_kwargs = {f: 4 for f in score_fields}
    valid_kwargs["justification"] = justification

    instance = rubric_cls(**valid_kwargs)
    assert instance.is_fallback is False
