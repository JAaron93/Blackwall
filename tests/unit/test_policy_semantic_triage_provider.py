"""Unit tests for the Tier-1 semantic triage result and provider contract (FR-01).

Governing spec: .kiro/specs/tier-1-jev-addition/
"""

import dataclasses
import inspect

import pytest

from blackwall.policy.semantic import (
    JevTriageBackend,
    SemanticTriageProvider,
    SemanticTriageResult,
)


# ----------------------------------------------------------------------
# SemanticTriageResult
# ----------------------------------------------------------------------


def test_result_defaults():
    """A bare result carries no confidence and no escalation flag."""
    result = SemanticTriageResult(threat_score=0.42)
    assert result.threat_score == 0.42
    assert result.confidence is None
    assert result.backend == "jev"
    assert result.escalate is False


def test_result_is_frozen():
    result = SemanticTriageResult(threat_score=0.42)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.threat_score = 0.9  # type: ignore[misc]


@pytest.mark.parametrize(
    "raw,expected",
    [(1.5, 1.0), (-0.2, 0.0), (0.0, 0.0), (1.0, 1.0), (0.75, 0.75)],
)
def test_result_clamps_threat_score(raw: float, expected: float):
    assert SemanticTriageResult(threat_score=raw).threat_score == expected


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_result_rejects_blank_backend(blank: str):
    with pytest.raises(ValueError):
        SemanticTriageResult(threat_score=0.5, backend=blank)


# ----------------------------------------------------------------------
# SemanticTriageProvider ABC (Jev is the only implementation)
# ----------------------------------------------------------------------


def test_provider_is_abstract():
    with pytest.raises(TypeError):
        SemanticTriageProvider()  # type: ignore[abstract]


def test_triage_is_an_async_abstract_method():
    assert inspect.iscoroutinefunction(SemanticTriageProvider.triage)


def test_jev_backend_is_a_provider():
    assert issubclass(JevTriageBackend, SemanticTriageProvider)
    assert JevTriageBackend(api_key="test-typesafe-key").name == "jev"
