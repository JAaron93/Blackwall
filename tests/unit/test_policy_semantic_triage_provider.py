"""Unit tests for the Tier-1 semantic triage provider seam (TASK-A01/A02, FR-01).

Governing spec: .kiro/specs/tier-1-jev-addition/
"""

import dataclasses
import inspect
import logging

import pytest

from blackwall.policy.semantic import (
    JEV_API_KEY_ENV_VAR,
    GeminiTriageBackend,
    JevTriageBackend,
    SemanticTriageProvider,
    SemanticTriageResult,
    build_semantic_provider,
    resolve_semantic_backend,
)

SEMANTIC_LOGGER = "blackwall.policy.semantic"


# ----------------------------------------------------------------------
# SemanticTriageResult
# ----------------------------------------------------------------------


def test_result_track_a_defaults():
    """Gemini-era results carry no confidence/escalation until Tracks B/C."""
    result = SemanticTriageResult(threat_score=0.42)
    assert result.threat_score == 0.42
    assert result.confidence is None
    assert result.backend == "gemini"
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
# SemanticTriageProvider ABC
# ----------------------------------------------------------------------


def test_provider_is_abstract():
    with pytest.raises(TypeError):
        SemanticTriageProvider()  # type: ignore[abstract]


def test_triage_is_an_async_abstract_method():
    assert inspect.iscoroutinefunction(SemanticTriageProvider.triage)


def test_gemini_backend_is_a_provider():
    assert issubclass(GeminiTriageBackend, SemanticTriageProvider)
    assert GeminiTriageBackend(client=object()).name == "gemini"


# ----------------------------------------------------------------------
# BW_SEMANTIC_BACKEND resolution
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "gemini"),
        ("", "gemini"),
        ("   ", "gemini"),
        ("gemini", "gemini"),
        ("GEMINI ", "gemini"),
        ("bogus", "gemini"),
    ],
)
def test_resolve_semantic_backend_defaults_to_gemini(raw, expected: str):
    assert resolve_semantic_backend(raw) == expected


@pytest.mark.parametrize("raw", ["jev", "JeV", " JEV "])
def test_resolve_semantic_backend_jev_with_key(raw, monkeypatch):
    """TASK-B01: `jev` resolves case-insensitively once the Gateway key exists."""
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "test-gateway-key")
    assert resolve_semantic_backend(raw) == "jev"


def test_resolve_semantic_backend_jev_without_key_warns_and_degrades(
    monkeypatch, caplog
):
    """Fail-closed: `jev` without paid-Gateway credentials degrades to gemini
    rather than disabling triage or failing open."""
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    with caplog.at_level(logging.WARNING, logger=SEMANTIC_LOGGER):
        assert resolve_semantic_backend("jev") == "gemini"
    assert JEV_API_KEY_ENV_VAR in caplog.text


def test_resolve_semantic_backend_unknown_warns(caplog):
    with caplog.at_level(logging.WARNING, logger=SEMANTIC_LOGGER):
        assert resolve_semantic_backend("definitely-not-a-backend") == "gemini"
    assert "unknown semantic triage backend" in caplog.text


def test_resolve_semantic_backend_gemini_is_silent(caplog):
    with caplog.at_level(logging.WARNING, logger=SEMANTIC_LOGGER):
        assert resolve_semantic_backend("gemini") == "gemini"
    assert caplog.text == ""


def test_build_semantic_provider_returns_gemini(monkeypatch):
    monkeypatch.delenv(JEV_API_KEY_ENV_VAR, raising=False)
    client = object()
    provider = build_semantic_provider(client, "jev")
    assert isinstance(provider, GeminiTriageBackend)
    assert provider.client is client


def test_build_semantic_provider_returns_jev_with_gemini_fallback(monkeypatch):
    monkeypatch.setenv(JEV_API_KEY_ENV_VAR, "test-gateway-key")
    provider = build_semantic_provider(object(), "jev")
    assert isinstance(provider, JevTriageBackend)
    assert isinstance(provider.fallback, GeminiTriageBackend)
