"""
Unit tests for scripts/burst_test.py (Paid Tier Burst Verification Tool).
"""

import sys
import os
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

# Ensure scripts directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")))

from burst_test import run_burst_test, burst_worker


@pytest.mark.asyncio
async def test_run_burst_test_invalid_concurrency_zero():
    result = await run_burst_test(0)
    assert result is False


@pytest.mark.asyncio
async def test_run_burst_test_invalid_concurrency_negative():
    result = await run_burst_test(-5)
    assert result is False


@pytest.mark.asyncio
async def test_run_burst_test_missing_gcp_project(monkeypatch):
    import blackwall.config
    blackwall.config._env_configured = False
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("BLACKWALL_TEST_MODE", raising=False)

    result = await run_burst_test(5)
    assert result is False


@pytest.mark.asyncio
async def test_run_burst_test_dummy_project_success():
    result = await run_burst_test(5)
    assert result is True


@pytest.mark.asyncio
async def test_burst_worker_dummy_latency():
    sem = asyncio.Semaphore(10)
    latency = await burst_worker(1, sem, client=None, is_dummy=True)
    assert latency >= 0.01


@pytest.mark.asyncio
async def test_burst_worker_live_model_call():
    sem = asyncio.Semaphore(10)
    mock_client = AsyncMock()
    mock_client.aio.models.generate_content = AsyncMock(return_value="mock response")

    latency = await burst_worker(1, sem, client=mock_client, is_dummy=False)
    assert latency >= 0.0
    mock_client.aio.models.generate_content.assert_called_once_with(
        model="gemini-3.1-flash-lite",
        contents="burst worker 1",
    )


@pytest.mark.asyncio
async def test_run_burst_test_worker_failure(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "real-gcp-project")
    mock_client = AsyncMock()
    mock_client.aio.models.generate_content = AsyncMock(side_effect=asyncio.TimeoutError("Request timed out"))

    with patch("burst_test.get_genai_client", return_value=mock_client):
        result = await run_burst_test(5)
        assert result is False
