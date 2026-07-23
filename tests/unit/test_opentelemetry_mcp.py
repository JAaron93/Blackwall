"""
Unit tests for open-source local `opentelemetry-mcp` adapter (`src/blackwall/enterprise/mcp/opentelemetry_mcp.py`).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from blackwall.enterprise.mcp.opentelemetry_mcp import OpenTelemetryMCPAdapter


@pytest.mark.asyncio
async def test_opentelemetry_mcp_lifecycle():
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")
    assert not adapter.is_connected

    # Unverified / mock connection
    connected = await adapter.connect(verify_endpoint=False)
    assert connected
    assert adapter.is_connected

    await adapter.disconnect()
    assert not adapter.is_connected


@pytest.mark.asyncio
async def test_opentelemetry_mcp_connect_with_endpoint_verification_success():
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")

    mock_response = MagicMock()
    mock_response.status = 200

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_response)
    cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = cm

    with patch("aiohttp.ClientSession", return_value=mock_session):
        connected = await adapter.connect(verify_endpoint=True)
        assert connected
        assert adapter.is_connected


@pytest.mark.asyncio
async def test_opentelemetry_mcp_connect_with_endpoint_verification_failure():
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.side_effect = Exception("Connection refused")

    with patch("aiohttp.ClientSession", return_value=mock_session):
        connected = await adapter.connect(verify_endpoint=True)
        assert not connected
        assert not adapter.is_connected


@pytest.mark.asyncio
async def test_opentelemetry_mcp_export_trace_span():
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    result = await adapter.export_trace_span(
        trace_id="tr_9901_abc",
        span_name="forensic_triage_interception",
        attributes={"severity": "CRITICAL", "threat_type": "rce_exploit"},
    )

    assert result["status"] == "exported"
    assert result["trace_id"] == "tr_9901_abc"
    assert result["span_name"] == "forensic_triage_interception"
    assert result["attributes"]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_opentelemetry_mcp_ingest_log_event():
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    result = await adapter.ingest_log_event(
        {
            "timestamp": "2026-07-23T07:30:00Z",
            "log_level": "WARNING",
            "message": "Attempted execution of /bin/nc -e /bin/sh",
            "pid": 14022,
        }
    )

    assert result["status"] == "ingested"
    assert "log_id" in result
    assert result["processed_bytes"] > 0


@pytest.mark.asyncio
async def test_opentelemetry_mcp_get_active_spans():
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.export_trace_span("tr_1", "span_1", {"key": "val1"})
    await adapter.export_trace_span("tr_2", "span_2", {"key": "val2"})

    spans = await adapter.get_active_spans()
    assert len(spans) >= 2
    assert any(s["trace_id"] == "tr_1" for s in spans)
