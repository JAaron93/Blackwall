"""
Unit tests for open-source local `opentelemetry-mcp` adapter (`src/blackwall/enterprise/mcp/opentelemetry_mcp.py`).
"""

import pytest
from blackwall.enterprise.mcp.opentelemetry_mcp import OpenTelemetryMCPAdapter


@pytest.mark.asyncio
async def test_opentelemetry_mcp_lifecycle():
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")
    assert not adapter.is_connected

    connected = await adapter.connect()
    assert connected
    assert adapter.is_connected

    await adapter.disconnect()
    assert not adapter.is_connected


@pytest.mark.asyncio
async def test_opentelemetry_mcp_export_trace_span():
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect()

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
    await adapter.connect()

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
    await adapter.connect()

    await adapter.export_trace_span("tr_1", "span_1", {"key": "val1"})
    await adapter.export_trace_span("tr_2", "span_2", {"key": "val2"})

    spans = await adapter.get_active_spans()
    assert len(spans) >= 2
    assert any(s["trace_id"] == "tr_1" for s in spans)
