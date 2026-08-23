"""Unit tests for OpenTelemetryMCPAdapter — Local OTel/Jaeger Adapter.

Covers: Task 3.2 from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
Target: src/blackwall/enterprise/mcp/opentelemetry_mcp.py — REQ-5.2
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from blackwall.enterprise.mcp.opentelemetry_mcp import OpenTelemetryMCPAdapter


# ---------------------------------------------------------------------------
# Connection lifecycle tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_initial_state_not_connected() -> None:
    """Adapter is NOT connected before connect() is called."""
    adapter = OpenTelemetryMCPAdapter()
    assert adapter.is_connected is False


@pytest.mark.asyncio
async def test_connect_disconnect_lifecycle_no_endpoint_verification() -> None:
    """connect(verify_endpoint=False) sets is_connected True; disconnect() resets it."""
    adapter = OpenTelemetryMCPAdapter(endpoint="mock://local:4318")

    connected = await adapter.connect(verify_endpoint=False)
    assert connected is True
    assert adapter.is_connected is True

    await adapter.disconnect()
    assert adapter.is_connected is False


@pytest.mark.asyncio
async def test_connect_with_mock_scheme_skips_http_check() -> None:
    """Endpoints starting with 'mock://' skip HTTP verification and connect immediately."""
    adapter = OpenTelemetryMCPAdapter(endpoint="mock://test-collector")
    connected = await adapter.connect(verify_endpoint=True)
    assert connected is True
    assert adapter.is_connected is True


@pytest.mark.asyncio
async def test_connect_verified_endpoint_success() -> None:
    """connect(verify_endpoint=True) with HTTP 200 → connected."""
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")

    mock_resp = MagicMock()
    mock_resp.status = 200

    resp_cm = MagicMock()
    resp_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    resp_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = resp_cm

    with patch("aiohttp.ClientSession", return_value=mock_session):
        connected = await adapter.connect(verify_endpoint=True)

    assert connected is True
    assert adapter.is_connected is True


@pytest.mark.asyncio
async def test_connect_verified_endpoint_failure() -> None:
    """connect(verify_endpoint=True) when endpoint raises → not connected, returns False."""
    adapter = OpenTelemetryMCPAdapter(endpoint="http://localhost:4318")

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.side_effect = ConnectionRefusedError("No OTel collector")

    with patch("aiohttp.ClientSession", return_value=mock_session):
        connected = await adapter.connect(verify_endpoint=True)

    assert connected is False
    assert adapter.is_connected is False


# ---------------------------------------------------------------------------
# export_trace_span tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_trace_span_returns_correct_shape() -> None:
    """export_trace_span returns dict with status, trace_id, span_name, span_id, attributes."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    result = await adapter.export_trace_span(
        trace_id="trace-abc-001",
        span_name="forensic_triage",
        attributes={"severity": "HIGH", "agent_id": "agent-99"},
    )

    assert result["status"] == "exported"
    assert result["trace_id"] == "trace-abc-001"
    assert result["span_name"] == "forensic_triage"
    assert "span_id" in result
    assert len(result["span_id"]) > 0
    assert result["attributes"]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_export_trace_span_stored_in_buffer() -> None:
    """Exported spans are buffered and retrievable via get_active_spans()."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.export_trace_span("tr1", "span_a", {"k": "v1"})
    await adapter.export_trace_span("tr2", "span_b", {"k": "v2"})

    spans = await adapter.get_active_spans()
    assert len(spans) == 2
    trace_ids = {s["trace_id"] for s in spans}
    assert "tr1" in trace_ids
    assert "tr2" in trace_ids


# ---------------------------------------------------------------------------
# ingest_log_event tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_log_event_returns_correct_shape() -> None:
    """ingest_log_event returns dict with status, log_id, processed_bytes >= 64."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    result = await adapter.ingest_log_event(
        {
            "timestamp": "2026-08-01T00:00:00Z",
            "log_level": "WARNING",
            "message": "Suspicious process spawn detected",
            "pid": 9999,
        }
    )

    assert result["status"] == "ingested"
    assert "log_id" in result
    assert result["log_id"].startswith("log_")
    assert result["processed_bytes"] >= 64


@pytest.mark.asyncio
async def test_ingest_log_event_stored_in_buffer() -> None:
    """Ingested logs are buffered and retrievable via get_ingested_logs()."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.ingest_log_event({"message": "event_one", "pid": 1})
    await adapter.ingest_log_event({"message": "event_two", "pid": 2})

    logs = await adapter.get_ingested_logs()
    assert len(logs) == 2


# ---------------------------------------------------------------------------
# get_active_spans / get_ingested_logs tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_active_spans_returns_previously_exported() -> None:
    """get_active_spans() returns a list including all previously exported spans."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.export_trace_span("tr-alpha", "span_alpha", {"key": "alpha"})
    spans = await adapter.get_active_spans()

    assert isinstance(spans, list)
    assert any(s["trace_id"] == "tr-alpha" for s in spans)


@pytest.mark.asyncio
async def test_get_ingested_logs_returns_previously_ingested() -> None:
    """get_ingested_logs() returns a list of previously ingested log records."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.ingest_log_event({"message": "important_log", "level": "ERROR"})
    logs = await adapter.get_ingested_logs()

    assert isinstance(logs, list)
    assert len(logs) == 1
    assert logs[0]["log_data"]["message"] == "important_log"


# ---------------------------------------------------------------------------
# clear_buffers tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clear_buffers_empties_spans_and_logs() -> None:
    """clear_buffers() empties both the exported spans and ingested logs deques."""
    adapter = OpenTelemetryMCPAdapter()
    await adapter.connect(verify_endpoint=False)

    await adapter.export_trace_span("tr-clear", "span_clear", {})
    await adapter.ingest_log_event({"msg": "clear_this"})

    assert len(await adapter.get_active_spans()) == 1
    assert len(await adapter.get_ingested_logs()) == 1

    adapter.clear_buffers()

    assert len(await adapter.get_active_spans()) == 0
    assert len(await adapter.get_ingested_logs()) == 0


# ---------------------------------------------------------------------------
# Buffer operations when not connected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_buffer_operations_work_without_connection() -> None:
    """Buffer-backed methods (export_trace_span, ingest_log_event) operate on in-memory
    deque regardless of _is_connected state — no guard raises errors on disconnected adapter.
    This test documents the actual implementation contract.
    """
    adapter = OpenTelemetryMCPAdapter()
    # Do NOT call connect(); adapter._is_connected remains False

    # export_trace_span writes to deque — no connection check
    result_span = await adapter.export_trace_span("tr-noconn", "noconn_span", {"k": "v"})
    assert result_span["status"] == "exported"

    # ingest_log_event writes to deque — no connection check
    result_log = await adapter.ingest_log_event({"message": "no conn log"})
    assert result_log["status"] == "ingested"

    # Both items retrievable
    spans = await adapter.get_active_spans()
    logs = await adapter.get_ingested_logs()
    assert len(spans) == 1
    assert len(logs) == 1


# ---------------------------------------------------------------------------
# max_buffer_size boundary test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_buffer_respects_max_buffer_size() -> None:
    """Deque enforces max_buffer_size; oldest entries are evicted when capacity is reached."""
    adapter = OpenTelemetryMCPAdapter(max_buffer_size=3)
    await adapter.connect(verify_endpoint=False)

    for i in range(6):
        await adapter.export_trace_span(f"tr-{i}", f"span_{i}", {"seq": i})
        await adapter.ingest_log_event({"seq": i})

    spans = await adapter.get_active_spans()
    logs = await adapter.get_ingested_logs()

    # Only last 3 survive due to deque(maxlen=3)
    assert len(spans) == 3
    assert len(logs) == 3
    assert spans[0]["trace_id"] == "tr-3"
    assert spans[-1]["trace_id"] == "tr-5"
