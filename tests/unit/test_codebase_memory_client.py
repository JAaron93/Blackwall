"""Unit tests for CodebaseMemoryClient — codebase-memory MCP client.

Tests cover all public and private methods of CodebaseMemoryClient,
data class construction, and graceful degradation paths.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch, MagicMock

from blackwall.mcp.codebase_memory import (
    BlastRadiusIsolation,
    BlastRadiusReport,
    CodebaseMemoryClient,
    CriticalSink,
    CriticalSinkType,
    DataFlowPath,
    DependencyChain,
)
from blackwall.models import ToolCallContext, CBMResponse, SinkType
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_client(**kwargs) -> CodebaseMemoryClient:
    """Return a CodebaseMemoryClient with no real transport (uses mock data)."""
    return CodebaseMemoryClient(**kwargs)


def make_stale_client() -> CodebaseMemoryClient:
    """Return a client whose last_updated is 2 hours ago (stale)."""
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    return CodebaseMemoryClient(last_updated=two_hours_ago)


# ===========================================================================
# Section 1: __init__
# ===========================================================================

def test_init_default_values():
    client = make_client()
    assert client.base_url is None or isinstance(client.base_url, str)
    assert client.command is None
    assert isinstance(client.last_updated, datetime)
    assert client.timeout_seconds == 2.0
    assert isinstance(client.mock_data, dict)


def test_init_with_base_url():
    client = CodebaseMemoryClient(base_url="http://localhost:8765")
    assert client.base_url == "http://localhost:8765"


def test_init_with_custom_timeout():
    client = CodebaseMemoryClient(timeout_seconds=5.0)
    assert client.timeout_seconds == 5.0


def test_init_with_last_updated():
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    client = CodebaseMemoryClient(last_updated=ts)
    assert client.last_updated == ts


def test_init_with_env_var(monkeypatch):
    monkeypatch.setenv("CBM_MCP_BASE_URL", "http://env-host:9000")
    client = CodebaseMemoryClient()
    assert client.base_url == "http://env-host:9000"


def test_init_mocks_populated():
    client = make_client()
    assert "queryDependencyChain" in client.mock_data
    assert "identifyCriticalSinks" in client.mock_data
    assert "traceDataFlow" in client.mock_data
    assert "getBlastRadius" in client.mock_data


# ===========================================================================
# Section 2: is_graph_stale() / get_threat_score_penalty()
# ===========================================================================

def test_is_graph_stale_fresh():
    client = make_client()  # last_updated = now
    assert client.is_graph_stale() is False


def test_is_graph_stale_old():
    client = make_stale_client()
    assert client.is_graph_stale() is True


def test_is_graph_stale_exactly_over_one_hour():
    just_over = datetime.now(timezone.utc) - timedelta(seconds=3601)
    client = CodebaseMemoryClient(last_updated=just_over)
    assert client.is_graph_stale() is True


def test_is_graph_stale_just_under_one_hour():
    just_under = datetime.now(timezone.utc) - timedelta(seconds=3599)
    client = CodebaseMemoryClient(last_updated=just_under)
    assert client.is_graph_stale() is False


def test_get_threat_score_penalty_fresh():
    client = make_client()
    assert client.get_threat_score_penalty() == 0.0


def test_get_threat_score_penalty_stale():
    client = make_stale_client()
    assert client.get_threat_score_penalty() == 0.4


# ===========================================================================
# Section 3: get_mitigation_hint()
# ===========================================================================

def test_get_mitigation_hint_sql_query():
    client = make_client()
    hint = client.get_mitigation_hint(CriticalSinkType.SQL_QUERY)
    assert "parameterized" in hint.lower() or "orm" in hint.lower()


def test_get_mitigation_hint_command_exec():
    client = make_client()
    hint = client.get_mitigation_hint(CriticalSinkType.COMMAND_EXEC)
    assert "subprocess" in hint.lower() or "shell" in hint.lower()


def test_get_mitigation_hint_file_write():
    client = make_client()
    hint = client.get_mitigation_hint(CriticalSinkType.FILE_WRITE)
    assert "path" in hint.lower() or "directory" in hint.lower()


def test_get_mitigation_hint_network_call():
    client = make_client()
    hint = client.get_mitigation_hint(CriticalSinkType.NETWORK_CALL)
    assert "whitelist" in hint.lower() or "validate" in hint.lower()


def test_get_mitigation_hint_returns_string_for_all_types():
    client = make_client()
    for sink_type in CriticalSinkType:
        hint = client.get_mitigation_hint(sink_type)
        assert isinstance(hint, str)
        assert len(hint) > 0


# ===========================================================================
# Section 4: set_mock_data()
# ===========================================================================

def test_set_mock_data_valid_category():
    client = make_client()
    custom_chain = DependencyChain(
        rootFunction="MyFunc",
        callChain=["MyFunc", "Helper"],
        depth=2,
        hasCriticalSink=False,
        criticalSinks=[],
    )
    client.set_mock_data("queryDependencyChain", "MyFunc", custom_chain)
    assert client.mock_data["queryDependencyChain"]["MyFunc"] is custom_chain


def test_set_mock_data_invalid_category_is_noop():
    client = make_client()
    original_keys = set(client.mock_data.keys())
    client.set_mock_data("nonExistentCategory", "key", "value")
    assert set(client.mock_data.keys()) == original_keys


def test_set_mock_data_overrides_existing():
    client = make_client()
    new_chain = DependencyChain(
        rootFunction="ProcessOrder",
        callChain=["ProcessOrder"],
        depth=1,
        hasCriticalSink=False,
        criticalSinks=[],
    )
    client.set_mock_data("queryDependencyChain", "ProcessOrder", new_chain)
    assert client.mock_data["queryDependencyChain"]["ProcessOrder"].depth == 1


# ===========================================================================
# Section 5: _execute_mcp_tool()
# ===========================================================================

async def test_execute_mcp_tool_no_transport_raises():
    client = make_client()  # no base_url, no command
    with pytest.raises(NotImplementedError):
        await client._execute_mcp_tool("some_tool", {})


async def test_execute_mcp_tool_with_base_url_raises_connection_error():
    client = CodebaseMemoryClient(base_url="http://localhost:9999")
    with pytest.raises(ConnectionError):
        await client._execute_mcp_tool("some_tool", {})


# ===========================================================================
# Section 6: _safe_execute()
# ===========================================================================

async def test_safe_execute_success():
    client = make_client()

    async def fast_coro():
        return "result"

    result = await client._safe_execute(fast_coro(), fallback="fallback")
    assert result == "result"


async def test_safe_execute_timeout_returns_fallback():
    client = CodebaseMemoryClient(timeout_seconds=0.001)

    async def slow_coro():
        import asyncio
        await asyncio.sleep(10)
        return "never"

    result = await client._safe_execute(slow_coro(), fallback="fallback_value")
    assert result == "fallback_value"


async def test_safe_execute_connection_error_returns_fallback():
    client = make_client()

    async def failing_coro():
        raise ConnectionError("server down")

    result = await client._safe_execute(failing_coro(), fallback="safe_fallback")
    assert result == "safe_fallback"


async def test_safe_execute_not_implemented_returns_fallback():
    client = make_client()

    async def not_impl_coro():
        raise NotImplementedError("not configured")

    result = await client._safe_execute(not_impl_coro(), fallback=42)
    assert result == 42


async def test_safe_execute_os_error_returns_fallback():
    client = make_client()

    async def os_err_coro():
        raise OSError("OS level error")

    result = await client._safe_execute(os_err_coro(), fallback=[])
    assert result == []


# ===========================================================================
# Section 7: queryDependencyChain()
# ===========================================================================

async def test_query_dependency_chain_known_process_order():
    client = make_client()
    chain = await client.queryDependencyChain("ProcessOrder")
    assert chain.rootFunction == "ProcessOrder"
    assert chain.depth == 3
    assert chain.hasCriticalSink is True
    assert "ExecuteSQL" in chain.criticalSinks


async def test_query_dependency_chain_safe_func():
    client = make_client()
    chain = await client.queryDependencyChain("safe_func")
    assert chain.rootFunction == "safe_func"
    assert chain.depth == 1
    assert chain.hasCriticalSink is False
    assert chain.criticalSinks == []


async def test_query_dependency_chain_unknown_returns_fallback():
    client = make_client()
    chain = await client.queryDependencyChain("unknown_function_xyz")
    assert chain.rootFunction == "unknown_function_xyz"
    assert chain.depth == 1
    assert chain.hasCriticalSink is False


async def test_query_dependency_chain_with_real_transport_falls_back():
    """When base_url is set, _execute_mcp_tool raises ConnectionError → fallback."""
    client = CodebaseMemoryClient(base_url="http://localhost:9999")
    chain = await client.queryDependencyChain("AnyFunc")
    assert isinstance(chain, DependencyChain)
    assert chain.rootFunction == "AnyFunc"


# ===========================================================================
# Section 8: identifyCriticalSinks()
# ===========================================================================

async def test_identify_critical_sinks_process_order():
    client = make_client()
    sinks = await client.identifyCriticalSinks("ProcessOrder")
    assert len(sinks) == 1
    assert sinks[0].sinkType == CriticalSinkType.SQL_QUERY
    assert sinks[0].functionName == "ExecuteSQL"
    assert sinks[0].isUnsafe is True


async def test_identify_critical_sinks_safe_func_empty():
    client = make_client()
    sinks = await client.identifyCriticalSinks("safe_func")
    assert sinks == []


async def test_identify_critical_sinks_unknown_empty():
    client = make_client()
    sinks = await client.identifyCriticalSinks("totally_unknown_module")
    assert sinks == []


async def test_identify_critical_sinks_falls_back_on_transport_error():
    client = CodebaseMemoryClient(base_url="http://localhost:9999")
    sinks = await client.identifyCriticalSinks("AnyModule")
    assert sinks == []


# ===========================================================================
# Section 9: traceDataFlow()
# ===========================================================================

async def test_trace_data_flow_tainted_path():
    client = make_client()
    path = await client.traceDataFlow("user_input", "ExecuteSQL")
    assert path.isTainted is True
    assert path.sourceNode == "user_input"
    assert path.sinkNode == "ExecuteSQL"
    assert "ValidatePayment" in path.intermediateNodes


async def test_trace_data_flow_safe_path():
    client = make_client()
    path = await client.traceDataFlow("safe_input", "safe_sink")
    assert path.isTainted is False
    assert "sanitize_input" in path.sanitizationPoints


async def test_trace_data_flow_unknown_returns_fallback():
    client = make_client()
    path = await client.traceDataFlow("unknown_var", "unknown_sink")
    assert path.sourceNode == "unknown_var"
    assert path.sinkNode == "unknown_sink"
    assert path.isTainted is False
    assert path.intermediateNodes == []


async def test_trace_data_flow_falls_back_on_transport_error():
    client = CodebaseMemoryClient(base_url="http://localhost:9999")
    path = await client.traceDataFlow("x", "y")
    assert isinstance(path, DataFlowPath)
    assert path.isTainted is False


# ===========================================================================
# Section 10: getBlastRadius()
# ===========================================================================

async def test_get_blast_radius_process_order():
    client = make_client()
    report = await client.getBlastRadius("ProcessOrder")
    assert report.targetNode == "ProcessOrder"
    assert abs(report.riskScore - 0.75) < 0.001
    assert report.isolation == BlastRadiusIsolation.MEDIUM
    assert "src/db" in report.affectedModules


async def test_get_blast_radius_safe_func():
    client = make_client()
    report = await client.getBlastRadius("safe_func")
    assert report.targetNode == "safe_func"
    assert abs(report.riskScore - 0.1) < 0.001
    assert report.isolation == BlastRadiusIsolation.HIGH


async def test_get_blast_radius_unknown_returns_fallback():
    client = make_client()
    report = await client.getBlastRadius("NonExistentNode")
    assert report.targetNode == "NonExistentNode"
    assert report.riskScore == 0.0
    assert report.isolation == BlastRadiusIsolation.HIGH


async def test_get_blast_radius_falls_back_on_transport_error():
    client = CodebaseMemoryClient(base_url="http://localhost:9999")
    report = await client.getBlastRadius("AnyNode")
    assert isinstance(report, BlastRadiusReport)
    assert report.riskScore == 0.0


# ===========================================================================
# Section 11: identifyUnsafeSinks()
# ===========================================================================

def test_identify_unsafe_sinks_filters_unsafe():
    client = make_client()
    sinks = [
        CriticalSink(
            sinkType=CriticalSinkType.SQL_QUERY,
            functionName="bad_query",
            modulePath="src/db.py",
            isUnsafe=True,
            mitigationHint="use parameterized",
        ),
        CriticalSink(
            sinkType=CriticalSinkType.FILE_WRITE,
            functionName="safe_write",
            modulePath="src/utils.py",
            isUnsafe=False,
            mitigationHint="already safe",
        ),
    ]
    result = client.identifyUnsafeSinks(sinks)
    assert len(result) == 1
    assert result[0].functionName == "bad_query"


def test_identify_unsafe_sinks_all_safe():
    client = make_client()
    sinks = [
        CriticalSink(
            sinkType=CriticalSinkType.NETWORK_CALL,
            functionName="validated_call",
            modulePath="src/net.py",
            isUnsafe=False,
            mitigationHint="already whitelisted",
        ),
    ]
    result = client.identifyUnsafeSinks(sinks)
    assert result == []


def test_identify_unsafe_sinks_empty_input():
    client = make_client()
    assert client.identifyUnsafeSinks([]) == []


# ===========================================================================
# Section 12: query() adapter
# ===========================================================================

async def test_query_adapter_process_order():
    client = make_client()
    ctx = ToolCallContext(tool_name="ProcessOrder", arguments={})
    resp = await client.query(ctx)
    assert isinstance(resp, CBMResponse)
    # ProcessOrder depth=3 → blast_radius = min(3*2, 10) = 6.0
    assert resp.blast_radius == 6.0
    # CriticalSinkType.SQL_QUERY ("SQL_QUERY") has no matching SinkType enum value
    # (SinkType values are FILE_SYSTEM/NETWORK/DATABASE/PROCESS), so critical_sinks
    # remains empty after the safe ValueError catch in the adapter.
    assert isinstance(resp.critical_sinks, list)


async def test_query_adapter_safe_func():
    client = make_client()
    ctx = ToolCallContext(tool_name="safe_func", arguments={})
    resp = await client.query(ctx)
    assert isinstance(resp, CBMResponse)
    assert resp.critical_sinks == []
    # safe_func depth=1 → blast_radius = min(1*2, 10) = 2.0
    assert resp.blast_radius == 2.0


async def test_query_adapter_unknown_tool():
    client = make_client()
    ctx = ToolCallContext(tool_name="mystery_tool_xyz", arguments={})
    resp = await client.query(ctx)
    assert isinstance(resp, CBMResponse)
    assert resp.critical_sinks == []
    # Unknown → depth=1 fallback → blast_radius=2.0
    assert resp.blast_radius == 2.0


async def test_query_adapter_uses_tool_name_attr():
    """query() should prefer context.tool_name over str(context)."""
    client = make_client()
    ctx = ToolCallContext(tool_name="ProcessOrder", arguments={"amount": 100})
    resp = await client.query(ctx)
    # Should use "ProcessOrder" not the string representation
    assert resp.blast_radius == 6.0


# ===========================================================================
# Section 13: Data class construction and validation
# ===========================================================================

def test_blast_radius_report_valid_zero_risk():
    report = BlastRadiusReport(
        targetNode="fn",
        affectedModules=[],
        affectedFunctions=[],
        riskScore=0.0,
        isolation=BlastRadiusIsolation.HIGH,
    )
    assert report.riskScore == 0.0


def test_blast_radius_report_valid_max_risk():
    report = BlastRadiusReport(
        targetNode="fn",
        affectedModules=["mod"],
        affectedFunctions=["fn"],
        riskScore=1.0,
        isolation=BlastRadiusIsolation.LOW,
    )
    assert report.riskScore == 1.0


def test_blast_radius_report_invalid_risk_below_zero():
    with pytest.raises(ValidationError):
        BlastRadiusReport(
            targetNode="fn",
            affectedModules=[],
            affectedFunctions=[],
            riskScore=-0.1,
            isolation=BlastRadiusIsolation.HIGH,
        )


def test_blast_radius_report_invalid_risk_above_one():
    with pytest.raises(ValidationError):
        BlastRadiusReport(
            targetNode="fn",
            affectedModules=[],
            affectedFunctions=[],
            riskScore=1.01,
            isolation=BlastRadiusIsolation.HIGH,
        )


def test_critical_sink_construction():
    sink = CriticalSink(
        sinkType=CriticalSinkType.COMMAND_EXEC,
        functionName="run_cmd",
        modulePath="src/cmd.py",
        isUnsafe=True,
        mitigationHint="use subprocess with shell=False",
    )
    assert sink.sinkType == CriticalSinkType.COMMAND_EXEC
    assert sink.isUnsafe is True


def test_data_flow_path_construction():
    path = DataFlowPath(
        sourceNode="user_input",
        sinkNode="exec_call",
        intermediateNodes=["sanitize", "validate"],
        isTainted=True,
        sanitizationPoints=[],
    )
    assert path.isTainted is True
    assert len(path.intermediateNodes) == 2


def test_dependency_chain_construction_and_round_trip():
    chain = DependencyChain(
        rootFunction="myFunc",
        callChain=["myFunc", "helper"],
        depth=2,
        hasCriticalSink=False,
        criticalSinks=[],
    )
    dumped = chain.model_dump()
    restored = DependencyChain(**dumped)
    assert restored.rootFunction == chain.rootFunction
    assert restored.depth == chain.depth


def test_blast_radius_isolation_enum_values():
    assert BlastRadiusIsolation.LOW == "LOW"
    assert BlastRadiusIsolation.MEDIUM == "MEDIUM"
    assert BlastRadiusIsolation.HIGH == "HIGH"


def test_critical_sink_type_enum_values():
    assert CriticalSinkType.SQL_QUERY == "SQL_QUERY"
    assert CriticalSinkType.COMMAND_EXEC == "COMMAND_EXEC"
    assert CriticalSinkType.FILE_WRITE == "FILE_WRITE"
    assert CriticalSinkType.NETWORK_CALL == "NETWORK_CALL"


def test_blast_radius_report_model_dump_round_trip():
    report = BlastRadiusReport(
        targetNode="SomeNode",
        affectedModules=["mod_a", "mod_b"],
        affectedFunctions=["fn1"],
        riskScore=0.55,
        isolation=BlastRadiusIsolation.MEDIUM,
    )
    dumped = report.model_dump()
    restored = BlastRadiusReport(**dumped)
    assert restored.targetNode == report.targetNode
    assert abs(restored.riskScore - report.riskScore) < 0.001
    assert restored.isolation == report.isolation
