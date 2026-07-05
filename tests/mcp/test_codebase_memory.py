import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from blackwall.mcp.codebase_memory import (
    CodebaseMemoryClient,
    CriticalSinkType,
    CriticalSink,
    DependencyChain,
    DataFlowPath,
    BlastRadiusIsolation,
    BlastRadiusReport,
)

@pytest.mark.asyncio
async def test_dependency_chain_query():
    """
    Test dependency chain query returns complete call path.
    """
    client = CodebaseMemoryClient()
    
    # Test existing mock target
    dep_chain = await client.queryDependencyChain("ProcessOrder")
    assert dep_chain.rootFunction == "ProcessOrder"
    assert dep_chain.callChain == ["ProcessOrder", "ValidatePayment", "ExecuteSQL"]
    assert dep_chain.depth == 3
    assert dep_chain.hasCriticalSink is True
    assert dep_chain.criticalSinks == ["ExecuteSQL"]

    # Test safe/fallback target
    safe_chain = await client.queryDependencyChain("non_existent_or_safe")
    assert safe_chain.rootFunction == "non_existent_or_safe"
    assert safe_chain.callChain == ["non_existent_or_safe"]
    assert safe_chain.depth == 1
    assert safe_chain.hasCriticalSink is False
    assert safe_chain.criticalSinks == []


@pytest.mark.asyncio
async def test_critical_sink_detection():
    """
    Test critical sink detection for SQL, command exec, file write, network.
    """
    client = CodebaseMemoryClient()

    # Pre-populate custom mock critical sinks for testing
    sinks = [
        CriticalSink(
            sinkType=CriticalSinkType.SQL_QUERY,
            functionName="query_db",
            modulePath="src/db.py",
            isUnsafe=True,
            mitigationHint="SQL hint"
        ),
        CriticalSink(
            sinkType=CriticalSinkType.COMMAND_EXEC,
            functionName="run_cmd",
            modulePath="src/shell.py",
            isUnsafe=False,
            mitigationHint="Command hint"
        ),
        CriticalSink(
            sinkType=CriticalSinkType.FILE_WRITE,
            functionName="write_log",
            modulePath="src/io.py",
            isUnsafe=True,
            mitigationHint="File hint"
        ),
        CriticalSink(
            sinkType=CriticalSinkType.NETWORK_CALL,
            functionName="send_http",
            modulePath="src/net.py",
            isUnsafe=False,
            mitigationHint="Network hint"
        )
    ]
    client.set_mock_data("identifyCriticalSinks", "TestModule", sinks)

    result = await client.identifyCriticalSinks("TestModule")
    assert len(result) == 4
    assert result[0].sinkType == CriticalSinkType.SQL_QUERY
    assert result[1].sinkType == CriticalSinkType.COMMAND_EXEC
    assert result[2].sinkType == CriticalSinkType.FILE_WRITE
    assert result[3].sinkType == CriticalSinkType.NETWORK_CALL


def test_unsafe_sink_identification():
    """
    Test unsafe sink identification (unsanitized input flag).
    """
    client = CodebaseMemoryClient()
    sinks = [
        CriticalSink(
            sinkType=CriticalSinkType.SQL_QUERY,
            functionName="unsafe_sql",
            modulePath="src/db.py",
            isUnsafe=True,
            mitigationHint="SQL hint"
        ),
        CriticalSink(
            sinkType=CriticalSinkType.COMMAND_EXEC,
            functionName="safe_cmd",
            modulePath="src/shell.py",
            isUnsafe=False,
            mitigationHint="Command hint"
        )
    ]

    unsafe_sinks = client.identifyUnsafeSinks(sinks)
    assert len(unsafe_sinks) == 1
    assert unsafe_sinks[0].functionName == "unsafe_sql"
    assert unsafe_sinks[0].isUnsafe is True


@pytest.mark.asyncio
async def test_data_flow_tracing():
    """
    Test data flow tracing from source to sink with taint propagation.
    """
    client = CodebaseMemoryClient()

    # Query tainted flow
    tainted_flow = await client.traceDataFlow("user_input", "ExecuteSQL")
    assert tainted_flow.sourceNode == "user_input"
    assert tainted_flow.sinkNode == "ExecuteSQL"
    assert tainted_flow.isTainted is True
    assert len(tainted_flow.intermediateNodes) == 1
    assert tainted_flow.intermediateNodes[0] == "ValidatePayment"

    # Query clean/sanitized flow
    clean_flow = await client.traceDataFlow("safe_input", "safe_sink")
    assert clean_flow.isTainted is False
    assert "sanitize_input" in clean_flow.sanitizationPoints


@pytest.mark.asyncio
async def test_blast_radius_calculation():
    """
    Test blast radius calculation with risk score.
    """
    client = CodebaseMemoryClient()

    report = await client.getBlastRadius("ProcessOrder")
    assert report.targetNode == "ProcessOrder"
    assert "src/db" in report.affectedModules
    assert "ProcessOrder" in report.affectedFunctions
    assert 0.0 <= report.riskScore <= 1.0
    assert report.riskScore == 0.75
    assert report.isolation == BlastRadiusIsolation.MEDIUM


@pytest.mark.asyncio
async def test_timeout_handling_graceful_fallback():
    """
    Test 2-second timeout handling via asyncio.wait_for() with graceful fallback.
    """
    client = CodebaseMemoryClient(base_url="http://localhost:8001", timeout_seconds=0.1)

    # Mock the tool executor to block/delay
    async def mock_execute(*args, **kwargs):
        await asyncio.sleep(1.0)
        return "Success"

    client._execute_mcp_tool = mock_execute

    # The client should timeout within 0.1s and return the graceful fallback
    dep_chain = await client.queryDependencyChain("ProcessOrder")
    assert dep_chain.rootFunction == "ProcessOrder"
    assert dep_chain.callChain == ["ProcessOrder"]
    assert dep_chain.depth == 1
    assert dep_chain.hasCriticalSink is False
    assert dep_chain.criticalSinks == []


def test_threat_score_penalty_stale_graph():
    """
    Test threat score penalty of 0.4 when graph is stale.
    """
    # 1. Fresh graph (updated 10 minutes ago)
    recent_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    client_fresh = CodebaseMemoryClient(last_updated=recent_time)
    assert client_fresh.is_graph_stale() is False
    assert client_fresh.get_threat_score_penalty() == 0.0

    # 2. Stale graph (updated 2 hours ago)
    stale_time = datetime.now(timezone.utc) - timedelta(hours=2)
    client_stale = CodebaseMemoryClient(last_updated=stale_time)
    assert client_stale.is_graph_stale() is True
    assert client_stale.get_threat_score_penalty() == 0.4


def test_mitigation_hint_generation():
    """
    Test mitigation hint generation for common vulnerabilities.
    """
    client = CodebaseMemoryClient()

    hint_sql = client.get_mitigation_hint(CriticalSinkType.SQL_QUERY)
    assert "parameterized queries" in hint_sql or "ORM" in hint_sql

    hint_cmd = client.get_mitigation_hint(CriticalSinkType.COMMAND_EXEC)
    assert "subprocess" in hint_cmd

    hint_file = client.get_mitigation_hint(CriticalSinkType.FILE_WRITE)
    assert "abspath" in hint_file

    hint_net = client.get_mitigation_hint(CriticalSinkType.NETWORK_CALL)
    assert "whitelist" in hint_net or "IP/domain" in hint_net

    hint_unknown = client.get_mitigation_hint("UNKNOWN_TYPE")
    assert "No specific mitigation hint" in hint_unknown
