"""Unit tests for the MCP Routing Layer.

Tests CodebaseMemoryRouter, GTIRouter, MCPRoutingViolation,
escape-attempt detection, and logging behavior.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from blackwall.mcp.codebase_memory import CodebaseMemoryClient
from blackwall.mcp.mcp_routing import (
    CodebaseMemoryRouter,
    GTIRouter,
    MCPRoutingViolation,
)


@pytest.fixture
def mock_cbm_client() -> AsyncMock:
    client = AsyncMock(spec=CodebaseMemoryClient)
    client.queryDependencyChain = AsyncMock(return_value="dep_chain_data")
    client.identifyCriticalSinks = AsyncMock(return_value="sinks_data")
    client.traceDataFlow = AsyncMock(return_value="data_flow_data")
    client.getBlastRadius = AsyncMock(return_value="blast_radius_data")
    return client


@pytest.fixture
def mock_gti_client() -> AsyncMock:
    client = AsyncMock()
    client.lookup_ip = AsyncMock(return_value="ip_data")
    client.lookup_url = AsyncMock(return_value="url_data")
    client.lookup_domain = AsyncMock(return_value="domain_data")
    client.lookup_file_hash = AsyncMock(return_value="hash_data")
    return client


# ============================================================================
# CodebaseMemoryRouter Tests
# ============================================================================


@pytest.mark.asyncio
async def test_cbm_router_permits_valid_ops(mock_cbm_client: AsyncMock) -> None:
    router = CodebaseMemoryRouter(mock_cbm_client)

    # Test query_dependency_chain
    res = await router.route("query_dependency_chain", function_name="test_func")
    assert res == "dep_chain_data"
    mock_cbm_client.queryDependencyChain.assert_called_once_with(functionName="test_func")

    # Test identify_critical_sinks
    res = await router.route("identify_critical_sinks", function_name="test_func")
    assert res == "sinks_data"
    mock_cbm_client.identifyCriticalSinks.assert_called_once_with(moduleName="test_func")

    # Test trace_data_flow
    res = await router.route("trace_data_flow", source="src", sink="snk")
    assert res == "data_flow_data"
    mock_cbm_client.traceDataFlow.assert_called_once_with(variableName="src", context="snk")

    # Test get_blast_radius
    res = await router.route("get_blast_radius", function_name="test_func")
    assert res == "blast_radius_data"
    mock_cbm_client.getBlastRadius.assert_called_once_with(targetNode="test_func")


@pytest.mark.asyncio
async def test_cbm_router_blocks_invalid_ops(mock_cbm_client: AsyncMock) -> None:

    router = CodebaseMemoryRouter(mock_cbm_client)

    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("list_files", directory="/root")
    
    assert exc_info.value.router == "CodebaseMemoryRouter"
    assert exc_info.value.operation == "list_files"
    assert "not in permitted list" in str(exc_info.value)
    mock_cbm_client.queryDependencyChain.assert_not_called()


@pytest.mark.asyncio
async def test_cbm_router_detects_escape_in_op_name(mock_cbm_client: AsyncMock) -> None:
    router = CodebaseMemoryRouter(mock_cbm_client)

    # Shell metacharacter
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("query_dependency_chain;exec('malicious')")
    assert "ESCAPE_ATTEMPT" in str(exc_info.value)

    # Deny keyword
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("eval_dependency_chain")
    assert "ESCAPE_ATTEMPT" in str(exc_info.value)

    # Path separator
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("query/dependency/chain")
    assert "ESCAPE_ATTEMPT" in str(exc_info.value)


@pytest.mark.asyncio
async def test_cbm_router_detects_escape_in_args(mock_cbm_client: AsyncMock) -> None:
    router = CodebaseMemoryRouter(mock_cbm_client)

    # Shell injection in arguments
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("query_dependency_chain", function_name="func; rm -rf /")
    assert "ESCAPE_ATTEMPT" in str(exc_info.value)

    # Deny keyword in arguments
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route("query_dependency_chain", function_name="__import__('os')")
    assert "ESCAPE_ATTEMPT" in str(exc_info.value)


# ============================================================================
# GTIRouter Tests
# ============================================================================


@pytest.mark.asyncio
async def test_gti_router_permits_async_contexts(mock_gti_client: AsyncMock) -> None:
    router = GTIRouter(mock_gti_client)

    # ASYNC_ANALYSIS
    res = await router.route(
        GTIRouter.ExecutionContext.ASYNC_ANALYSIS,
        "lookup_ip",
        ip="192.168.1.1"
    )
    assert res == "ip_data"
    mock_gti_client.lookup_ip.assert_called_once_with(ip="192.168.1.1")

    # BATCH_RESOLUTION
    res = await router.route(
        GTIRouter.ExecutionContext.BATCH_RESOLUTION,
        "lookup_url",
        url="http://malicious.com"
    )
    assert res == "url_data"
    mock_gti_client.lookup_url.assert_called_once_with(url="http://malicious.com")


@pytest.mark.asyncio
async def test_gti_router_blocks_sync_context(mock_gti_client: AsyncMock) -> None:
    router = GTIRouter(mock_gti_client)

    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route(
            GTIRouter.ExecutionContext.SYNC_INTERCEPTION,
            "lookup_ip",
            ip="192.168.1.1"
        )
    assert "forbidden" in str(exc_info.value)
    mock_gti_client.lookup_ip.assert_not_called()


@pytest.mark.asyncio
async def test_gti_router_blocks_invalid_ops(mock_gti_client: AsyncMock) -> None:
    router = GTIRouter(mock_gti_client)

    with pytest.raises(MCPRoutingViolation) as exc_info:
        await router.route(
            GTIRouter.ExecutionContext.ASYNC_ANALYSIS,
            "delete_indicators",
            indicators=["192.168.1.1"]
        )
    assert "not permitted on GTI router" in str(exc_info.value)


# ============================================================================
# Logging Tests
# ============================================================================


@pytest.mark.asyncio
async def test_router_logging_decisions(
    mock_cbm_client: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    router = CodebaseMemoryRouter(mock_cbm_client)

    with caplog.at_level(logging.DEBUG, logger="blackwall.mcp_routing"):
        # Permitted logs at DEBUG
        await router.route("query_dependency_chain", function_name="test_func")
        assert any(
            record.levelname == "DEBUG" and "allowed and routed 'query_dependency_chain'" in record.message
            for record in caplog.records
        )

        caplog.clear()

        # Blocked logs at WARNING
        with pytest.raises(MCPRoutingViolation):
            await router.route("list_files")
        assert any(
            record.levelname == "WARNING" and "blocked 'list_files'" in record.message
            for record in caplog.records
        )

        caplog.clear()

        # Escape attempts logged at WARNING with [ESCAPE_ATTEMPT]
        with pytest.raises(MCPRoutingViolation):
            await router.route("query_dependency_chain;exec()")
        assert any(
            record.levelname == "WARNING" and "[ESCAPE_ATTEMPT]" in record.message
            for record in caplog.records
        )
