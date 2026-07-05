"""Integration tests for the MCP Routing Layer.

Simulates end-to-end security gating paths and attack scenarios
to verify that routing boundaries are correctly enforced.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from blackwall.mcp.codebase_memory import CodebaseMemoryClient
from blackwall.mcp.gti_client import GTIClient
from blackwall.mcp.mcp_routing import (
    CodebaseMemoryRouter,
    GTIRouter,
    MCPRoutingViolation,
)


@pytest.fixture
def real_cbm_client() -> CodebaseMemoryClient:
    # CodebaseMemoryClient uses mock data internally if no base_url or command is configured.
    return CodebaseMemoryClient()


@pytest.fixture
def mock_gti_client() -> AsyncMock:
    client = AsyncMock(spec=GTIClient)
    client.lookup_ip = AsyncMock(return_value="mock_gti_resp")
    return client


# ============================================================================
# Synchronous Path Gating Integration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_synchronous_path_blocks_gti_queries(mock_gti_client: AsyncMock) -> None:
    """Integration simulation: The synchronous before_tool_callback callback hook

    intercepts a tool call and attempts to verify an IP address using GTI.
    The GTIRouter must raise an exception immediately, preventing the call.
    """
    gti_router = GTIRouter(mock_gti_client)

    # Simulate the before_tool_callback context (sync interception)
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await gti_router.route(
            GTIRouter.ExecutionContext.SYNC_INTERCEPTION,
            "lookup_ip",
            ip="198.51.100.12"
        )

    assert exc_info.value.router == "GTIRouter"
    assert "Execution context" in str(exc_info.value)
    assert "forbidden" in str(exc_info.value)
    mock_gti_client.lookup_ip.assert_not_called()


@pytest.mark.asyncio
async def test_async_analysis_path_allows_gti_queries(mock_gti_client: AsyncMock) -> None:
    """Integration simulation: The background async evaluation loop resolves

    the threat reputation of an extracted IP indicator.
    The GTIRouter must permit the call and delegate it to the client.
    """
    gti_router = GTIRouter(mock_gti_client)

    res = await gti_router.route(
        GTIRouter.ExecutionContext.ASYNC_ANALYSIS,
        "lookup_ip",
        ip="198.51.100.12"
    )

    assert res == "mock_gti_resp"
    mock_gti_client.lookup_ip.assert_called_once_with(ip="198.51.100.12")


# ============================================================================
# Attack Simulation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_attack_simulation_cbm_operations(real_cbm_client: CodebaseMemoryClient) -> None:
    """Simulates adversarial attempts to bypass structural sandbox.

    Verifies that the CodebaseMemoryRouter blocks various escape attempts.
    """
    cbm_router = CodebaseMemoryRouter(real_cbm_client)

    # Attack 1: Rogue agent tries to invoke a non-allowlisted tool method (e.g., list files)
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await cbm_router.route("list_files", directory="/app/src")
    assert "not in permitted list" in str(exc_info.value)

    # Attack 2: Rogue agent tries shell command execution via shell metacharacters in method name
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await cbm_router.route("query_dependency_chain; rm -rf /")
    assert "[ESCAPE_ATTEMPT]" in str(exc_info.value)

    # Attack 3: Rogue agent tries code injection via python magic keywords in method name
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await cbm_router.route("query_dependency_chain.__class__")
    assert "[ESCAPE_ATTEMPT]" in str(exc_info.value)

    # Attack 4: Rogue agent passes malicious command payload in keyword arguments
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await cbm_router.route("query_dependency_chain", function_name="eval(import('os').system('id'))")
    assert "[ESCAPE_ATTEMPT]" in str(exc_info.value)


@pytest.mark.asyncio
async def test_attack_simulation_gti_operations(mock_gti_client: AsyncMock) -> None:
    """Simulates adversarial attempts to pass malicious indicators or injection

    payloads to the GTI router, verifying they are blocked.
    """
    gti_router = GTIRouter(mock_gti_client)

    # Attack 1: Rogue agent tries to lookup an IP containing shell injection metacharacters
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await gti_router.route(
            GTIRouter.ExecutionContext.ASYNC_ANALYSIS,
            "lookup_ip",
            ip="198.51.100.24; cat /etc/passwd"
        )
    assert "[ESCAPE_ATTEMPT]" in str(exc_info.value)
    mock_gti_client.lookup_ip.assert_not_called()

    # Attack 2: Rogue agent tries to run eval via URL indicator
    with pytest.raises(MCPRoutingViolation) as exc_info:
        await gti_router.route(
            GTIRouter.ExecutionContext.ASYNC_ANALYSIS,
            "lookup_url",
            url="http://malicious.com?q=__import__('subprocess').run('whoami')"
        )
    assert "[ESCAPE_ATTEMPT]" in str(exc_info.value)


# ============================================================================
# End-to-End Real Fallback & Delegation
# ============================================================================


@pytest.mark.asyncio
async def test_cbm_router_e2e_mock_fallback(real_cbm_client: CodebaseMemoryClient) -> None:
    """Verifies that the CodebaseMemoryRouter correctly routes to CodebaseMemoryClient

    and that the client falls back to mock responses or returns actual parsed results.
    """
    cbm_router = CodebaseMemoryRouter(real_cbm_client)

    # Query dependency chain for a known function in CBM's mock database
    resp = await cbm_router.route("query_dependency_chain", function_name="ProcessOrder")
    assert resp.rootFunction == "ProcessOrder"
    assert resp.depth == 3
    assert "ExecuteSQL" in resp.callChain
    assert resp.hasCriticalSink is True
