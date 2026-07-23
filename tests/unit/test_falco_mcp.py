"""
Unit tests for Task K02: ebpf-falco-mcp Integration.
Verifies local open-source Falco / eBPF kernel telemetry MCP adapter.
"""

import pytest


def test_falco_mcp_adapter_initialization():
    """Verify FalcoMCPAdapter initializes with default local endpoint."""
    from blackwall.enterprise.mcp.falco_mcp import FalcoMCPAdapter

    adapter = FalcoMCPAdapter()
    assert adapter.endpoint == "http://localhost:8765"
    assert adapter.is_connected is False


@pytest.mark.asyncio
async def test_falco_mcp_query_process_lineage():
    """Verify process lineage extraction from Falco telemetry stream."""
    from blackwall.enterprise.mcp.falco_mcp import FalcoMCPAdapter

    adapter = FalcoMCPAdapter()
    lineage = await adapter.get_process_lineage(pid=14092)

    assert isinstance(lineage, dict)
    assert "pid" in lineage
    assert lineage["pid"] == 14092
    assert "process_name" in lineage
    assert "parent_pid" in lineage
