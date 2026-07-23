"""
Unit tests for ContainerSandboxMCPAdapter / container-sandbox-mcp (TASK-P02).
Tests local Docker API / gVisor (runsc) sandbox adapter.
"""

import pytest
from blackwall.enterprise.mcp.sandbox_mcp import ContainerSandboxMCPAdapter


@pytest.fixture
def sandbox_adapter():
    return ContainerSandboxMCPAdapter(endpoint="http://localhost:2375")


@pytest.mark.asyncio
async def test_sandbox_adapter_connection_lifecycle(sandbox_adapter):
    assert sandbox_adapter.is_connected is False
    connected = await sandbox_adapter.connect()
    assert connected is True
    assert sandbox_adapter.is_connected is True
    await sandbox_adapter.disconnect()
    assert sandbox_adapter.is_connected is False


@pytest.mark.asyncio
async def test_run_in_sandbox(sandbox_adapter):
    await sandbox_adapter.connect()
    res = await sandbox_adapter.run_in_sandbox(
        payload="print('hello from sandbox')",
        sandbox_type="gvisor",
    )

    assert res["contained"] is True
    assert res["status"] == "SUCCESS"
    assert "sandbox_id" in res
    assert res["sandbox_id"].startswith("sbx_")
    assert res["sandbox_type"] == "gvisor"


@pytest.mark.asyncio
async def test_destroy_sandbox(sandbox_adapter):
    await sandbox_adapter.connect()
    res = await sandbox_adapter.run_in_sandbox("x = 42")
    sandbox_id = res["sandbox_id"]

    destroyed = await sandbox_adapter.destroy_sandbox(sandbox_id)
    assert destroyed is True

    # Destroying non-existent or destroyed sandbox returns False
    destroyed_again = await sandbox_adapter.destroy_sandbox(sandbox_id)
    assert destroyed_again is False
