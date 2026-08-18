"""
Unit tests for VaultMCPAdapter / hashicorp-vault-mcp (TASK-I02).
Tests local HashiCorp Vault Dev Mode / LocalStack adapter, JIT token issuance (15 min TTL),
token revocation, and honey-token rotation.
"""

import pytest
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter


@pytest.fixture
def vault_adapter():
    return VaultMCPAdapter(endpoint="http://127.0.0.1:8200")


@pytest.mark.asyncio
async def test_vault_adapter_connection_lifecycle(vault_adapter):
    assert vault_adapter.is_connected is False
    connected = await vault_adapter.connect()
    assert connected is True
    assert vault_adapter.is_connected is True
    await vault_adapter.disconnect()
    assert vault_adapter.is_connected is False


@pytest.mark.asyncio
async def test_issue_jit_token(vault_adapter):
    await vault_adapter.connect()
    token_info = await vault_adapter.issue_jit_token(
        role="analytics-reader", ttl_seconds=900
    )

    assert "token_id" in token_info
    assert token_info["token_id"].startswith("bw_jit_")
    assert token_info["role"] == "analytics-reader"
    assert token_info["ttl_seconds"] == 900
    assert "expires_at" in token_info
    assert "synthetic_token" in token_info


@pytest.mark.asyncio
async def test_revoke_token(vault_adapter):
    await vault_adapter.connect()
    token_info = await vault_adapter.issue_jit_token(
        role="ephemeral-worker", ttl_seconds=600
    )
    token_id = token_info["token_id"]

    revoked = await vault_adapter.revoke_token(token_id)
    assert revoked is True

    # Revoking non-existent or already revoked token returns False
    revoked_again = await vault_adapter.revoke_token(token_id)
    assert revoked_again is False


@pytest.mark.asyncio
async def test_rotate_honeytokens(vault_adapter):
    await vault_adapter.connect()
    rotation = await vault_adapter.rotate_honeytokens()
    assert isinstance(rotation, dict)
    assert "rotation_timestamp" in rotation
    assert "status" in rotation
    assert rotation["status"] == "ROTATED"


@pytest.mark.asyncio
async def test_ownership_less_token_binding_and_revocation(vault_adapter):
    """Verify tokens can be revoked by token_id, metadata agent_id, or role."""
    await vault_adapter.connect()
    # 1. Issue token with metadata agent_id
    token_info = await vault_adapter.issue_jit_token(
        role="worker-node", ttl_seconds=300, metadata={"agent_id": "agent-meta-worker"}
    )
    assert token_info["agent_id"] == "agent-meta-worker"
    token_id = token_info["token_id"]

    # Revoking by agent_id via revoke_agent_tokens
    revoked = await vault_adapter.revoke_agent_tokens("agent-meta-worker")
    assert token_id in revoked
    assert vault_adapter._issued_tokens[token_id]["status"] == "REVOKED"

    # 2. Issue another token without explicit agent_id, revoke by token_id
    token_info2 = await vault_adapter.issue_jit_token(role="worker-node", ttl_seconds=300)
    token_id2 = token_info2["token_id"]

    revoked2 = await vault_adapter.revoke_agent_tokens(token_id2)
    assert token_id2 in revoked2
    assert vault_adapter._issued_tokens[token_id2]["status"] == "REVOKED"

    # 3. Issue third token, revoke by role
    token_info3 = await vault_adapter.issue_jit_token(role="special-role", ttl_seconds=300)
    token_id3 = token_info3["token_id"]

    revoked3 = await vault_adapter.revoke_agent_tokens("special-role")
    assert token_id3 in revoked3
    assert vault_adapter._issued_tokens[token_id3]["status"] == "REVOKED"
