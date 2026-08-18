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
    """Verify tokens issued without explicit agent_id/principal_id bind non-None principals and can be revoked."""
    await vault_adapter.connect()
    # Issue token with no explicit agent_id/principal_id
    token_info = await vault_adapter.issue_jit_token(role="worker-node", ttl_seconds=300)
    assert token_info["agent_id"] is not None
    assert token_info["principal_id"] is not None
    token_id = token_info["token_id"]

    # Revoking by token_id via revoke_agent_tokens
    revoked = await vault_adapter.revoke_agent_tokens(token_id)
    assert token_id in revoked
    assert vault_adapter._issued_tokens[token_id]["status"] == "REVOKED"

    # Issue another token without explicit agent_id
    token_info2 = await vault_adapter.issue_jit_token(role="worker-node", ttl_seconds=300)
    token_id2 = token_info2["token_id"]
    bound_principal = token_info2["principal_id"]

    # Revoking by bound principal / role
    revoked2 = await vault_adapter.revoke_agent_tokens(bound_principal)
    assert token_id2 in revoked2
    assert vault_adapter._issued_tokens[token_id2]["status"] == "REVOKED"
