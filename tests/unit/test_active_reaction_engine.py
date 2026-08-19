"""Unit tests for Active Threat Reaction Engine (Pillar 6 Task 24).

Validates Requirements 22.1 - 22.5, 14.5.
"""

import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock


import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    EventSource,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.evaluation import (
    EvaluationEnvironmentManager,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    ActiveReactionPayload,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
)
from blackwall.enterprise.identity.sidecar import SecretVaultSidecar
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter


def test_payload_creation() -> None:
    """Test ActiveReactionPayload model creation and validation."""
    evidence_id = uuid.uuid4()
    payload = ActiveReactionPayload(
        trigger_evidence_id=evidence_id,
        target_agent_id="agent-rogue-01",
        target_pid=1234,
        target_ip="192.168.1.50",
        action_type=ReactionActionType.EBPF_DROP,
    )
    assert payload.target_agent_id == "agent-rogue-01"
    assert payload.target_pid == 1234
    assert payload.target_ip == "192.168.1.50"
    assert payload.action_type == ReactionActionType.EBPF_DROP
    assert payload.timestamp.tzinfo is not None

    # Test invalid target_agent_id
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=evidence_id,
            target_agent_id="",
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Test invalid target_pid
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=evidence_id,
            target_agent_id="agent-01",
            target_pid=-5,
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Test invalid target_ip
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=evidence_id,
            target_agent_id="agent-01",
            target_ip="invalid-ip-format",
            action_type=ReactionActionType.EBPF_DROP,
        )


@pytest.mark.asyncio
async def test_ebpf_socket_drop() -> None:
    """Test dynamic eBPF socket drop rule injection within SLA."""
    driver = UserSpaceAuditDriver()
    alert_bus = AlertBus()
    engine = ActiveReactionEngine(kernel_driver=driver, alert_bus=alert_bus)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="compromised-agent-99",
        target_pid=4321,
        target_ip="10.0.0.99",
        action_type=ReactionActionType.EBPF_DROP,
    )

    result = await engine.execute_ebpf_socket_drop(payload)
    assert result is True
    assert payload.status == "COMPLETED"
    assert payload.execution_duration_ms < 50.0  # SLA < 50ms
    assert 4321 in driver._dropped_pids
    assert "10.0.0.99" in driver._dropped_sockets

    history = engine.get_reaction_history()
    assert len(history) == 1
    assert history[0].reaction_id == payload.reaction_id


@pytest.mark.asyncio
async def test_mesh_broadcast() -> None:
    """Test fleet-wide ZeroMQ threat signature broadcast within SLA."""
    broadcast_mock = AsyncMock(return_value=True)
    alert_bus = AlertBus()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcast_mock, alert_bus=alert_bus)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="compromised-swarm-02",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )

    result = await engine.broadcast_fleet_signature(payload)
    assert result is True
    assert payload.status == "COMPLETED"
    assert payload.execution_duration_ms < 15.0  # SLA < 15ms
    assert broadcast_mock.called


@pytest.mark.asyncio
async def test_credential_invalidation() -> None:
    """Test Vault JIT credential revocation for compromised agent."""
    vault_adapter = VaultMCPAdapter()
    await vault_adapter.issue_jit_token(role="worker", agent_id="agent-breached-03")
    assert len(vault_adapter._issued_tokens) == 1

    alert_bus = AlertBus()
    engine = ActiveReactionEngine(vault_adapter=vault_adapter, alert_bus=alert_bus)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-breached-03",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )

    result = await engine.revoke_identity_session(payload)
    assert result is True
    assert payload.status == "COMPLETED"
    active_tokens = [t for t in vault_adapter._issued_tokens.values() if t.get("status") == "ACTIVE"]
    assert len(active_tokens) == 0


@pytest.mark.asyncio
async def test_evaluation_mode_suppression() -> None:
    """Test suppression of all production actions when evidence is from evaluation mode."""
    driver = UserSpaceAuditDriver()
    broadcast_mock = AsyncMock(return_value=True)
    vault_adapter = VaultMCPAdapter()
    await vault_adapter.issue_jit_token(role="eval-worker", agent_id="eval-agent-01")

    eval_mgr = EvaluationEnvironmentManager()
    eval_env = eval_mgr.get_or_create_environment("eval-test-sandbox")

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcast_mock,
        vault_adapter=vault_adapter,
        eval_manager=eval_mgr,
    )

    # 1. Payload with explicit evaluation_env_id
    payload_ebpf = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="eval-agent-01",
        target_pid=9999,
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id="eval-test-sandbox",
    )

    res_ebpf = await engine.execute_ebpf_socket_drop(payload_ebpf)
    assert res_ebpf is False
    assert payload_ebpf.status == "SUPPRESSED_EVALUATION"
    assert 9999 not in driver._dropped_pids

    # 2. Payload with evidence ID derived from evaluation environment
    raw_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.TOOL_CALL,
        agent_id="eval-agent-01",
        action="suspicious_eval_action",
        target="eval_target",
        risk_score=0.9,
    )
    node = await eval_env.insert_event(raw_event)

    payload_mesh = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id="eval-agent-01",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )
    res_mesh = await engine.broadcast_fleet_signature(payload_mesh)
    assert res_mesh is False
    assert payload_mesh.status == "SUPPRESSED_EVALUATION"
    assert not broadcast_mock.called

    payload_vault = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id="eval-agent-01",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    res_vault = await engine.revoke_identity_session(payload_vault)
    assert res_vault is False
    assert payload_vault.status == "SUPPRESSED_EVALUATION"
    active_tokens = [t for t in vault_adapter._issued_tokens.values() if t.get("status") == "ACTIVE"]
    assert len(active_tokens) == 1


@pytest.mark.asyncio
async def test_envelope_metadata_evaluation_suppression() -> None:
    """Test suppression when payload carries is_evaluation / eval_mode in metadata without store provenance."""
    driver = UserSpaceAuditDriver()
    broadcast_mock = AsyncMock(return_value=True)
    vault_adapter = VaultMCPAdapter()
    await vault_adapter.issue_jit_token(role="worker", agent_id="eval-agent-metadata")

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcast_mock,
        vault_adapter=vault_adapter,
    )

    # 1. Test is_evaluation=True in metadata
    payload_ebpf = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="eval-agent-metadata",
        target_pid=7777,
        action_type=ReactionActionType.EBPF_DROP,
        metadata={"is_evaluation": True},
    )
    res_ebpf = await engine.execute_ebpf_socket_drop(payload_ebpf)
    assert res_ebpf is False
    assert payload_ebpf.status == "SUPPRESSED_EVALUATION"
    assert 7777 not in driver._dropped_pids

    # 2. Test eval_mode=True in metadata
    payload_mesh = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="eval-agent-metadata",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
        metadata={"eval_mode": True},
    )
    res_mesh = await engine.broadcast_fleet_signature(payload_mesh)
    assert res_mesh is False
    assert payload_mesh.status == "SUPPRESSED_EVALUATION"
    assert not broadcast_mock.called

    # 3. Test evaluation_uri in metadata
    raw_id = uuid.uuid4()
    payload_vault = ActiveReactionPayload(
        trigger_evidence_id=raw_id,
        target_agent_id="eval-agent-metadata",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"evaluation_uri": f"blackwall://eval/meta-env/{raw_id}"},
    )
    res_vault = await engine.revoke_identity_session(payload_vault)
    assert res_vault is False
    assert payload_vault.status == "SUPPRESSED_EVALUATION"
    active_tokens = [t for t in vault_adapter._issued_tokens.values() if t.get("status") == "ACTIVE"]
    assert len(active_tokens) == 1


@pytest.mark.asyncio
async def test_unverified_metadata_url_does_not_suppress_production_mitigation() -> None:
    """Verify ordinary metadata strings like /eval/status or forged unverified env_id do not suppress production actions."""
    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver)

    # 1. Ordinary metadata containing /eval/ in an arbitrary URL
    payload_ordinary = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="production-agent-01",
        target_pid=os.getpid(),
        action_type=ReactionActionType.EBPF_DROP,
        metadata={"target_url": "https://service/eval/status"},
    )
    is_eval = await engine.is_evaluation_mode(
        payload_ordinary.trigger_evidence_id,
        metadata=payload_ordinary.metadata,
    )
    assert is_eval is False
    res = await engine.execute_ebpf_socket_drop(payload_ordinary)
    assert res is True
    assert payload_ordinary.status == "COMPLETED"




@pytest.mark.asyncio
async def test_token_id_principal_resolution_revocation() -> None:
    """Verify revoking by token_id or metadata token_id resolves owner and revokes tokens (Rule 39)."""
    vault_adapter = VaultMCPAdapter()
    token_info = await vault_adapter.issue_jit_token(
        role="data-loader",
        agent_id="agent-rogue-principal-01",
    )
    token_id = token_info["token_id"]
    assert vault_adapter._issued_tokens[token_id]["status"] == "ACTIVE"

    engine = ActiveReactionEngine(vault_adapter=vault_adapter)

    # 1. Supply token_id directly as target_agent_id
    payload_direct = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=token_id,
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    res = await engine.revoke_identity_session(payload_direct)
    assert res is True
    assert vault_adapter._issued_tokens[token_id]["status"] == "REVOKED"

    # 2. Issue a new token, supply metadata token_id
    token_info2 = await vault_adapter.issue_jit_token(
        role="data-loader",
        agent_id="agent-rogue-principal-02",
    )
    token_id2 = token_info2["token_id"]

    payload_meta = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="generic-agent-ref",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": token_id2},
    )
    res2 = await engine.revoke_identity_session(payload_meta)
    assert res2 is True
    assert vault_adapter._issued_tokens[token_id2]["status"] == "REVOKED"


async def test_no_double_scoped_revocation_when_explicit_target_differs_from_metadata_token_owner() -> None:
    """Verify explicit target_agent_id prevents cross-revoking metadata token owner (Rule 39)."""
    vault_adapter = VaultMCPAdapter()
    token_a = await vault_adapter.issue_jit_token(role="worker", agent_id="principal-A")
    token_b = await vault_adapter.issue_jit_token(role="worker", agent_id="principal-B")

    tid_a = token_a["token_id"]
    tid_b = token_b["token_id"]

    engine = ActiveReactionEngine(vault_adapter=vault_adapter)

    # Explicit target is principal-B, metadata has token of principal-A
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="principal-B",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": tid_a},
    )
    res = await engine.revoke_identity_session(payload)
    assert res is True
    assert vault_adapter._issued_tokens[tid_b]["status"] == "REVOKED"
    # principal-A's token must remain ACTIVE (no double-scoped revocation)
    assert vault_adapter._issued_tokens[tid_a]["status"] == "ACTIVE"


async def test_deterministic_evaluation_namespace_containment() -> None:
    """Verify eval namespace URIs and derived event IDs are suppressed from production reaction."""
    engine = ActiveReactionEngine()

    # 1. Direct blackwall://eval/ URI to is_evaluation_mode
    is_eval = await engine.is_evaluation_mode(
        "blackwall://eval/cyber-env-01/12345678-1234-5678-1234-567812345678"
    )
    assert is_eval is True

    # 2. Payload with evaluation URI in metadata
    raw_id = uuid.uuid4()
    payload_uri = ActiveReactionPayload(
        trigger_evidence_id=raw_id,
        target_agent_id="agent-eval-01",
        target_pid=4444,
        action_type=ReactionActionType.EBPF_DROP,
        metadata={"evaluation_uri": f"blackwall://eval/cyber-env-01/{raw_id}"},
    )
    is_eval2 = await engine.is_evaluation_mode(
        payload_uri.trigger_evidence_id, metadata=payload_uri.metadata
    )
    assert is_eval2 is True
    res = await engine.execute_ebpf_socket_drop(payload_uri)
    assert res is False
    assert payload_uri.status == "SUPPRESSED_EVALUATION"


async def test_sidecar_delegation_revocation_in_active_reaction_engine() -> None:
    """Verify ActiveReactionEngine successfully revokes credentials when configured with SecretVaultSidecar."""
    from blackwall.enterprise.identity.sidecar import SecretVaultSidecar

    sidecar = SecretVaultSidecar()
    cred = await sidecar.get_jit_credential(role="worker", agent_id="agent-breached-sidecar")
    token_id = cred["token_id"]

    assert sidecar._issued_tokens[token_id]["status"] == "ACTIVE"

    engine = ActiveReactionEngine(vault_adapter=sidecar)
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-breached-sidecar",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    res = await engine.revoke_identity_session(payload)
    assert res is True
    assert payload.status == "COMPLETED"
    assert sidecar._issued_tokens[token_id]["status"] == "REVOKED"


async def test_unsupported_vault_adapter_fails_closed() -> None:
    """Verify ActiveReactionEngine fails closed when vault adapter has no revocation capabilities."""
    dummy_adapter = object()
    engine = ActiveReactionEngine(vault_adapter=dummy_adapter)
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-breached-dummy",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    res = await engine.revoke_identity_session(payload)
    assert res is False
    assert payload.status == "FAILED"

