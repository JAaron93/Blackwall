"""Property-based tests for Active Threat Reaction Engine (Pillar 6 Task 24).

Validates Properties 89, 90, 91, 92, 104 against Requirements 22.1 - 22.5, 14.5.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter


@st.composite
def valid_reaction_payload(draw: st.DrawFn, action_type: ReactionActionType | None = None) -> ActiveReactionPayload:
    act = action_type or draw(st.sampled_from(list(ReactionActionType)))
    agent_id = draw(st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="-_"), min_size=1, max_size=32))
    pid = draw(st.one_of(st.none(), st.integers(min_value=1, max_value=65535)))
    ip = draw(st.one_of(st.none(), st.sampled_from(["127.0.0.1", "10.0.0.1", "192.168.1.100", "172.16.0.5"])))
    return ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=agent_id,
        target_pid=pid,
        target_ip=ip,
        action_type=act,
    )


@given(payload=valid_reaction_payload(action_type=ReactionActionType.EBPF_DROP))
@settings(max_examples=25, deadline=None)
def test_property_89_dynamic_ebpf_socket_drop_injection(payload: ActiveReactionPayload) -> None:
    """Property 89: Dynamic eBPF Socket Drop Injection.

    For all valid eBPF drop payloads, execution completes, records execution duration <50ms SLA,
    and updates driver dropped filters.
    """
    async def _run() -> None:
        driver = UserSpaceAuditDriver()
        alert_bus = AlertBus()
        engine = ActiveReactionEngine(kernel_driver=driver, alert_bus=alert_bus)

        res = await engine.execute_ebpf_socket_drop(payload)
        assert res is True
        assert payload.status == "COMPLETED"
        assert payload.execution_duration_ms < 50.0

        if payload.target_pid is not None:
            assert payload.target_pid in driver._dropped_pids
        if payload.target_ip is not None:
            assert payload.target_ip in driver._dropped_sockets

    asyncio.run(_run())


@given(payload=valid_reaction_payload(action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST))
@settings(max_examples=25, deadline=None)
def test_property_90_zero_latency_threat_mesh_broadcast(payload: ActiveReactionPayload) -> None:
    """Property 90: Zero-Latency Threat Mesh Broadcast.

    For all valid broadcast payloads, signature broadcast completes in <15ms SLA.
    """
    async def _run() -> None:
        broadcast_mock = AsyncMock(return_value=True)
        alert_bus = AlertBus()
        engine = ActiveReactionEngine(mesh_broadcaster=broadcast_mock, alert_bus=alert_bus)

        res = await engine.broadcast_fleet_signature(payload)
        assert res is True
        assert payload.status == "COMPLETED"
        assert payload.execution_duration_ms < 15.0
        assert broadcast_mock.called

    asyncio.run(_run())


@given(payload=valid_reaction_payload(action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS))
@settings(max_examples=25, deadline=None)
def test_property_91_identity_credential_invalidation(payload: ActiveReactionPayload) -> None:
    """Property 91: Identity Credential Invalidation.

    For all compromised agents, Vault sidecar revokes JIT tokens matching the target agent ID.
    """
    async def _run() -> None:
        vault_adapter = VaultMCPAdapter()
        await vault_adapter.issue_jit_token(role="worker", agent_id=payload.target_agent_id)
        alert_bus = AlertBus()
        engine = ActiveReactionEngine(vault_adapter=vault_adapter, alert_bus=alert_bus)

        res = await engine.revoke_identity_session(payload)
        assert res is True
        assert payload.status == "COMPLETED"
        active_tokens = [
            t for t in vault_adapter._issued_tokens.values()
            if t.get("agent_id") == payload.target_agent_id and t.get("status") == "ACTIVE"
        ]
        assert len(active_tokens) == 0

    asyncio.run(_run())


@given(payload=valid_reaction_payload())
@settings(max_examples=25, deadline=None)
def test_property_92_reaction_execution_logging(payload: ActiveReactionPayload) -> None:
    """Property 92: Reaction Execution Logging.

    Every mitigation action logs an ActiveReactionPayload record in reaction history.
    """
    async def _run() -> None:
        driver = UserSpaceAuditDriver()
        broadcast_mock = AsyncMock(return_value=True)
        vault_adapter = VaultMCPAdapter()
        engine = ActiveReactionEngine(
            kernel_driver=driver,
            mesh_broadcaster=broadcast_mock,
            vault_adapter=vault_adapter,
        )

        if payload.action_type == ReactionActionType.EBPF_DROP:
            await engine.execute_ebpf_socket_drop(payload)
        elif payload.action_type == ReactionActionType.MESH_SIGNATURE_BROADCAST:
            await engine.broadcast_fleet_signature(payload)
        elif payload.action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS:
            await engine.revoke_identity_session(payload)

        history = engine.get_reaction_history()
        assert len(history) >= 1
        assert any(h.reaction_id == payload.reaction_id for h in history)

    asyncio.run(_run())


@given(
    payload=valid_reaction_payload(),
    env_id=st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="-_"), min_size=1, max_size=16),
)
@settings(max_examples=25, deadline=None)
def test_property_104_evaluation_mode_reaction_suppression(payload: ActiveReactionPayload, env_id: str) -> None:
    """Property 104: Evaluation Mode Reaction Suppression.

    Evidence originating from an evaluation environment strictly suppresses all production mitigation actions.
    """
    async def _run() -> None:
        driver = UserSpaceAuditDriver()
        broadcast_mock = AsyncMock(return_value=True)
        vault_adapter = VaultMCPAdapter()
        eval_mgr = EvaluationEnvironmentManager()
        eval_env = eval_mgr.get_or_create_environment(env_id)

        raw_event = NormalizedEvent(
            event_id=payload.trigger_evidence_id,
            timestamp=datetime.now(UTC),
            source=EventSource.TOOL_CALL,
            agent_id=payload.target_agent_id,
            action="eval_action",
            target="eval_target",
            risk_score=0.95,
        )
        node = await eval_env.insert_event(raw_event)

        eval_payload = ActiveReactionPayload(
            trigger_evidence_id=node.node_id,
            target_agent_id=payload.target_agent_id,
            target_pid=payload.target_pid,
            target_ip=payload.target_ip,
            action_type=payload.action_type,
        )

        engine = ActiveReactionEngine(
            kernel_driver=driver,
            mesh_broadcaster=broadcast_mock,
            vault_adapter=vault_adapter,
            eval_manager=eval_mgr,
        )

        if eval_payload.action_type == ReactionActionType.EBPF_DROP:
            res = await engine.execute_ebpf_socket_drop(eval_payload)
            assert res is False
            assert eval_payload.status == "SUPPRESSED_EVALUATION"
            if eval_payload.target_pid is not None:
                assert eval_payload.target_pid not in driver._dropped_pids
        elif eval_payload.action_type == ReactionActionType.MESH_SIGNATURE_BROADCAST:
            res = await engine.broadcast_fleet_signature(eval_payload)
            assert res is False
            assert eval_payload.status == "SUPPRESSED_EVALUATION"
            assert not broadcast_mock.called
        elif eval_payload.action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS:
            res = await engine.revoke_identity_session(eval_payload)
            assert res is False
            assert eval_payload.status == "SUPPRESSED_EVALUATION"

    asyncio.run(_run())
