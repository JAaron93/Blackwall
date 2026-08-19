"""BDD Step Definitions for Active Threat Reaction Engine (`tests/features/active_threat_reaction.feature`)."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    AlertBus,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
    ReactionActionType,
)
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter
from tests.step_defs.async_utils import run_async

scenarios("../features/active_threat_reaction.feature")


class ActiveReactionBDDState:
    """State holder for Active Threat Reaction BDD scenarios."""

    def __init__(self) -> None:
        self.driver: UserSpaceAuditDriver | None = None
        self.broadcaster: AsyncMock | None = None
        self.vault_adapter: VaultMCPAdapter | None = None
        self.eval_mgr: EvaluationEnvironmentManager | None = None
        self.alert_bus: AlertBus = AlertBus()
        self.engine: ActiveReactionEngine | None = None
        self.last_payload: ActiveReactionPayload | None = None
        self.last_result: bool | None = None
        self.eval_node: Any = None
        self.suppressed_payloads: list[ActiveReactionPayload] = []


@pytest.fixture
def bdd_state() -> ActiveReactionBDDState:
    return ActiveReactionBDDState()


# Scenario 1


@given("an Active Reaction Engine configured with a kernel probe driver")
def given_engine_with_kernel(bdd_state: ActiveReactionBDDState) -> None:
    bdd_state.driver = UserSpaceAuditDriver()
    bdd_state.engine = ActiveReactionEngine(
        kernel_driver=bdd_state.driver,
        alert_bus=bdd_state.alert_bus,
    )


@when(
    parsers.parse(
        'a CRITICAL swarm detection payload is dispatched for target process {pid:d} on IP "{ip}"'
    )
)
def when_dispatch_swarm_payload(
    bdd_state: ActiveReactionBDDState, pid: int, ip: str
) -> None:
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="swarm-agent-99",
        target_pid=pid,
        target_ip=ip,
        action_type=ReactionActionType.EBPF_DROP,
    )
    bdd_state.last_payload = payload
    bdd_state.last_result = run_async(bdd_state.engine.execute_ebpf_socket_drop(payload))


@then(
    parsers.parse(
        'the kernel probe driver injects socket drop rules for PID {pid:d} and IP "{ip}"'
    )
)
def then_kernel_injects_drop(
    bdd_state: ActiveReactionBDDState, pid: int, ip: str
) -> None:
    assert bdd_state.last_result is True
    assert pid in bdd_state.driver._dropped_pids
    assert ip in bdd_state.driver._dropped_sockets


@then("the reaction execution duration is less than 50 milliseconds")
def then_duration_less_than_50(bdd_state: ActiveReactionBDDState) -> None:
    assert bdd_state.last_payload is not None
    assert bdd_state.last_payload.execution_duration_ms < 50.0


@then(parsers.parse('the reaction status is "{expected_status}"'))
def then_reaction_status_matches(
    bdd_state: ActiveReactionBDDState, expected_status: str
) -> None:
    assert bdd_state.last_payload is not None
    assert bdd_state.last_payload.status == expected_status


# Scenario 2


@given("an Active Reaction Engine configured with a threat mesh broadcaster")
def given_engine_with_broadcaster(bdd_state: ActiveReactionBDDState) -> None:
    bdd_state.broadcaster = AsyncMock(return_value=True)
    bdd_state.engine = ActiveReactionEngine(
        mesh_broadcaster=bdd_state.broadcaster,
        alert_bus=bdd_state.alert_bus,
    )


@when(
    parsers.parse(
        'a CRITICAL exploit chain payload is dispatched for agent "{agent_id}"'
    )
)
def when_dispatch_exploit_payload(
    bdd_state: ActiveReactionBDDState, agent_id: str
) -> None:
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=agent_id,
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )
    bdd_state.last_payload = payload
    bdd_state.last_result = run_async(bdd_state.engine.broadcast_fleet_signature(payload))


@then("the threat mesh broadcaster publishes the zero-latency block signature")
def then_threat_mesh_publishes(bdd_state: ActiveReactionBDDState) -> None:
    assert bdd_state.last_result is True
    assert bdd_state.broadcaster.called


@then("the reaction execution duration is less than 15 milliseconds")
def then_duration_less_than_15(bdd_state: ActiveReactionBDDState) -> None:
    assert bdd_state.last_payload is not None
    assert bdd_state.last_payload.execution_duration_ms < 15.0


# Scenario 3


@given("an Active Reaction Engine configured with a Vault MCP adapter")
def given_engine_with_vault(bdd_state: ActiveReactionBDDState) -> None:
    bdd_state.vault_adapter = VaultMCPAdapter()
    bdd_state.engine = ActiveReactionEngine(
        vault_adapter=bdd_state.vault_adapter,
        alert_bus=bdd_state.alert_bus,
    )


@given(
    parsers.parse(
        'active JIT credentials issued for compromised agent "{agent_id}"'
    )
)
def given_active_jit_credentials(
    bdd_state: ActiveReactionBDDState, agent_id: str
) -> None:
    run_async(bdd_state.vault_adapter.issue_jit_token(role="worker", agent_id=agent_id))
    active = [
        t for t in bdd_state.vault_adapter._issued_tokens.values()
        if t.get("agent_id") == agent_id and t.get("status") == "ACTIVE"
    ]
    assert len(active) == 1


@when(
    parsers.parse(
        'an AILM breach mitigation payload is dispatched for agent "{agent_id}"'
    )
)
def when_dispatch_ailm_payload(
    bdd_state: ActiveReactionBDDState, agent_id: str
) -> None:
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=agent_id,
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    bdd_state.last_payload = payload
    bdd_state.last_result = run_async(bdd_state.engine.revoke_identity_session(payload))


@then(
    parsers.parse(
        'the Vault MCP adapter revokes all active JIT tokens for agent "{agent_id}"'
    )
)
def then_vault_revokes_tokens(
    bdd_state: ActiveReactionBDDState, agent_id: str
) -> None:
    assert bdd_state.last_result is True
    active = [
        t for t in bdd_state.vault_adapter._issued_tokens.values()
        if t.get("agent_id") == agent_id and t.get("status") == "ACTIVE"
    ]
    assert len(active) == 0


# Scenario 4


@given("an Active Reaction Engine configured with kernel driver, mesh broadcaster, Vault adapter, and evaluation environment manager")
def given_full_engine_with_eval(bdd_state: ActiveReactionBDDState) -> None:
    bdd_state.driver = UserSpaceAuditDriver()
    bdd_state.broadcaster = AsyncMock(return_value=True)
    bdd_state.vault_adapter = VaultMCPAdapter()
    bdd_state.eval_mgr = EvaluationEnvironmentManager()
    bdd_state.engine = ActiveReactionEngine(
        kernel_driver=bdd_state.driver,
        mesh_broadcaster=bdd_state.broadcaster,
        vault_adapter=bdd_state.vault_adapter,
        eval_manager=bdd_state.eval_mgr,
        alert_bus=bdd_state.alert_bus,
    )


@given(
    parsers.parse(
        'an evaluation environment "{env_id}" with an event node'
    )
)
def given_eval_env_with_event(
    bdd_state: ActiveReactionBDDState, env_id: str
) -> None:
    env = bdd_state.eval_mgr.get_or_create_environment(env_id)
    ev = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.TOOL_CALL,
        agent_id="eval-agent-x",
        action="eval_syscall",
        target="eval_target",
        risk_score=0.9,
    )
    bdd_state.eval_node = run_async(env.insert_event(ev))


@when("an eBPF drop payload derived from the evaluation event is dispatched")
def when_dispatch_eval_ebpf(bdd_state: ActiveReactionBDDState) -> None:
    p = ActiveReactionPayload(
        trigger_evidence_id=bdd_state.eval_node.node_id,
        target_agent_id="eval-agent-x",
        target_pid=8888,
        target_ip="192.168.1.1",
        action_type=ReactionActionType.EBPF_DROP,
    )
    run_async(bdd_state.engine.execute_ebpf_socket_drop(p))
    bdd_state.suppressed_payloads.append(p)


@when("a Threat Mesh broadcast payload derived from the evaluation event is dispatched")
def when_dispatch_eval_mesh(bdd_state: ActiveReactionBDDState) -> None:
    p = ActiveReactionPayload(
        trigger_evidence_id=bdd_state.eval_node.node_id,
        target_agent_id="eval-agent-x",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )
    run_async(bdd_state.engine.broadcast_fleet_signature(p))
    bdd_state.suppressed_payloads.append(p)


@when("a Vault revocation payload derived from the evaluation event is dispatched")
def when_dispatch_eval_vault(bdd_state: ActiveReactionBDDState) -> None:
    p = ActiveReactionPayload(
        trigger_evidence_id=bdd_state.eval_node.node_id,
        target_agent_id="eval-agent-x",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    run_async(bdd_state.engine.revoke_identity_session(p))
    bdd_state.suppressed_payloads.append(p)


@then(parsers.parse('all three reaction payloads have status "{expected_status}"'))
def then_all_payloads_suppressed(
    bdd_state: ActiveReactionBDDState, expected_status: str
) -> None:
    assert len(bdd_state.suppressed_payloads) == 3
    for p in bdd_state.suppressed_payloads:
        assert p.status == expected_status


@then("no production socket drop rules are injected")
def then_no_socket_drop_injected(bdd_state: ActiveReactionBDDState) -> None:
    assert 8888 not in bdd_state.driver._dropped_pids
    assert "192.168.1.1" not in bdd_state.driver._dropped_sockets


@then("no threat signatures are broadcast to the production mesh")
def then_no_threat_signatures_broadcast(bdd_state: ActiveReactionBDDState) -> None:
    assert not bdd_state.broadcaster.called
