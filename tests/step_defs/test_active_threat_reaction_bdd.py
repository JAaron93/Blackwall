"""BDD Step Definitions for Active Threat Reaction Engine (`tests/features/active_threat_reaction.feature`)."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    Alert,
    AlertBus,
    AttackGraphStore,
    AttackNode,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
    ReactionActionType,
)
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter
from tests.step_defs.async_utils import run_async

scenarios("../features/active_threat_reaction.feature")


class MockBDDMeshBroadcaster:
    """Mock broadcaster for Threat Mesh BDD testing."""

    def __init__(self) -> None:
        self.broadcasted_messages: list[dict] = []

    async def broadcast_signature(self, signature: dict) -> bool:
        self.broadcasted_messages.append(signature)
        return True


class ActiveReactionBDDState:
    """State carrier for Active Threat Reaction BDD scenarios."""

    def __init__(self) -> None:
        self.kernel_driver: UserSpaceAuditDriver | None = None
        self.mesh_broadcaster: MockBDDMeshBroadcaster | None = None
        self.vault_adapter: VaultMCPAdapter | None = None
        self.eval_manager: EvaluationEnvironmentManager | None = None
        self.graph_store: AttackGraphStore | None = None
        self.alert_bus: AlertBus | None = None
        self.engine: ActiveReactionEngine | None = None

        self.jit_token: dict[str, Any] | None = None
        self.eval_evidence_node: AttackNode | None = None
        self.dispatched_payload: ActiveReactionPayload | None = None
        self.received_alerts: list[Alert] = []


@pytest.fixture
def state() -> ActiveReactionBDDState:
    return ActiveReactionBDDState()


# ============================================================================
# Scenario 1: Dynamic eBPF socket drop injection on critical threat detection
# ============================================================================


@given("an ActiveReactionEngine configured with Pillar 1 Kernel Probe Driver")
def setup_engine_with_kernel(state: ActiveReactionBDDState) -> None:
    state.kernel_driver = UserSpaceAuditDriver()
    state.engine = ActiveReactionEngine(kernel_driver=state.kernel_driver)


@when(
    parsers.parse(
        'a critical threat reaction payload with action "{action_str}" is dispatched for PID {pid:d} and IP "{ip}"'
    )
)
def dispatch_ebpf_reaction(
    state: ActiveReactionBDDState, action_str: str, pid: int, ip: str
) -> None:
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="rce-attacker",
        target_pid=pid,
        target_ip=ip,
        action_type=ReactionActionType(action_str),
    )
    state.dispatched_payload = run_async(state.engine.dispatch_reaction(payload))


@then(
    parsers.parse(
        'the kernel driver injects a drop rule for PID {pid:d} and IP "{ip}"'
    )
)
def verify_kernel_drop_rule(
    state: ActiveReactionBDDState, pid: int, ip: str
) -> None:
    assert state.kernel_driver is not None
    assert f"pid:{pid}" in state.kernel_driver._blocked_patterns
    assert f"ip:{ip}" in state.kernel_driver._blocked_patterns
    assert len(state.engine.ebpf_drop_rules) == 1
    assert state.engine.ebpf_drop_rules[0]["target_pid"] == pid
    assert state.engine.ebpf_drop_rules[0]["target_ip"] == ip


@then(
    parsers.parse(
        'the reaction execution completes in less than {ms:d} milliseconds with status "{status}"'
    )
)
def verify_reaction_sla(
    state: ActiveReactionBDDState, ms: int, status: str
) -> None:
    assert state.dispatched_payload is not None
    assert state.dispatched_payload.status == status
    assert state.dispatched_payload.execution_duration_ms < float(ms)


# ============================================================================
# Scenario 2: Zero-latency threat mesh signature broadcast across peer nodes
# ============================================================================


@given("an ActiveReactionEngine configured with Pillar 2 Threat Mesh Broadcaster")
def setup_engine_with_mesh(state: ActiveReactionBDDState) -> None:
    state.mesh_broadcaster = MockBDDMeshBroadcaster()
    state.engine = ActiveReactionEngine(mesh_broadcaster=state.mesh_broadcaster)


@when(
    parsers.parse(
        'a critical threat reaction payload with action "{action_str}" is dispatched for agent "{agent_id}"'
    )
)
def dispatch_mesh_reaction(
    state: ActiveReactionBDDState, action_str: str, agent_id: str
) -> None:
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=agent_id,
        action_type=ReactionActionType(action_str),
    )
    state.dispatched_payload = run_async(state.engine.dispatch_reaction(payload))


@then("the Threat Mesh broadcaster transmits the signature across cluster nodes")
def verify_mesh_broadcast(state: ActiveReactionBDDState) -> None:
    assert state.mesh_broadcaster is not None
    assert len(state.mesh_broadcaster.broadcasted_messages) == 1
    assert len(state.engine.broadcasted_signatures) == 1
    assert (
        state.mesh_broadcaster.broadcasted_messages[0]["target_agent_id"]
        == "c2-infiltrator"
    )


@then(
    parsers.parse(
        'the broadcast reaction completes in less than {ms:d} milliseconds with status "{status}"'
    )
)
def verify_broadcast_sla(
    state: ActiveReactionBDDState, ms: int, status: str
) -> None:
    assert state.dispatched_payload is not None
    assert state.dispatched_payload.status == status
    assert state.dispatched_payload.execution_duration_ms < float(ms)


# ============================================================================
# Scenario 3: Identity credential invalidation upon lateral movement or token theft
# ============================================================================


@given(
    "an ActiveReactionEngine configured with Pillar 3 Ephemeral Identity Sidecar and Vault MCP"
)
def setup_engine_with_vault(state: ActiveReactionBDDState) -> None:
    state.vault_adapter = VaultMCPAdapter()
    run_async(state.vault_adapter.connect())
    state.engine = ActiveReactionEngine(vault_adapter=state.vault_adapter)


@given(parsers.parse('an active JIT credential issued for agent "{agent_id}"'))
def issue_jit_credential(state: ActiveReactionBDDState, agent_id: str) -> None:
    assert state.vault_adapter is not None
    state.jit_token = run_async(
        state.vault_adapter.issue_jit_token(role="agent_role", ttl_seconds=900)
    )
    assert state.jit_token["status"] == "ACTIVE"


@when(
    parsers.parse(
        'an active reaction payload with action "{action_str}" is dispatched for agent "{agent_id}"'
    )
)
def dispatch_vault_revocation(
    state: ActiveReactionBDDState, action_str: str, agent_id: str
) -> None:
    assert state.jit_token is not None
    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id=agent_id,
        action_type=ReactionActionType(action_str),
        metadata={"token_id": state.jit_token["token_id"]},
    )
    state.dispatched_payload = run_async(state.engine.dispatch_reaction(payload))


@then("the active JIT credential is revoked and synthetic honey-tokens are rotated")
def verify_vault_revoked(state: ActiveReactionBDDState) -> None:
    assert state.vault_adapter is not None
    assert state.jit_token is not None
    assert (
        state.vault_adapter._issued_tokens[state.jit_token["token_id"]]["status"]
        == "REVOKED"
    )
    assert len(state.engine.revoked_identities) == 1


@then(parsers.parse('the reaction status is "{status}"'))
def verify_reaction_status(state: ActiveReactionBDDState, status: str) -> None:
    assert state.dispatched_payload is not None
    assert state.dispatched_payload.status == status


# ============================================================================
# Scenario 4: Mitigation actions are suppressed when evidence originates in evaluation mode
# ============================================================================


@given("an ActiveReactionEngine connected to an EvaluationEnvironmentManager")
def setup_engine_with_eval(state: ActiveReactionBDDState) -> None:
    state.kernel_driver = UserSpaceAuditDriver()
    state.mesh_broadcaster = MockBDDMeshBroadcaster()
    state.vault_adapter = VaultMCPAdapter()
    run_async(state.vault_adapter.connect())
    state.eval_manager = EvaluationEnvironmentManager(in_memory=True)

    state.engine = ActiveReactionEngine(
        kernel_driver=state.kernel_driver,
        mesh_broadcaster=state.mesh_broadcaster,
        vault_adapter=state.vault_adapter,
        eval_manager=state.eval_manager,
    )


@given(
    parsers.parse(
        'security evidence generated within evaluation environment "{env_id}"'
    )
)
def create_eval_evidence(state: ActiveReactionBDDState, env_id: str) -> None:
    assert state.eval_manager is not None
    env = state.eval_manager.get_or_create_environment(env_id)
    eval_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="eval-redteam-01",
        action="execve",
        target="/tmp/sandbox_exploit",
        risk_score=0.99,
    )
    state.eval_evidence_node = run_async(env.insert_event(eval_event))


@when("an active reaction payload is dispatched referencing the evaluation evidence")
def dispatch_reaction_on_eval_evidence(state: ActiveReactionBDDState) -> None:
    assert state.eval_evidence_node is not None
    # Intentionally payload.evaluation_env_id is None to test evidence-derived containment
    payload = ActiveReactionPayload(
        trigger_evidence_id=state.eval_evidence_node.node_id,
        target_agent_id="eval-redteam-01",
        target_pid=6677,
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id=None,
    )
    state.dispatched_payload = run_async(state.engine.dispatch_reaction(payload))


@then(
    parsers.parse(
        'the production mitigation action is suppressed with status "{status}"'
    )
)
def verify_eval_suppression(state: ActiveReactionBDDState, status: str) -> None:
    assert state.dispatched_payload is not None
    assert state.dispatched_payload.status == status


@then("zero drop rules or mesh signatures are injected into production")
def verify_zero_production_side_effects(state: ActiveReactionBDDState) -> None:
    assert len(state.engine.ebpf_drop_rules) == 0
    assert len(state.engine.broadcasted_signatures) == 0
    assert len(state.engine.revoked_identities) == 0


# ============================================================================
# Scenario 5: Active reactions are logged to attack graph and emitted to alert bus
# ============================================================================


@given("an ActiveReactionEngine configured with AttackGraphStore and AlertBus")
def setup_engine_with_store_and_bus(state: ActiveReactionBDDState) -> None:
    state.graph_store = AttackGraphStore(in_memory=True)
    run_async(state.graph_store.initialize())
    state.alert_bus = AlertBus()
    state.alert_bus.subscribe(lambda a: state.received_alerts.append(a))

    state.kernel_driver = UserSpaceAuditDriver()
    state.engine = ActiveReactionEngine(
        kernel_driver=state.kernel_driver,
        graph_store=state.graph_store,
        alert_bus=state.alert_bus,
    )


@when(
    parsers.parse(
        'an active reaction payload is dispatched for compromised agent "{agent_id}"'
    )
)
def dispatch_logged_reaction(
    state: ActiveReactionBDDState, agent_id: str
) -> None:
    trigger_id = uuid.uuid4()
    trigger_event = NormalizedEvent(
        event_id=trigger_id,
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve",
        target="/bin/compromised_script",
        metadata={"is_evaluation": False},
        risk_score=0.9,
    )
    assert state.graph_store is not None
    run_async(state.graph_store.insert_event(trigger_event))

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id=agent_id,
        target_pid=8899,
        action_type=ReactionActionType.EBPF_DROP,
    )
    state.dispatched_payload = run_async(state.engine.dispatch_reaction(payload))


@then("the reaction execution record is inserted into the AttackGraphStore")
def verify_graph_store_logging(state: ActiveReactionBDDState) -> None:
    assert state.graph_store is not None
    assert state.dispatched_payload is not None
    node = run_async(state.graph_store.get_node(state.dispatched_payload.reaction_id))
    assert node is not None
    assert node.event.agent_id == "agent-compromised-99"
    assert node.event.metadata["status"] == "SUCCESS"


@then("an audit notification alert is published to the AlertBus")
def verify_alert_bus_notification(state: ActiveReactionBDDState) -> None:
    assert len(state.received_alerts) == 1
    alert = state.received_alerts[0]
    assert alert.threat_type == "active_threat_reaction"
    assert alert.agent_id == "agent-compromised-99"
    assert alert.metadata["action_type"] == "EBPF_DROP"
    assert alert.metadata["status"] == "SUCCESS"
