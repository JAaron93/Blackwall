"""Unit tests for Active Threat Reaction Engine (Requirement 22 & Task 24)."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection import (
    ActiveReactionEngine,
    ActiveReactionPayload,
    Alert,
    AlertBus,
    AlertSeverity,
    AttackGraphStore,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
    ReactionActionType,
)
from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter


class MockMeshBroadcaster:
    """Mock broadcaster for Pillar 2 ZeroMQ Threat Mesh."""

    def __init__(self) -> None:
        self.broadcasted_messages: list[dict] = []

    async def broadcast_signature(self, signature: dict) -> bool:
        self.broadcasted_messages.append(signature)
        return True


# ============================================================================
# 1. ActiveReactionPayload Data Model Validations
# ============================================================================


def test_active_reaction_payload_valid():
    """Verify ActiveReactionPayload instantiation with valid fields."""
    reaction_id = uuid.uuid4()
    trigger_id = uuid.uuid4()
    payload = ActiveReactionPayload(
        reaction_id=reaction_id,
        trigger_evidence_id=trigger_id,
        target_agent_id="compromised-agent-01",
        target_pid=1234,
        target_ip="192.168.1.100",
        action_type=ReactionActionType.EBPF_DROP,
        timestamp=datetime.now(UTC),
    )
    assert payload.reaction_id == reaction_id
    assert payload.trigger_evidence_id == trigger_id
    assert payload.target_agent_id == "compromised-agent-01"
    assert payload.target_pid == 1234
    assert payload.target_ip == "192.168.1.100"
    assert payload.action_type == ReactionActionType.EBPF_DROP
    assert payload.status == "PENDING"
    assert payload.execution_duration_ms == 0.0


def test_active_reaction_payload_rejections():
    """Verify field constraints and validations on ActiveReactionPayload."""
    valid_uuid = uuid.uuid4()

    # Invalid UUID
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            reaction_id="invalid-uuid",
            trigger_evidence_id=valid_uuid,
            target_agent_id="agent-01",
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Empty agent_id
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="",
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Whitespace-only agent_id
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="   ",
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Negative PID
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="agent-01",
            target_pid=-5,
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Zero PID
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="agent-01",
            target_pid=0,
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Invalid IP
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="agent-01",
            target_ip="999.999.999.999",
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Naive timestamp
    with pytest.raises(ValidationError):
        ActiveReactionPayload(
            trigger_evidence_id=valid_uuid,
            target_agent_id="agent-01",
            timestamp=datetime.now(),
            action_type=ReactionActionType.EBPF_DROP,
        )

    # Non-UTC timezone offset
    with pytest.raises(ValidationError):
        other_tz = datetime.now(UTC).astimezone(datetime.now().astimezone().tzinfo)
        if other_tz.utcoffset() != timedelta(0):
            ActiveReactionPayload(
                trigger_evidence_id=valid_uuid,
                target_agent_id="agent-01",
                timestamp=other_tz,
                action_type=ReactionActionType.EBPF_DROP,
            )


# ============================================================================
# 2. Pillar 1: eBPF Socket Drop Injection Tests (Requirement 22.1)
# ============================================================================


@pytest.mark.asyncio
async def test_ebpf_socket_drop_production():
    """Verify eBPF socket drop in production mode executes within 50ms (Requirement 22.1)."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-rce-01",
            action="execve",
            target="/bin/bash",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-rce-01",
        target_pid=4412,
        target_ip="10.0.0.99",
        action_type=ReactionActionType.EBPF_DROP,
    )

    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert payload.execution_duration_ms < 50.0
    assert len(engine.ebpf_drop_rules) == 1
    assert engine.ebpf_drop_rules[0]["target_pid"] == 4412
    assert engine.ebpf_drop_rules[0]["target_ip"] == "10.0.0.99"
    assert "pid:4412" in driver._blocked_patterns
    assert "ip:10.0.0.99" in driver._blocked_patterns


@pytest.mark.asyncio
async def test_ebpf_socket_drop_evaluation_suppressed():
    """Verify eBPF socket drop is suppressed when explicit evaluation env ID is provided (Requirement 22.5)."""
    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-eval-01",
        target_pid=4412,
        target_ip="10.0.0.99",
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id="eval-env-redteam",
    )

    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is False
    assert payload.status == "SUPPRESSED"
    assert len(engine.ebpf_drop_rules) == 0
    assert "pid:4412" not in driver._blocked_patterns


# ============================================================================
# 3. Pillar 2: Threat Mesh Signature Broadcast Tests (Requirement 22.2)
# ============================================================================


@pytest.mark.asyncio
async def test_mesh_signature_broadcast_production():
    """Verify Threat Mesh signature broadcast in production executes within 15ms (Requirement 22.2)."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-c2-01",
            action="connect",
            target="198.51.100.23",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    broadcaster = MockMeshBroadcaster()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-c2-01",
        target_ip="198.51.100.23",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )

    success = await engine.broadcast_fleet_signature(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert payload.execution_duration_ms < 15.0
    assert len(engine.broadcasted_signatures) == 1
    assert len(broadcaster.broadcasted_messages) == 1
    assert broadcaster.broadcasted_messages[0]["target_agent_id"] == "agent-c2-01"
    assert broadcaster.broadcasted_messages[0]["threat_level"] == "CRITICAL"


@pytest.mark.asyncio
async def test_mesh_signature_broadcast_evaluation_suppressed():
    """Verify Threat Mesh signature broadcast is suppressed in evaluation mode (Requirement 22.5)."""
    broadcaster = MockMeshBroadcaster()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-eval-c2",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
        evaluation_env_id="eval-env-mesh",
    )

    success = await engine.broadcast_fleet_signature(payload)
    assert success is False
    assert payload.status == "SUPPRESSED"
    assert len(engine.broadcasted_signatures) == 0
    assert len(broadcaster.broadcasted_messages) == 0


# ============================================================================
# 4. Pillar 3: Ephemeral Identity Revocation Tests (Requirement 22.3)
# ============================================================================


@pytest.mark.asyncio
async def test_identity_session_revocation_production():
    """Verify Identity token revocation and honey-token rotation in production (Requirement 22.3)."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="agent-ailm-01",
            action="token_access",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault_adapter = VaultMCPAdapter()
    await vault_adapter.connect()
    token = await vault_adapter.issue_jit_token(role="worker", agent_id="agent-ailm-01", ttl_seconds=900)

    engine = ActiveReactionEngine(vault_adapter=vault_adapter, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-ailm-01",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": token["token_id"]},
    )

    success = await engine.revoke_identity_session(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert len(engine.revoked_identities) == 1
    assert engine.revoked_identities[0]["target_agent_id"] == "agent-ailm-01"
    assert vault_adapter._issued_tokens[token["token_id"]]["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_identity_session_revocation_evaluation_suppressed():
    """Verify Identity revocation is suppressed in evaluation mode (Requirement 22.5)."""
    vault_adapter = VaultMCPAdapter()
    await vault_adapter.connect()
    token = await vault_adapter.issue_jit_token(role="worker", ttl_seconds=900)

    engine = ActiveReactionEngine(vault_adapter=vault_adapter)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-eval-ailm",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        evaluation_env_id="eval-env-vault",
        metadata={"token_id": token["token_id"]},
    )

    success = await engine.revoke_identity_session(payload)
    assert success is False
    assert payload.status == "SUPPRESSED"
    assert len(engine.revoked_identities) == 0
    assert vault_adapter._issued_tokens[token["token_id"]]["status"] == "ACTIVE"


# ============================================================================
# 5. Mandatory Evidence-Derived Evaluation Containment Gate (Requirement 14.5, 22.5 & Property 104)
# ============================================================================


@pytest.mark.asyncio
async def test_evidence_derived_evaluation_containment_gate():
    """Verify mitigation actions are suppressed when trigger evidence originated in evaluation mode (Property 104)."""
    eval_manager = EvaluationEnvironmentManager(in_memory=True)
    env = eval_manager.get_or_create_environment("eval-quarantine-01")

    # Insert an event into the evaluation environment
    eval_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="redteam-agent",
        action="execve",
        target="/tmp/exploit",
        risk_score=0.95,
    )
    node = await env.insert_event(eval_event)

    driver = UserSpaceAuditDriver()
    broadcaster = MockMeshBroadcaster()
    vault = VaultMCPAdapter()
    await vault.connect()

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault,
        eval_manager=eval_manager,
    )

    # Crucial test: payload.evaluation_env_id is None, but trigger_evidence_id belongs to eval_env
    payload_ebpf = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id="redteam-agent",
        target_pid=7788,
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id=None,
    )
    res_ebpf = await engine.dispatch_reaction(payload_ebpf)
    assert res_ebpf.status == "SUPPRESSED"
    assert len(engine.ebpf_drop_rules) == 0

    payload_mesh = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id="redteam-agent",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
        evaluation_env_id=None,
    )
    res_mesh = await engine.dispatch_reaction(payload_mesh)
    assert res_mesh.status == "SUPPRESSED"
    assert len(engine.broadcasted_signatures) == 0

    payload_vault = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id="redteam-agent",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        evaluation_env_id=None,
    )
    res_vault = await engine.dispatch_reaction(payload_vault)
    assert res_vault.status == "SUPPRESSED"
    assert len(engine.revoked_identities) == 0


# ============================================================================
# 6. Dispatch Logging and Alert Bus Audit (Requirement 22.4 & Property 92)
# ============================================================================


@pytest.mark.asyncio
async def test_dispatch_logging_to_attack_graph_and_alert_bus():
    """Verify every reaction is logged to attack graph and emitted to AlertBus (Requirement 22.4)."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    alert_bus = AlertBus()

    received_alerts: list[Alert] = []
    alert_bus.subscribe(lambda a: received_alerts.append(a))

    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(
        kernel_driver=driver,
        graph_store=graph_store,
        alert_bus=alert_bus,
    )

    trigger_id = uuid.uuid4()
    trigger_event = NormalizedEvent(
        event_id=trigger_id,
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="malicious-agent-07",
        action="execve",
        target="/bin/bash",
        metadata={"is_evaluation": False},
        risk_score=0.9,
    )
    await graph_store.insert_event(trigger_event)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="malicious-agent-07",
        target_pid=9001,
        action_type=ReactionActionType.EBPF_DROP,
    )

    dispatched = await engine.dispatch_reaction(payload)
    assert dispatched.status == "SUCCESS"

    # Verify reaction history
    assert len(engine.reaction_history) == 1
    assert engine.reaction_history[0].reaction_id == payload.reaction_id

    # Verify Attack Graph Store logging
    logged_node = await graph_store.get_node(payload.reaction_id)
    assert logged_node is not None
    assert logged_node.event.agent_id == "malicious-agent-07"
    assert logged_node.event.action == "active_reaction_ebpf_drop"
    assert logged_node.event.metadata["status"] == "SUCCESS"

    # Verify Alert Bus audit notification
    assert len(received_alerts) == 1
    assert received_alerts[0].threat_type == "active_threat_reaction"
    assert received_alerts[0].agent_id == "malicious-agent-07"
    assert received_alerts[0].metadata["action_type"] == "EBPF_DROP"
    assert received_alerts[0].metadata["status"] == "SUCCESS"


# ============================================================================
# 7. Automatic Alert-Driven Reaction Dispatch (`react_to_alert`)
# ============================================================================


@pytest.mark.asyncio
async def test_react_to_alert_c2_and_swarm():
    """Verify react_to_alert synthesizes appropriate reaction payloads for CRITICAL alerts."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()

    c2_ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=c2_ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="c2-agent",
            action="connect",
            target="203.0.113.5",
            metadata={"is_evaluation": False},
            risk_score=0.95,
        )
    )

    swarm_ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=swarm_ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="swarm-leader",
            action="token_access",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.95,
        )
    )

    driver = UserSpaceAuditDriver()
    broadcaster = MockMeshBroadcaster()
    vault = VaultMCPAdapter()
    await vault.connect()

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault,
        graph_store=graph_store,
    )

    # C2 Alert -> eBPF drop + Mesh broadcast
    c2_alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="c2_infrastructure",
        title="C2 Channel Detected",
        description="Active beaconing observed",
        evidence_id=c2_ev_id,
        agent_id="c2-agent",
        evidence={"pid": 1122, "ip": "203.0.113.5"},
    )
    c2_reactions = await engine.react_to_alert(c2_alert)
    assert len(c2_reactions) == 2
    assert {r.action_type for r in c2_reactions} == {
        ReactionActionType.EBPF_DROP,
        ReactionActionType.MESH_SIGNATURE_BROADCAST,
    }
    assert all(r.status == "SUCCESS" for r in c2_reactions)

    # Swarm Alert -> Token revocation
    swarm_token = await vault.issue_jit_token(role="swarm_role", agent_id="swarm-leader", ttl_seconds=900)
    swarm_alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="agent_swarm",
        title="Agent Swarm Activity",
        description="Coordinated swarm detected",
        evidence_id=swarm_ev_id,
        agent_id="swarm-leader",
        metadata={"token_id": swarm_token["token_id"]},
    )
    swarm_reactions = await engine.react_to_alert(swarm_alert)
    assert len(swarm_reactions) == 1
    assert swarm_reactions[0].action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS
    assert swarm_reactions[0].status == "SUCCESS"
    assert swarm_reactions[0].metadata.get("token_id") == swarm_token["token_id"]
    assert vault._issued_tokens[swarm_token["token_id"]]["status"] == "REVOKED"

    # Non-critical alert -> No reactions dispatched
    low_alert = Alert(
        severity=AlertSeverity.LOW,
        threat_type="port_scan",
        title="Low risk scan",
        description="Minor scan",
    )
    low_reactions = await engine.react_to_alert(low_alert)
    assert len(low_reactions) == 0


# ============================================================================
# 8. Robustness & Error Handling: Adapter Failure and Fail-Closed Containment
# ============================================================================


@pytest.mark.asyncio
async def test_adapter_absence_and_rejection_marks_failed():
    """Verify that absent adapters or rejected operations set status to FAILED."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-01",
            action="execve",
            target="/bin/bash",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    # Engine with no adapters configured but valid production graph store
    empty_engine = ActiveReactionEngine(graph_store=graph_store)

    payload_ebpf = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-01",
        target_pid=1234,
        action_type=ReactionActionType.EBPF_DROP,
    )
    assert await empty_engine.execute_ebpf_socket_drop(payload_ebpf) is False
    assert payload_ebpf.status == "FAILED"

    payload_mesh = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-01",
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )
    assert await empty_engine.broadcast_fleet_signature(payload_mesh) is False
    assert payload_mesh.status == "FAILED"

    payload_vault = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-01",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )
    assert await empty_engine.revoke_identity_session(payload_vault) is False
    assert payload_vault.status == "FAILED"


@pytest.mark.asyncio
async def test_evaluation_lookup_exception_fails_closed():
    """Verify that evaluation lookup exceptions fail closed to contain mitigations."""
    class FailingEvalManager:
        async def is_evaluation_mode(self, evidence_id, env_id=None):
            raise RuntimeError("Database connection lost")

    engine = ActiveReactionEngine(
        kernel_driver=UserSpaceAuditDriver(),
        eval_manager=FailingEvalManager(),
    )

    is_eval = await engine.is_evaluation_mode(uuid.uuid4())
    assert is_eval is True

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="agent-eval-fail",
        target_pid=5555,
        action_type=ReactionActionType.EBPF_DROP,
    )
    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is False
    assert payload.status == "SUPPRESSED"


@pytest.mark.asyncio
async def test_honeytoken_rotation_does_not_mask_failed_token_revocation():
    """Verify that honeytoken rotation alone does not mark REVOKE_IDENTITY_TOKENS as SUCCESS if token revocation fails."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="non-existent-agent",
            action="token_access",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()
    # Note: no tokens issued for "non-existent-agent"

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    # Attempt to revoke non-existent token for an unknown agent
    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="non-existent-agent",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": "bw_jit_nonexistent123"},
    )

    success = await engine.revoke_identity_session(payload)
    assert success is False
    assert payload.status == "FAILED"


@pytest.mark.asyncio
async def test_unresolved_evidence_with_eval_markers_fails_closed():
    """Verify that unresolvable evidence containing evaluation markers fails closed (returns True) to prevent unintended execution."""
    eval_manager = EvaluationEnvironmentManager(in_memory=True)
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()

    engine = ActiveReactionEngine(
        kernel_driver=UserSpaceAuditDriver(),
        eval_manager=eval_manager,
        graph_store=graph_store,
    )

    # An evidence ID with eval marker fails closed to contain
    eval_evidence_id = "eval-test-threat-uuid"
    is_eval = await engine.is_evaluation_mode(eval_evidence_id)
    assert is_eval is True

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
        target_agent_id="production-agent",
        target_pid=9999,
        action_type=ReactionActionType.EBPF_DROP,
        evaluation_env_id="eval-quarantine-env",
    )
    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is False
    assert payload.status == "SUPPRESSED"


@pytest.mark.asyncio
async def test_unsupported_kernel_driver_fails_socket_drop():
    """Verify that a kernel driver without inject_socket_drop or drop_socket fails execution."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="target-agent",
            action="execve",
            target="/bin/bash",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    class DummyDriverWithoutDrop:
        def start_tracing(self): pass
        def stop_tracing(self): pass

    engine = ActiveReactionEngine(kernel_driver=DummyDriverWithoutDrop(), graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="target-agent",
        target_pid=1234,
        action_type=ReactionActionType.EBPF_DROP,
    )
    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is False
    assert payload.status == "FAILED"


@pytest.mark.asyncio
async def test_evaluation_containment_eval_manager_without_graph_store():
    """Verify that when eval manager is configured without graph store, evaluation evidence is contained."""
    eval_manager = EvaluationEnvironmentManager(in_memory=True)
    env = eval_manager.get_or_create_environment("eval-quarantine")
    eval_node = await env.insert_event(
        NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-01",
            action="execve",
            target="/bin/bash",
            risk_score=0.9,
        )
    )

    engine = ActiveReactionEngine(
        kernel_driver=UserSpaceAuditDriver(),
        eval_manager=eval_manager,
        graph_store=None,
    )

    is_eval = await engine.is_evaluation_mode(eval_node.node_id)
    assert is_eval is True

    payload = ActiveReactionPayload(
        trigger_evidence_id=eval_node.node_id,
        target_agent_id="agent-01",
        target_pid=1234,
        action_type=ReactionActionType.EBPF_DROP,
    )
    res = await engine.execute_ebpf_socket_drop(payload)
    assert res is False
    assert payload.status == "SUPPRESSED"


@pytest.mark.asyncio
async def test_revoke_identity_session_exact_role_matching_no_substring_crossover():
    """Verify that token revocation scopes strictly to the target agent_id without cross-revoking sibling agents sharing roles."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="agent-1",
            action="token_access",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()

    # Issue token for agent-10 sharing role "worker"
    token_10 = await vault.issue_jit_token(role="worker", agent_id="agent-10", ttl_seconds=300)
    assert token_10 is not None

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    # Attempt to revoke for agent-1 (which is a substring of agent-10 and shares "worker" role)
    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="agent-1",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
    )

    # Should fail because agent-1 has no issued token and must NOT revoke agent-10's token
    success = await engine.revoke_identity_session(payload)
    assert success is False
    assert payload.status == "FAILED"

    # Verify agent-10's token is still ACTIVE in Vault
    assert vault._issued_tokens[token_10["token_id"]]["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_production_alert_with_aggregate_evidence_id_succeeds():
    """Verify that production alerts with synthetic or aggregate evidence IDs execute mitigations in production."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()

    aggregate_ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=aggregate_ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="c2-agent-aggregate",
            action="connect",
            target="198.51.100.50",
            metadata={"is_evaluation": False},
            risk_score=0.95,
        )
    )

    driver = UserSpaceAuditDriver()
    broadcaster = MockMeshBroadcaster()

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        graph_store=graph_store,
    )

    alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="c2_infrastructure",
        title="Aggregate C2 Detection",
        description="Aggregate detection from detector",
        evidence_id=aggregate_ev_id,
        agent_id="c2-agent-aggregate",
        evidence={"pid": 4321, "ip": "198.51.100.50"},
    )

    reactions = await engine.react_to_alert(alert)
    assert len(reactions) == 2
    assert all(r.status == "SUCCESS" for r in reactions)
    assert len(engine.ebpf_drop_rules) == 1
    assert len(engine.broadcasted_signatures) == 1


@pytest.mark.asyncio
async def test_linux_ebpf_driver_unloaded_bpf_fails_socket_drop():
    """Verify that if LinuxeBPFDriver has _ebpf_available=True but _bpf_instance is None, inject_socket_drop returns False."""
    from blackwall.enterprise.kernel.probe import LinuxeBPFDriver

    driver = LinuxeBPFDriver()
    driver._ebpf_available = True
    driver._bpf_instance = None

    # Injection must return False rather than reporting false containment
    res = driver.inject_socket_drop(pid=1234, ip="10.0.0.1")
    assert res is False


@pytest.mark.asyncio
async def test_targetless_socket_drop_fails():
    """Verify that an eBPF drop without target PID or IP fails execution."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="target-agent",
            action="execve",
            target="/bin/bash",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id="target-agent",
        target_pid=None,
        target_ip=None,
        action_type=ReactionActionType.EBPF_DROP,
    )
    res = await engine.execute_ebpf_socket_drop(payload)
    assert res is False
    assert payload.status == "FAILED"
    assert len(engine.ebpf_drop_rules) == 0


@pytest.mark.asyncio
async def test_react_to_alert_revokes_multiple_active_tokens():
    """Verify that react_to_alert discovers and revokes all active tokens for a compromised agent."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="compromised-agent",
            action="token_theft",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()

    # Issue multiple active tokens for the compromised agent
    token1 = await vault.issue_jit_token(role="worker", agent_id="compromised-agent", ttl_seconds=600)
    token2 = await vault.issue_jit_token(role="admin", agent_id="compromised-agent", ttl_seconds=600)
    # Issue a token for a different agent that must NOT be revoked
    other_token = await vault.issue_jit_token(role="worker", agent_id="innocent-agent", ttl_seconds=600)

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    # Trigger credential alert without specifying a single token_id
    alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="credential_theft",
        title="Credential harvesting detected",
        description="Multiple credentials compromised",
        evidence_id=ev_id,
        agent_id="compromised-agent",
    )

    reactions = await engine.react_to_alert(alert)
    assert len(reactions) == 1
    assert reactions[0].action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS
    assert reactions[0].status == "SUCCESS"
    assert reactions[0].metadata.get("token_ids") == [token1["token_id"], token2["token_id"]]

    # Verify both compromised tokens were revoked
    assert vault._issued_tokens[token1["token_id"]]["status"] == "REVOKED"
    assert vault._issued_tokens[token2["token_id"]]["status"] == "REVOKED"
    # Verify innocent agent token is still active
    assert vault._issued_tokens[other_token["token_id"]]["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_explicit_token_alert_revokes_sibling_active_tokens():
    """Verify that an alert providing one explicit token also revokes all sibling active tokens for that agent."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="multi-session-agent",
            action="token_theft",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()

    # Issue multiple active tokens for the target agent
    primary_token = await vault.issue_jit_token(role="worker", agent_id="multi-session-agent", ttl_seconds=600)
    sibling_token1 = await vault.issue_jit_token(role="worker", agent_id="multi-session-agent", ttl_seconds=600)
    sibling_token2 = await vault.issue_jit_token(role="admin", agent_id="multi-session-agent", ttl_seconds=600)
    unrelated_token = await vault.issue_jit_token(role="worker", agent_id="other-agent", ttl_seconds=600)

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    # Alert specifies only primary_token["token_id"]
    alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="token_theft",
        title="Token Compromised",
        description="Explicit token leak",
        evidence_id=ev_id,
        agent_id="multi-session-agent",
        metadata={"token_id": primary_token["token_id"]},
    )

    reactions = await engine.react_to_alert(alert)
    assert len(reactions) == 1
    assert reactions[0].action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS
    assert reactions[0].status == "SUCCESS"
    assert set(reactions[0].metadata.get("token_ids", [])) == {
        primary_token["token_id"],
        sibling_token1["token_id"],
        sibling_token2["token_id"],
    }

    # Verify primary and all sibling tokens were revoked
    assert vault._issued_tokens[primary_token["token_id"]]["status"] == "REVOKED"
    assert vault._issued_tokens[sibling_token1["token_id"]]["status"] == "REVOKED"
    assert vault._issued_tokens[sibling_token2["token_id"]]["status"] == "REVOKED"
    # Verify unrelated agent token is still active
    assert vault._issued_tokens[unrelated_token["token_id"]]["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_idempotent_revocation_of_already_revoked_token_succeeds():
    """Verify that a reaction attempting to revoke an already-revoked token succeeds idempotently."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="idempotent-agent",
            action="token_theft",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()
    token = await vault.issue_jit_token(role="worker", agent_id="idempotent-agent", ttl_seconds=600)
    assert token is not None

    # Revoke it once
    res1 = await vault.revoke_token(token["token_id"])
    assert res1 is True
    assert vault._issued_tokens[token["token_id"]]["status"] == "REVOKED"

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    # Dispatch reaction targeting the already-revoked token
    payload = ActiveReactionPayload(
        trigger_evidence_id=ev_id,
        target_agent_id="idempotent-agent",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": token["token_id"]},
    )
    success = await engine.revoke_identity_session(payload)
    assert success is True
    assert payload.status == "SUCCESS"


@pytest.mark.asyncio
async def test_mixed_already_revoked_and_failed_active_token_revocation_fails():
    """Verify that an already-revoked token does NOT mask failures when revoking active tokens."""
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    ev_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=ev_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="mixed-agent",
            action="token_theft",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()
    token_revoked = await vault.issue_jit_token(role="worker", agent_id="mixed-agent", ttl_seconds=600)
    await vault.revoke_token(token_revoked["token_id"])
    assert vault._issued_tokens[token_revoked["token_id"]]["status"] == "REVOKED"

    # Mock vault.revoke_token to reject any subsequent active token revocations
    async def mock_failing_revoke(t_id: str) -> bool:
        return False

    vault.revoke_token = mock_failing_revoke  # type: ignore

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=ev_id,
        target_agent_id="mixed-agent",
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_ids": [token_revoked["token_id"], "bw_jit_active_failed_token"]},
    )
    success = await engine.revoke_identity_session(payload)
    assert success is False
    assert payload.status == "FAILED"


@pytest.mark.asyncio
async def test_unresolvable_evidence_missing_from_graph_store_fails_closed_eval_mode():
    """Verify that unresolvable evidence not present in graph store fails closed to eval mode."""
    engine = ActiveReactionEngine(
        kernel_driver=UserSpaceAuditDriver(),
        eval_manager=None,
        graph_store=None,
    )

    ev_id = uuid.uuid4()
    is_eval = await engine.is_evaluation_mode(ev_id)
    assert is_eval is True

    payload = ActiveReactionPayload(
        trigger_evidence_id=ev_id,
        target_agent_id="prod-agent",
        target_pid=9999,
        action_type=ReactionActionType.EBPF_DROP,
    )
    res = await engine.execute_ebpf_socket_drop(payload)
    assert res is False
    assert payload.status == "SUPPRESSED"
