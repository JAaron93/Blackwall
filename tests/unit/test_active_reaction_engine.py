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
    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
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
    broadcaster = MockMeshBroadcaster()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
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
    vault_adapter = VaultMCPAdapter()
    await vault_adapter.connect()
    token = await vault_adapter.issue_jit_token(role="worker", ttl_seconds=900)

    engine = ActiveReactionEngine(vault_adapter=vault_adapter)

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
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

    payload = ActiveReactionPayload(
        trigger_evidence_id=uuid.uuid4(),
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
    driver = UserSpaceAuditDriver()
    broadcaster = MockMeshBroadcaster()
    vault = VaultMCPAdapter()
    await vault.connect()

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault,
    )

    # C2 Alert -> eBPF drop + Mesh broadcast
    c2_alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="c2_infrastructure",
        title="C2 Channel Detected",
        description="Active beaconing observed",
        evidence_id=uuid.uuid4(),
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
    swarm_alert = Alert(
        alert_id=uuid.uuid4(),
        severity=AlertSeverity.CRITICAL,
        threat_type="agent_swarm",
        title="Agent Swarm Activity",
        description="Coordinated swarm detected",
        evidence_id=uuid.uuid4(),
        agent_id="swarm-leader",
    )
    swarm_reactions = await engine.react_to_alert(swarm_alert)
    assert len(swarm_reactions) == 1
    assert swarm_reactions[0].action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS
    assert swarm_reactions[0].status == "SUCCESS"

    # Non-critical alert -> No reactions dispatched
    low_alert = Alert(
        severity=AlertSeverity.LOW,
        threat_type="port_scan",
        title="Low risk scan",
        description="Minor scan",
    )
    low_reactions = await engine.react_to_alert(low_alert)
    assert len(low_reactions) == 0
