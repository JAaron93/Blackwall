"""Hypothesis Property-Based Tests for Active Threat Reaction Engine (Pillar 6 Task 24).

Properties tested:
- Property 89: Dynamic eBPF Socket Drop Injection (Requirement 22.1)
- Property 90: Zero-Latency Threat Mesh Broadcast (Requirement 22.2)
- Property 91: Identity Credential Invalidation (Requirement 22.3)
- Property 92: Reaction Execution Logging (Requirement 22.4)
- Property 104: Evaluation Mode Reaction Suppression (Requirement 14.5, 22.5)
"""

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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


class MockPropertyBroadcaster:
    """Mock broadcaster for Threat Mesh property testing."""

    def __init__(self) -> None:
        self.broadcasted_messages: list[dict] = []

    async def broadcast_signature(self, signature: dict) -> bool:
        self.broadcasted_messages.append(signature)
        return True


# Strategy generators
agent_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{3,20}", fullmatch=True)
pid_strategy = st.integers(min_value=1, max_value=65535)
ip_strategy = st.sampled_from(
    [
        "10.0.0.1",
        "192.168.1.100",
        "172.16.5.20",
        "203.0.113.45",
        "198.51.100.12",
        "fe80::1",
        "::1",
    ]
)
eval_env_id_strategy = st.from_regex(r"eval-[a-z0-9_-]{3,15}", fullmatch=True)


# ============================================================================
# Property 89: Dynamic eBPF Socket Drop Injection (Requirement 22.1)
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=agent_id_strategy,
    pid=pid_strategy,
    ip=ip_strategy,
)
@pytest.mark.asyncio
async def test_property_89_dynamic_ebpf_socket_drop_injection(
    agent_id: str, pid: int, ip: str
):
    """Feature: blackwall-advanced-threat-detection, Property 89: Dynamic eBPF Socket Drop Injection.

    For any CRITICAL threat evidence, the ActiveReactionEngine SHALL inject an eBPF socket drop
    rule for the offending PID or IP into Pillar 1 within 50 milliseconds.
    """
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action="execve",
            target=str(pid),
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    driver = UserSpaceAuditDriver()
    engine = ActiveReactionEngine(kernel_driver=driver, graph_store=graph_store)

    # Warmup query to bypass JIT compilation / DB pool init overhead (Rule 1)
    await engine.is_evaluation_mode(trigger_id)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id=agent_id,
        target_pid=pid,
        target_ip=ip,
        action_type=ReactionActionType.EBPF_DROP,
    )

    success = await engine.execute_ebpf_socket_drop(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert payload.execution_duration_ms < 50.0
    assert len(engine.ebpf_drop_rules) == 1
    assert engine.ebpf_drop_rules[0]["target_pid"] == pid
    assert engine.ebpf_drop_rules[0]["target_ip"] == ip
    assert f"pid:{pid}" in driver._blocked_patterns
    assert f"ip:{ip}" in driver._blocked_patterns


# ============================================================================
# Property 90: Zero-Latency Threat Mesh Broadcast (Requirement 22.2)
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=agent_id_strategy,
    ip=ip_strategy,
)
@pytest.mark.asyncio
async def test_property_90_zero_latency_threat_mesh_broadcast(
    agent_id: str, ip: str
):
    """Feature: blackwall-advanced-threat-detection, Property 90: Zero-Latency Threat Mesh Broadcast.

    For any CRITICAL threat evidence, the ActiveReactionEngine SHALL broadcast a block signature
    to Pillar 2 Threat Mesh in less than 15 milliseconds.
    """
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action="connect",
            target=ip,
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    broadcaster = MockPropertyBroadcaster()
    engine = ActiveReactionEngine(mesh_broadcaster=broadcaster, graph_store=graph_store)

    # Warmup query to bypass JIT compilation / DB pool init overhead (Rule 1)
    await engine.is_evaluation_mode(trigger_id)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id=agent_id,
        target_ip=ip,
        action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
    )

    success = await engine.broadcast_fleet_signature(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert payload.execution_duration_ms < 15.0
    assert len(engine.broadcasted_signatures) == 1
    assert len(broadcaster.broadcasted_messages) == 1
    assert broadcaster.broadcasted_messages[0]["target_agent_id"] == agent_id
    assert broadcaster.broadcasted_messages[0]["threat_level"] == "CRITICAL"


# ============================================================================
# Property 91: Identity Credential Invalidation (Requirement 22.3)
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=agent_id_strategy,
)
@pytest.mark.asyncio
async def test_property_91_identity_credential_invalidation(agent_id: str):
    """Feature: blackwall-advanced-threat-detection, Property 91: Identity Credential Invalidation.

    For any detected AILM breach or credential theft event, the ActiveReactionEngine SHALL
    trigger Pillar 3 Vault sidecar to invalidate JIT credentials for the compromised agent.
    """
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    trigger_id = uuid.uuid4()
    await graph_store.insert_event(
        NormalizedEvent(
            event_id=trigger_id,
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id=agent_id,
            action="token_access",
            target="vault",
            metadata={"is_evaluation": False},
            risk_score=0.9,
        )
    )

    vault = VaultMCPAdapter()
    await vault.connect()
    token = await vault.issue_jit_token(role="worker", agent_id=agent_id, ttl_seconds=900)

    engine = ActiveReactionEngine(vault_adapter=vault, graph_store=graph_store)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id=agent_id,
        action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
        metadata={"token_id": token["token_id"]},
    )

    success = await engine.revoke_identity_session(payload)
    assert success is True
    assert payload.status == "SUCCESS"
    assert len(engine.revoked_identities) == 1
    assert engine.revoked_identities[0]["target_agent_id"] == agent_id
    assert vault._issued_tokens[token["token_id"]]["status"] == "REVOKED"


# ============================================================================
# Property 92: Reaction Execution Logging (Requirement 22.4)
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=agent_id_strategy,
    action_type=st.sampled_from(list(ReactionActionType)),
)
@pytest.mark.asyncio
async def test_property_92_reaction_execution_logging(
    agent_id: str, action_type: ReactionActionType
):
    """Feature: blackwall-advanced-threat-detection, Property 92: Reaction Execution Logging.

    For any mitigation action taken by the ActiveReactionEngine, an ActiveReactionPayload record
    SHALL be logged to the attack graph and an alert emitted to the Alert Bus.
    """
    graph_store = AttackGraphStore(in_memory=True)
    await graph_store.initialize()
    alert_bus = AlertBus()

    received_alerts: list[Alert] = []
    alert_bus.subscribe(lambda a: received_alerts.append(a))

    driver = UserSpaceAuditDriver()
    broadcaster = MockPropertyBroadcaster()
    vault = VaultMCPAdapter()
    await vault.connect()
    token = await vault.issue_jit_token(role="worker", agent_id=agent_id, ttl_seconds=900)

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault,
        graph_store=graph_store,
        alert_bus=alert_bus,
    )

    trigger_id = uuid.uuid4()
    trigger_event = NormalizedEvent(
        event_id=trigger_id,
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="property_test_action",
        target="1024",
        metadata={"is_evaluation": False},
        risk_score=0.9,
    )
    await graph_store.insert_event(trigger_event)

    payload = ActiveReactionPayload(
        trigger_evidence_id=trigger_id,
        target_agent_id=agent_id,
        target_pid=1024,
        action_type=action_type,
        metadata={"token_id": token["token_id"]} if action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS else {},
    )

    dispatched = await engine.dispatch_reaction(payload)
    assert dispatched.status == "SUCCESS"
    assert len(engine.reaction_history) == 1

    # Verify node logged in attack graph store
    node = await graph_store.get_node(payload.reaction_id)
    assert node is not None
    assert node.event.agent_id == agent_id
    assert node.event.metadata["action_type"] == action_type.value

    # Verify alert published to alert bus
    assert len(received_alerts) == 1
    assert received_alerts[0].agent_id == agent_id
    assert received_alerts[0].metadata["action_type"] == action_type.value


# ============================================================================
# Property 104: Evaluation Mode Reaction Suppression (Requirement 14.5, 22.5)
# ============================================================================


@settings(max_examples=100)
@given(
    env_id=eval_env_id_strategy,
    agent_id=agent_id_strategy,
    action_type=st.sampled_from(list(ReactionActionType)),
    explicit_env_tag=st.booleans(),
)
@pytest.mark.asyncio
async def test_property_104_evaluation_mode_reaction_suppression(
    env_id: str,
    agent_id: str,
    action_type: ReactionActionType,
    explicit_env_tag: bool,
):
    """Feature: blackwall-advanced-threat-detection, Property 104: Evaluation Mode Reaction Suppression.

    For any reaction method invoked on ActiveReactionEngine, the engine SHALL resolve evaluation state
    by querying is_evaluation_mode(payload.trigger_evidence_id) from the underlying threat evidence graph.
    If the trigger evidence was generated within an evaluation environment, the engine SHALL quash
    production eBPF drops, fleet Threat Mesh broadcasts, and Vault revocations regardless of whether
    payload.evaluation_env_id is populated or None.
    """
    eval_manager = EvaluationEnvironmentManager(in_memory=True)
    env = eval_manager.get_or_create_environment(env_id)

    # Ingest event into evaluation environment
    eval_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve",
        target="/bin/eval_probe",
        risk_score=0.9,
    )
    node = await env.insert_event(eval_event)

    driver = UserSpaceAuditDriver()
    broadcaster = MockPropertyBroadcaster()
    vault = VaultMCPAdapter()
    await vault.connect()

    engine = ActiveReactionEngine(
        kernel_driver=driver,
        mesh_broadcaster=broadcaster,
        vault_adapter=vault,
        eval_manager=eval_manager,
    )

    # If explicit_env_tag is False, payload.evaluation_env_id is None, forcing evidence-derived resolution
    payload = ActiveReactionPayload(
        trigger_evidence_id=node.node_id,
        target_agent_id=agent_id,
        target_pid=2048,
        action_type=action_type,
        evaluation_env_id=env_id if explicit_env_tag else None,
    )

    dispatched = await engine.dispatch_reaction(payload)
    assert dispatched.status == "SUPPRESSED"

    # Verify all production action stores remain empty
    assert len(engine.ebpf_drop_rules) == 0
    assert len(engine.broadcasted_signatures) == 0
    assert len(engine.revoked_identities) == 0
    assert len(broadcaster.broadcasted_messages) == 0
