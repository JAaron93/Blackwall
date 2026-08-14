"""Unit tests for Evaluation Environment Support (Requirement 14 & Task 18)."""

import uuid
from datetime import UTC, datetime

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    Alert,
    AlertSeverity,
    AttackGraphStore,
    AttackNode,
    EvaluationEnvironment,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
)


def create_sample_event(
    event_id: uuid.UUID | None = None,
    agent_id: str = "eval-agent-01",
    action: str = "execve",
    target: str = "/bin/sh",
    risk_score: float = 0.8,
    timestamp: datetime | None = None,
    metadata: dict | None = None,
) -> NormalizedEvent:
    """Helper to construct a valid NormalizedEvent."""
    return NormalizedEvent(
        event_id=event_id or uuid.uuid4(),
        timestamp=timestamp or datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=dict(metadata) if metadata else {"pid": 2048},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_eval_labeling():
    """Verify evaluation environment labeling on events and alerts (Requirement 14.1 & 14.2)."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-redteam-01")

    raw_event = create_sample_event(agent_id="redteam-agent")
    assert "evaluation_env_id" not in raw_event.metadata
    assert not manager.is_evaluation_event(raw_event)
    assert not manager.should_suppress_production_reaction(raw_event)

    # Label via manager
    labeled_event = manager.label_event(raw_event, "eval-redteam-01")
    assert labeled_event.metadata["evaluation_env_id"] == "eval-redteam-01"
    assert labeled_event.metadata["is_evaluation"] is True
    assert labeled_event.metadata["eval_mode"] is True
    assert manager.is_evaluation_event(labeled_event)
    assert manager.should_suppress_production_reaction(labeled_event)

    # Label via environment directly
    node = await env.insert_event(raw_event)
    assert isinstance(node, AttackNode)
    assert node.event.metadata["evaluation_env_id"] == "eval-redteam-01"
    assert node.event.metadata["is_evaluation"] is True

    # Label raw dictionary
    dict_event = {
        "event_id": str(uuid.uuid4()),
        "agent_id": "redteam-agent",
        "action": "curl",
        "target": "https://example.local",
        "metadata": {"custom_k": "custom_v"},
    }
    labeled_dict = manager.label_raw_event(dict_event, "eval-redteam-01")
    assert labeled_dict["metadata"]["evaluation_env_id"] == "eval-redteam-01"
    assert labeled_dict["metadata"]["is_evaluation"] is True
    assert labeled_dict["metadata"]["custom_k"] == "custom_v"

    # Alert labeling & suppression
    alert = Alert(
        severity=AlertSeverity.CRITICAL,
        threat_type="swarm_attack",
        title="Detected Swarm in Eval",
        description="Red team swarm behavior",
        evidence_id=uuid.uuid4(),
    )
    assert not manager.is_evaluation_alert(alert)
    assert not manager.should_suppress_production_reaction(alert)

    labeled_alert = manager.label_alert(alert, "eval-redteam-01")
    assert labeled_alert.metadata["evaluation_env_id"] == "eval-redteam-01"
    assert labeled_alert.metadata["is_evaluation"] is True
    assert manager.is_evaluation_alert(labeled_alert)
    assert manager.should_suppress_production_reaction(labeled_alert)


def test_eval_labeling_rejection():
    """Verify invalid or empty evaluation environment IDs raise ValueError."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    event = create_sample_event()

    with pytest.raises(ValueError):
        manager.get_or_create_environment("")

    with pytest.raises(ValueError):
        manager.get_or_create_environment("   ")

    with pytest.raises(ValueError):
        manager.label_event(event, "")

    with pytest.raises(ValueError):
        manager.label_event(event, "  ")

    with pytest.raises(ValueError):
        EvaluationEnvironment(env_id="")


@pytest.mark.asyncio
async def test_graph_isolation():
    """Verify isolated attack graph instances per evaluation environment (Requirement 14.3)."""
    manager = EvaluationEnvironmentManager(in_memory=True)

    env1 = manager.get_or_create_environment("eval-alpha")
    env2 = manager.get_or_create_environment("eval-beta")
    prod_store = AttackGraphStore(in_memory=True)
    await prod_store.initialize()

    assert env1.store is not env2.store
    assert env1.store is not prod_store

    ev1 = create_sample_event(agent_id="agent-env1", action="read_secrets")
    ev2 = create_sample_event(agent_id="agent-env2", action="lateral_pivot")
    ev_prod = create_sample_event(agent_id="agent-prod", action="authorized_deploy")

    node1 = await env1.insert_event(ev1)
    node2 = await env2.insert_event(ev2)
    node_prod = await prod_store.insert_event(ev_prod)

    # Check env1 graph
    all_nodes_env1 = await env1.store.get_all_nodes()
    assert len(all_nodes_env1) == 1
    assert all_nodes_env1[0].node_id == node1.node_id
    assert await env1.store.get_node(node2.node_id) is None
    assert await env1.store.get_node(node_prod.node_id) is None

    # Check env2 graph
    all_nodes_env2 = await env2.store.get_all_nodes()
    assert len(all_nodes_env2) == 1
    assert all_nodes_env2[0].node_id == node2.node_id
    assert await env2.store.get_node(node1.node_id) is None
    assert await env2.store.get_node(node_prod.node_id) is None

    # Check production store
    all_nodes_prod = await prod_store.get_all_nodes()
    assert len(all_nodes_prod) == 1
    assert all_nodes_prod[0].node_id == node_prod.node_id
    assert await prod_store.get_node(node1.node_id) is None
    assert await prod_store.get_node(node2.node_id) is None


@pytest.mark.asyncio
async def test_state_reset():
    """Verify evaluation environment state can be reset to clean baseline (Requirement 14.4)."""
    manager = EvaluationEnvironmentManager(in_memory=True)

    env1 = manager.get_or_create_environment("eval-reset-01")
    env2 = manager.get_or_create_environment("eval-keep-02")

    ev1 = create_sample_event(agent_id="agent-reset")
    ev2 = create_sample_event(agent_id="agent-keep")

    await env1.insert_event(ev1)
    await env2.insert_event(ev2)

    # Publish an alert in env1
    alert = Alert(
        severity=AlertSeverity.HIGH,
        threat_type="privilege_escalation",
        title="Eval Alert",
        description="Eval Alert Description",
    )
    await env1.publish_alert(alert)
    assert len(env1.alert_bus.get_alerts()) == 1

    # Verify both environments have nodes before reset
    assert len(await env1.store.get_all_nodes()) == 1
    assert len(await env2.store.get_all_nodes()) == 1

    # Reset env1
    await manager.reset_environment("eval-reset-01")

    # env1 must be empty
    assert len(await env1.store.get_all_nodes()) == 0
    assert len(env1.alert_bus.get_alerts()) == 0

    # env2 must remain unaffected
    assert len(await env2.store.get_all_nodes()) == 1

    # Batch reset all
    await manager.reset_all()
    assert len(await env2.store.get_all_nodes()) == 0


@pytest.mark.asyncio
async def test_evidence_derived_is_evaluation_mode():
    """Verify evidence-derived evaluation containment checks (Architecture Rule 20)."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-containment-01")

    ev = create_sample_event(agent_id="agent-containment")
    node = await env.insert_event(ev)

    # Check known node in eval env
    assert await manager.is_evaluation_mode(node.node_id) is True
    assert await manager.is_evaluation_mode(str(node.node_id)) is True
    assert await manager.is_evaluation_mode(node.node_id, env_id="eval-containment-01") is True

    # Unknown ID or different environment
    random_id = uuid.uuid4()
    assert await manager.is_evaluation_mode(random_id) is False
    assert await manager.is_evaluation_mode(node.node_id, env_id="nonexistent-env") is False
    assert await manager.is_evaluation_mode("invalid-uuid-string") is False


@pytest.mark.asyncio
async def test_manager_crud_and_lifecycle():
    """Verify manager lifecycle: create, list, delete, and close environments."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    assert manager.list_environments() == []

    manager.get_or_create_environment("env-1")
    manager.get_or_create_environment("env-2")
    assert set(manager.list_environments()) == {"env-1", "env-2"}

    assert manager.get_environment("env-1") is not None
    assert manager.get_environment("env-unknown") is None

    await manager.delete_environment("env-1")
    assert manager.list_environments() == ["env-2"]
    assert manager.get_environment("env-1") is None

    await manager.close_all()
    assert manager.list_environments() == []
