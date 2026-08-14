"""Unit tests for Evaluation Environment Support (Requirement 14 & Task 18)."""

import asyncio
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


@pytest.mark.asyncio
async def test_concurrent_insert_and_reset_safety():
    """Verify concurrent inserts and resets do not corrupt state or cause deadlocks."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-concurrent-01")

    async def insert_worker():
        for i in range(20):
            ev = create_sample_event(agent_id=f"agent-conc-{i}")
            await env.insert_event(ev)

    async def reset_worker():
        for _ in range(5):
            await env.reset()

    # Run concurrently
    await asyncio.gather(insert_worker(), reset_worker())

    # State is consistent and operable
    final_ev = create_sample_event(agent_id="agent-after-concurrency")
    final_node = await env.insert_event(final_ev)
    assert final_node is not None
    assert await env.store.get_node(final_node.node_id) is not None


@pytest.mark.asyncio
async def test_scoped_db_reset_query_execution():
    """Verify scoped DB reset queries target only the specific evaluation_env_id."""
    from unittest.mock import AsyncMock, MagicMock

    env = EvaluationEnvironment("eval-scoped-test", in_memory=True)

    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_txn = MagicMock()

    mock_txn.__aenter__ = AsyncMock(return_value=None)
    mock_txn.__aexit__ = AsyncMock(return_value=None)
    mock_conn.transaction.return_value = mock_txn

    mock_acquire_cm = MagicMock()
    mock_acquire_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_acquire_cm.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire.return_value = mock_acquire_cm

    fake_node_id = str(uuid.uuid4())
    fake_edge_id = str(uuid.uuid4())
    mock_conn.fetch = AsyncMock(
        side_effect=[
            [{"node_id": fake_node_id}],
            [{"edge_id": fake_edge_id}],
        ]
    )
    mock_conn.execute = AsyncMock(return_value=None)

    env.store._pool = mock_pool

    await env.reset()

    # Verify scoped fetch was performed with env_id
    assert mock_conn.fetch.call_count == 2
    fetch_args = mock_conn.fetch.call_args_list[0][0]
    assert "metadata->>'evaluation_env_id' = $1" in fetch_args[0]
    assert fetch_args[1] == "eval-scoped-test"

    # Verify scoped deletes and surviving node edge cleanup
    assert mock_conn.execute.call_count == 3
    del_edges_call = mock_conn.execute.call_args_list[0][0]
    assert "DELETE FROM causal_edges" in del_edges_call[0]
    assert del_edges_call[1] == [fake_node_id]

    update_edges_call = mock_conn.execute.call_args_list[1][0]
    assert "UPDATE event_nodes" in update_edges_call[0]
    assert update_edges_call[1] == [fake_edge_id]

    del_nodes_call = mock_conn.execute.call_args_list[2][0]
    assert "DELETE FROM event_nodes WHERE metadata->>'evaluation_env_id' = $1" in del_nodes_call[0]
    assert del_nodes_call[1] == "eval-scoped-test"


@pytest.mark.asyncio
async def test_closed_environment_rejects_operations():
    """Verify closed environments explicitly reject writes and operations rather than detaching in memory."""
    env = EvaluationEnvironment("eval-closed-test", in_memory=True)
    await env.initialize()
    await env.close()

    ev = create_sample_event(agent_id="agent-closed")

    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.insert_event(ev)

    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.insert_events_batch([ev])

    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.reset()

    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.get_node(ev.event_id)

    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.publish_alert(
            Alert(
                severity=AlertSeverity.HIGH,
                threat_type="rce",
                title="test",
                description="test",
            )
        )


@pytest.mark.asyncio
async def test_shared_graph_production_node_isolation():
    """Verify is_evaluation_mode rejects production nodes present in underlying store without eval metadata."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-shared-test")

    # Directly insert an un-labeled production event into the environment's store
    prod_event = create_sample_event(agent_id="prod-agent-01")
    assert "evaluation_env_id" not in prod_event.metadata
    prod_node = await env.store.insert_event(prod_event)

    # Manager must NOT consider this node as evaluation mode because metadata lacks evaluation stamp
    assert await manager.is_evaluation_mode(prod_node.node_id) is False
    assert await manager.is_evaluation_mode(prod_node.node_id, env_id="eval-shared-test") is False
    assert await env.get_node(prod_node.node_id) is None


@pytest.mark.asyncio
async def test_failed_db_reset_raises_runtime_error_and_preserves_memory_state():
    """Verify reset raises RuntimeError and does not falsely claim success when DB transaction fails."""
    from unittest.mock import AsyncMock, MagicMock

    env = EvaluationEnvironment("eval-fail-reset", in_memory=True)
    ev = create_sample_event(agent_id="agent-persist")
    node = await env.insert_event(ev)

    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_txn = MagicMock()

    mock_txn.__aenter__ = AsyncMock(return_value=None)
    mock_txn.__aexit__ = AsyncMock(return_value=None)
    mock_conn.transaction.return_value = mock_txn

    mock_acquire_cm = MagicMock()
    mock_acquire_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_acquire_cm.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire.return_value = mock_acquire_cm

    mock_conn.fetch = AsyncMock(side_effect=Exception("Simulated PostgreSQL connection failure"))

    env.store._pool = mock_pool

    with pytest.raises(RuntimeError, match="Failed to reset evaluation environment 'eval-fail-reset'"):
        await env.reset()

    # In-memory nodes and state must still exist because DB delete failed
    assert len(env.store._nodes) == 1
    assert await env.store.get_node(node.node_id) is not None


@pytest.mark.asyncio
async def test_delete_environment_closes_pool_on_reset_failure():
    """Verify delete_environment closes store pool and cleans manager references even if reset fails."""
    from unittest.mock import AsyncMock, MagicMock

    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-del-fail")

    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_txn = MagicMock()

    mock_txn.__aenter__ = AsyncMock(return_value=None)
    mock_txn.__aexit__ = AsyncMock(return_value=None)
    mock_conn.transaction.return_value = mock_txn

    mock_acquire_cm = MagicMock()
    mock_acquire_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_acquire_cm.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire.return_value = mock_acquire_cm

    mock_conn.fetch = AsyncMock(side_effect=Exception("DB Failure during reset"))
    mock_pool.close = AsyncMock(return_value=None)

    env.store._pool = mock_pool

    with pytest.raises(RuntimeError, match="Failed to reset evaluation environment 'eval-del-fail'"):
        await manager.delete_environment("eval-del-fail")

    # Manager environment entry must be removed
    assert manager.get_environment("eval-del-fail") is None
    assert "eval-del-fail" not in manager.list_environments()

    # Environment must be transitioned to closed state and pool closed
    assert env._closed is True
    mock_pool.close.assert_called_once()


@pytest.mark.asyncio
async def test_retained_graph_store_rejects_writes_after_environment_closure():
    """Verify that a store reference obtained via get_graph_store rejects writes once closed."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    store = manager.get_graph_store("eval-retained-store")

    ev = create_sample_event(agent_id="agent-before-close")
    await store.insert_event(ev)

    # Delete / close environment
    await manager.delete_environment("eval-retained-store")

    # Retained store reference must reject writes rather than silently writing in memory
    ev_after = create_sample_event(agent_id="agent-after-close")
    with pytest.raises(RuntimeError, match="graph store is closed and cannot accept writes"):
        await store.insert_event(ev_after)

    with pytest.raises(RuntimeError, match="graph store is closed and cannot accept writes"):
        await store.insert_events_batch([ev_after])

    with pytest.raises(RuntimeError, match="graph store is closed and cannot accept writes"):
        await store.link_events(ev.event_id, ev_after.event_id, "caused")


@pytest.mark.asyncio
async def test_shared_database_event_identifier_collision_isolation():
    """Verify that two evaluation environments ingesting the same event ID are completely isolated without collisions."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_a = manager.get_or_create_environment("eval-tenant-a")
    env_b = manager.get_or_create_environment("eval-tenant-b")

    shared_event = create_sample_event(agent_id="agent-collision-test")
    raw_id = shared_event.event_id

    # Ingest the same identical event into both evaluation environments
    node_a = await env_a.insert_event(shared_event)
    node_b = await env_b.insert_event(shared_event)

    # Scoped event IDs must be distinct per environment
    assert node_a.node_id != node_b.node_id
    assert node_a.event.event_id != node_b.event.event_id
    assert node_a.event.metadata["evaluation_env_id"] == "eval-tenant-a"
    assert node_b.event.metadata["evaluation_env_id"] == "eval-tenant-b"

    # Both environments resolve their respective nodes correctly
    assert await manager.is_evaluation_mode(raw_id, env_id="eval-tenant-a") is True
    assert await manager.is_evaluation_mode(raw_id, env_id="eval-tenant-b") is True
    assert await manager.is_evaluation_mode(node_a.node_id, env_id="eval-tenant-a") is True
    assert await manager.is_evaluation_mode(node_b.node_id, env_id="eval-tenant-b") is True

    # Cross-tenant queries return False
    assert await manager.is_evaluation_mode(node_a.node_id, env_id="eval-tenant-b") is False
    assert await manager.is_evaluation_mode(node_b.node_id, env_id="eval-tenant-a") is False

    # Resetting tenant A must NOT delete or affect tenant B
    await env_a.reset()
    assert await manager.is_evaluation_mode(raw_id, env_id="eval-tenant-a") is False
    assert await manager.is_evaluation_mode(raw_id, env_id="eval-tenant-b") is True
    assert await manager.is_evaluation_mode(node_b.node_id, env_id="eval-tenant-b") is True
    assert await env_b.get_node(raw_id) is not None
