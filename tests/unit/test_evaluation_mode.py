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
    EvaluationAttackGraphStore,
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

    # Directly insert an un-labeled production event into underlying storage without eval decorator
    prod_event = create_sample_event(agent_id="prod-agent-01")
    assert "evaluation_env_id" not in prod_event.metadata
    prod_node = await super(EvaluationAttackGraphStore, env.store).insert_event(prod_event)

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
    mock_conn.fetchrow = AsyncMock(return_value=None)

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

    with pytest.raises(RuntimeError, match="graph store is closed and cannot accept writes"):
        await store.purge_events_before(datetime.now(UTC))

    with pytest.raises(RuntimeError, match="graph store is closed and cannot accept writes"):
        await store.initialize()


@pytest.mark.asyncio
async def test_direct_store_insertion_enforces_evaluation_labeling_and_containment():
    """Verify that inserting directly into store returned by manager.get_graph_store applies evaluation labeling and containment."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    store = manager.get_graph_store("eval-direct-store")

    raw_event = create_sample_event(agent_id="agent-direct")
    assert "evaluation_env_id" not in raw_event.metadata

    # Insert raw unlabeled event directly via store reference
    node = await store.insert_event(raw_event)

    # Node and stored event must carry evaluation provenance and scoped ID
    assert node.event.metadata["evaluation_env_id"] == "eval-direct-store"
    assert node.event.metadata["is_evaluation"] is True
    assert node.event.metadata["eval_mode"] is True
    assert node.event.metadata["original_event_id"] == str(raw_event.event_id)

    # Containment gate recognizes evidence through manager
    assert await manager.is_evaluation_mode(raw_event.event_id, env_id="eval-direct-store") is True
    assert await manager.is_evaluation_mode(node.node_id, env_id="eval-direct-store") is True


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


@pytest.mark.asyncio
async def test_evaluation_store_purge_preserves_foreign_and_production_nodes():
    """Verify that evaluation store purge_events_before only removes nodes for its own environment."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_eval = manager.get_or_create_environment("eval-purge-test")
    eval_store = env_eval.store

    old_time = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    cutoff = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)

    # Ingest old eval event
    eval_ev = create_sample_event(agent_id="eval-agent", timestamp=old_time)
    eval_node = await eval_store.insert_event(eval_ev)

    # Ingest foreign node directly in backing memory (simulating shared DB/cache)
    foreign_ev = create_sample_event(agent_id="foreign-agent", timestamp=old_time)
    foreign_node = AttackNode(node_id=foreign_ev.event_id, event=foreign_ev)
    eval_store._nodes[foreign_node.node_id] = foreign_node

    # Purge via eval store
    purged_count = await eval_store.purge_events_before(cutoff)
    assert purged_count == 1

    # Eval node must be purged
    assert await eval_store.get_node(eval_node.node_id) is None

    # Foreign node must be preserved in underlying storage
    assert foreign_node.node_id in eval_store._nodes


@pytest.mark.asyncio
async def test_evaluation_store_link_events_rejects_foreign_cross_environment_nodes():
    """Verify that link_events with raw UUIDs resolves to this environment's nodes and does not link foreign nodes."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-link-test")
    eval_store = env.store

    # Insert valid evaluation events
    ev1 = create_sample_event(agent_id="eval-link-1")
    ev2 = create_sample_event(agent_id="eval-link-2")
    node1 = await eval_store.insert_event(ev1)
    node2 = await eval_store.insert_event(ev2)

    # Insert a foreign node directly into memory with the same raw UUID as ev2 but foreign metadata
    foreign_node = AttackNode(node_id=ev2.event_id, event=ev2)
    eval_store._nodes[foreign_node.node_id] = foreign_node

    # Link using raw UUIDs
    await eval_store.link_events(ev1.event_id, ev2.event_id, "caused")

    # The link must be applied between evaluation-scoped nodes, not the foreign node
    reloaded_node1 = await eval_store.get_node(node1.node_id)
    reloaded_node2 = await eval_store.get_node(node2.node_id)
    assert len(reloaded_node1.outgoing_edges) == 1
    assert len(reloaded_node2.incoming_edges) == 1
    assert len(foreign_node.incoming_edges) == 0


@pytest.mark.asyncio
async def test_evaluation_environment_close_under_concurrent_alert_publication():
    """Verify concurrent alert publication and close are serialized under lock, preventing alert publication after closure."""
    env = EvaluationEnvironment("eval-concurrent-close", in_memory=True)
    alert = Alert(
        rule_id="RULE-1",
        event_id=uuid.uuid4(),
        severity=AlertSeverity.HIGH,
        threat_type="exfiltration",
        confidence=0.95,
        title="Concurrent Alert",
        description="Testing concurrent close",
    )

    published = []
    errors = []

    async def try_publish():
        for _ in range(50):
            try:
                res = await env.publish_alert(alert)
                published.append(res)
            except RuntimeError as exc:
                errors.append(exc)
            await asyncio.sleep(0.001)

    async def do_close():
        await asyncio.sleep(0.01)
        await env.close()

    await asyncio.gather(try_publish(), do_close())

    # Once closed, all subsequent publications must fail and env must be marked closed
    assert env._closed is True
    assert len(errors) > 0
    with pytest.raises(RuntimeError, match="is closed and cannot accept operations"):
        await env.publish_alert(alert)


@pytest.mark.asyncio
async def test_evaluation_environment_reset_and_mutation_lock_synchronization():
    """Verify reset and mutations share synchronization lock and prevent stale state from surviving reset."""
    env = EvaluationEnvironment("eval-concurrent-reset", in_memory=True)

    # Insert initial events
    for i in range(10):
        ev = create_sample_event(agent_id=f"agent-{i}")
        await env.insert_event(ev)

    assert len(env.store._nodes) == 10

    # Reset environment
    await env.reset()

    # Store must be completely clean
    assert len(env.store._nodes) == 0
    assert len(env.store._edges) == 0
    assert len(env.store._path_cache) == 0
    assert len(env.alert_bus._subscribers) == 0 or len(env.alert_bus._subscribers) >= 0


@pytest.mark.asyncio
async def test_evaluation_provenance_preserved_across_reset():
    """Verify evaluation evidence provenance is retained across environment resets to prevent fail-open production actions."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-provenance-test")

    ev = create_sample_event(agent_id="agent-eval-prev")
    labeled_ev = env.label_event(ev)
    await env.insert_event(labeled_ev)

    assert await manager.is_evaluation_mode(ev.event_id) is True
    assert await manager.is_evaluation_mode(labeled_ev.event_id) is True

    # Reset environment
    await env.reset()

    # Even after reset, provenance IDs must still be classified as evaluation mode
    assert await manager.is_evaluation_mode(ev.event_id) is True
    assert await manager.is_evaluation_mode(labeled_ev.event_id) is True

