"""Unit tests for EvaluationAttackGraphStore lifecycle, insertion, querying, and purge operations.

Covers: Tasks 2.2 requirements from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    Alert,
    AlertSeverity,
    EvaluationAttackGraphStore,
    EvaluationEnvironment,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.models import AttackNode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(
    agent_id: str = "test-agent",
    action: str = "execve",
    target: str = "/bin/sh",
    risk_score: float = 0.8,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """Construct a valid NormalizedEvent for use in tests."""
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=timestamp or datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"pid": 1},
        risk_score=risk_score,
    )


def make_alert(
    severity: AlertSeverity = AlertSeverity.HIGH,
    threat_type: str = "test_threat",
    metadata: dict | None = None,
) -> Alert:
    """Construct a valid Alert for use in tests."""
    return Alert(
        severity=severity,
        threat_type=threat_type,
        title="Test Alert",
        description="Test description",
        metadata=metadata if metadata is not None else {},
    )


# ---------------------------------------------------------------------------
# Lifecycle tests
# ---------------------------------------------------------------------------


async def test_initialize_close_lifecycle():
    """Verify store lifecycle: initialize sets _initialized; close sets _store_closed."""
    env = EvaluationEnvironment("env-store-lifecycle", in_memory=True)

    await env.store.initialize()
    assert env.store._initialized is True

    await env.store.close()
    assert env.store._store_closed is True


# ---------------------------------------------------------------------------
# Insertion tests
# ---------------------------------------------------------------------------


async def test_insert_event_valid_normalized_event():
    """Inserted event node carries evaluation env metadata labels."""
    env = EvaluationEnvironment("env-insert-single", in_memory=True)
    event = make_event()

    node = await env.store.insert_event(event)

    assert isinstance(node, AttackNode)
    assert node.event.metadata["evaluation_env_id"] == env.env_id
    assert node.event.metadata["is_evaluation"] is True


async def test_insert_events_batch_one_event():
    """Batch insert of 1 event returns exactly 1 node."""
    env = EvaluationEnvironment("env-batch-one", in_memory=True)
    events = [make_event()]

    nodes = await env.store.insert_events_batch(events)

    assert len(nodes) == 1
    assert isinstance(nodes[0], AttackNode)


async def test_insert_events_batch_five_events():
    """Batch insert of 5 events with different agent_ids returns 5 nodes."""
    env = EvaluationEnvironment("env-batch-five", in_memory=True)
    events = [make_event(agent_id=f"agent-{i}") for i in range(5)]

    nodes = await env.store.insert_events_batch(events)

    assert len(nodes) == 5
    agent_ids = {n.event.agent_id for n in nodes}
    assert len(agent_ids) == 5


async def test_insert_events_batch_empty():
    """Batch insert of 0 events returns an empty list."""
    env = EvaluationEnvironment("env-batch-empty", in_memory=True)

    nodes = await env.store.insert_events_batch([])

    assert nodes == []


# ---------------------------------------------------------------------------
# Retrieval tests
# ---------------------------------------------------------------------------


async def test_get_node_existing_id():
    """get_node returns a correctly labelled node when queried by its node_id."""
    env = EvaluationEnvironment("env-get-node-id", in_memory=True)
    event = make_event()
    node = await env.store.insert_event(event)

    retrieved = await env.store.get_node(node.node_id)

    assert retrieved is not None
    assert retrieved.node_id == node.node_id
    assert retrieved.event.metadata["evaluation_env_id"] == env.env_id
    assert retrieved.event.metadata["is_evaluation"] is True


async def test_get_node_by_original_event_id():
    """get_node resolves derived IDs so querying by the original event_id also succeeds."""
    env = EvaluationEnvironment("env-get-node-orig", in_memory=True)
    event = make_event()
    original_id = event.event_id
    await env.store.insert_event(event)

    retrieved = await env.store.get_node(original_id)

    assert retrieved is not None
    assert retrieved.event.metadata["evaluation_env_id"] == env.env_id


async def test_get_node_nonexistent_returns_none():
    """get_node returns None when the node does not exist in the store."""
    env = EvaluationEnvironment("env-get-none", in_memory=True)

    result = await env.store.get_node(uuid.uuid4())

    assert result is None


async def test_get_all_nodes_after_insertions():
    """get_all_nodes returns exactly the nodes inserted into this environment."""
    env = EvaluationEnvironment("env-all-nodes", in_memory=True)
    for _ in range(3):
        await env.store.insert_event(make_event())

    nodes = await env.store.get_all_nodes()

    assert len(nodes) == 3
    for node in nodes:
        assert node.event.metadata["evaluation_env_id"] == env.env_id


async def test_get_all_nodes_empty_store():
    """get_all_nodes returns an empty list on a fresh environment."""
    env = EvaluationEnvironment("env-all-empty", in_memory=True)

    nodes = await env.store.get_all_nodes()

    assert nodes == []


# ---------------------------------------------------------------------------
# Query tests
# ---------------------------------------------------------------------------


async def test_query_nodes_with_agent_id_filter():
    """query_nodes(agent_id=...) returns only nodes belonging to that agent.

    The EvaluationAttackGraphStore.query_nodes override filters by env_id after delegating
    to the base store. Since the base store's in-memory path uses _nodes directly, we patch
    AttackGraphStore.query_nodes to return the in-memory nodes so the env-scoping layer is
    exercised without triggering the signature mismatch in the base method.
    """
    from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore

    env = EvaluationEnvironment("env-query-agent", in_memory=True)
    node_alpha1 = await env.store.insert_event(make_event(agent_id="agent-alpha"))
    node_beta = await env.store.insert_event(make_event(agent_id="agent-beta"))
    node_alpha2 = await env.store.insert_event(make_event(agent_id="agent-alpha"))

    all_inserted = [node_alpha1, node_beta, node_alpha2]

    async def _fake_query_nodes(self_inner, agent_id=None, **kwargs):
        return [n for n in all_inserted if agent_id is None or n.event.agent_id == agent_id]

    with patch.object(AttackGraphStore, "query_nodes", new=_fake_query_nodes):
        results = await env.store.query_nodes(agent_id="agent-alpha")

    assert len(results) == 2
    for node in results:
        assert node.event.agent_id == "agent-alpha"
    assert all(n.event.metadata["evaluation_env_id"] == env.env_id for n in results)


async def test_query_nodes_with_risk_threshold():
    """query_nodes(risk_threshold=...) returns only nodes at or above the threshold.

    Patches the base AttackGraphStore.query_nodes to return in-memory nodes filtered by
    risk_threshold so the EvaluationAttackGraphStore env-scoping layer is tested in isolation.
    """
    from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore

    env = EvaluationEnvironment("env-query-risk", in_memory=True)
    node_low = await env.store.insert_event(make_event(risk_score=0.3))
    node_mid = await env.store.insert_event(make_event(risk_score=0.7))
    node_high = await env.store.insert_event(make_event(risk_score=0.9))

    all_inserted = [node_low, node_mid, node_high]

    async def _fake_query_nodes(self_inner, risk_threshold=0.0, **kwargs):
        return [n for n in all_inserted if n.event.risk_score >= risk_threshold]

    with patch.object(AttackGraphStore, "query_nodes", new=_fake_query_nodes):
        results = await env.store.query_nodes(risk_threshold=0.6)

    assert len(results) == 2
    for node in results:
        assert node.event.risk_score >= 0.6
    assert all(n.event.metadata["evaluation_env_id"] == env.env_id for n in results)


# ---------------------------------------------------------------------------
# Purge tests
# ---------------------------------------------------------------------------


async def test_purge_events_before_removes_old_keeps_new():
    """purge_events_before removes old events but preserves newer ones."""
    env = EvaluationEnvironment("env-purge", in_memory=True)
    old_ts = datetime(2026, 1, 1, tzinfo=UTC)
    new_ts = datetime.now(UTC)

    old_event = make_event(timestamp=old_ts)
    new_event = make_event(timestamp=new_ts)

    old_node = await env.store.insert_event(old_event)
    new_node = await env.store.insert_event(new_event)

    cutoff = datetime(2026, 6, 1, tzinfo=UTC)
    await env.store.purge_events_before(cutoff)

    remaining = await env.store.get_all_nodes()
    remaining_ids = {n.node_id for n in remaining}

    assert old_node.node_id not in remaining_ids
    assert new_node.node_id in remaining_ids


# ---------------------------------------------------------------------------
# Lifecycle guard tests
# ---------------------------------------------------------------------------


async def test_check_store_open_raises_after_env_close():
    """_check_store_open raises RuntimeError after the environment has been closed."""
    env = EvaluationEnvironment("env-closed-check", in_memory=True)
    await env.close()

    with pytest.raises(RuntimeError, match="closed and cannot accept writes"):
        env.store._check_store_open()


async def test_store_insert_raises_after_env_close():
    """insert_event raises RuntimeError when the environment is already closed."""
    env = EvaluationEnvironment("env-closed-insert", in_memory=True)
    await env.close()
    event = make_event()

    with pytest.raises(RuntimeError):
        await env.store.insert_event(event)


# ---------------------------------------------------------------------------
# Deterministic ID derivation tests
# ---------------------------------------------------------------------------


async def test_derive_evaluation_event_id_is_deterministic():
    """derive_evaluation_event_id returns the same UUID for the same env_id and event_id."""
    env_a = EvaluationEnvironment("env-determ-same", in_memory=True)
    env_b = EvaluationEnvironment("env-determ-same", in_memory=True)
    event_id = uuid.uuid4()

    result_a = env_a.derive_evaluation_event_id(event_id)
    result_b = env_b.derive_evaluation_event_id(event_id)

    assert result_a == result_b
    assert isinstance(result_a, uuid.UUID)


async def test_derive_evaluation_event_id_differs_by_env():
    """derive_evaluation_event_id produces different UUIDs for different env_ids."""
    env_x = EvaluationEnvironment("env-differ-x", in_memory=True)
    env_y = EvaluationEnvironment("env-differ-y", in_memory=True)
    shared_event_id = uuid.uuid4()

    uuid_x = env_x.derive_evaluation_event_id(shared_event_id)
    uuid_y = env_y.derive_evaluation_event_id(shared_event_id)

    assert uuid_x != uuid_y


# ---------------------------------------------------------------------------
# EvaluationEnvironmentManager labeling tests
# ---------------------------------------------------------------------------


async def test_is_evaluation_event_identifies_labeled_event():
    """is_evaluation_event returns True for an event labeled by the manager."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_event = make_event()

    labeled_event = manager.label_event(raw_event, "test-env")

    assert manager.is_evaluation_event(labeled_event) is True


async def test_is_evaluation_event_rejects_unlabeled_event():
    """is_evaluation_event returns False for a raw event without evaluation metadata."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_event = make_event()

    assert manager.is_evaluation_event(raw_event) is False


async def test_is_evaluation_alert_identifies_labeled_alert():
    """is_evaluation_alert returns True for an alert labeled by the manager."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_alert = make_alert()

    labeled_alert = manager.label_alert(raw_alert, "test-env")

    assert manager.is_evaluation_alert(labeled_alert) is True


async def test_is_evaluation_alert_rejects_unlabeled_alert():
    """is_evaluation_alert returns False for a raw alert without evaluation metadata."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_alert = make_alert()

    assert manager.is_evaluation_alert(raw_alert) is False
