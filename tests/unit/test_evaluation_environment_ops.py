"""Unit tests for EvaluationEnvironment operations: labeling, suppression, reset, and close lifecycle.

Covers: Tasks 2.3 requirements from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
"""

import uuid
from datetime import UTC, datetime

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    Alert,
    AlertSeverity,
    EvaluationEnvironment,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(
    event_id: uuid.UUID | None = None,
    agent_id: str = "test-agent",
    action: str = "execve",
    target: str = "/bin/sh",
    risk_score: float = 0.8,
    metadata: dict | None = None,
) -> NormalizedEvent:
    """Create a minimal valid NormalizedEvent for use in tests."""
    return NormalizedEvent(
        event_id=event_id or uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=dict(metadata) if metadata else {"pid": 1},
        risk_score=risk_score,
    )


def make_alert(
    severity: AlertSeverity = AlertSeverity.HIGH,
    threat_type: str = "test_threat",
    title: str = "Test Alert",
    description: str = "Test description",
    metadata: dict | None = None,
) -> Alert:
    """Create a minimal valid Alert for use in tests."""
    return Alert(
        severity=severity,
        threat_type=threat_type,
        title=title,
        description=description,
        metadata=dict(metadata) if metadata else {},
    )


# ---------------------------------------------------------------------------
# 1. is_production_action_suppressed
# ---------------------------------------------------------------------------


def test_is_production_action_suppressed_always_returns_true():
    """EvaluationEnvironment.is_production_action_suppressed() must always return True."""
    env = EvaluationEnvironment("ops-env-1", in_memory=True)
    assert env.is_production_action_suppressed() is True


# ---------------------------------------------------------------------------
# 2. is_evaluation_mode via manager
# ---------------------------------------------------------------------------


async def test_is_evaluation_mode_via_manager_returns_true_for_eval_node():
    """Manager.is_evaluation_mode returns True for a node inserted into an eval env."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("eval-mode-env")

    event = make_event()
    node = await env.insert_event(event)

    result = await manager.is_evaluation_mode(node.node_id)
    assert result is True


# ---------------------------------------------------------------------------
# 3-8. should_suppress_production_reaction
# ---------------------------------------------------------------------------


def test_should_suppress_production_reaction_for_labeled_alert():
    """should_suppress_production_reaction returns True for a labeled Alert."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_alert = make_alert()
    labeled_alert = manager.label_alert(raw_alert, "test-env")
    assert manager.should_suppress_production_reaction(labeled_alert) is True


def test_should_suppress_production_reaction_for_labeled_event():
    """should_suppress_production_reaction returns True for a labeled NormalizedEvent."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_event = make_event()
    labeled_event = manager.label_event(raw_event, "test-env")
    assert manager.should_suppress_production_reaction(labeled_event) is True


def test_should_suppress_production_reaction_for_labeled_dict_event():
    """should_suppress_production_reaction returns True for a labeled dict event."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_dict = {"event_id": str(uuid.uuid4()), "metadata": {}}
    labeled_dict = manager.label_raw_event(raw_dict, "test-env")
    assert manager.should_suppress_production_reaction(labeled_dict) is True


def test_should_suppress_production_reaction_false_for_unlabeled_alert():
    """should_suppress_production_reaction returns False for an unlabeled Alert."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_alert = make_alert()
    assert manager.should_suppress_production_reaction(raw_alert) is False


def test_should_suppress_production_reaction_false_for_unlabeled_event():
    """should_suppress_production_reaction returns False for an unlabeled NormalizedEvent."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_event = make_event()
    assert manager.should_suppress_production_reaction(raw_event) is False


def test_should_suppress_production_reaction_false_for_none():
    """should_suppress_production_reaction returns False when passed None."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    assert manager.should_suppress_production_reaction(None) is False


# ---------------------------------------------------------------------------
# 9-11. label_event
# ---------------------------------------------------------------------------


def test_label_event_attaches_evaluation_env_id():
    """label_event stamps metadata with evaluation_env_id and is_evaluation=True."""
    env = EvaluationEnvironment("label-env", in_memory=True)
    raw_event = make_event()
    result = env.label_event(raw_event)
    assert result.metadata["evaluation_env_id"] == "label-env"
    assert result.metadata["is_evaluation"] is True


def test_label_event_sets_original_event_id():
    """label_event preserves the original event_id in metadata under original_event_id."""
    env = EvaluationEnvironment("label-env", in_memory=True)
    event = make_event()
    result = env.label_event(event)
    assert result.metadata["original_event_id"] == str(event.event_id)


def test_label_event_changes_event_id_to_derived():
    """label_event replaces event_id with a deterministically derived UUID."""
    env = EvaluationEnvironment("label-env", in_memory=True)
    event = make_event()
    result = env.label_event(event)
    assert result.event_id != event.event_id


# ---------------------------------------------------------------------------
# 12. label_alert
# ---------------------------------------------------------------------------


def test_label_alert_attaches_evaluation_env_id():
    """label_alert stamps metadata with evaluation_env_id and is_evaluation=True."""
    env = EvaluationEnvironment("label-env", in_memory=True)
    alert = make_alert()
    result = env.label_alert(alert)
    assert result.metadata["evaluation_env_id"] == env.env_id
    assert result.metadata["is_evaluation"] is True


# ---------------------------------------------------------------------------
# 13-14. label_raw_event
# ---------------------------------------------------------------------------


def test_label_raw_event_stamps_dict_metadata():
    """label_raw_event stamps dict with evaluation metadata while preserving existing keys."""
    env = EvaluationEnvironment("raw-label-env", in_memory=True)
    raw_dict = {"event_id": str(uuid.uuid4()), "metadata": {"key": "value"}}
    result = env.label_raw_event(raw_dict)
    assert result["metadata"]["evaluation_env_id"] == env.env_id
    assert result["metadata"]["is_evaluation"] is True
    assert result["metadata"]["key"] == "value"


def test_label_raw_event_without_existing_metadata():
    """label_raw_event creates a metadata dict and stamps it even if no 'metadata' key existed."""
    env = EvaluationEnvironment("raw-label-env-2", in_memory=True)
    raw_dict = {"event_id": str(uuid.uuid4())}
    result = env.label_raw_event(raw_dict)
    assert result["metadata"]["evaluation_env_id"] == env.env_id


# ---------------------------------------------------------------------------
# 15-18. reset
# ---------------------------------------------------------------------------


async def test_reset_clears_store_nodes():
    """reset() removes all nodes from the in-memory store."""
    env = EvaluationEnvironment("reset-env-1", in_memory=True)
    events = [make_event() for _ in range(3)]
    for ev in events:
        await env.insert_event(ev)
    assert len(env.store._nodes) == 3

    await env.reset()
    assert len(env.store._nodes) == 0


async def test_reset_clears_store_edges():
    """reset() removes all edges from the in-memory store."""
    env = EvaluationEnvironment("reset-env-2", in_memory=True)
    ev1 = make_event()
    ev2 = make_event()
    node1 = await env.insert_event(ev1)
    node2 = await env.insert_event(ev2)
    await env.store.link_events(node1.node_id, node2.node_id)
    assert len(env.store._edges) > 0

    await env.reset()
    assert len(env.store._edges) == 0


async def test_reset_clears_path_cache():
    """reset() empties the path cache."""
    env = EvaluationEnvironment("reset-env-3", in_memory=True)
    ev1 = make_event()
    ev2 = make_event()
    await env.insert_event(ev1)
    await env.insert_event(ev2)
    # Directly inject a sentinel entry into the path cache to verify reset clears it.
    sentinel_key = ("test-agent", datetime.now(UTC), datetime.now(UTC), 100)
    env.store._path_cache[sentinel_key] = []
    assert len(env.store._path_cache) > 0

    await env.reset()
    assert len(env.store._path_cache) == 0


async def test_reset_preserves_env_open_state():
    """reset() does not close the environment; _closed remains False."""
    env = EvaluationEnvironment("reset-env-4", in_memory=True)
    await env.reset()
    assert env._closed is False


# ---------------------------------------------------------------------------
# 19-24. close lifecycle
# ---------------------------------------------------------------------------


async def test_close_makes_insert_event_raise_runtime_error():
    """insert_event raises RuntimeError after close()."""
    env = EvaluationEnvironment("close-env-1", in_memory=True)
    await env.close()
    event = make_event()
    with pytest.raises(RuntimeError):
        await env.insert_event(event)


async def test_close_makes_insert_events_batch_raise_runtime_error():
    """insert_events_batch raises RuntimeError after close()."""
    env = EvaluationEnvironment("close-env-2", in_memory=True)
    await env.close()
    events = [make_event()]
    with pytest.raises(RuntimeError):
        await env.insert_events_batch(events)


async def test_close_makes_reset_raise_runtime_error():
    """reset() raises RuntimeError after close()."""
    env = EvaluationEnvironment("close-env-3", in_memory=True)
    await env.close()
    with pytest.raises(RuntimeError):
        await env.reset()


async def test_close_makes_get_node_raise_runtime_error():
    """get_node raises RuntimeError after close()."""
    env = EvaluationEnvironment("close-env-4", in_memory=True)
    await env.close()
    with pytest.raises(RuntimeError):
        await env.get_node(uuid.uuid4())


async def test_close_makes_publish_alert_raise_runtime_error():
    """publish_alert raises RuntimeError after close()."""
    env = EvaluationEnvironment("close-env-5", in_memory=True)
    await env.close()
    alert = make_alert()
    with pytest.raises(RuntimeError):
        await env.publish_alert(alert)


async def test_close_sets_closed_flag():
    """close() sets _closed to True."""
    env = EvaluationEnvironment("close-env-6", in_memory=True)
    assert env._closed is False
    await env.close()
    assert env._closed is True
