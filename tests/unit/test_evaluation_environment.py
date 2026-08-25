"""Unit tests for EvaluationEnvironmentManager lifecycle, CRUD operations, and thread-safety.

Covers: Task 2.1 requirements from .kiro/specs/blackwall-test-coverage-remediation/tasks.md
Target: EvaluationEnvironmentManager full lifecycle per REQ-4.1
"""

import asyncio
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
    agent_id: str = "mgr-test-agent",
    action: str = "execve",
    target: str = "/bin/sh",
    risk_score: float = 0.7,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """Construct a minimal valid NormalizedEvent."""
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=timestamp or datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"pid": 1234},
        risk_score=risk_score,
    )


def make_alert(
    severity: AlertSeverity = AlertSeverity.HIGH,
    threat_type: str = "test_threat",
    metadata: dict | None = None,
) -> Alert:
    """Construct a minimal valid Alert."""
    return Alert(
        severity=severity,
        threat_type=threat_type,
        title="Test Alert",
        description="Test description",
        metadata=dict(metadata) if metadata else {},
    )


# ---------------------------------------------------------------------------
# Task 2.1: EvaluationEnvironmentManager unit tests
# ---------------------------------------------------------------------------


def test_get_or_create_environment_creates_new_env():
    """get_or_create_environment creates a new EvaluationEnvironment on first call."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("mgr-create-01")

    assert env is not None
    assert isinstance(env, EvaluationEnvironment)
    assert env.env_id == "mgr-create-01"
    assert "mgr-create-01" in manager.list_environments()


def test_get_or_create_environment_idempotent_returns_same_instance():
    """Second call to get_or_create_environment returns the exact same instance."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_first = manager.get_or_create_environment("mgr-idempotent-01")
    env_second = manager.get_or_create_environment("mgr-idempotent-01")

    assert env_first is env_second
    # Only one environment should be registered
    assert manager.list_environments().count("mgr-idempotent-01") == 1


def test_get_or_create_environment_separate_instances_for_different_ids():
    """Different env IDs produce distinct EvaluationEnvironment instances."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_a = manager.get_or_create_environment("mgr-sep-a")
    env_b = manager.get_or_create_environment("mgr-sep-b")

    assert env_a is not env_b
    assert env_a.env_id != env_b.env_id


def test_list_environments_zero():
    """list_environments returns empty list when no environments have been created."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    assert manager.list_environments() == []


def test_list_environments_one():
    """list_environments returns single-element list after one environment created."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-list-one")
    envs = manager.list_environments()

    assert len(envs) == 1
    assert "mgr-list-one" in envs


def test_list_environments_five():
    """list_environments returns all five environment IDs."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    expected_ids = {f"mgr-list-env-{i}" for i in range(5)}
    for env_id in expected_ids:
        manager.get_or_create_environment(env_id)

    envs = manager.list_environments()
    assert len(envs) == 5
    assert set(envs) == expected_ids


async def test_delete_environment_removes_from_list():
    """delete_environment removes the environment from list_environments."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-del-01")
    manager.get_or_create_environment("mgr-del-02")

    assert "mgr-del-01" in manager.list_environments()
    await manager.delete_environment("mgr-del-01")

    assert "mgr-del-01" not in manager.list_environments()
    assert "mgr-del-02" in manager.list_environments()


async def test_delete_environment_nonexistent_id_is_noop():
    """delete_environment with a non-existing ID completes without raising."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-del-keep")

    # Should not raise
    await manager.delete_environment("mgr-del-nonexistent")

    # Existing environment unaffected
    assert "mgr-del-keep" in manager.list_environments()


async def test_delete_environment_returned_instance_becomes_closed():
    """After delete_environment, the previously obtained instance is closed."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("mgr-del-closed")
    await manager.delete_environment("mgr-del-closed")

    assert env._closed is True


async def test_reset_environment_clears_events_but_preserves_registration():
    """reset_environment purges graph nodes but keeps the env in list_environments."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("mgr-reset-01")

    # Insert several events
    for i in range(3):
        await env.insert_event(make_event(agent_id=f"agent-reset-{i}"))

    all_nodes_before = await env.store.get_all_nodes()
    assert len(all_nodes_before) == 3

    # Reset
    await manager.reset_environment("mgr-reset-01")

    # Nodes cleared
    all_nodes_after = await env.store.get_all_nodes()
    assert len(all_nodes_after) == 0

    # Registration preserved
    assert "mgr-reset-01" in manager.list_environments()
    assert manager.get_environment("mgr-reset-01") is env


async def test_reset_environment_nonexistent_id_is_noop():
    """reset_environment with non-existing ID completes without raising."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-reset-keep")

    # Must not raise
    await manager.reset_environment("mgr-reset-nonexistent")

    # Existing environment unaffected
    assert "mgr-reset-keep" in manager.list_environments()


async def test_close_all_makes_all_environments_unusable():
    """close_all transitions all managed environments to closed state."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_a = manager.get_or_create_environment("mgr-closeall-a")
    env_b = manager.get_or_create_environment("mgr-closeall-b")

    await manager.close_all()

    # After close_all, environments list is cleared
    assert manager.list_environments() == []

    # Closed environments reject further operations
    event = make_event()
    with pytest.raises(RuntimeError):
        await env_a.insert_event(event)

    with pytest.raises(RuntimeError):
        await env_b.insert_event(event)


async def test_reset_all_resets_state_without_closing():
    """reset_all clears all environments' graph state but does not close them."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_a = manager.get_or_create_environment("mgr-resetall-a")
    env_b = manager.get_or_create_environment("mgr-resetall-b")

    # Insert events in both environments
    await env_a.insert_event(make_event(agent_id="agent-a"))
    await env_b.insert_event(make_event(agent_id="agent-b"))

    nodes_a_before = await env_a.store.get_all_nodes()
    nodes_b_before = await env_b.store.get_all_nodes()
    assert len(nodes_a_before) == 1
    assert len(nodes_b_before) == 1

    # Reset all
    await manager.reset_all()

    # Both stores are cleared
    assert len(await env_a.store.get_all_nodes()) == 0
    assert len(await env_b.store.get_all_nodes()) == 0

    # Environments are still open (not closed)
    assert env_a._closed is False
    assert env_b._closed is False

    # Environments still in list_environments
    assert "mgr-resetall-a" in manager.list_environments()
    assert "mgr-resetall-b" in manager.list_environments()

    # Can still insert events after reset_all
    new_node = await env_a.insert_event(make_event(agent_id="agent-a-after-reset"))
    assert new_node is not None


def test_get_environment_valid_id_returns_env():
    """get_environment with a valid existing ID returns the EvaluationEnvironment."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("mgr-get-01")
    result = manager.get_environment("mgr-get-01")

    assert result is env
    assert result.env_id == "mgr-get-01"


def test_get_environment_unknown_id_returns_none():
    """get_environment returns None for a non-existent environment ID."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-get-existing")

    result = manager.get_environment("mgr-get-nonexistent")
    assert result is None


def test_get_environment_empty_string_returns_none():
    """get_environment returns None when given an empty string."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    result = manager.get_environment("")
    assert result is None


def test_get_environment_none_returns_none():
    """get_environment returns None when given None."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    result = manager.get_environment(None)  # type: ignore[arg-type]
    assert result is None


def test_get_or_create_environment_rejects_empty_id():
    """get_or_create_environment raises ValueError for empty env_id."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    with pytest.raises(ValueError):
        manager.get_or_create_environment("")


def test_get_or_create_environment_rejects_whitespace_only_id():
    """get_or_create_environment raises ValueError for whitespace-only env_id."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    with pytest.raises(ValueError):
        manager.get_or_create_environment("   ")


async def test_concurrent_get_or_create_environment_returns_same_instance():
    """Concurrent calls to get_or_create_environment with the same ID return the same instance."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env_id = "mgr-concurrent-01"

    results: list[EvaluationEnvironment] = []

    async def create_env():
        await asyncio.sleep(0)  # yield to the event loop so all 20 coroutines are
        # scheduled before any of them calls get_or_create_environment, genuinely
        # interleaving execution and stressing the idempotency check-then-insert path.
        env = manager.get_or_create_environment(env_id)
        results.append(env)

    # Spawn many concurrent coroutines
    await asyncio.gather(*[create_env() for _ in range(20)])

    # All results must be the same instance
    assert len(results) == 20
    first = results[0]
    for env in results:
        assert env is first

    # Exactly one environment registered
    assert manager.list_environments().count(env_id) == 1


async def test_get_graph_store_returns_isolated_store():
    """get_graph_store returns the EvaluationAttackGraphStore for the given env_id."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    store = manager.get_graph_store("mgr-store-01")

    assert store is not None
    # Insert event through store and verify env isolation
    event = make_event(agent_id="store-agent")
    node = await store.insert_event(event)
    assert node.event.metadata["evaluation_env_id"] == "mgr-store-01"


async def test_manager_label_event_stamps_env_id():
    """Manager.label_event stamps the event with the specified env_id."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    event = make_event()
    labeled = manager.label_event(event, "mgr-label-env")

    assert labeled.metadata["evaluation_env_id"] == "mgr-label-env"
    assert labeled.metadata["is_evaluation"] is True


async def test_manager_label_alert_stamps_env_id():
    """Manager.label_alert stamps the alert with the specified env_id."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    alert = make_alert()
    labeled = manager.label_alert(alert, "mgr-label-alert-env")

    assert labeled.metadata["evaluation_env_id"] == "mgr-label-alert-env"
    assert labeled.metadata["is_evaluation"] is True


async def test_manager_label_raw_event_stamps_dict():
    """Manager.label_raw_event stamps dict-based event with env metadata."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw = {"event_id": str(uuid.uuid4()), "metadata": {"custom": "data"}}
    labeled = manager.label_raw_event(raw, "mgr-raw-env")

    assert labeled["metadata"]["evaluation_env_id"] == "mgr-raw-env"
    assert labeled["metadata"]["is_evaluation"] is True
    assert labeled["metadata"]["custom"] == "data"


async def test_should_suppress_production_reaction_labeled_event():
    """should_suppress_production_reaction returns True for labeled NormalizedEvent."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    event = make_event()
    labeled = manager.label_event(event, "mgr-suppress-env")
    assert manager.should_suppress_production_reaction(labeled) is True


async def test_should_suppress_production_reaction_labeled_alert():
    """should_suppress_production_reaction returns True for labeled Alert."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    alert = make_alert()
    labeled = manager.label_alert(alert, "mgr-suppress-alert-env")
    assert manager.should_suppress_production_reaction(labeled) is True


async def test_should_suppress_production_reaction_unlabeled_event_false():
    """should_suppress_production_reaction returns False for unlabeled event."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    raw_event = make_event()
    assert manager.should_suppress_production_reaction(raw_event) is False


async def test_is_evaluation_mode_returns_true_for_inserted_event():
    """is_evaluation_mode returns True for a node inserted into an eval environment."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment("mgr-eval-mode-01")

    event = make_event()
    node = await env.insert_event(event)

    result = await manager.is_evaluation_mode(node.node_id)
    assert result is True


async def test_is_evaluation_mode_returns_false_for_unknown_id():
    """is_evaluation_mode returns False for a random UUID not in any eval environment."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    manager.get_or_create_environment("mgr-eval-mode-miss")

    result = await manager.is_evaluation_mode(uuid.uuid4())
    assert result is False


async def test_is_evaluation_mode_returns_false_for_invalid_string():
    """is_evaluation_mode returns False for a non-UUID string."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    result = await manager.is_evaluation_mode("not-a-uuid")
    assert result is False
