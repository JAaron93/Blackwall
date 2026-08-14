"""Hypothesis Property-Based Tests for Evaluation Environment Support (Pillar 6 Task 18.4).

Properties tested:
- Property 69: Evaluation Mode Event Labeling (Requirement 14.1)
- Property 70: Evaluation Mode Alert Isolation (Requirement 14.2)
- Property 71: Evaluation Environment Graph Isolation (Requirement 14.3)
- Property 72: Evaluation State Reset (Requirement 14.4)
"""

import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.enterprise.advanced_threat_detection import (
    Alert,
    AlertSeverity,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
)

# Custom Hypothesis strategies
valid_env_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{3,20}", fullmatch=True)
invalid_env_id_strategy = st.sampled_from(["", "   ", "\t", "\n", "  \n  "])
valid_agent_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{3,15}", fullmatch=True)
valid_action_strategy = st.sampled_from(
    ["execve", "read_token", "curl", "connect", "spawn_pod", "chmod", "eval_action"]
)
valid_target_strategy = st.from_regex(r"[a-zA-Z0-9_./:-]{3,25}", fullmatch=True)
valid_risk_score_strategy = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


def create_property_event(
    agent_id: str,
    action: str,
    target: str,
    risk_score: float,
) -> NormalizedEvent:
    """Helper to construct a valid NormalizedEvent for property testing."""
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        risk_score=risk_score,
    )


# ============================================================================
# Property 69: Evaluation Mode Event Labeling (Requirement 14.1)
# ============================================================================


@settings(max_examples=100)
@given(
    env_id=valid_env_id_strategy,
    agent_id=valid_agent_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk_score=valid_risk_score_strategy,
)
def test_property_69_eval_mode_event_labeling_valid_acceptance(
    env_id: str,
    agent_id: str,
    action: str,
    target: str,
    risk_score: float,
):
    """Property 69: For any event processed in eval mode, an evaluation env ID must be stamped in metadata."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    event = create_property_event(agent_id, action, target, risk_score)

    labeled = manager.label_event(event, env_id)
    assert labeled.metadata["evaluation_env_id"] == env_id
    assert labeled.metadata["is_evaluation"] is True
    assert labeled.metadata["eval_mode"] is True
    assert manager.is_evaluation_event(labeled) is True
    assert manager.should_suppress_production_reaction(labeled) is True


@settings(max_examples=100)
@given(
    invalid_env_id=invalid_env_id_strategy,
    agent_id=valid_agent_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk_score=valid_risk_score_strategy,
)
def test_property_69_eval_mode_event_labeling_rejection(
    invalid_env_id: str,
    agent_id: str,
    action: str,
    target: str,
    risk_score: float,
):
    """Property 69 Rejection: Empty or whitespace-only evaluation env IDs must raise ValueError."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    event = create_property_event(agent_id, action, target, risk_score)

    with pytest.raises(ValueError):
        manager.label_event(event, invalid_env_id)

    with pytest.raises(ValueError):
        manager.label_raw_event({"action": action}, invalid_env_id)


# ============================================================================
# Property 70: Evaluation Mode Alert Isolation (Requirement 14.2)
# ============================================================================


@settings(max_examples=100)
@given(
    env_id=valid_env_id_strategy,
    threat_type=st.from_regex(r"[a-zA-Z0-9_-]{3,20}", fullmatch=True),
    title=st.from_regex(r"[a-zA-Z0-9_ -]{3,30}", fullmatch=True),
    description=st.from_regex(r"[a-zA-Z0-9_ -]{3,50}", fullmatch=True),
    severity=st.sampled_from(list(AlertSeverity)),
)
def test_property_70_eval_mode_alert_isolation_valid_acceptance(
    env_id: str,
    threat_type: str,
    title: str,
    description: str,
    severity: AlertSeverity,
):
    """Property 70: For any alert generated in eval mode, it must be suppressed from production workflows."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    alert = Alert(
        severity=severity,
        threat_type=threat_type,
        title=title,
        description=description,
        evidence_id=uuid.uuid4(),
    )

    labeled_alert = manager.label_alert(alert, env_id)
    assert labeled_alert.metadata["evaluation_env_id"] == env_id
    assert labeled_alert.metadata["is_evaluation"] is True
    assert manager.is_evaluation_alert(labeled_alert) is True
    assert manager.should_suppress_production_reaction(labeled_alert) is True


@settings(max_examples=100)
@given(
    threat_type=st.from_regex(r"[a-zA-Z0-9_-]{3,20}", fullmatch=True),
    title=st.from_regex(r"[a-zA-Z0-9_ -]{3,30}", fullmatch=True),
    description=st.from_regex(r"[a-zA-Z0-9_ -]{3,50}", fullmatch=True),
    severity=st.sampled_from(list(AlertSeverity)),
)
def test_property_70_eval_mode_alert_isolation_rejection(
    threat_type: str,
    title: str,
    description: str,
    severity: AlertSeverity,
):
    """Property 70 Rejection: Non-evaluation alerts must not be suppressed from production workflows."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    unlabeled_alert = Alert(
        severity=severity,
        threat_type=threat_type,
        title=title,
        description=description,
    )
    assert manager.is_evaluation_alert(unlabeled_alert) is False
    assert manager.should_suppress_production_reaction(unlabeled_alert) is False


# ============================================================================
# Property 71: Evaluation Environment Graph Isolation (Requirement 14.3)
# ============================================================================


@settings(max_examples=100)
@given(
    env_id_1=st.from_regex(r"alpha-[a-z0-9]{3,8}", fullmatch=True),
    env_id_2=st.from_regex(r"beta-[a-z0-9]{3,8}", fullmatch=True),
    agent_id_1=valid_agent_id_strategy,
    agent_id_2=valid_agent_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk_score=valid_risk_score_strategy,
)
@pytest.mark.asyncio
async def test_property_71_evaluation_environment_graph_isolation(
    env_id_1: str,
    env_id_2: str,
    agent_id_1: str,
    agent_id_2: str,
    action: str,
    target: str,
    risk_score: float,
):
    """Property 71: Graph instances across distinct evaluation environments must be strictly isolated."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env1 = manager.get_or_create_environment(env_id_1)
    env2 = manager.get_or_create_environment(env_id_2)

    ev1 = create_property_event(agent_id_1, action, target, risk_score)
    ev2 = create_property_event(agent_id_2, action, target, risk_score)

    node1 = await env1.insert_event(ev1)
    node2 = await env2.insert_event(ev2)

    # env1 store has node1 and NOT node2
    assert await env1.store.get_node(node1.node_id) is not None
    assert await env1.store.get_node(node2.node_id) is None

    # env2 store has node2 and NOT node1
    assert await env2.store.get_node(node2.node_id) is not None
    assert await env2.store.get_node(node1.node_id) is None

    # Node count in each isolated store is exactly 1
    assert len(await env1.store.get_all_nodes()) == 1
    assert len(await env2.store.get_all_nodes()) == 1


# ============================================================================
# Property 72: Evaluation State Reset (Requirement 14.4)
# ============================================================================


@settings(max_examples=100)
@given(
    env_id=valid_env_id_strategy,
    other_env_id=st.from_regex(r"other-[a-z0-9]{3,8}", fullmatch=True),
    event_count=st.integers(min_value=1, max_value=5),
    agent_id=valid_agent_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk_score=valid_risk_score_strategy,
)
@pytest.mark.asyncio
async def test_property_72_evaluation_state_reset(
    env_id: str,
    other_env_id: str,
    event_count: int,
    agent_id: str,
    action: str,
    target: str,
    risk_score: float,
):
    """Property 72: Resetting an evaluation environment returns its state to clean baseline while isolating others."""
    manager = EvaluationEnvironmentManager(in_memory=True)
    env = manager.get_or_create_environment(env_id)
    other_env = manager.get_or_create_environment(other_env_id)

    # Insert events into target environment
    events = [
        create_property_event(f"{agent_id}-{i}", action, target, risk_score)
        for i in range(event_count)
    ]
    await env.insert_events_batch(events)

    # Insert one event into other environment
    other_ev = create_property_event(agent_id, action, target, risk_score)
    await other_env.insert_event(other_ev)

    assert len(await env.store.get_all_nodes()) == event_count
    assert len(await other_env.store.get_all_nodes()) == 1

    # Reset target environment
    await manager.reset_environment(env_id)

    # Target environment is clean
    assert len(await env.store.get_all_nodes()) == 0
    assert len(env.alert_bus.get_alerts()) == 0

    # Other environment remains completely intact
    assert len(await other_env.store.get_all_nodes()) == 1
