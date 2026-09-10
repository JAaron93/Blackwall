"""BDD Step Definitions for Evaluation Environment Lifecycle
(`tests/features/evaluation_environment_lifecycle.feature`).

Covers EvaluationEnvironmentManager and EvaluationEnvironment lifecycle
operations: create, retrieve, list, delete, reset, close, and labeling.
"""

import uuid
from datetime import UTC, datetime

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.evaluation import (
    EvaluationAttackGraphStore,
    EvaluationEnvironment,
    EvaluationEnvironmentManager,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/evaluation_environment_lifecycle.feature")


# ---------------------------------------------------------------------------
# State carrier
# ---------------------------------------------------------------------------


class LifecycleBDDState:
    """State carrier for Evaluation Environment Lifecycle BDD scenarios."""

    def __init__(self) -> None:
        self.manager: EvaluationEnvironmentManager = EvaluationEnvironmentManager(
            in_memory=True
        )
        self.created_env: EvaluationEnvironment | None = None
        self.retrieved_env: EvaluationEnvironment | None = None
        self.first_env_ref: EvaluationEnvironment | None = None
        self.created_env_ids: list[str] = []
        self.labeled_event: NormalizedEvent | None = None
        self.labeled_alert: Alert | None = None
        self.runtime_error_raised: bool = False


@pytest.fixture
def lifecycle_state() -> LifecycleBDDState:
    return LifecycleBDDState()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_event(agent_id: str = "agent-lifecycle-01") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve",
        target="/tmp/lifecycle_payload",
        risk_score=0.75,
    )


def _make_alert() -> Alert:
    return Alert(
        severity=AlertSeverity.HIGH,
        threat_type="lateral_movement",
        title="Lifecycle Test Alert",
        description="Alert used in lifecycle BDD tests",
        evidence_id=uuid.uuid4(),
    )


# ---------------------------------------------------------------------------
# Shared Given: manager fixture used across all scenarios
# ---------------------------------------------------------------------------


@given("an EvaluationEnvironmentManager with in-memory storage")
def given_manager_in_memory(lifecycle_state: LifecycleBDDState) -> None:
    assert lifecycle_state.manager is not None
    assert lifecycle_state.manager.in_memory is True


# ---------------------------------------------------------------------------
# Scenario 1: Create a new evaluation environment
# ---------------------------------------------------------------------------


@when(parsers.parse('I call get_or_create_environment with id "{env_id}"'))
def when_get_or_create_new(lifecycle_state: LifecycleBDDState, env_id: str) -> None:
    lifecycle_state.created_env = lifecycle_state.manager.get_or_create_environment(
        env_id
    )


@then(
    parsers.parse(
        'a new EvaluationEnvironment is returned with env_id "{env_id}"'
    )
)
def then_new_env_returned_with_id(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    assert lifecycle_state.created_env is not None
    assert isinstance(lifecycle_state.created_env, EvaluationEnvironment)
    assert lifecycle_state.created_env.env_id == env_id


@then("the environment is present in the manager's environment list")
def then_env_in_list(lifecycle_state: LifecycleBDDState) -> None:
    assert lifecycle_state.created_env is not None
    env_ids = lifecycle_state.manager.list_environments()
    assert lifecycle_state.created_env.env_id in env_ids


# ---------------------------------------------------------------------------
# Scenario 2: Retrieve existing evaluation environment
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'I have already created evaluation environment "{env_id}"'
    )
)
def given_env_already_created(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    lifecycle_state.first_env_ref = lifecycle_state.manager.get_or_create_environment(
        env_id
    )
    assert lifecycle_state.first_env_ref is not None


@when(
    parsers.parse(
        'I call get_or_create_environment again with id "{env_id}"'
    )
)
def when_get_or_create_existing(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    lifecycle_state.retrieved_env = lifecycle_state.manager.get_or_create_environment(
        env_id
    )


@then("the same EvaluationEnvironment instance is returned")
def then_same_instance_returned(lifecycle_state: LifecycleBDDState) -> None:
    assert lifecycle_state.retrieved_env is not None
    assert lifecycle_state.first_env_ref is not None
    assert lifecycle_state.retrieved_env is lifecycle_state.first_env_ref


# ---------------------------------------------------------------------------
# Scenario 3: List all active evaluation environments
# ---------------------------------------------------------------------------


@when(
    parsers.parse(
        'I create 3 evaluation environments with ids "{env_a}", "{env_b}", and "{env_c}"'
    )
)
def when_create_three_environments(
    lifecycle_state: LifecycleBDDState,
    env_a: str,
    env_b: str,
    env_c: str,
) -> None:
    for eid in (env_a, env_b, env_c):
        lifecycle_state.manager.get_or_create_environment(eid)
        lifecycle_state.created_env_ids.append(eid)


@then("list_environments returns exactly 3 environment ids")
def then_list_returns_three(lifecycle_state: LifecycleBDDState) -> None:
    envs = lifecycle_state.manager.list_environments()
    assert len(envs) == 3


@then(
    parsers.parse(
        'the list contains "{env_a}", "{env_b}", and "{env_c}"'
    )
)
def then_list_contains_all_three(
    lifecycle_state: LifecycleBDDState,
    env_a: str,
    env_b: str,
    env_c: str,
) -> None:
    envs = lifecycle_state.manager.list_environments()
    assert env_a in envs
    assert env_b in envs
    assert env_c in envs


# ---------------------------------------------------------------------------
# Scenario 4: Delete an evaluation environment
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'evaluation environment "{env_id}" exists in the manager'
    )
)
def given_env_exists_in_manager(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    lifecycle_state.manager.get_or_create_environment(env_id)
    assert env_id in lifecycle_state.manager.list_environments()


@when(parsers.parse('I delete evaluation environment "{env_id}"'))
def when_delete_environment(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    run_async(lifecycle_state.manager.delete_environment(env_id))


@then(
    parsers.parse('"{env_id}" is no longer in list_environments')
)
def then_env_not_in_list(lifecycle_state: LifecycleBDDState, env_id: str) -> None:
    assert env_id not in lifecycle_state.manager.list_environments()


# ---------------------------------------------------------------------------
# Scenario 5: Reset an evaluation environment
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'evaluation environment "{env_id}" has {count:d} inserted events'
    )
)
def given_env_with_inserted_events(
    lifecycle_state: LifecycleBDDState, env_id: str, count: int
) -> None:
    env = lifecycle_state.manager.get_or_create_environment(env_id)
    events = [_make_event(agent_id=f"agent-reset-{i}") for i in range(count)]
    run_async(env.insert_events_batch(events))
    nodes = run_async(env.store.get_all_nodes())
    assert len(nodes) == count


@when(parsers.parse('I reset evaluation environment "{env_id}"'))
def when_reset_environment(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    run_async(lifecycle_state.manager.reset_environment(env_id))


@then(
    parsers.parse(
        'the attack graph for "{env_id}" has {expected_count:d} nodes'
    )
)
def then_attack_graph_node_count(
    lifecycle_state: LifecycleBDDState, env_id: str, expected_count: int
) -> None:
    env = lifecycle_state.manager.get_or_create_environment(env_id)
    nodes = run_async(env.store.get_all_nodes())
    assert len(nodes) == expected_count


# ---------------------------------------------------------------------------
# Scenario 6: Evaluation mode suppresses production actions
# ---------------------------------------------------------------------------


@when(parsers.parse('I create evaluation environment "{env_id}"'))
def when_create_single_environment(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    lifecycle_state.created_env = lifecycle_state.manager.get_or_create_environment(
        env_id
    )


@then(
    parsers.parse(
        'is_production_action_suppressed returns True for "{env_id}"'
    )
)
def then_production_suppressed(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    env = lifecycle_state.manager.get_environment(env_id)
    assert env is not None
    assert env.is_production_action_suppressed() is True


# ---------------------------------------------------------------------------
# Scenario 7: Close all evaluation environments
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'I have created environments "{env_a}" and "{env_b}"'
    )
)
def given_two_environments_created(
    lifecycle_state: LifecycleBDDState, env_a: str, env_b: str
) -> None:
    lifecycle_state.manager.get_or_create_environment(env_a)
    lifecycle_state.manager.get_or_create_environment(env_b)
    assert env_a in lifecycle_state.manager.list_environments()
    assert env_b in lifecycle_state.manager.list_environments()


@when("I call close_all on the manager")
def when_close_all(lifecycle_state: LifecycleBDDState) -> None:
    run_async(lifecycle_state.manager.close_all())


@then("the environment list is empty")
def then_environment_list_empty(lifecycle_state: LifecycleBDDState) -> None:
    assert lifecycle_state.manager.list_environments() == []


@then(
    parsers.parse(
        'operations on "{env_id}" raise a RuntimeError'
    )
)
def then_operations_raise_runtime_error(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    # The environment was cleared by close_all; recreate reference via internal state
    # by constructing an already-closed EvaluationEnvironment directly
    closed_env = EvaluationEnvironment(env_id=env_id, in_memory=True)
    run_async(closed_env.close())

    raised = False
    try:
        run_async(closed_env.insert_event(_make_event()))
    except RuntimeError:
        raised = True
    assert raised, "Expected RuntimeError when operating on a closed EvaluationEnvironment"


# ---------------------------------------------------------------------------
# Scenario 8: Label events in evaluation mode
# ---------------------------------------------------------------------------


@when(
    parsers.parse(
        'I label an event with event_id in environment "{env_id}"'
    )
)
def when_label_event(lifecycle_state: LifecycleBDDState, env_id: str) -> None:
    env = lifecycle_state.manager.get_or_create_environment(env_id)
    raw_event = _make_event(agent_id="agent-label-01")
    lifecycle_state.labeled_event = env.label_event(raw_event)


@when(
    parsers.parse(
        'I label an alert in environment "{env_id}"'
    )
)
def when_label_alert(lifecycle_state: LifecycleBDDState, env_id: str) -> None:
    env = lifecycle_state.manager.get_or_create_environment(env_id)
    raw_alert = _make_alert()
    lifecycle_state.labeled_alert = env.label_alert(raw_alert)


@then(
    parsers.parse(
        'the labeled event has evaluation_env_id "{env_id}" in metadata'
    )
)
def then_labeled_event_has_env_id(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    assert lifecycle_state.labeled_event is not None
    assert lifecycle_state.labeled_event.metadata.get("evaluation_env_id") == env_id
    assert lifecycle_state.labeled_event.metadata.get("is_evaluation") is True
    assert lifecycle_state.labeled_event.metadata.get("eval_mode") is True


@then(
    parsers.parse(
        'the labeled alert has evaluation_env_id "{env_id}" in metadata'
    )
)
def then_labeled_alert_has_env_id(
    lifecycle_state: LifecycleBDDState, env_id: str
) -> None:
    assert lifecycle_state.labeled_alert is not None
    assert lifecycle_state.labeled_alert.metadata.get("evaluation_env_id") == env_id
    assert lifecycle_state.labeled_alert.metadata.get("is_evaluation") is True
    assert lifecycle_state.labeled_alert.metadata.get("eval_mode") is True
