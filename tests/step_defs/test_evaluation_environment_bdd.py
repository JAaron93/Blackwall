"""BDD Step Definitions for Evaluation Environment Support (`tests/features/evaluation_environment.feature`)."""

import uuid
from datetime import UTC, datetime

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    Alert,
    AlertSeverity,
    AttackGraphStore,
    AttackNode,
    EvaluationEnvironmentManager,
    EventSource,
    NormalizedEvent,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/evaluation_environment.feature")


class EvaluationBDDState:
    """State carrier for Evaluation Environment BDD scenarios."""

    def __init__(self) -> None:
        self.manager = EvaluationEnvironmentManager(in_memory=True)
        self.prod_store = AttackGraphStore(in_memory=True)
        self.active_event: NormalizedEvent | None = None
        self.labeled_event: NormalizedEvent | None = None
        self.active_alert: Alert | None = None
        self.labeled_alert: Alert | None = None
        self.suppressed: bool | None = None
        self.env_nodes: dict[str, list[AttackNode]] = {}


@pytest.fixture
def eval_state() -> EvaluationBDDState:
    state = EvaluationBDDState()
    run_async(state.prod_store.initialize())
    return state


# ---------------------------------------------------------------------------
# Scenario 1: events in evaluation mode carry eval environment identifier
# ---------------------------------------------------------------------------


@given("an EvaluationEnvironmentManager initialized with evaluation mode active")
def given_eval_manager_active(eval_state: EvaluationBDDState) -> None:
    assert eval_state.manager is not None
    assert eval_state.manager.in_memory is True


@when(
    parsers.parse(
        'a security event is processed in evaluation environment "{env_id}"'
    )
)
def when_process_event_in_eval_env(
    eval_state: EvaluationBDDState, env_id: str
) -> None:
    raw_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="eval-agent-01",
        action="execve",
        target="/tmp/eval_payload",
        risk_score=0.85,
    )
    eval_state.active_event = raw_event
    env = eval_state.manager.get_or_create_environment(env_id)
    node = run_async(env.insert_event(raw_event))
    eval_state.labeled_event = node.event


@then(
    parsers.parse(
        'the normalized event metadata contains "evaluation_env_id" with value "{env_id}"'
    )
)
def then_event_metadata_contains_env_id(
    eval_state: EvaluationBDDState, env_id: str
) -> None:
    assert eval_state.labeled_event is not None
    assert eval_state.labeled_event.metadata.get("evaluation_env_id") == env_id


@then("the normalized event is flagged as an evaluation event")
def then_event_flagged_as_eval(eval_state: EvaluationBDDState) -> None:
    assert eval_state.labeled_event is not None
    assert eval_state.labeled_event.metadata.get("is_evaluation") is True
    assert eval_state.manager.is_evaluation_event(eval_state.labeled_event) is True


# ---------------------------------------------------------------------------
# Scenario 2: alerts generated in evaluation mode do not trigger production response
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'an alert generated from an attack detection within evaluation environment "{env_id}"'
    )
)
def given_alert_in_eval_env(eval_state: EvaluationBDDState, env_id: str) -> None:
    raw_alert = Alert(
        severity=AlertSeverity.CRITICAL,
        threat_type="agent_swarm",
        title="Detected Swarm Coordination",
        description="Coordinated swarm behavior identified during eval",
        evidence_id=uuid.uuid4(),
    )
    env = eval_state.manager.get_or_create_environment(env_id)
    eval_state.active_alert = raw_alert
    eval_state.labeled_alert = env.label_alert(raw_alert)


@when("the AlertBus evaluates production containment rules for the alert")
def when_alertbus_evaluates_containment(eval_state: EvaluationBDDState) -> None:
    assert eval_state.labeled_alert is not None
    eval_state.suppressed = eval_state.manager.should_suppress_production_reaction(
        eval_state.labeled_alert
    )


@then("the alert is marked as an evaluation alert")
def then_alert_marked_eval(eval_state: EvaluationBDDState) -> None:
    assert eval_state.labeled_alert is not None
    assert eval_state.manager.is_evaluation_alert(eval_state.labeled_alert) is True


@then("production mitigation and incident response workflows are suppressed")
def then_workflows_suppressed(eval_state: EvaluationBDDState) -> None:
    assert eval_state.suppressed is True


# ---------------------------------------------------------------------------
# Scenario 3: two evaluation environments use isolated attack graph instances
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'two separate evaluation environments "{env_a}" and "{env_b}"'
    )
)
def given_two_eval_environments(
    eval_state: EvaluationBDDState, env_a: str, env_b: str
) -> None:
    env1 = eval_state.manager.get_or_create_environment(env_a)
    env2 = eval_state.manager.get_or_create_environment(env_b)
    assert env1.store is not env2.store
    eval_state.env_nodes[env_a] = []
    eval_state.env_nodes[env_b] = []


@when(
    parsers.parse(
        '"{env_id}" ingests an attack path event for agent "{agent_id}"'
    )
)
def when_env_ingests_event(
    eval_state: EvaluationBDDState, env_id: str, agent_id: str
) -> None:
    env = eval_state.manager.get_or_create_environment(env_id)
    ev = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.PIPELINE_EXECUTION,
        agent_id=agent_id,
        action="pickle_load",
        target="s3://data/weights.pkl",
        risk_score=0.9,
    )
    node = run_async(env.insert_event(ev))
    eval_state.env_nodes[env_id].append(node)


@then(
    parsers.parse(
        'the attack graph for "{env_id}" contains only events from "{expected_env}"'
    )
)
def then_attack_graph_scoped(
    eval_state: EvaluationBDDState, env_id: str, expected_env: str
) -> None:
    env = eval_state.manager.get_or_create_environment(env_id)
    nodes = run_async(env.store.get_all_nodes())
    assert len(nodes) == len(eval_state.env_nodes[expected_env])
    for n in nodes:
        assert n.event.metadata.get("evaluation_env_id") == expected_env


@then("neither evaluation environment shares nodes with each other or production")
def then_no_shared_nodes(eval_state: EvaluationBDDState) -> None:
    envs = list(eval_state.env_nodes.keys())
    assert len(envs) >= 2
    env_a, env_b = envs[0], envs[1]

    nodes_a = run_async(
        eval_state.manager.get_environment(env_a).store.get_all_nodes()
    )
    nodes_b = run_async(
        eval_state.manager.get_environment(env_b).store.get_all_nodes()
    )
    nodes_prod = run_async(eval_state.prod_store.get_all_nodes())

    ids_a = {n.node_id for n in nodes_a}
    ids_b = {n.node_id for n in nodes_b}
    ids_prod = {n.node_id for n in nodes_prod}

    assert ids_a.isdisjoint(ids_b)
    assert ids_a.isdisjoint(ids_prod)
    assert ids_b.isdisjoint(ids_prod)


# ---------------------------------------------------------------------------
# Scenario 4: resetting evaluation state returns clean initial state
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'an evaluation environment "{env_id}" with {count:d} ingested attack events'
    )
)
def given_env_with_events(
    eval_state: EvaluationBDDState, env_id: str, count: int
) -> None:
    env = eval_state.manager.get_or_create_environment(env_id)
    events = [
        NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            source=EventSource.IDENTITY_ACCESS,
            agent_id=f"agent-{i}",
            action="request_token",
            target="vault://secrets/db",
            risk_score=0.75,
        )
        for i in range(count)
    ]
    run_async(env.insert_events_batch(events))

    alert = Alert(
        severity=AlertSeverity.HIGH,
        threat_type="credential_access",
        title="Eval Alert",
        description="Eval Alert Description",
    )
    run_async(env.publish_alert(alert))

    assert len(run_async(env.store.get_all_nodes())) == count
    assert len(env.alert_bus.get_alerts()) == 1


@when(
    parsers.parse('the evaluation environment "{env_id}" is reset')
)
def when_env_reset(eval_state: EvaluationBDDState, env_id: str) -> None:
    run_async(eval_state.manager.reset_environment(env_id))


@then(
    parsers.parse(
        'the attack graph for "{env_id}" contains {expected_nodes:d} nodes'
    )
)
def then_graph_node_count(
    eval_state: EvaluationBDDState, env_id: str, expected_nodes: int
) -> None:
    env = eval_state.manager.get_or_create_environment(env_id)
    nodes = run_async(env.store.get_all_nodes())
    assert len(nodes) == expected_nodes


@then(
    parsers.parse(
        'the alert history for "{env_id}" is completely empty'
    )
)
def then_alert_history_empty(
    eval_state: EvaluationBDDState, env_id: str
) -> None:
    env = eval_state.manager.get_or_create_environment(env_id)
    assert len(env.alert_bus.get_alerts()) == 0
