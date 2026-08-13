"""BDD Step Definitions for Path Correlation (`tests/features/path_correlation.feature`)."""

from datetime import UTC, datetime, timedelta
import uuid
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphStore,
    AttackNode,
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from tests.step_defs.async_utils import run_async

scenarios("../features/path_correlation.feature")


class PathBDDState:
    def __init__(self):
        self.store = AttackGraphStore(in_memory=True)
        self.correlator = PathCorrelator(store=self.store)
        self.agent_id = "agent-path-bdd"
        self.base_time = datetime.now(UTC)
        self.nodes = []
        self.adj_graph = {}
        self.paths = []
        self.mapped_stages = []


@pytest.fixture
def path_state():
    return PathBDDState()


# Scenario 1 steps
@given("two events for an agent occurring 3 minutes apart")
def given_two_events_3_mins_apart(path_state):
    e1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=path_state.agent_id,
        action="sys_clone",
        target="proc1",
        risk_score=0.5,
    )
    e2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=3),
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="exec_cmd",
        target="sh",
        risk_score=0.7,
    )
    n1 = AttackNode(node_id=e1.event_id, event=e1)
    n2 = AttackNode(node_id=e2.event_id, event=e2)
    path_state.nodes = [n1, n2]


@when("building the temporal adjacency graph")
def when_build_adj_graph(path_state):
    path_state.adj_graph = path_state.correlator.build_temporal_adjacency_graph(
        path_state.nodes
    )


@then("an edge should exist between the first event node and the second event node")
def then_edge_exists(path_state):
    n1_id = path_state.nodes[0].node_id
    n2_id = path_state.nodes[1].node_id
    neighbors = path_state.adj_graph.get(n1_id, [])
    target_ids = [target.node_id for target, _ in neighbors]
    assert n2_id in target_ids


# Scenario 2 steps
@given("two events for an agent occurring 10 minutes apart")
def given_two_events_10_mins_apart(path_state):
    e1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=path_state.agent_id,
        action="sys_clone",
        target="proc1",
        risk_score=0.5,
    )
    e2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=10),
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="exec_cmd",
        target="sh",
        risk_score=0.7,
    )
    n1 = AttackNode(node_id=e1.event_id, event=e1)
    n2 = AttackNode(node_id=e2.event_id, event=e2)
    path_state.nodes = [n1, n2]


@then("no edge should exist between the first event node and the second event node")
def then_no_edge_exists(path_state):
    n1_id = path_state.nodes[0].node_id
    n2_id = path_state.nodes[1].node_id
    neighbors = path_state.adj_graph.get(n1_id, [])
    target_ids = [target.node_id for target, _ in neighbors]
    assert n2_id not in target_ids


# Scenario 3 steps
@given("a sequence of 3 temporally adjacent events for an agent")
def given_3_adjacent_events(path_state):
    run_async(path_state.store.initialize())
    for i in range(3):
        ev = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=path_state.base_time + timedelta(minutes=i),
            source=EventSource.TOOL_CALL,
            agent_id=path_state.agent_id,
            action=f"action_{i}",
            target=f"target_{i}",
            risk_score=0.6,
        )
        run_async(path_state.store.insert_event(ev))


@when("correlating attack paths with min_path_length 2")
def when_correlate_min_length_2(path_state):
    time_win = (
        path_state.base_time - timedelta(minutes=1),
        path_state.base_time + timedelta(minutes=15),
    )
    path_state.paths = run_async(
        path_state.correlator.correlate_attack_paths(
            path_state.agent_id, time_win, min_path_length=2
        )
    )


@then("DFS should find attack paths of length at least 2")
def then_dfs_finds_paths(path_state):
    assert len(path_state.paths) >= 1
    assert all(len(p.nodes) >= 2 for p in path_state.paths)


# Scenario 4 steps
@given("multiple attack paths generated for an agent with varying risk scores")
def given_multiple_attack_paths(path_state):
    run_async(path_state.store.initialize())
    # Low-risk event sequence
    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time,
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="read_log",
        target="/tmp/log",
        risk_score=0.1,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=1),
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="cat_file",
        target="/tmp/log",
        risk_score=0.2,
    )
    # High-risk event sequence
    ev3 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=5),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=path_state.agent_id,
        action="sudo_grant",
        target="root",
        risk_score=0.9,
    )
    ev4 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=6),
        source=EventSource.FORENSIC_ALERT,
        agent_id=path_state.agent_id,
        action="dump_credentials",
        target="secrets",
        risk_score=0.95,
    )
    for ev in [ev1, ev2, ev3, ev4]:
        run_async(path_state.store.insert_event(ev))


@when("correlating attack paths for the agent")
def when_correlate_attack_paths(path_state):
    time_win = (
        path_state.base_time - timedelta(minutes=1),
        path_state.base_time + timedelta(minutes=20),
    )
    path_state.paths = run_async(
        path_state.correlator.correlate_attack_paths(
            path_state.agent_id, time_win, min_path_length=2
        )
    )


@then("the returned attack paths should be ordered by risk_score descending")
def then_paths_ordered_by_risk(path_state):
    assert len(path_state.paths) >= 2
    for i in range(len(path_state.paths) - 1):
        assert path_state.paths[i].risk_score >= path_state.paths[i + 1].risk_score


# Scenario 5 steps
@given("an agent with 1 event in the store")
def given_single_event_in_store(path_state):
    run_async(path_state.store.initialize())
    ev = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time,
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="single_action",
        target="target",
        risk_score=0.5,
    )
    run_async(path_state.store.insert_event(ev))


@then("an empty list of attack paths should be returned")
def then_empty_list_returned(path_state):
    assert path_state.paths == []


# Scenario 6 steps
@given('attack nodes with actions "exec command" and "sudo elevate"')
def given_attack_nodes_mitre(path_state):
    e1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time,
        source=EventSource.TOOL_CALL,
        agent_id=path_state.agent_id,
        action="exec command",
        target="bash",
        risk_score=0.8,
    )
    e2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=path_state.base_time + timedelta(minutes=1),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=path_state.agent_id,
        action="sudo elevate",
        target="root",
        risk_score=0.9,
    )
    n1 = AttackNode(node_id=e1.event_id, event=e1)
    n2 = AttackNode(node_id=e2.event_id, event=e2)
    path_state.nodes = [n1, n2]


@when("mapping MITRE techniques for the attack path")
def when_map_mitre_techniques(path_state):
    path_state.mapped_stages = path_state.correlator.map_mitre_techniques(
        path_state.nodes
    )


@then('the attack stages should contain valid MITRE technique IDs "T1059" and "T1068"')
def then_mitre_stages_valid(path_state):
    assert "T1059" in path_state.mapped_stages
    assert "T1068" in path_state.mapped_stages
