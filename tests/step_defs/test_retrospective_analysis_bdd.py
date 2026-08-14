"""BDD Step Definitions for Retrospective Analysis (`tests/features/retrospective_analysis.feature`)."""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphStore,
    AttackNode,
    AttackPath,
    EventSource,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.graph_export import (
    AttackGraphExporter,
)
from blackwall.enterprise.advanced_threat_detection.retrospective import (
    RetrospectiveAnalyzer,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/retrospective_analysis.feature")


class RetroBDDState:
    def __init__(self):
        self.store = AttackGraphStore(in_memory=True)
        self.analyzer = RetrospectiveAnalyzer(store=self.store)
        self.exporter = AttackGraphExporter()
        self.agent_id = ""
        self.window_7d = None
        self.paths_7d = []
        self.stealth_paths = []
        self.swarm_results = []
        self.sample_nodes = []
        self.sample_edges = []
        self.json_output = ""
        self.graphml_output = ""


@pytest.fixture
def retro_state():
    return RetroBDDState()


# ---------------------------------------------------------------------------
# Scenario 1: historical time window query spanning 7 days
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'an AttackGraphStore populated with multi-day event history for agent "{agent_id}"'
    )
)
def given_populated_store(retro_state, agent_id):
    run_async(retro_state.store.initialize())
    retro_state.agent_id = agent_id
    now = datetime.now(UTC)

    events = []
    for day in range(10, 0, -1):
        ts = now - timedelta(days=day)
        ev1 = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=ts,
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action="git_fetch",
            target="git://repo.local",
            risk_score=0.3,
        )
        ev2 = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=ts + timedelta(minutes=5),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action="execve",
            target="/bin/bash",
            risk_score=0.85,
        )
        events.extend([ev1, ev2])

    run_async(retro_state.store.insert_events_batch(events))


@when(
    parsers.parse(
        'the RetrospectiveAnalyzer queries attack paths for "{agent_id}" across a 7-day historical window'
    )
)
def when_query_7day_window(retro_state, agent_id):
    now = datetime.now(UTC)
    retro_state.window_7d = (now - timedelta(days=7), now)
    retro_state.paths_7d = run_async(
        retro_state.analyzer.analyze_historical_window(
            agent_id=agent_id, time_window=retro_state.window_7d
        )
    )


@then("all returned attack paths start and end within the 7-day historical window")
def then_verify_window_bounds(retro_state):
    start_w, end_w = retro_state.window_7d
    for path in retro_state.paths_7d:
        assert start_w <= path.start_time <= end_w
        assert start_w <= path.end_time <= end_w


@then("the number of identified attack paths is at least 1")
def then_verify_min_paths(retro_state):
    assert len(retro_state.paths_7d) >= 1


# ---------------------------------------------------------------------------
# Scenario 2: retrospective analysis identifies attack paths missed in real-time
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'a stealth multi-hop attack campaign spread across 3 days with causal links for agent "{agent_id}"'
    )
)
def given_stealth_campaign(retro_state, agent_id):
    run_async(retro_state.store.initialize())
    retro_state.agent_id = agent_id
    now = datetime.now(UTC)

    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now - timedelta(days=3),
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action="port_scan",
        target="192.168.1.0/24",
        risk_score=0.5,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now - timedelta(days=2),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=agent_id,
        action="acquire_token",
        target="vault://secret/k8s",
        risk_score=0.8,
    )
    ev3 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now - timedelta(days=1),
        source=EventSource.PIPELINE_EXECUTION,
        agent_id=agent_id,
        action="exfiltrate_model",
        target="https://attacker.io/drop",
        risk_score=0.95,
    )

    n1 = run_async(retro_state.store.insert_event(ev1))
    n2 = run_async(retro_state.store.insert_event(ev2))
    n3 = run_async(retro_state.store.insert_event(ev3))

    run_async(retro_state.store.link_events(n1.node_id, n2.node_id, "ENABLES"))
    run_async(retro_state.store.link_events(n2.node_id, n3.node_id, "TRIGGERS"))


@when("the RetrospectiveAnalyzer performs batch retrospective detection over a 5-day window")
def when_detect_retrospective(retro_state):
    now = datetime.now(UTC)
    time_window = (now - timedelta(days=5), now)
    retro_state.stealth_paths = run_async(
        retro_state.analyzer.detect_retrospective_paths(
            agent_id=retro_state.agent_id,
            time_window=time_window,
            batch_size=50,
            min_path_length=2,
        )
    )


@then("the multi-day attack path is successfully reconstructed with at least 2 nodes")
def then_verify_reconstructed_path(retro_state):
    assert len(retro_state.stealth_paths) >= 1
    path = retro_state.stealth_paths[0]
    assert len(path.nodes) >= 2


@then("the attack path risk_score reflects the accumulated threat severity")
def then_verify_risk_score(retro_state):
    path = retro_state.stealth_paths[0]
    assert path.risk_score >= 0.8


# ---------------------------------------------------------------------------
# Scenario 3: multi-agent correlation across 30-day history
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'multiple agents "{agents_str}" executing coordinated actions spaced days apart'
    )
)
def given_coordinated_agents(retro_state, agents_str):
    run_async(retro_state.store.initialize())
    agent_list = [a.strip() for a in agents_str.split(",")]
    now = datetime.now(UTC)

    events = []
    for idx, agent in enumerate(agent_list):
        ts = now - timedelta(days=15 - (idx * 2))
        ev = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=ts,
            source=EventSource.TOOL_CALL,
            agent_id=agent,
            action="recon_target",
            target="k8s://production-db",
            risk_score=0.75,
        )
        events.append(ev)

    run_async(retro_state.store.insert_events_batch(events))


@when("the RetrospectiveAnalyzer correlates multi-agent history across the 30-day window")
def when_correlate_30day_history(retro_state):
    now = datetime.now(UTC)
    retro_state.swarm_results = run_async(
        retro_state.analyzer.correlate_multi_agent_history(
            time_window=(now - timedelta(days=30), now),
            similarity_threshold=0.5,
            min_agents=2,
        )
    )


@then("a SwarmEvidence record is produced containing at least 2 coordinated agents")
def then_verify_swarm_evidence(retro_state):
    assert len(retro_state.swarm_results) >= 1
    evidence = retro_state.swarm_results[0]
    assert isinstance(evidence, SwarmEvidence)
    assert len(evidence.agent_ids) >= 2


@then("the coordination_score is strictly positive")
def then_verify_coordination_score(retro_state):
    evidence = retro_state.swarm_results[0]
    assert evidence.coordination_score > 0.0


# ---------------------------------------------------------------------------
# Scenario 4: attack graph export produces valid JSON and GraphML output
# ---------------------------------------------------------------------------


@given("an attack graph with 2 nodes and a causal edge")
def given_graph_with_nodes_and_edge(retro_state):
    now = datetime.now(UTC)
    edge_id = uuid.uuid4()
    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.TOOL_CALL,
        agent_id="agent-export-1",
        action="action_a",
        target="target_a",
        risk_score=0.6,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now + timedelta(seconds=10),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-export-1",
        action="action_b",
        target="target_b",
        risk_score=0.9,
    )
    n1 = AttackNode(node_id=ev1.event_id, event=ev1, outgoing_edges=[edge_id])
    n2 = AttackNode(node_id=ev2.event_id, event=ev2, incoming_edges=[edge_id])
    retro_state.sample_nodes = [n1, n2]
    retro_state.sample_edges = [
        {
            "edge_id": str(edge_id),
            "from_node": str(n1.node_id),
            "to_node": str(n2.node_id),
            "relationship": "CAUSES",
            "created_at": now.isoformat(),
        }
    ]


@when('the AttackGraphExporter exports the graph in "json" format')
def when_export_json(retro_state):
    retro_state.json_output = retro_state.exporter.export_json(
        nodes=retro_state.sample_nodes, edges=retro_state.sample_edges
    )


@then("the JSON output parses into valid graph nodes and edges")
def then_verify_json_output(retro_state):
    parsed = json.loads(retro_state.json_output)
    assert "nodes" in parsed
    assert "edges" in parsed
    assert len(parsed["nodes"]) == 2
    assert len(parsed["edges"]) == 1


@when('the AttackGraphExporter exports the graph in "graphml" format')
def when_export_graphml(retro_state):
    retro_state.graphml_output = retro_state.exporter.export_graphml(
        nodes=retro_state.sample_nodes, edges=retro_state.sample_edges
    )


@then("the GraphML output parses into a valid XML tree with directed graph elements")
def then_verify_graphml_output(retro_state):
    root = ET.fromstring(retro_state.graphml_output)
    tag_clean = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    assert tag_clean == "graphml"
    # Locate graph
    graph_elem = None
    for elem in root.iter():
        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if elem_tag == "graph":
            graph_elem = elem
            break
    assert graph_elem is not None
    assert graph_elem.attrib.get("edgedefault") == "directed"
