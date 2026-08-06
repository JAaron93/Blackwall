"""Unit tests for PathCorrelator (Blackwall Pillar 6 Task 5)."""

from datetime import datetime, timezone, timedelta
import uuid
from typing import Union
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    AttackNode,
    AttackGraphStore,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator


def create_event(
    agent_id: str = "agent-unit-01",
    action: str = "exec",
    target: str = "/bin/bash",
    offset_seconds: float = 0.0,
    risk_score: float = 0.5,
    source: EventSource = EventSource.KERNEL_SYSCALL,
    base_time: datetime = None,
) -> NormalizedEvent:
    """Helper to create a UTC-aware NormalizedEvent."""
    if base_time is None:
        base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"unit_test": True},
        risk_score=risk_score,
    )


def create_node(event: NormalizedEvent, node_id: Union[str, uuid.UUID] = None) -> AttackNode:
    """Helper to create an AttackNode."""
    return AttackNode(
        node_id=node_id or uuid.uuid4(),
        event=event,
        incoming_edges=[],
        outgoing_edges=[],
    )


@pytest.mark.asyncio
async def test_temporal_adjacency():
    """Verify 5-minute (300s) temporal window edge linking (Subtask 5.1).

    Events <= 300s apart should be linked in the temporal adjacency graph.
    Events > 300s apart without explicit causal edge should NOT be linked.
    Events > 300s apart WITH explicit causal edge SHOULD be linked.
    """
    correlator = PathCorrelator()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    event_a = create_event(offset_seconds=0.0, base_time=base_time)
    event_b = create_event(offset_seconds=200.0, base_time=base_time)  # <= 300s
    event_c = create_event(offset_seconds=400.0, base_time=base_time)  # > 300s, no causal edge
    event_d = create_event(offset_seconds=500.0, base_time=base_time)  # > 300s, with causal edge

    edge_id = uuid.uuid4()
    node_a = create_node(event_a)
    node_a.outgoing_edges.append(edge_id)

    node_b = create_node(event_b)
    node_c = create_node(event_c)

    node_d = create_node(event_d)
    node_d.incoming_edges.append(edge_id)

    nodes = [node_a, node_b, node_c, node_d]
    adj_graph = correlator.build_temporal_adjacency_graph(nodes)

    # Check node A neighbors
    neighbors_a = [target.node_id for target, weight in adj_graph[node_a.node_id]]

    # node_b is within 200s <= 300s, so it must be linked
    assert node_b.node_id in neighbors_a

    # node_c is 400s > 300s apart without causal edge, so it must NOT be linked directly from node_a
    assert node_c.node_id not in neighbors_a

    # node_d is 500s > 300s apart BUT shares a causal edge (edge_id), so it MUST be linked
    assert node_d.node_id in neighbors_a


@pytest.mark.asyncio
async def test_dfs_path_finding():
    """Verify DFS path enumeration for paths >= min_path_length and empty list for insufficient events (Subtasks 5.2 & 5.6)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    agent_id = "agent-dfs-test"
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Test empty list when event count < min_path_length
    single_event = create_event(agent_id=agent_id, base_time=base_time, offset_seconds=0.0)
    await store.insert_event(single_event)

    time_win = (base_time - timedelta(seconds=10), base_time + timedelta(seconds=1000))
    paths_insufficient = await correlator.correlate_attack_paths(agent_id, time_win, min_path_length=2)
    assert paths_insufficient == []

    # 2. Add more events to form a multi-node chain
    event_2 = create_event(agent_id=agent_id, action="sudo elevate", base_time=base_time, offset_seconds=100.0, risk_score=0.8)
    event_3 = create_event(agent_id=agent_id, action="token exfiltrate", base_time=base_time, offset_seconds=200.0, risk_score=0.9)

    await store.insert_event(event_2)
    await store.insert_event(event_3)

    paths = await correlator.correlate_attack_paths(agent_id, time_win, min_path_length=2)

    # Must find paths meeting min_path_length >= 2
    assert len(paths) > 0
    for path in paths:
        assert len(path.nodes) >= 2
        assert path.agent_id == agent_id

    # Check invalid min_path_length < 2 raises ValueError
    with pytest.raises(ValueError, match="min_path_length must be at least 2"):
        await correlator.correlate_attack_paths(agent_id, time_win, min_path_length=1)


@pytest.mark.asyncio
async def test_mitre_mapping():
    """Verify mapping of event action sequences to valid MITRE ATT&CK technique IDs (Subtask 5.3)."""
    correlator = PathCorrelator()

    events_and_expected = [
        (create_event(action="exec bash script", target="/bin/sh"), "T1059"),
        (create_event(action="sudo privilege elevate", target="root"), "T1068"),
        (create_event(action="read credential token", target="/var/run/secrets"), "T1552"),
        (create_event(action="socket connect beacon", target="requestbin.com"), "T1071"),
        (create_event(action="setup cron timer", target="/etc/cron.d"), "T1053"),
        (create_event(action="k8s pod container spawn", target="pypi-repo"), "T1613"),
        (create_event(action="custom_unknown_action", target="/dev/null"), "T1005"),
    ]

    nodes = [create_node(ev) for ev, _ in events_and_expected]
    mapped_techniques = correlator.map_mitre_techniques(nodes)

    for _, expected_tech in events_and_expected:
        assert expected_tech in mapped_techniques

    # Check mapped techniques are non-empty and contain expected standard MITRE patterns
    assert len(mapped_techniques) == len(set(mapped_techniques))  # Deduplicated


@pytest.mark.asyncio
async def test_risk_scoring():
    """Verify aggregate risk_score and correlation_score in [0.0, 1.0] and paths sorted by risk_score descending (Subtask 5.4)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    agent_id = "agent-risk-test"
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Path 1: Low risk events
    ev1 = create_event(agent_id=agent_id, action="read file", risk_score=0.1, offset_seconds=0.0, base_time=base_time)
    ev2 = create_event(agent_id=agent_id, action="ls directory", risk_score=0.2, offset_seconds=10.0, base_time=base_time)

    # Path 2: High risk events
    ev3 = create_event(agent_id=agent_id, action="sudo elevate", risk_score=0.9, offset_seconds=50.0, base_time=base_time)
    ev4 = create_event(agent_id=agent_id, action="credential exfiltrate", risk_score=0.95, offset_seconds=60.0, base_time=base_time)

    await store.insert_event(ev1)
    await store.insert_event(ev2)
    await store.insert_event(ev3)
    await store.insert_event(ev4)

    time_win = (base_time - timedelta(seconds=10), base_time + timedelta(seconds=500))
    paths = await correlator.correlate_attack_paths(agent_id, time_win, min_path_length=2)

    assert len(paths) >= 2

    # Verify risk_score and correlation_score bounds
    for path in paths:
        assert 0.0 <= path.risk_score <= 1.0
        assert 0.0 <= path.correlation_score <= 1.0

    # Verify paths are sorted by risk_score descending
    risk_scores = [p.risk_score for p in paths]
    assert risk_scores == sorted(risk_scores, reverse=True)


@pytest.mark.asyncio
async def test_invalid_time_window_validation():
    """Verify ValueError is raised when time_window has naive datetimes or end_time < start_time."""
    correlator = PathCorrelator()
    agent_id = "agent-time-win-val"
    aware_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    naive_time = datetime(2026, 8, 5, 12, 0, 0)

    # Test naive start_time
    with pytest.raises(ValueError, match="timezone-aware"):
        await correlator.correlate_attack_paths(agent_id, (naive_time, aware_time))

    # Test naive end_time
    with pytest.raises(ValueError, match="timezone-aware"):
        await correlator.correlate_attack_paths(agent_id, (aware_time, naive_time))

    # Test end_time < start_time
    earlier_time = aware_time - timedelta(hours=1)
    with pytest.raises(ValueError, match="end_time must be greater than or equal to start_time"):
        await correlator.correlate_attack_paths(agent_id, (aware_time, earlier_time))


@pytest.mark.asyncio
async def test_unsorted_nodes_temporal_adjacency():
    """Verify passing unsorted nodes to build_temporal_adjacency_graph does not create negative delta edges."""
    correlator = PathCorrelator()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Node 1 is at T+600s, Node 2 is at T+0s
    node_late = create_node(create_event(offset_seconds=600.0, base_time=base_time))
    node_early = create_node(create_event(offset_seconds=0.0, base_time=base_time))

    # Pass unsorted nodes list [node_late, node_early]
    adj_graph = correlator.build_temporal_adjacency_graph([node_late, node_early])

    # node_late occurs 600s after node_early (> 300s). No edge from node_early to node_late.
    neighbors_early = [target.node_id for target, _ in adj_graph[node_early.node_id]]
    assert node_late.node_id not in neighbors_early

    # No reverse-time edge from node_late to node_early either
    neighbors_late = [target.node_id for target, _ in adj_graph[node_late.node_id]]
    assert node_early.node_id not in neighbors_late


@pytest.mark.asyncio
async def test_db_mode_non_adjacent_causal_edge_node_retrieval():
    """Verify DB-mode node retrieval via query_nodes finds non-adjacent causally linked nodes.

    Scenario:
    - Node 1 at T=0s
    - Node 2 at T=1000s (> 600s after Node 1, no causal link to Node 1)
    - Node 3 at T=2000s (> 600s after Node 2, BUT causally linked to Node 1 via explicit edge)

    In query_paths(min_path_length=2), Node 1, 2, and 3 are in separate temporal groups (>600s apart with no adjacent causal links),
    so query_paths() would return [] (no paths >= 2 nodes).
    PathCorrelator calling query_nodes() retrieves all 3 nodes, builds the adjacency graph (linking Node 1 -> Node 3 via causal edge),
    and correctly correlates path [Node 1, Node 3].
    """
    from unittest.mock import AsyncMock, MagicMock

    store = AttackGraphStore(in_memory=False)
    # Mock connection pool
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    agent_id = "agent-db-causal"
    edge_causal = str(uuid.uuid4())

    node1_id = uuid.uuid4()
    node2_id = uuid.uuid4()
    node3_id = uuid.uuid4()

    rows = [
        {
            "node_id": node1_id,
            "event_id": uuid.uuid4(),
            "timestamp": base_time,
            "source": EventSource.KERNEL_SYSCALL.value,
            "agent_id": agent_id,
            "action": "exec",
            "target": "/bin/sh",
            "metadata": {},
            "risk_score": 0.8,
            "incoming_edges": [],
            "outgoing_edges": [edge_causal],
        },
        {
            "node_id": node2_id,
            "event_id": uuid.uuid4(),
            "timestamp": base_time + timedelta(seconds=1000),
            "source": EventSource.TOOL_CALL.value,
            "agent_id": agent_id,
            "action": "tool_call",
            "target": "shell",
            "metadata": {},
            "risk_score": 0.3,
            "incoming_edges": [],
            "outgoing_edges": [],
        },
        {
            "node_id": node3_id,
            "event_id": uuid.uuid4(),
            "timestamp": base_time + timedelta(seconds=2000),
            "source": EventSource.IDENTITY_ACCESS.value,
            "agent_id": agent_id,
            "action": "access_token",
            "target": "/var/run/secrets",
            "metadata": {},
            "risk_score": 0.9,
            "incoming_edges": [edge_causal],
            "outgoing_edges": [],
        },
    ]

    mock_conn.fetch = AsyncMock(return_value=rows)
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    store._pool = mock_pool

    correlator = PathCorrelator(store=store)

    time_win = (base_time - timedelta(minutes=1), base_time + timedelta(seconds=3000))

    # Verify query_paths directly on store returns empty list due to >600s gaps between adjacent nodes
    store_paths = await store.query_paths(agent_id, time_win, min_path_length=2)
    assert store_paths == []

    # Verify PathCorrelator calls query_nodes and finds non-adjacent causally linked path [node1, node3]
    paths = await correlator.correlate_attack_paths(agent_id, time_win, min_path_length=2)

    assert len(paths) == 1
    assert [n.node_id for n in paths[0].nodes] == [node1_id, node3_id]
