"""Property-based tests for AttackGraphStore using Hypothesis (Pillar 6 Task 2.5)."""

from datetime import datetime, timezone, timedelta
import uuid

from hypothesis import given, settings, strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection import EventSource, NormalizedEvent
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


# Hypothesis strategies
@st.composite
def normalized_events(draw, agent_id: str = "agent-prop-01"):
    """Strategy to generate valid UTC-aware NormalizedEvent instances."""
    event_id = str(uuid.uuid4())
    # Generate offset in seconds to ensure valid UTC datetimes
    offset_sec = draw(st.integers(min_value=0, max_value=86400 * 30))
    ts = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=offset_sec
    )
    source = draw(st.sampled_from(list(EventSource)))
    action = draw(
        st.text(
            min_size=1,
            max_size=20,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
        )
    )
    target = draw(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
        )
    )
    risk_score = draw(st.floats(min_value=0.0, max_value=1.0))

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source=source,
        agent_id=agent_id,
        action=action or "action",
        target=target or "/target",
        metadata={"prop_test": True},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    st.lists(normalized_events(agent_id="agent-prop-temporal"), min_size=2, max_size=10)
)
async def test_property_6_temporal_ordering_preservation(events):
    """Property 6: Temporal Ordering Preservation.

    For any sequence of events inserted into AttackGraphStore, temporal ordering based
    on timestamps is preserved in graph structure.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await store.query_paths(
        agent_id="agent-prop-temporal", time_window=time_window, min_path_length=2
    )

    for path in paths:
        path_timestamps = [n.event.timestamp for n in path.nodes]
        # Assert timestamps in returned path nodes are sorted in non-decreasing order
        assert path_timestamps == sorted(path_timestamps)

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    normalized_events(agent_id="agent-causal-1"),
    normalized_events(agent_id="agent-causal-1"),
    st.sampled_from(["SPAWNED", "READ", "WRITTEN", "EXECUTED", "TRIGGERED"]),
)
async def test_property_7_causal_edge_creation(event1, event2, relationship):
    """Property 7: Causal Edge Creation.

    For any pair of causally related events, a directed edge with relationship type
    exists in AttackGraphStore connecting them.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    node1 = await store.insert_event(event1)
    node2 = await store.insert_event(event2)

    await store.link_events(
        from_node=node1.node_id, to_node=node2.node_id, relationship=relationship
    )

    fetched1 = await store.get_node(node1.node_id)
    fetched2 = await store.get_node(node2.node_id)

    assert fetched1 is not None
    assert fetched2 is not None
    assert len(fetched1.outgoing_edges) > 0
    assert len(fetched2.incoming_edges) > 0

    matching_edges = [
        e
        for e in store._edges
        if e["from_node"] == node1.node_id
        and e["to_node"] == node2.node_id
        and e["relationship"] == relationship
    ]
    assert len(matching_edges) >= 1

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    st.integers(min_value=2, max_value=5),
    st.lists(normalized_events(agent_id="agent-min-len"), min_size=2, max_size=8),
)
async def test_property_8_path_query_min_length(min_len, events):
    """Property 8: Path Query Minimum Length Enforcement.

    For any attack path query with a specified minimum path length, all returned paths
    contain at least that minimum number of nodes.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await store.query_paths(
        agent_id="agent-min-len", time_window=time_window, min_path_length=min_len
    )

    for path in paths:
        assert (
            len(path.nodes) >= min_len
        ), f"Returned path has {len(path.nodes)} nodes, expected at least {min_len}"

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    normalized_events(agent_id="agent-edge-integrity"),
    normalized_events(agent_id="agent-edge-integrity"),
    st.sampled_from(["CALLS", "TRANSFERS_TO", "ACCESSES"]),
)
async def test_property_9_node_edge_list_integrity(event1, event2, relationship):
    """Property 9: Node Edge List Integrity.

    For any node in AttackGraphStore with edges, the incoming_edges and outgoing_edges
    lists accurately reflect all connected edges.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    node1 = await store.insert_event(event1)
    node2 = await store.insert_event(event2)

    await store.link_events(
        from_node=node1.node_id, to_node=node2.node_id, relationship=relationship
    )

    fetched1 = await store.get_node(node1.node_id)
    fetched2 = await store.get_node(node2.node_id)

    assert fetched1 is not None
    assert fetched2 is not None

    # Outgoing edge of source node and incoming edge of target node match
    common_edges = set(fetched1.outgoing_edges).intersection(
        set(fetched2.incoming_edges)
    )
    assert len(common_edges) >= 1

    edge_id = list(common_edges)[0]

    # Verify that edge list accurately reflects connected edges in store
    edges_for_node1 = [e for e in store._edges if e["from_node"] == node1.node_id]
    edges_for_node2 = [e for e in store._edges if e["to_node"] == node2.node_id]

    assert edge_id in [e["edge_id"] for e in edges_for_node1]
    assert edge_id in [e["edge_id"] for e in edges_for_node2]

    await store.close()
