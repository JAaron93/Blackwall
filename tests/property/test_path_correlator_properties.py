"""Property-based tests for PathCorrelator using Hypothesis (Pillar 6 Task 5 / Properties 14-20)."""

from datetime import datetime, timezone, timedelta
import re
import uuid

from hypothesis import given, settings, strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    AttackNode,
    AttackGraphStore,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator


# MITRE ATT&CK technique regex pattern: e.g. T1059 or T1059.001
MITRE_PATTERN_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


@st.composite
def normalized_events(draw, agent_id: str = "agent-prop-correlator", base_time: datetime = None):
    """Strategy to generate valid UTC-aware NormalizedEvent instances."""
    if base_time is None:
        base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    
    event_id = str(uuid.uuid4())
    offset_sec = draw(st.integers(min_value=0, max_value=3600))
    ts = base_time + timedelta(seconds=offset_sec)
    source = draw(st.sampled_from(list(EventSource)))
    action = draw(st.sampled_from([
        "exec bash", "sudo privilege elevate", "read credential token",
        "socket connect c2", "setup cron timer", "k8s pod container spawn",
        "custom_local_action"
    ]))
    target = draw(st.sampled_from([
        "/bin/sh", "root", "/var/run/secrets", "requestbin.com",
        "/etc/cron.d", "pypi-repo", "/dev/null"
    ]))
    risk_score = draw(st.floats(min_value=0.0, max_value=1.0))

    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"property_test": True},
        risk_score=risk_score,
    )


@st.composite
def attack_nodes(draw, agent_id: str = "agent-prop-correlator"):
    """Strategy to generate AttackNode instances."""
    event = draw(normalized_events(agent_id=agent_id))
    node_id = uuid.uuid4()
    return AttackNode(
        node_id=node_id,
        event=event,
        incoming_edges=[],
        outgoing_edges=[],
    )


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    st.lists(normalized_events(agent_id="agent-prop-14"), min_size=2, max_size=10),
    st.integers(min_value=0, max_value=1800),
    st.integers(min_value=300, max_value=1800),
)
async def test_property_14_time_window_filtering(events, window_start_offset, window_duration):
    """Property 14: Time Window Filtering (Req 3.1).

    All events in returned paths must be within requested time_window.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    for ev in events:
        await store.insert_event(ev)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    win_start = base_time + timedelta(seconds=window_start_offset)
    win_end = win_start + timedelta(seconds=window_duration)
    time_window = (win_start, win_end)

    paths = await correlator.correlate_attack_paths(agent_id="agent-prop-14", time_window=time_window, min_path_length=2)

    for path in paths:
        for node in path.nodes:
            assert win_start <= node.event.timestamp <= win_end, (
                f"Node timestamp {node.event.timestamp} outside window {time_window}"
            )

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(st.lists(normalized_events(agent_id="agent-prop-15"), min_size=2, max_size=8))
async def test_property_15_temporal_adjacency_rule(events):
    """Property 15: Temporal Adjacency Rule (Req 3.2).

    Adjacent nodes in paths must be <= 5 minutes (300s) apart or linked by explicit causal edge.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await correlator.correlate_attack_paths(agent_id="agent-prop-15", time_window=time_window, min_path_length=2)

    for path in paths:
        for i in range(len(path.nodes) - 1):
            node_a = path.nodes[i]
            node_b = path.nodes[i + 1]

            delta_sec = (node_b.event.timestamp - node_a.event.timestamp).total_seconds()
            is_causal = any(e in node_a.outgoing_edges for e in node_b.incoming_edges)

            assert delta_sec <= 300 or is_causal, (
                f"Nodes {node_a.node_id} and {node_b.node_id} are {delta_sec}s apart without causal edge"
            )

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    attack_nodes(agent_id="agent-prop-16"),
    attack_nodes(agent_id="agent-prop-16"),
)
async def test_property_16_edge_weight_computation(node_a, node_b):
    """Property 16: Edge Weight Computation (Req 3.3).

    Edge weights computed based on temporal proximity and semantic relationships, bounded in [0.0, 1.0].
    """
    correlator = PathCorrelator()

    # Ensure node_b is after or at node_a in time
    if node_b.event.timestamp < node_a.event.timestamp:
        node_a, node_b = node_b, node_a

    weight = correlator.compute_edge_weight(node_a, node_b)
    assert 0.0 <= weight <= 1.0, f"Edge weight {weight} out of bounds [0.0, 1.0]"


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    st.integers(min_value=2, max_value=5),
    st.lists(normalized_events(agent_id="agent-prop-17"), min_size=2, max_size=6),
)
async def test_property_17_path_finding_completeness(min_path_length, events):
    """Property 17: Path Finding Completeness (Req 3.4).

    DFS finds all valid paths meeting min_path_length. All returned paths contain >= min_path_length nodes.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await correlator.correlate_attack_paths(agent_id="agent-prop-17", time_window=time_window, min_path_length=min_path_length)

    for path in paths:
        assert len(path.nodes) >= min_path_length, (
            f"Returned path has {len(path.nodes)} nodes, expected at least {min_path_length}"
        )

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(st.lists(normalized_events(agent_id="agent-prop-18"), min_size=2, max_size=8))
async def test_property_18_risk_score_ordering(events):
    """Property 18: Risk Score Ordering (Req 3.5).

    Output paths are sorted by risk_score in descending order.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await correlator.correlate_attack_paths(agent_id="agent-prop-18", time_window=time_window, min_path_length=2)

    risk_scores = [p.risk_score for p in paths]
    assert risk_scores == sorted(risk_scores, reverse=True), (
        f"Paths are not sorted by risk_score descending: {risk_scores}"
    )

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(
    st.integers(min_value=2, max_value=6),
    st.integers(min_value=0, max_value=1),
)
async def test_property_19_empty_path_list_for_insufficient_events(min_path_length, event_count):
    """Property 19: Empty Path List for Insufficient Events (Req 3.6).

    Returns [] when event count < min_path_length.
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    agent_id = "agent-prop-19"
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Insert fewer events than min_path_length (0 or 1 event when min_path_length >= 2)
    actual_count = min(event_count, min_path_length - 1)
    for i in range(actual_count):
        ev = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=base_time + timedelta(seconds=i * 10),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action="exec",
            target="/bin/ls",
            risk_score=0.5,
        )
        await store.insert_event(ev)

    time_window = (base_time - timedelta(seconds=10), base_time + timedelta(seconds=1000))
    paths = await correlator.correlate_attack_paths(agent_id=agent_id, time_window=time_window, min_path_length=min_path_length)

    assert paths == [], f"Expected empty list when events ({actual_count}) < min_path_length ({min_path_length}), got {paths}"

    await store.close()


@pytest.mark.asyncio
@settings(max_examples=100)
@given(st.lists(normalized_events(agent_id="agent-prop-20"), min_size=2, max_size=8))
async def test_property_20_mitre_technique_mapping(events):
    r"""Property 20: MITRE Technique Mapping (Req 3.7).

    attack_stages contain valid MITRE ATT&CK technique IDs matching pattern r"^T\d{4}(\.\d{3})?$".
    """
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    correlator = PathCorrelator(store=store)

    for ev in events:
        await store.insert_event(ev)

    min_ts = min(ev.timestamp for ev in events)
    max_ts = max(ev.timestamp for ev in events)
    time_window = (min_ts - timedelta(seconds=1), max_ts + timedelta(seconds=1))

    paths = await correlator.correlate_attack_paths(agent_id="agent-prop-20", time_window=time_window, min_path_length=2)

    for path in paths:
        assert len(path.attack_stages) > 0, "AttackPath attack_stages must not be empty"
        for tech_id in path.attack_stages:
            assert MITRE_PATTERN_REGEX.match(tech_id) is not None, (
                f"Technique ID '{tech_id}' does not match pattern r'^T\\d{{4}}(\\.\\d{{3}})?$'"
            )

    await store.close()
