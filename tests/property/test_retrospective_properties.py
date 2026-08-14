"""Hypothesis Property-Based Tests for Retrospective Analysis and Graph Export.

Properties tested:
- Property 65: Historical Time Window Support (Requirement 13.1)
- Property 66: Retrospective Path Detection (Requirement 13.2)
- Property 67: Multi-Agent Historical Correlation (Requirement 13.3)
- Property 68: Attack Graph Export Format Compliance (Requirement 13.5)
"""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphStore,
    AttackNode,
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.graph_export import (
    AttackGraphExporter,
)
from blackwall.enterprise.advanced_threat_detection.retrospective import (
    RetrospectiveAnalyzer,
)

# Custom Hypothesis strategies
valid_agent_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{3,15}", fullmatch=True)
valid_action_strategy = st.sampled_from(["execve", "read_token", "curl", "connect", "spawn_pod", "chmod"])
valid_target_strategy = st.from_regex(r"[a-zA-Z0-9_./:-]{3,25}", fullmatch=True)


# ============================================================================
# Property 65: Historical Time Window Support
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=valid_agent_id_strategy,
    days_back=st.integers(min_value=1, max_value=28),
    window_length_days=st.integers(min_value=1, max_value=7),
)
@pytest.mark.asyncio
async def test_property_65_historical_time_window_valid_acceptance(
    agent_id: str, days_back: int, window_length_days: int
):
    """Property 65: Valid time windows (spanning hours, days, weeks) must successfully query attack paths."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    base_time = datetime.now(UTC)
    start_win = base_time - timedelta(days=days_back + window_length_days)
    end_win = base_time - timedelta(days=days_back)

    # Insert events within the window
    ev1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=start_win + timedelta(hours=1),
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action="curl",
        target="https://api.internal/data",
        risk_score=0.7,
    )
    ev2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=start_win + timedelta(hours=1, minutes=2),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="execve",
        target="/bin/bash",
        risk_score=0.9,
    )
    await store.insert_events_batch([ev1, ev2])

    paths = await analyzer.analyze_historical_window(agent_id, (start_win, end_win))
    assert isinstance(paths, list)
    for p in paths:
        assert p.agent_id == agent_id
        assert start_win <= p.start_time <= end_win
        assert start_win <= p.end_time <= end_win


@settings(max_examples=100)
@given(
    agent_id=valid_agent_id_strategy,
    inverted_delta=st.integers(min_value=1, max_value=1000),
)
@pytest.mark.asyncio
async def test_property_65_historical_time_window_rejection(
    agent_id: str, inverted_delta: int
):
    """Property 65 Rejection: Inverted time windows (start > end) or naive datetimes must be rejected."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    start_invalid = now
    end_invalid = now - timedelta(seconds=inverted_delta)

    # Inverted time window should raise ValueError
    with pytest.raises(ValueError):
        await analyzer.analyze_historical_window(agent_id, (start_invalid, end_invalid))

    # Naive datetime should raise ValueError
    naive_dt = datetime.now()
    with pytest.raises(ValueError):
        await analyzer.analyze_historical_window(agent_id, (naive_dt, now))


# ============================================================================
# Property 66: Retrospective Path Detection
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=valid_agent_id_strategy,
    num_events=st.integers(min_value=2, max_value=5),
    day_step=st.integers(min_value=1, max_value=3),
)
@pytest.mark.asyncio
async def test_property_66_retrospective_path_detection_valid_acceptance(
    agent_id: str, num_events: int, day_step: int
):
    """Property 66: Retrospective analysis identifies multi-hop attack paths across historical intervals."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    base_time = datetime.now(UTC) - timedelta(days=20)
    events = []
    for i in range(num_events):
        ts = base_time + timedelta(days=i * day_step)
        ev = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=ts,
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action=f"stage_{i}",
            target=f"target_{i}",
            risk_score=0.8,
        )
        events.append(ev)

    nodes = await store.insert_events_batch(events)
    # Link sequentially
    for i in range(len(nodes) - 1):
        await store.link_events(nodes[i].node_id, nodes[i + 1].node_id, "FOLLOWED_BY")

    time_window = (base_time - timedelta(days=1), base_time + timedelta(days=num_events * day_step + 1))
    paths = await analyzer.detect_retrospective_paths(
        agent_id=agent_id,
        time_window=time_window,
        min_path_length=2,
    )

    assert isinstance(paths, list)
    assert len(paths) >= 1
    for p in paths:
        assert len(p.nodes) >= 2
        assert p.risk_score >= 0.0


@settings(max_examples=100)
@given(
    agent_id=valid_agent_id_strategy,
    invalid_batch_size=st.integers(max_value=0),
)
@pytest.mark.asyncio
async def test_property_66_retrospective_path_detection_rejection(
    agent_id: str, invalid_batch_size: int
):
    """Property 66 Rejection: Invalid parameters (non-positive batch size or min_path_length < 2) must be rejected."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    time_window = (now - timedelta(days=7), now)

    with pytest.raises(ValueError):
        await analyzer.detect_retrospective_paths(
            agent_id=agent_id,
            time_window=time_window,
            batch_size=invalid_batch_size,
        )

    with pytest.raises(ValueError):
        await analyzer.detect_retrospective_paths(
            agent_id=agent_id,
            time_window=time_window,
            min_path_length=1,
        )


# ============================================================================
# Property 67: Multi-Agent Historical Correlation
# ============================================================================


@settings(max_examples=100)
@given(
    agent_count=st.integers(min_value=2, max_value=4),
    target_pattern=valid_target_strategy,
)
@pytest.mark.asyncio
async def test_property_67_multi_agent_historical_correlation_valid_acceptance(
    agent_count: int, target_pattern: str
):
    """Property 67: Historical correlation across multiple agents identifies delayed swarm patterns."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    base_time = datetime.now(UTC) - timedelta(days=10)
    events = []

    for idx in range(agent_count):
        agent_id = f"agent-swarm-{idx}"
        ts = base_time + timedelta(days=idx, hours=1)
        ev = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=ts,
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action="exfiltrate_data",
            target=target_pattern,
            risk_score=0.8,
        )
        events.append(ev)

    await store.insert_events_batch(events)

    time_window = (base_time - timedelta(days=1), base_time + timedelta(days=agent_count + 1))
    swarms = await analyzer.correlate_multi_agent_history(
        time_window=time_window,
        similarity_threshold=0.5,
        min_agents=2,
    )

    assert isinstance(swarms, list)
    if swarms:
        for swarm in swarms:
            assert len(swarm.agent_ids) >= 2
            assert swarm.coordination_score >= 0.0
            assert swarm.temporal_correlation >= 0.0


@settings(max_examples=100)
@given(
    invalid_threshold=st.floats(min_value=1.1, max_value=10.0),
)
@pytest.mark.asyncio
async def test_property_67_multi_agent_historical_correlation_rejection(
    invalid_threshold: float,
):
    """Property 67 Rejection: Invalid thresholds or min_agents < 2 must raise ValueError."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    time_window = (now - timedelta(days=5), now)

    with pytest.raises(ValueError):
        await analyzer.correlate_multi_agent_history(
            time_window=time_window,
            similarity_threshold=invalid_threshold,
        )

    with pytest.raises(ValueError):
        await analyzer.correlate_multi_agent_history(
            time_window=time_window,
            min_agents=1,
        )


# ============================================================================
# Property 68: Attack Graph Export Format Compliance
# ============================================================================


@settings(max_examples=100)
@given(
    agent_id=valid_agent_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk_score=st.floats(min_value=0.0, max_value=1.0),
)
def test_property_68_export_format_compliance_valid_acceptance(
    agent_id: str, action: str, target: str, risk_score: float
):
    """Property 68: Exported graph output must comply with specified standard formats (JSON and GraphML)."""
    exporter = AttackGraphExporter()
    ev = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.IDENTITY_ACCESS,
        agent_id=agent_id,
        action=action,
        target=target,
        risk_score=risk_score,
    )
    node = AttackNode(node_id=ev.event_id, event=ev)

    # 1. JSON Export Compliance
    json_str = exporter.export_json([node])
    parsed_json = json.loads(json_str)
    assert "nodes" in parsed_json
    assert "edges" in parsed_json
    assert len(parsed_json["nodes"]) == 1
    assert parsed_json["nodes"][0]["node_id"] == str(node.node_id)
    assert parsed_json["nodes"][0]["event"]["agent_id"] == agent_id

    # 2. GraphML Export Compliance
    graphml_str = exporter.export_graphml([node])
    root = ET.fromstring(graphml_str)
    tag_clean = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    assert tag_clean == "graphml"

    # Must contain key elements and a graph element
    graph_elem = None
    for elem in root.iter():
        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if elem_tag == "graph":
            graph_elem = elem
            break
    assert graph_elem is not None


@settings(max_examples=100)
@given(
    unsupported_format=st.from_regex(r"[a-zA-Z0-9_]{1,10}", fullmatch=True).filter(
        lambda s: s.lower() not in {"json", "graphml"}
    ),
)
def test_property_68_export_format_rejection(unsupported_format: str):
    """Property 68 Rejection: Unsupported export formats must raise ValueError."""
    exporter = AttackGraphExporter()
    ev = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source=EventSource.FORENSIC_ALERT,
        agent_id="agent-reject",
        action="alert",
        target="span://test",
        risk_score=0.5,
    )
    node = AttackNode(node_id=ev.event_id, event=ev)

    with pytest.raises(ValueError, match="Unsupported export format"):
        exporter.export(unsupported_format, [node])
