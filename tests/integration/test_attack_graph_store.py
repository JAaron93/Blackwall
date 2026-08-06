"""Integration tests for AttackGraphStore (Pillar 6 Task 2)."""

from datetime import datetime, timezone, timedelta
import time
import uuid

import pytest

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def create_test_event(
    agent_id: str = "agent-001",
    action: str = "execve",
    target: str = "/bin/ls",
    risk_score: float = 0.5,
    timestamp: datetime = None,
) -> NormalizedEvent:
    """Helper to create a test NormalizedEvent."""
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"pid": 1234},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_connection_pool():
    """Test Subtask 2.1: AttackGraphStore connection pool creation and closure."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    assert store._initialized is True

    await store.close()
    assert store._initialized is False


@pytest.mark.asyncio
async def test_insert_event():
    """Test Subtask 2.2: Insert event storing NormalizedEvent as AttackNode."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    event = create_test_event(agent_id="agent-002", action="socket_connect", risk_score=0.8)
    node = await store.insert_event(event)

    assert isinstance(node, AttackNode)
    assert node.node_id == event.event_id
    assert node.event.agent_id == "agent-002"
    assert node.incoming_edges == []
    assert node.outgoing_edges == []

    fetched = await store.get_node(node.node_id)
    assert fetched is not None
    assert fetched.node_id == node.node_id

    # Re-inserting duplicate event preserves existing node and edges
    event2 = create_test_event(agent_id="agent-002", action="connect")
    node2 = await store.insert_event(event2)
    await store.link_events(from_node=node.node_id, to_node=node2.node_id, relationship="FOLLOWED_BY")

    # Re-insert first event to verify cached edge lists are preserved
    reinserted = await store.insert_event(event)
    assert len(reinserted.outgoing_edges) == 1

    await store.close()


@pytest.mark.asyncio
async def test_link_events():
    """Test Subtask 2.3: Causal edge creation between nodes."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    now = datetime.now(timezone.utc)
    event1 = create_test_event(agent_id="agent-003", action="execve", timestamp=now)
    event2 = create_test_event(agent_id="agent-003", action="connect", timestamp=now + timedelta(seconds=2))

    node1 = await store.insert_event(event1)
    node2 = await store.insert_event(event2)

    await store.link_events(from_node=node1.node_id, to_node=node2.node_id, relationship="SPAWNED")

    updated_node1 = await store.get_node(node1.node_id)
    updated_node2 = await store.get_node(node2.node_id)

    assert len(updated_node1.outgoing_edges) == 1
    assert len(updated_node2.incoming_edges) == 1

    await store.close()


@pytest.mark.asyncio
async def test_query_paths_performance():
    """Test Subtask 2.4: Multi-hop path query engine filtering and sub-500ms performance."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    now = datetime.now(timezone.utc)
    agent_id = "agent-perf-test"

    # Insert a chain of 5 events for agent-perf-test
    prev_node = None
    first_time = now
    last_time = now

    for i in range(5):
        event_time = now + timedelta(seconds=i * 10)
        last_time = event_time
        risk = 0.2 + (i * 0.15)
        event = create_test_event(
            agent_id=agent_id,
            action=f"step_{i}",
            target=f"/path/{i}",
            risk_score=risk,
            timestamp=event_time,
        )
        node = await store.insert_event(event)
        if prev_node:
            await store.link_events(from_node=prev_node.node_id, to_node=node.node_id, relationship="FOLLOWED_BY")
        prev_node = node

    time_window = (first_time - timedelta(minutes=1), last_time + timedelta(minutes=1))

    # Untimed warmup call to bypass cold-start overhead
    await store.query_paths(agent_id=agent_id, time_window=time_window, min_path_length=2)

    # Benchmark path query execution time
    start_bench = time.perf_counter()
    paths = await store.query_paths(agent_id=agent_id, time_window=time_window, min_path_length=2)
    elapsed_ms = (time.perf_counter() - start_bench) * 1000

    assert elapsed_ms < 500.0, f"Query path execution took {elapsed_ms:.2f}ms, exceeding 500ms SLA"
    assert len(paths) >= 1
    assert all(isinstance(p, AttackPath) for p in paths)
    assert all(len(p.nodes) >= 2 for p in paths)

    # Verify risk_score descending order
    risk_scores = [p.risk_score for p in paths]
    assert risk_scores == sorted(risk_scores, reverse=True)

    # Test empty path list when fewer events than min_path_length
    short_agent = "agent-short"
    event_short = create_test_event(agent_id=short_agent)
    await store.insert_event(event_short)
    empty_paths = await store.query_paths(agent_id=short_agent, time_window=time_window, min_path_length=2)
    assert empty_paths == []

    # Test min_path_length < 2 raises ValueError
    with pytest.raises(ValueError, match="min_path_length must be at least 2"):
        await store.query_paths(agent_id=agent_id, time_window=time_window, min_path_length=1)

    await store.close()


@pytest.mark.asyncio
async def test_query_nodes_db_mode_does_not_pollute_memory_cache():
    """Verify DB-backed mode query_nodes does not insert fetched nodes into self._nodes cache."""
    from unittest.mock import AsyncMock, MagicMock

    store = AttackGraphStore(in_memory=False)
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    agent_id = "agent-db-uncached"

    node_id = uuid.uuid4()
    rows = [
        {
            "node_id": node_id,
            "event_id": uuid.uuid4(),
            "timestamp": base_time,
            "source": EventSource.KERNEL_SYSCALL.value,
            "agent_id": agent_id,
            "action": "exec",
            "target": "/bin/sh",
            "metadata": {},
            "risk_score": 0.8,
            "incoming_edges": [],
            "outgoing_edges": [],
        }
    ]

    mock_conn.fetch = AsyncMock(return_value=rows)
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    store._pool = mock_pool

    time_win = (base_time - timedelta(minutes=1), base_time + timedelta(minutes=1))

    # Before query, in-memory cache is empty
    assert len(store._nodes) == 0

    # Query nodes in DB mode
    fetched_nodes = await store.query_nodes(agent_id, time_win)
    assert len(fetched_nodes) == 1
    assert fetched_nodes[0].node_id == node_id

    # Verify self._nodes is still empty (no memory leak/accumulation)
    assert len(store._nodes) == 0


@pytest.mark.asyncio
async def test_query_nodes_skips_malformed_edge_uuids_with_warning(caplog):
    """Verify query_nodes skips malformed edge UUID entries and logs warning instead of raising ValueError."""
    import logging
    from unittest.mock import AsyncMock, MagicMock

    store = AttackGraphStore(in_memory=False)
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    agent_id = "agent-malformed-edge"

    valid_edge = uuid.uuid4()
    bad_edge = "not-a-valid-uuid-v4"
    node_id = uuid.uuid4()

    rows = [
        {
            "node_id": node_id,
            "event_id": uuid.uuid4(),
            "timestamp": base_time,
            "source": EventSource.KERNEL_SYSCALL.value,
            "agent_id": agent_id,
            "action": "exec",
            "target": "/bin/sh",
            "metadata": {},
            "risk_score": 0.8,
            "incoming_edges": [str(valid_edge), bad_edge],
            "outgoing_edges": [bad_edge],
        }
    ]

    mock_conn.fetch = AsyncMock(return_value=rows)
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    store._pool = mock_pool

    time_win = (base_time - timedelta(minutes=1), base_time + timedelta(minutes=1))

    with caplog.at_level(logging.WARNING):
        fetched_nodes = await store.query_nodes(agent_id, time_win)

    assert len(fetched_nodes) == 1
    assert fetched_nodes[0].incoming_edges == [valid_edge]
    assert fetched_nodes[0].outgoing_edges == []
    assert "Skipping malformed edge UUID 'not-a-valid-uuid-v4'" in caplog.text
