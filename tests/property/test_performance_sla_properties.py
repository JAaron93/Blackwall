"""Property-based tests for Performance Optimization and SLA Validation using Hypothesis (Pillar 6 Task 16)."""

import asyncio
from datetime import UTC, datetime, timedelta
import uuid

from hypothesis import given, settings
from hypothesis import strategies as st
import pytest

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector

valid_id_strategy = st.from_regex(r"[a-zA-Z0-9_-]{1,20}", fullmatch=True)
valid_action_strategy = st.from_regex(r"[a-zA-Z0-9_./-]{1,30}", fullmatch=True)
valid_target_strategy = st.from_regex(r"[a-zA-Z0-9_./:-]{1,40}", fullmatch=True)


def _run(coro):
    """Run async coroutines in synchronous hypothesis tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Property: Batch Normalization Valid Acceptance
# ---------------------------------------------------------------------------
@given(
    source=st.sampled_from(list(EventSource)),
    agent_id=valid_id_strategy,
    action=valid_action_strategy,
    target=valid_target_strategy,
    risk=st.floats(min_value=0.0, max_value=1.0),
    batch_size=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=100)
def test_property_batch_normalization_valid_acceptance(
    source: EventSource,
    agent_id: str,
    action: str,
    target: str,
    risk: float,
    batch_size: int,
):
    """Property: EventStreamCollector.process_event_batch successfully normalizes all valid raw events."""
    collector = EventStreamCollector()
    now = datetime.now(UTC)

    raw_batch = [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": (now + timedelta(seconds=i)).isoformat(),
            "agent_id": f"{agent_id}_{i}",
            "action": f"{action}_{i}",
            "target": f"{target}_{i}",
            "metadata": {"idx": i},
            "risk_score": risk,
        }
        for i in range(batch_size)
    ]

    normalized = collector.process_event_batch(source, raw_batch)
    assert len(normalized) == batch_size
    for ev in normalized:
        assert isinstance(ev, NormalizedEvent)
        assert ev.source == source
        assert ev.timestamp.tzinfo is UTC
        assert 0.0 <= ev.risk_score <= 1.0


# ---------------------------------------------------------------------------
# Property: Batch Normalization Malformed Rejection
# ---------------------------------------------------------------------------
@given(
    source=st.sampled_from(list(EventSource)),
    invalid_agent=st.sampled_from(["", "   ", "\t", "\n"]),
)
@settings(max_examples=50)
def test_property_batch_normalization_malformed_rejection(
    source: EventSource,
    invalid_agent: str,
):
    """Property: EventStreamCollector.process_event_batch safely discards malformed and invalid items."""
    collector = EventStreamCollector()
    now = datetime.now(UTC)

    mixed_batch = [
        # Non-dict item
        "not_a_dict",
        12345,
        # Dict with empty agent_id
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": invalid_agent,
            "action": "test_action",
            "target": "/test",
        },
        # Valid item
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "valid-agent",
            "action": "valid_action",
            "target": "/valid",
        },
    ]

    normalized = collector.process_event_batch(source, mixed_batch)
    assert len(normalized) == 1
    assert normalized[0].agent_id == "valid-agent"


# ---------------------------------------------------------------------------
# Property: Batch Store Persistence and Deduplication
# ---------------------------------------------------------------------------
@given(
    agent_id=valid_id_strategy,
    num_events=st.integers(min_value=2, max_value=8),
)
@settings(max_examples=50)
def test_property_batch_store_persistence_and_deduplication(
    agent_id: str,
    num_events: int,
):
    """Property: AttackGraphStore.insert_events_batch handles duplicates cleanly and updates agent indexes."""
    store = AttackGraphStore(in_memory=True)
    _run(store.initialize())
    now = datetime.now(UTC)

    events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=i),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action=f"action_{i}",
            target=f"/path/{i}",
            metadata={},
            risk_score=0.5,
        )
        for i in range(num_events)
    ]

    # Batch 1: insert events
    nodes1 = _run(store.insert_events_batch(events))
    assert len(nodes1) == num_events

    # Batch 2: re-insert with duplicates
    nodes2 = _run(store.insert_events_batch(events))
    assert len(nodes2) == num_events

    # Verify nodes retrieved match agent index
    queried = _run(
        store.query_nodes(
            agent_id, (now - timedelta(minutes=1), now + timedelta(hours=1))
        )
    )
    assert len(queried) == num_events

    _run(store.close())


# ---------------------------------------------------------------------------
# Property: Query Path Caching and Invalidation
# ---------------------------------------------------------------------------
@given(
    agent_id=valid_id_strategy,
)
@settings(max_examples=50)
def test_property_query_path_caching_and_invalidation(agent_id: str):
    """Property: AttackGraphStore.query_paths caches results and invalidates upon new event insertion."""
    store = AttackGraphStore(in_memory=True)
    _run(store.initialize())
    now = datetime.now(UTC)
    tw = (now - timedelta(minutes=5), now + timedelta(minutes=30))

    events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=i * 10),
            source=EventSource.KERNEL_SYSCALL,
            agent_id=agent_id,
            action=f"action_{i}",
            target=f"/target/{i}",
            metadata={},
            risk_score=0.6,
        )
        for i in range(3)
    ]
    _run(store.insert_events_batch(events))

    # First query populates cache
    paths1 = _run(store.query_paths(agent_id, tw, min_path_length=2))
    assert len(paths1) >= 1
    cache_key = (agent_id, tw[0], tw[1], 2)
    assert cache_key in store._path_cache

    # Second query returns from cache
    paths2 = _run(store.query_paths(agent_id, tw, min_path_length=2))
    assert len(paths2) == len(paths1)

    # Invalidate cache when new event is inserted
    new_event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=50),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="new_action",
        target="/new_target",
        metadata={},
        risk_score=0.8,
    )
    _run(store.insert_event(new_event))
    assert cache_key not in store._path_cache

    _run(store.close())


# ---------------------------------------------------------------------------
# Property: Incremental Fingerprint Valid Acceptance and Rejection
# ---------------------------------------------------------------------------
@given(
    agent_id=valid_id_strategy,
    num_events=st.integers(min_value=1, max_value=10),
    window=st.integers(min_value=60, max_value=7200),
)
@settings(max_examples=50)
def test_property_incremental_fingerprint_valid_acceptance(
    agent_id: str,
    num_events: int,
    window: int,
):
    """Property: AgentSwarmDetector.update_fingerprint_incremental produces valid 64-char SHA-256 hashes."""
    detector = AgentSwarmDetector()
    now = datetime.now(UTC)

    events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=i * 5),
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action=f"op_{i}",
            target=f"tgt_{i}",
            metadata={},
            risk_score=0.3,
        )
        for i in range(num_events)
    ]

    fp = detector.update_fingerprint_incremental(
        agent_id=agent_id, new_events=events, window=window
    )
    assert isinstance(fp, str)
    assert len(fp) == 64


@given(
    invalid_agent=st.sampled_from(["", "   ", "\t"]),
    invalid_window=st.integers(max_value=0),
)
@settings(max_examples=30)
def test_property_incremental_fingerprint_rejection(
    invalid_agent: str,
    invalid_window: int,
):
    """Property: AgentSwarmDetector.update_fingerprint_incremental rejects invalid agent_id and non-positive window."""
    detector = AgentSwarmDetector()
    now = datetime.now(UTC)
    sample_events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now,
            source=EventSource.TOOL_CALL,
            agent_id="test",
            action="act",
            target="tgt",
            metadata={},
            risk_score=0.2,
        )
    ]

    with pytest.raises(ValueError, match="agent_id"):
        detector.update_fingerprint_incremental(
            agent_id=invalid_agent, new_events=sample_events, window=3600
        )

    with pytest.raises(ValueError, match="window"):
        detector.update_fingerprint_incremental(
            agent_id="valid-agent", new_events=sample_events, window=invalid_window
        )
