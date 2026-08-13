"""Integration tests for Performance Optimization and SLA Validation (Pillar 6 Task 16)."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector


def create_test_event(
    agent_id: str = "agent-perf-001",
    action: str = "execve",
    target: str = "/bin/bash",
    risk_score: float = 0.5,
    timestamp: datetime | None = None,
    source: EventSource = EventSource.KERNEL_SYSCALL,
) -> NormalizedEvent:
    """Helper to create a valid NormalizedEvent for performance tests."""
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(UTC),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"pid": 1234, "cpu": 0.5},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_event_processing_latency():
    """Test Subtask 16.1: Event processing latency from all five pillars < 100ms (Requirement 11.1)."""
    collector = EventStreamCollector()
    now = datetime.now(UTC)

    raw_events_by_source = {
        EventSource.KERNEL_SYSCALL: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-ebpf-01",
            "action": "sys_enter_execve",
            "target": "/usr/bin/python",
            "metadata": {"syscall_nr": 59},
        },
        EventSource.TOOL_CALL: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-adk-01",
            "action": "run_command",
            "target": "cat /etc/passwd",
            "metadata": {"tool": "terminal"},
        },
        EventSource.IDENTITY_ACCESS: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-vault-01",
            "action": "request_token",
            "target": "vault://secret/prod",
            "metadata": {"sts_grant": "read"},
        },
        EventSource.PIPELINE_EXECUTION: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-pipe-01",
            "action": "load_dataset",
            "target": "dataset://production-features",
            "metadata": {"batch_size": 128},
        },
        EventSource.FORENSIC_ALERT: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-forensic-01",
            "action": "triage_anomaly",
            "target": "otel://span-9988",
            "metadata": {"anomaly_score": 0.95},
        },
    }

    # Testing Rule 1: Untimed warmup run to bypass initial JIT and class loader overhead
    for source, raw in raw_events_by_source.items():
        collector.normalize_event(source, raw)

    # Timed benchmark run across all 5 pillars
    for source, raw in raw_events_by_source.items():
        start_time = time.perf_counter()
        normalized = collector.normalize_event(source, raw)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        assert normalized is not None
        assert normalized.source == source
        assert (
            elapsed_ms < 100.0
        ), f"Event normalization for {source} took {elapsed_ms:.2f}ms, exceeding 100ms SLA"


@pytest.mark.asyncio
async def test_path_query_latency():
    """Test Subtask 16.2: Attack graph path queries < 500ms for 17,000+ events (Requirement 11.2)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    now = datetime.now(UTC)
    target_agent = "target-agent-attack-path"

    # Pre-generate 17,100 events: 17,000 background events across 100 agents + 100 targeted attack events
    total_events: list[NormalizedEvent] = []

    # 17,000 background events
    for i in range(17000):
        agent = f"background-agent-{i % 100}"
        ev = create_test_event(
            agent_id=agent,
            action=f"action_{i % 5}",
            target=f"/resource/{i % 10}",
            risk_score=0.1,
            timestamp=now + timedelta(milliseconds=i * 50),
        )
        total_events.append(ev)

    # 100 targeted attack events for target_agent
    for j in range(100):
        ev = create_test_event(
            agent_id=target_agent,
            action="execve" if j % 2 == 0 else "socket_connect",
            target="/bin/sh" if j % 2 == 0 else "10.0.0.1:443",
            risk_score=0.7 + (j % 3) * 0.1,
            timestamp=now + timedelta(seconds=j * 10),
        )
        total_events.append(ev)

    # Insert all events via batch insertion
    await store.insert_events_batch(total_events)

    time_window = (now - timedelta(minutes=5), now + timedelta(hours=2))

    correlator = PathCorrelator(store=store)

    # Testing Rule 1: Untimed warmup query before SLA timing
    await store.query_paths(
        agent_id=target_agent, time_window=time_window, min_path_length=2
    )
    await correlator.correlate_attack_paths(
        agent_id=target_agent, time_window=time_window, min_path_length=2
    )

    # Timed path query on store
    start_store_query = time.perf_counter()
    paths = await store.query_paths(
        agent_id=target_agent, time_window=time_window, min_path_length=2
    )
    store_query_elapsed_ms = (time.perf_counter() - start_store_query) * 1000.0

    assert len(paths) >= 1
    assert (
        store_query_elapsed_ms < 500.0
    ), f"Store path query took {store_query_elapsed_ms:.2f}ms, exceeding 500ms SLA"

    # Timed correlation analysis on PathCorrelator
    start_correlator_query = time.perf_counter()
    correlated_paths = await correlator.correlate_attack_paths(
        agent_id=target_agent, time_window=time_window, min_path_length=2
    )
    correlator_elapsed_ms = (time.perf_counter() - start_correlator_query) * 1000.0

    assert len(correlated_paths) >= 1
    assert (
        correlator_elapsed_ms < 500.0
    ), f"Correlator path query took {correlator_elapsed_ms:.2f}ms, exceeding 500ms SLA"

    await store.close()


@pytest.mark.asyncio
async def test_sustained_throughput():
    """Test Subtask 16.3: System handles >= 1,000 events/second sustained throughput (Requirement 11.3)."""
    collector = EventStreamCollector()
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    now = datetime.now(UTC)
    batch_size = 2000
    raw_batch = [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": (now + timedelta(milliseconds=i)).isoformat(),
            "agent_id": f"agent-throughput-{i % 50}",
            "action": "tool_exec",
            "target": f"/data/{i}",
            "metadata": {"batch_idx": i},
            "risk_score": 0.3,
        }
        for i in range(batch_size)
    ]

    # Testing Rule 1: Warmup run
    collector.process_event_batch(EventSource.TOOL_CALL, raw_batch[:10])

    # Measure normalization throughput
    start_norm = time.perf_counter()
    normalized_batch = collector.process_event_batch(EventSource.TOOL_CALL, raw_batch)
    norm_elapsed = time.perf_counter() - start_norm
    norm_throughput = len(normalized_batch) / norm_elapsed

    assert len(normalized_batch) == batch_size
    assert (
        norm_throughput >= 1000.0
    ), f"Normalization throughput was {norm_throughput:.2f} events/s, expected >= 1000"

    # Measure batch ingestion throughput
    start_ingest = time.perf_counter()
    nodes = await store.insert_events_batch(normalized_batch)
    ingest_elapsed = time.perf_counter() - start_ingest
    ingest_throughput = len(nodes) / ingest_elapsed

    assert len(nodes) == batch_size
    assert (
        ingest_throughput >= 1000.0
    ), f"Store batch ingest throughput was {ingest_throughput:.2f} events/s, expected >= 1000"

    await store.close()


@pytest.mark.asyncio
async def test_fingerprint_latency():
    """Test Subtask 16.4: Behavioral fingerprinting for 1-hour windows < 2 seconds (Requirement 11.4)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    agent_id = "agent-fp-benchmark"
    now = datetime.now(UTC)

    # Generate dense 1-hour window of 600 events (1 event every 6 seconds)
    events: list[NormalizedEvent] = []
    for i in range(600):
        ev = create_test_event(
            agent_id=agent_id,
            action=f"action_{i % 8}",
            target=f"resource_{i % 4}",
            risk_score=0.4,
            timestamp=now - timedelta(seconds=3600 - (i * 6)),
        )
        events.append(ev)

    await store.insert_events_batch(events)

    # Testing Rule 1: Untimed warmup run
    await detector.fingerprint_agent(
        agent_id=agent_id, window=3600, end_time=now
    )

    # Timed fingerprint computation
    start_time = time.perf_counter()
    fp = await detector.fingerprint_agent(
        agent_id=agent_id, window=3600, end_time=now
    )
    elapsed = time.perf_counter() - start_time

    assert isinstance(fp, str)
    assert len(fp) == 64  # SHA-256 hex string
    assert (
        elapsed < 2.0
    ), f"Fingerprint generation took {elapsed:.2f}s, exceeding 2.0s SLA"

    # Test incremental fingerprint update
    new_events = [
        create_test_event(
            agent_id=agent_id,
            action="new_action",
            target="new_target",
            timestamp=now + timedelta(seconds=1),
        )
    ]
    start_inc = time.perf_counter()
    inc_fp = detector.update_fingerprint_incremental(
        agent_id=agent_id, new_events=new_events, window=3600
    )
    inc_elapsed = time.perf_counter() - start_inc

    assert isinstance(inc_fp, str)
    assert len(inc_fp) == 64
    assert inc_elapsed < 2.0

    await store.close()


@pytest.mark.asyncio
async def test_batch_processing_and_connection_pooling():
    """Test Subtask 16.1: Batch processing helpers and connection pooling parameters."""
    store = AttackGraphStore(in_memory=True, min_pool_size=3, max_pool_size=15)
    assert store.min_pool_size == 3
    assert store.max_pool_size == 15

    await store.initialize()
    assert store._initialized is True

    collector = EventStreamCollector()
    raw_events = [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": "agent-batch-test",
            "action": f"op_{i}",
            "target": f"/file/{i}",
            "metadata": {},
        }
        for i in range(10)
    ]

    stored_nodes = await collector.collect_and_store_batch(
        store=store, source=EventSource.KERNEL_SYSCALL, raw_events=raw_events
    )
    assert len(stored_nodes) == 10

    # Invalidate cache check
    store._invalidate_path_cache("agent-batch-test")
    store._invalidate_path_cache(None)

    await store.close()
    assert store._initialized is False
