"""Unit tests for error handling and resilience in Blackwall Advanced Threat Detection (Task 20)."""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    NormalizedEvent,
)


@pytest.mark.asyncio
async def test_pillar_failure_recovery(caplog: pytest.LogCaptureFixture) -> None:
    """Test pillar connection failure recovery with exponential backoff and multi-pillar continuity."""
    collector = EventStreamCollector(
        reconnect_max_attempts=3, reconnect_backoff_base=0.01
    )

    # 1. Non-AsyncIterable factory output raises TypeError immediately without backoff
    def bad_factory() -> Any:
        return 12345

    with pytest.raises(TypeError, match="non-AsyncIterable"):
        async for _ in collector.collect_with_reconnect(
            EventSource.KERNEL_SYSCALL, bad_factory
        ):
            pass

    # 2. Non-callable stream_factory raises ValueError immediately
    with pytest.raises(ValueError, match="must be a callable"):
        async for _ in collector.collect_with_reconnect(
            EventSource.KERNEL_SYSCALL, None  # type: ignore[arg-type]
        ):
            pass

    # 3. Stream that fails once and recovers on attempt 2
    attempts = 0

    class TransientStream:
        def __aiter__(self) -> "TransientStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ConnectionResetError("Connection lost to kernel probe")
            elif attempts == 2:
                return {
                    "event_id": "00000000-0000-4000-8000-000000000001",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": "agent-1",
                    "action": "execve",
                    "target": "/bin/ls",
                }
            else:
                raise StopAsyncIteration

    def transient_factory() -> TransientStream:
        return TransientStream()

    with caplog.at_level(logging.WARNING):
        events: list[NormalizedEvent] = []
        async for ev in collector.collect_with_reconnect(
            EventSource.KERNEL_SYSCALL, transient_factory
        ):
            events.append(ev)

    assert len(events) == 1
    assert events[0].agent_id == "agent-1"
    assert any("KERNEL_SYSCALL" in rec.message or "EventSource.KERNEL_SYSCALL" in str(rec.args) for rec in caplog.records)

    # 4. Multi-stream collection where one pillar fails permanently but others continue
    class PermanentFailingStream:
        def __aiter__(self) -> "PermanentFailingStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            raise RuntimeError("Pillar 1 dead")

    class HealthyStream:
        def __init__(self, agent: str) -> None:
            self.agent = agent
            self.yielded = False

        def __aiter__(self) -> "HealthyStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            if not self.yielded:
                self.yielded = True
                return {
                    "event_id": "00000000-0000-4000-8000-000000000002",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": self.agent,
                    "action": "token_access",
                    "target": "vault_secret",
                }
            raise StopAsyncIteration

    factories = {
        EventSource.KERNEL_SYSCALL: lambda: PermanentFailingStream(),
        EventSource.IDENTITY_ACCESS: lambda: HealthyStream("agent-healthy"),
    }

    multi_events: list[NormalizedEvent] = []
    async for ev in collector.collect_all_streams(factories):
        multi_events.append(ev)

    assert len(multi_events) == 1
    assert multi_events[0].agent_id == "agent-healthy"
    assert multi_events[0].source == EventSource.IDENTITY_ACCESS


@pytest.mark.asyncio
async def test_database_failure_handling(caplog: pytest.LogCaptureFixture) -> None:
    """Test database transaction retry, query timeout partial results, and connection failure handling."""
    from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore

    # 1. Store with simulated pool failure retrying up to 3 times
    mock_pool = MagicMock()
    mock_conn = AsyncMock()
    
    attempts = 0
    
    class FailingTransaction:
        async def __aenter__(self) -> "FailingTransaction":
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise ConnectionResetError("DB connection dropped")
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    mock_conn.transaction = MagicMock(side_effect=lambda: FailingTransaction())
    mock_conn.fetchrow.return_value = {
        "node_id": "00000000-0000-4000-8000-000000000003",
        "event_id": "00000000-0000-4000-8000-000000000003",
        "timestamp": datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC),
        "source": "kernel_syscall",
        "agent_id": "agent-db-test",
        "action": "write",
        "target": "/tmp/test",
        "metadata": "{}",
        "risk_score": 0.2,
        "incoming_edges": "[]",
        "outgoing_edges": "[]",
    }
    
    # acquire context manager
    class AcquireCtx:
        async def __aenter__(self) -> AsyncMock:
            return mock_conn
        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass
            
    mock_pool.acquire = MagicMock(side_effect=lambda: AcquireCtx())

    store = AttackGraphStore(pool=mock_pool, max_retries=3, retry_backoff_base=0.01)
    
    event = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000003",
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-db-test",
        action="write",
        target="/tmp/test",
        risk_score=0.2,
    )

    # insert_event should retry and succeed on attempt 3
    node = await store.insert_event(event)
    assert node.node_id == event.event_id
    assert attempts == 3

    # 2. Database permanent failure after 3 retries raises / returns error result
    mock_conn_fail = AsyncMock()
    fail_attempts = 0

    class PermFailingTransaction:
        async def __aenter__(self) -> "PermFailingTransaction":
            nonlocal fail_attempts
            fail_attempts += 1
            raise RuntimeError("Database connection permanently broken")

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    mock_conn_fail.transaction = MagicMock(side_effect=lambda: PermFailingTransaction())
    
    class AcquireCtxFail:
        async def __aenter__(self) -> AsyncMock:
            return mock_conn_fail
        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    mock_pool_fail = MagicMock()
    mock_pool_fail.acquire = MagicMock(side_effect=lambda: AcquireCtxFail())

    failing_store = AttackGraphStore(pool=mock_pool_fail, max_retries=3, retry_backoff_base=0.01)

    with pytest.raises(RuntimeError, match="permanently broken"):
        await failing_store.insert_event(event)
    assert fail_attempts == 3
    assert event.event_id not in failing_store._nodes

    # 3. link_events eviction on retry exhaustion to prevent stale cache divergence
    store_link = AttackGraphStore(pool=mock_pool_fail, max_retries=3, retry_backoff_base=0.01)
    ev_a = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000021",
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-link-test",
        action="read",
        target="/tmp/a",
        risk_score=0.1,
    )
    ev_b = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000022",
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-link-test",
        action="write",
        target="/tmp/b",
        risk_score=0.2,
    )
    # Pre-populate local cache
    store_link._nodes[ev_a.event_id] = AttackNode(node_id=ev_a.event_id, event=ev_a)
    store_link._nodes[ev_b.event_id] = AttackNode(node_id=ev_b.event_id, event=ev_b)

    with pytest.raises(RuntimeError, match="permanently broken"):
        await store_link.link_events(ev_a.event_id, ev_b.event_id, "CAUSED_BY")

    # Endpoints must be evicted from cache to avoid stale relationship state
    assert ev_a.event_id not in store_link._nodes
    assert ev_b.event_id not in store_link._nodes

    # 4. purge_events_before cache sync on retry exhaustion
    store_purge = AttackGraphStore(pool=mock_pool_fail, max_retries=3, retry_backoff_base=0.01)
    ev_old = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000031",
        timestamp=datetime(2026, 8, 15, 8, 0, 0, tzinfo=UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-purge-test",
        action="read",
        target="/tmp/old",
        risk_score=0.1,
    )
    ev_retained = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000032",
        timestamp=datetime(2026, 8, 15, 10, 0, 0, tzinfo=UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-purge-test",
        action="write",
        target="/tmp/retained",
        risk_score=0.1,
    )
    store_purge._nodes[ev_old.event_id] = AttackNode(node_id=ev_old.event_id, event=ev_old)
    store_purge._nodes[ev_retained.event_id] = AttackNode(node_id=ev_retained.event_id, event=ev_retained)
    
    with pytest.raises(RuntimeError, match="permanently broken"):
        await store_purge.purge_events_before(datetime(2026, 8, 15, 9, 0, 0, tzinfo=UTC))
    
    # Store cache must be cleared on retry exhaustion to prevent serving stale / dangling adjacency
    assert len(store_purge._nodes) == 0
    assert len(store_purge._edges) == 0

    # 5. Query timeout returning partial results
    in_memory_store = AttackGraphStore(in_memory=True)
    
    ev1 = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000011",
        timestamp=datetime(2026, 8, 15, 10, 0, 0, tzinfo=UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-timeout",
        action="execve",
        target="/bin/bash",
        risk_score=0.5,
    )
    ev2 = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000012",
        timestamp=datetime(2026, 8, 15, 10, 2, 0, tzinfo=UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-timeout",
        action="read",
        target="/etc/shadow",
        risk_score=0.8,
    )
    await in_memory_store.insert_event(ev1)
    await in_memory_store.insert_event(ev2)

    # Patch query_nodes with artificial delay to test timeout
    async def delayed_query_nodes(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(0.1)
        return []

    with patch.object(in_memory_store, "query_nodes", side_effect=delayed_query_nodes):
        with caplog.at_level(logging.WARNING):
            paths = await in_memory_store.query_paths(
                agent_id="agent-timeout",
                time_window=(
                    datetime(2026, 8, 15, 9, 0, 0, tzinfo=UTC),
                    datetime(2026, 8, 15, 11, 0, 0, tzinfo=UTC),
                ),
                min_path_length=2,
                timeout_seconds=0.01,
            )
            assert paths == []  # Gracefully returns empty / partial paths without crashing
            assert any("timed out" in rec.message.lower() for rec in caplog.records)


@pytest.mark.asyncio
async def test_detection_error_recovery(caplog: pytest.LogCaptureFixture) -> None:
    """Test detection algorithm crash isolation, per-detector timeouts, and resource throttling."""
    from blackwall.enterprise.advanced_threat_detection.resilience import (
        ResourceThrottler,
        SafeDetectionRunner,
    )

    runner = SafeDetectionRunner(default_timeout_seconds=0.1)

    # 1. Normal successful execution
    async def healthy_detector() -> list[str]:
        return ["threat_detected_A"]

    res = await runner.run_safe(
        "healthy_detector", healthy_detector(), fallback=[]
    )
    assert res == ["threat_detected_A"]

    # 2. Crash isolation: unhandled exception in detector does not crash caller, returns fallback
    async def crashing_detector() -> list[str]:
        raise ZeroDivisionError("Math error in graph traversal")

    with caplog.at_level(logging.WARNING):
        res_crash = await runner.run_safe(
            "crashing_detector", crashing_detector(), fallback=[]
        )
        assert res_crash == []
        assert any(
            "crashing_detector" in rec.message and "Math error" in rec.message
            for rec in caplog.records
        )

    # 3. Timeout isolation
    async def slow_detector() -> list[str]:
        await asyncio.sleep(0.5)
        return ["threat_too_late"]

    with caplog.at_level(logging.WARNING):
        res_timeout = await runner.run_safe(
            "slow_detector", slow_detector(), fallback=[], timeout_seconds=0.02
        )
        assert res_timeout == []
        assert any(
            "slow_detector" in rec.message and "timed out" in rec.message.lower()
            for rec in caplog.records
        )

    # 4. Immediate Exception Re-raising for TypeError/ValueError per Architecture Rule 8
    async def buggy_detector() -> list[str]:
        raise TypeError("Invalid parameter type passed to detector")

    with pytest.raises(TypeError, match="Invalid parameter type"):
        await runner.run_safe("buggy_detector", buggy_detector(), fallback=[])

    # 5. Parallel isolated execution of multiple detectors
    async def detector_1() -> str:
        return "result_1"

    async def detector_2() -> str:
        raise RuntimeError("Detector 2 failed")

    async def detector_3() -> str:
        await asyncio.sleep(0.5)
        return "result_3"

    parallel_results = await runner.run_parallel_safe(
        {
            "d1": (detector_1(), "fallback_1", None),
            "d2": (detector_2(), "fallback_2", None),
            "d3": (detector_3(), "fallback_3", 0.02),
        }
    )
    assert parallel_results["d1"] == "result_1"
    assert parallel_results["d2"] == "fallback_2"
    assert parallel_results["d3"] == "fallback_3"

    # 6. ResourceThrottler capacity monitoring and dynamic degradation
    throttler = ResourceThrottler(
        max_events_per_second=10,
        max_queue_size=5,
    )
    assert throttler.should_throttle(current_queue_size=2) is False
    assert throttler.get_analysis_depth(base_depth=5, current_queue_size=2) == 5

    # High queue size triggers throttling and depth degradation
    assert throttler.should_throttle(current_queue_size=10) is True
    assert throttler.get_analysis_depth(base_depth=5, current_queue_size=10) < 5

    # Rate limiting trigger
    for _ in range(15):
        throttler.record_event()
    assert throttler.should_throttle(current_queue_size=0) is True
