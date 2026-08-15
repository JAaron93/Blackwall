"""Integration tests for Error Handling and Resilience scenarios (Task 20.4).

Verifies multi-pillar disconnection resilience, database failover/retry handling,
and partial system degradation during high load or detector failures.
"""

import asyncio
from datetime import UTC, datetime, timedelta
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.resilience import (
    ResourceThrottler,
    SafeDetectionRunner,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def create_mock_event(
    agent_id: str,
    action: str,
    target: str,
    source: EventSource,
    risk_score: float = 0.5,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(UTC),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"session": "test-session"},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_pillar_disconnection_integration() -> None:
    """Verify multi-pillar collection resilience when one pillar experiences transient disconnection."""
    collector = EventStreamCollector(
        reconnect_max_attempts=3, reconnect_backoff_base=0.01
    )
    store = AttackGraphStore(in_memory=True)
    await store.initialize()

    kernel_disconnect_count = 0

    class TransientKernelStream:
        def __aiter__(self) -> "TransientKernelStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            nonlocal kernel_disconnect_count
            kernel_disconnect_count += 1
            if kernel_disconnect_count == 1:
                raise ConnectionResetError("eBPF probe socket lost")
            elif kernel_disconnect_count == 2:
                return {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": "agent-resilient",
                    "action": "execve",
                    "target": "/bin/sh",
                }
            raise StopAsyncIteration

    class StableIdentityStream:
        def __init__(self) -> None:
            self.delivered = False

        def __aiter__(self) -> "StableIdentityStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            if not self.delivered:
                self.delivered = True
                return {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": "agent-resilient",
                    "action": "vault_token_read",
                    "target": "secret/data/db",
                }
            raise StopAsyncIteration

    class StableToolCallStream:
        def __init__(self) -> None:
            self.delivered = False

        def __aiter__(self) -> "StableToolCallStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            if not self.delivered:
                self.delivered = True
                return {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": "agent-resilient",
                    "action": "bash_tool",
                    "target": "cat /etc/passwd",
                }
            raise StopAsyncIteration

    factories = {
        EventSource.KERNEL_SYSCALL: lambda: TransientKernelStream(),
        EventSource.IDENTITY_ACCESS: lambda: StableIdentityStream(),
        EventSource.TOOL_CALL: lambda: StableToolCallStream(),
    }

    collected_events: list[NormalizedEvent] = []
    async for event in collector.collect_all_streams(factories):
        collected_events.append(event)
        await store.insert_event(event)

    # All 3 streams should have delivered their events (kernel recovered on retry)
    assert len(collected_events) == 3
    sources = {e.source for e in collected_events}
    assert EventSource.KERNEL_SYSCALL in sources
    assert EventSource.IDENTITY_ACCESS in sources
    assert EventSource.TOOL_CALL in sources

    nodes = await store.get_all_nodes()
    assert len(nodes) == 3


@pytest.mark.asyncio
async def test_database_failover_integration(caplog: pytest.LogCaptureFixture) -> None:
    """Verify database retry and failover resilience during batch event ingestion."""
    mock_pool = MagicMock()
    mock_conn = AsyncMock()

    txn_attempts = 0

    class FailoverTransaction:
        async def __aenter__(self) -> "FailoverTransaction":
            nonlocal txn_attempts
            txn_attempts += 1
            if txn_attempts <= 2:
                raise ConnectionError("PostgreSQL master failover in progress")
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    mock_conn.transaction = MagicMock(side_effect=lambda: FailoverTransaction())
    mock_conn.fetch.return_value = []

    class AcquireCtx:
        async def __aenter__(self) -> AsyncMock:
            return mock_conn

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    mock_pool.acquire = MagicMock(side_effect=lambda: AcquireCtx())

    store = AttackGraphStore(pool=mock_pool, max_retries=3, retry_backoff_base=0.01)

    events = [
        create_mock_event("agent-failover", "execve", "/usr/bin/curl", EventSource.KERNEL_SYSCALL, 0.7),
        create_mock_event("agent-failover", "connect", "10.0.0.1:443", EventSource.PIPELINE_EXECUTION, 0.8),
    ]

    with caplog.at_level(logging.WARNING):
        nodes = await store.insert_events_batch(events)

    assert txn_attempts == 3
    assert len(nodes) == 2
    assert any("retrying" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_partial_system_degradation_integration(caplog: pytest.LogCaptureFixture) -> None:
    """Verify detection pipeline resilience and degradation under resource pressure and detector crashes."""
    runner = SafeDetectionRunner(default_timeout_seconds=0.05)
    throttler = ResourceThrottler(max_events_per_second=5, max_queue_size=10)

    # 1. Simulate burst of incoming events
    for _ in range(10):
        throttler.record_event()

    # Throttler indicates system under load
    assert throttler.should_throttle(current_queue_size=8) is True
    reduced_depth = throttler.get_analysis_depth(base_depth=6, current_queue_size=8)
    assert reduced_depth <= 3

    # 2. Parallel detection run where some engines crash or hang
    async def fast_swarm_detector() -> dict[str, Any]:
        return {"swarm_detected": True, "agents": ["a1", "a2"]}

    async def crashing_exploit_analyzer() -> dict[str, Any]:
        raise ValueError("Invalid AST node in decompiled payload")

    async def hanging_c2_detector() -> dict[str, Any]:
        await asyncio.sleep(0.5)
        return {"c2_beacon": True}

    # ValueError is contract violation and should raise if directly thrown
    with pytest.raises(ValueError, match="Invalid AST node"):
        await runner.run_safe(
            "exploit_analyzer", crashing_exploit_analyzer(), fallback={}
        )

    # For general non-programming exceptions (e.g. Runtime, network, memory)
    async def memory_error_detector() -> dict[str, Any]:
        raise MemoryError("Out of memory in matrix factorization")

    results = await runner.run_parallel_safe(
        {
            "swarm": (fast_swarm_detector(), {}, None),
            "memory_faulty": (memory_error_detector(), {"swarm_detected": False}, None),
            "hanging": (hanging_c2_detector(), {"c2_beacon": False}, 0.02),
        }
    )

    assert results["swarm"]["swarm_detected"] is True
    assert results["memory_faulty"]["swarm_detected"] is False
    assert results["hanging"]["c2_beacon"] is False
