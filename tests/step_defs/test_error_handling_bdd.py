"""BDD Step Definitions for Error Handling and Resilience (`tests/features/error_handling.feature`)."""

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.resilience import (
    ResourceThrottler,
    SafeDetectionRunner,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from tests.step_defs.async_utils import run_async

scenarios("../features/error_handling.feature")


class ErrorHandlingBDDState:
    def __init__(self) -> None:
        self.collector: EventStreamCollector | None = None
        self.factories: dict[EventSource, Any] = {}
        self.collected_events: list[NormalizedEvent] = []

        self.store: AttackGraphStore | None = None
        self.mock_pool: MagicMock | None = None
        self.mock_conn: AsyncMock | None = None
        self.inserted_node: AttackNode | None = None
        self.txn_attempts: int = 0

        self.runner: SafeDetectionRunner | None = None
        self.detector_result: Any = None

        self.throttler: ResourceThrottler | None = None
        self.recommended_depth: int = 0


@pytest.fixture
def state() -> ErrorHandlingBDDState:
    return ErrorHandlingBDDState()


# --- Scenario 1: Multi-pillar collection with failing pillar ---
@given("a multi-pillar collector with one failing pillar and one healthy pillar")
def given_multi_pillar_collector(state: ErrorHandlingBDDState) -> None:
    state.collector = EventStreamCollector(
        reconnect_max_attempts=2,
        reconnect_backoff_base=0.01,
    )

    class FailingKernelStream:
        def __aiter__(self) -> "FailingKernelStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            raise ConnectionError("Kernel stream permanent failure")

    class HealthyIdentityStream:
        def __init__(self) -> None:
            self.delivered = False

        def __aiter__(self) -> "HealthyIdentityStream":
            return self

        async def __anext__(self) -> dict[str, Any]:
            if not self.delivered:
                self.delivered = True
                return {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent_id": "agent-bdd-healthy",
                    "action": "token_issue",
                    "target": "auth_service",
                }
            raise StopAsyncIteration

    state.factories = {
        EventSource.KERNEL_SYSCALL: lambda: FailingKernelStream(),
        EventSource.IDENTITY_ACCESS: lambda: HealthyIdentityStream(),
    }


@when("the collector ingests from all pillar streams concurrently")
def when_collector_ingests_all_streams(state: ErrorHandlingBDDState) -> None:
    async def _collect() -> list[NormalizedEvent]:
        events = []
        if state.collector:
            async for ev in state.collector.collect_all_streams(state.factories):
                events.append(ev)
        return events

    state.collected_events = run_async(_collect())


@then("events from the healthy pillar are successfully received without pipeline interruption")
def then_healthy_events_received(state: ErrorHandlingBDDState) -> None:
    assert len(state.collected_events) == 1
    assert state.collected_events[0].agent_id == "agent-bdd-healthy"
    assert state.collected_events[0].source == EventSource.IDENTITY_ACCESS


# --- Scenario 2: Attack graph store retries transactions ---
@given("an attack graph store with transient transaction failures")
def given_store_with_transient_failures(state: ErrorHandlingBDDState) -> None:
    state.mock_pool = MagicMock()
    state.mock_conn = AsyncMock()
    state.txn_attempts = 0

    class FailingTransaction:
        async def __aenter__(self) -> "FailingTransaction":
            state.txn_attempts += 1
            if state.txn_attempts < 2:
                raise ConnectionResetError("Transient DB connection drop")
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    state.mock_conn.transaction = MagicMock(side_effect=lambda: FailingTransaction())
    state.mock_conn.fetchrow.return_value = {
        "node_id": "00000000-0000-4000-8000-000000000099",
        "event_id": "00000000-0000-4000-8000-000000000099",
        "timestamp": datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC),
        "source": "kernel_syscall",
        "agent_id": "agent-bdd-retry",
        "action": "open",
        "target": "/etc/passwd",
        "metadata": "{}",
        "risk_score": 0.3,
        "incoming_edges": "[]",
        "outgoing_edges": "[]",
    }

    class AcquireCtx:
        async def __aenter__(self) -> AsyncMock:
            return state.mock_conn

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    state.mock_pool.acquire = MagicMock(side_effect=lambda: AcquireCtx())
    state.store = AttackGraphStore(
        pool=state.mock_pool, max_retries=3, retry_backoff_base=0.01
    )


@when("an event is inserted into the attack graph store")
def when_event_inserted_with_retry(state: ErrorHandlingBDDState) -> None:
    event = NormalizedEvent(
        event_id="00000000-0000-4000-8000-000000000099",
        timestamp=datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-retry",
        action="open",
        target="/etc/passwd",
        risk_score=0.3,
    )

    async def _insert() -> AttackNode:
        assert state.store is not None
        return await state.store.insert_event(event)

    state.inserted_node = run_async(_insert())


@then("the store retries the database operation and commits successfully")
def then_store_retries_and_commits(state: ErrorHandlingBDDState) -> None:
    assert state.txn_attempts == 2
    assert state.inserted_node is not None
    assert str(state.inserted_node.node_id) == "00000000-0000-4000-8000-000000000099"


# --- Scenario 3: Detection runner isolates crashes ---
@given("a safe detection runner and a faulty detection algorithm")
def given_runner_and_faulty_algorithm(state: ErrorHandlingBDDState) -> None:
    state.runner = SafeDetectionRunner(default_timeout_seconds=0.1)


@when("the detection algorithm raises an unhandled runtime error")
def when_detector_crashes(state: ErrorHandlingBDDState) -> None:
    async def faulty_algorithm() -> list[str]:
        raise RuntimeError("Simulated unhandled detector failure")

    async def _run() -> Any:
        assert state.runner is not None
        return await state.runner.run_safe(
            detector_name="faulty_algo",
            coro=faulty_algorithm(),
            fallback=["fallback_result"],
        )

    state.detector_result = run_async(_run())


@then("the safe detection runner captures the error and returns the fallback value")
def then_fallback_returned(state: ErrorHandlingBDDState) -> None:
    assert state.detector_result == ["fallback_result"]


# --- Scenario 4: Resource throttler reduces depth under load ---
@given("a resource throttler under high event load")
def given_throttler_under_load(state: ErrorHandlingBDDState) -> None:
    state.throttler = ResourceThrottler(
        max_events_per_second=10,
        max_queue_size=5,
    )
    for _ in range(15):
        state.throttler.record_event()


@when("querying for recommended analysis depth")
def when_querying_analysis_depth(state: ErrorHandlingBDDState) -> None:
    assert state.throttler is not None
    state.recommended_depth = state.throttler.get_analysis_depth(
        base_depth=6, current_queue_size=6
    )


@then("the throttler reduces the analysis depth to maintain pipeline throughput")
def then_depth_reduced(state: ErrorHandlingBDDState) -> None:
    assert state.recommended_depth <= 3
