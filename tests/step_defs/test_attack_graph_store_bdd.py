"""BDD Step Definitions for Attack Graph Store (`tests/features/attack_graph_store.feature`)."""

import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Tuple

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from tests.step_defs.async_utils import run_async

scenarios("../features/attack_graph_store.feature")


class AttackGraphStoreBDDState:
    def __init__(self) -> None:
        self.store: AttackGraphStore | None = None
        self.events: List[NormalizedEvent] = []
        self.nodes: List[AttackNode] = []
        self.event1: NormalizedEvent | None = None
        self.event2: NormalizedEvent | None = None
        self.queried_paths: List[AttackPath] = []
        self.benchmark_elapsed_ms: float = 0.0
        self.limit_exceptions: List[Exception] = []
        self.time_window: Tuple[datetime, datetime] = (
            datetime.now(timezone.utc) - timedelta(hours=1),
            datetime.now(timezone.utc) + timedelta(hours=24),
        )


@pytest.fixture
def state() -> AttackGraphStoreBDDState:
    s = AttackGraphStoreBDDState()
    yield s
    if s.store:
        run_async(s.store.close())


# Scenario 1: inserting a NormalizedEvent creates a node with temporal ordering preserved
@given("an initialized AttackGraphStore instance")
def given_initialized_store_instance(state: AttackGraphStoreBDDState) -> None:
    async def _init_store() -> AttackGraphStore:
        st = AttackGraphStore(in_memory=True)
        await st.initialize()
        return st

    state.store = run_async(_init_store())


@when("multiple NormalizedEvents with different timestamps are inserted")
def when_multiple_events_inserted(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None
    base_time = datetime.now(timezone.utc)
    t1 = base_time + timedelta(seconds=10)
    t2 = base_time + timedelta(seconds=20)
    t3 = base_time + timedelta(seconds=30)

    e1 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=t1,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-temporal-01",
        action="read",
        target="/etc/passwd",
        risk_score=0.2,
    )
    e2 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=t2,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-temporal-01",
        action="execve",
        target="/usr/bin/python3",
        risk_score=0.4,
    )
    e3 = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=t3,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-temporal-01",
        action="connect",
        target="192.168.1.10:8080",
        risk_score=0.8,
    )

    state.events = [e1, e2, e3]

    async def _insert_events() -> None:
        # Insert out of order to verify temporal sorting in query
        await state.store.insert_event(e3)
        await state.store.insert_event(e1)
        await state.store.insert_event(e2)

    run_async(_insert_events())


@then("each event creates an AttackNode in the store")
def then_each_event_creates_node(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None
    async def _verify_nodes() -> List[AttackNode]:
        fetched: List[AttackNode] = []
        for e in state.events:
            node = await state.store.get_node(e.event_id)
            assert node is not None
            assert node.event.event_id == e.event_id
            fetched.append(node)
        return fetched

    state.nodes = run_async(_verify_nodes())
    assert len(state.nodes) == len(state.events)


@then("querying nodes returns them ordered by timestamp ascending")
def and_querying_nodes_ordered(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None
    async def _query() -> List[AttackNode]:
        return await state.store.query_nodes(
            agent_id="agent-temporal-01",
            time_window=state.time_window,
        )

    ordered_nodes = run_async(_query())
    assert len(ordered_nodes) == 3
    assert ordered_nodes[0].event.timestamp < ordered_nodes[1].event.timestamp
    assert ordered_nodes[1].event.timestamp < ordered_nodes[2].event.timestamp


# Scenario 2: linking two events creates a directed edge with the specified relationship type
@given("an initialized AttackGraphStore containing two inserted events")
def given_store_with_two_events(state: AttackGraphStoreBDDState) -> None:
    async def _setup() -> Tuple[AttackGraphStore, NormalizedEvent, NormalizedEvent]:
        st = AttackGraphStore(in_memory=True)
        await st.initialize()
        now = datetime.now(timezone.utc)
        ev1 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now,
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-link-01",
            action="open",
            target="/tmp/payload.sh",
            risk_score=0.3,
        )
        ev2 = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=5),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-link-01",
            action="execve",
            target="/tmp/payload.sh",
            risk_score=0.9,
        )
        await st.insert_event(ev1)
        await st.insert_event(ev2)
        return st, ev1, ev2

    state.store, state.event1, state.event2 = run_async(_setup())


@when('link_events is called with relationship type "EXECUTES_NEXT"')
def when_link_events(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None
    assert state.event1 is not None
    assert state.event2 is not None

    async def _link() -> None:
        await state.store.link_events(
            state.event1.event_id,
            state.event2.event_id,
            "EXECUTES_NEXT",
        )

    run_async(_link())


@then(
    "a directed edge is created connecting the source node outgoing_edges to target node incoming_edges"
)
def then_directed_edge_created(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None
    assert state.event1 is not None
    assert state.event2 is not None

    async def _check_edge() -> Tuple[AttackNode | None, AttackNode | None]:
        n1 = await state.store.get_node(state.event1.event_id)
        n2 = await state.store.get_node(state.event2.event_id)
        return n1, n2

    src_node, tgt_node = run_async(_check_edge())
    assert src_node is not None
    assert tgt_node is not None

    assert len(src_node.outgoing_edges) == 1
    assert len(tgt_node.incoming_edges) == 1
    assert src_node.outgoing_edges[0] == tgt_node.incoming_edges[0]


# Scenario 3: querying paths returns only paths with at least min_path_length nodes within the time window
@given("an initialized AttackGraphStore with events forming paths of varying lengths")
def given_store_with_varying_length_paths(state: AttackGraphStoreBDDState) -> None:
    async def _setup() -> AttackGraphStore:
        st = AttackGraphStore(in_memory=True)
        await st.initialize()

        base_t = datetime.now(timezone.utc)
        agent_id = "agent-path-len-01"

        # Path 1: 4 events (spaced 30s apart, within 600s window)
        for i in range(4):
            e = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=base_t + timedelta(seconds=i * 30),
                source=EventSource.KERNEL_SYSCALL,
                agent_id=agent_id,
                action=f"action_long_{i}",
                target=f"target_{i}",
                risk_score=0.5,
            )
            await st.insert_event(e)

        # Gap of 30 minutes (1800s > 600s) to split into a separate path
        base_t_short = base_t + timedelta(minutes=30)
        # Path 2: 2 events (spaced 30s apart)
        for j in range(2):
            e = NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=base_t_short + timedelta(seconds=j * 30),
                source=EventSource.KERNEL_SYSCALL,
                agent_id=agent_id,
                action=f"action_short_{j}",
                target=f"target_short_{j}",
                risk_score=0.4,
            )
            await st.insert_event(e)

        return st

    state.store = run_async(_setup())


@when("query_paths is called with min_path_length of 3")
def when_query_paths_min_length_3(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None

    async def _query() -> List[AttackPath]:
        return await state.store.query_paths(
            agent_id="agent-path-len-01",
            time_window=state.time_window,
            min_path_length=3,
        )

    state.queried_paths = run_async(_query())


@then("only attack paths containing at least 3 nodes within the time window are returned")
def then_only_min_length_paths_returned(state: AttackGraphStoreBDDState) -> None:
    assert len(state.queried_paths) == 1
    assert len(state.queried_paths[0].nodes) == 4
    for path in state.queried_paths:
        assert len(path.nodes) >= 3


# Scenario 4: path query on a 17K+ event graph completes in under 500ms (warmup run excluded)
@given("an initialized AttackGraphStore populated with over 17000 normalized events")
def given_store_with_17k_events(state: AttackGraphStoreBDDState) -> None:
    async def _setup() -> AttackGraphStore:
        st = AttackGraphStore(in_memory=True)
        await st.initialize()

        base_t = datetime.now(timezone.utc)
        agent_id = "agent-17k"

        # Bulk generate 17,500 events
        events: List[NormalizedEvent] = []
        for i in range(17500):
            events.append(
                NormalizedEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=base_t + timedelta(milliseconds=i * 50),
                    source=EventSource.KERNEL_SYSCALL,
                    agent_id=agent_id,
                    action="execve" if i % 2 == 0 else "read",
                    target=f"/var/log/file_{i % 100}.log",
                    risk_score=0.1 + (i % 80) / 100.0,
                )
            )

        # Populate store
        for ev in events:
            await st.insert_event(ev)

        return st

    state.store = run_async(_setup())


@when("query_paths is executed with a warmup run followed by a benchmark run")
def when_query_paths_warmup_and_benchmark(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None

    async def _run_benchmark() -> Tuple[List[AttackPath], float]:
        agent_id = "agent-17k"
        time_win = (
            datetime.now(timezone.utc) - timedelta(hours=1),
            datetime.now(timezone.utc) + timedelta(hours=24),
        )

        # 1. Warmup run (excluded from measurement)
        await state.store.query_paths(
            agent_id=agent_id,
            time_window=time_win,
            min_path_length=2,
        )

        # 2. Benchmark run
        t0 = time.perf_counter()
        paths = await state.store.query_paths(
            agent_id=agent_id,
            time_window=time_win,
            min_path_length=2,
        )
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0
        return paths, elapsed_ms

    state.queried_paths, state.benchmark_elapsed_ms = run_async(_run_benchmark())


@then("the benchmark query execution time is under 500 milliseconds")
def then_benchmark_query_under_500ms(state: AttackGraphStoreBDDState) -> None:
    assert len(state.queried_paths) > 0
    assert state.benchmark_elapsed_ms < 500.0, (
        f"Path query took {state.benchmark_elapsed_ms:.2f}ms, expected < 500ms"
    )


# Scenario 5: non-positive limit parameter raises ValueError
@when("query_nodes is called with a non-positive limit parameter")
def when_query_nodes_non_positive_limit(state: AttackGraphStoreBDDState) -> None:
    assert state.store is not None

    async def _test_limits() -> List[Exception]:
        exceptions: List[Exception] = []
        for lim in [0, -1, -10]:
            try:
                await state.store.query_nodes(
                    agent_id="agent-limit-test",
                    time_window=state.time_window,
                    limit=lim,
                )
            except ValueError as exc:
                exceptions.append(exc)
        return exceptions

    state.limit_exceptions = run_async(_test_limits())


@then("a ValueError is raised stating limit must be positive")
def then_value_error_raised_limit_must_be_positive(
    state: AttackGraphStoreBDDState,
) -> None:
    assert len(state.limit_exceptions) == 3
    for exc in state.limit_exceptions:
        assert isinstance(exc, ValueError)
        assert "limit must be positive" in str(exc).lower()
