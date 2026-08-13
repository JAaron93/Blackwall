"""BDD Step Definitions for Performance and SLA Validation (`tests/features/performance_sla.feature`)."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from tests.step_defs.async_utils import run_async

scenarios("../features/performance_sla.feature")


class PerformanceBDDState:
    def __init__(self):
        self.collector = EventStreamCollector()
        self.store = AttackGraphStore(in_memory=True)
        self.detector = AgentSwarmDetector(store=self.store)
        self.correlator = PathCorrelator(store=self.store)
        self.latencies = {}
        self.query_paths_result = []
        self.query_elapsed_ms = 0.0
        self.throughput_rate = 0.0
        self.fingerprint_result = ""
        self.fingerprint_elapsed_s = 0.0
        self.incremental_fp_result = ""
        self.incremental_fp_elapsed_s = 0.0
        self.agent_id = "agent-bdd-perf"


@pytest.fixture
def state():
    return PerformanceBDDState()


# Scenario 1: event processing latency is under 100ms
@given("an EventStreamCollector receiving events from all five Blackwall pillars")
def given_collector_all_pillars(state):
    run_async(state.store.initialize())


@when("raw events from each pillar are normalized after a warmup run")
def when_events_normalized_after_warmup(state):
    now = datetime.now(UTC)
    raw_payloads = {
        EventSource.KERNEL_SYSCALL: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-k",
            "action": "execve",
            "target": "/bin/ls",
            "metadata": {},
        },
        EventSource.TOOL_CALL: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-t",
            "action": "bash",
            "target": "echo hello",
            "metadata": {},
        },
        EventSource.IDENTITY_ACCESS: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-i",
            "action": "get_token",
            "target": "vault://key",
            "metadata": {},
        },
        EventSource.PIPELINE_EXECUTION: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-p",
            "action": "preprocess",
            "target": "pipe://data",
            "metadata": {},
        },
        EventSource.FORENSIC_ALERT: {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": "agent-f",
            "action": "alert",
            "target": "span://01",
            "metadata": {},
        },
    }

    # Warmup
    for src, raw in raw_payloads.items():
        state.collector.normalize_event(src, raw)

    # Measure
    for src, raw in raw_payloads.items():
        t0 = time.perf_counter()
        ev = state.collector.normalize_event(src, raw)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        assert ev is not None
        state.latencies[src] = elapsed_ms


@then("the event normalization latency for each pillar should be under 100 milliseconds")
def then_latencies_under_100ms(state):
    for src, lat_ms in state.latencies.items():
        assert lat_ms < 100.0, f"Latency for {src} was {lat_ms}ms, expected < 100ms"


# Scenario 2: path query on 17K+ event graph completes in under 500ms
@given("an AttackGraphStore populated with over 17000 events")
def given_store_17k_events(state):
    run_async(state.store.initialize())
    now = datetime.now(UTC)
    events = []
    # 17,000 background events
    for i in range(17000):
        events.append(
            NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now + timedelta(milliseconds=i * 20),
                source=EventSource.KERNEL_SYSCALL,
                agent_id=f"bg-agent-{i % 100}",
                action="step",
                target="/tmp",
                metadata={},
                risk_score=0.1,
            )
        )
    # 50 target events
    for j in range(50):
        events.append(
            NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now + timedelta(seconds=j * 10),
                source=EventSource.KERNEL_SYSCALL,
                agent_id=state.agent_id,
                action="execve" if j % 2 == 0 else "connect",
                target="/bin/sh" if j % 2 == 0 else "1.2.3.4:80",
                metadata={},
                risk_score=0.8,
            )
        )
    run_async(state.store.insert_events_batch(events))


@when("a multi-hop attack path query is executed for a target agent after a warmup query")
def when_path_query_executed(state):
    now = datetime.now(UTC)
    tw = (now - timedelta(minutes=5), now + timedelta(hours=2))

    async def _run():
        # Warmup
        await state.store.query_paths(state.agent_id, tw, min_path_length=2)
        t0 = time.perf_counter()
        paths = await state.store.query_paths(state.agent_id, tw, min_path_length=2)
        state.query_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        state.query_paths_result = paths

    run_async(_run())


@then("the attack path query latency should be under 500 milliseconds and return valid paths")
def then_query_under_500ms(state):
    assert len(state.query_paths_result) >= 1
    assert (
        state.query_elapsed_ms < 500.0
    ), f"Query elapsed: {state.query_elapsed_ms:.2f}ms"


# Scenario 3: system sustains 1,000 events/second for at least 5 minutes without errors
@given("an event stream workload of 1000 events per second")
def given_workload_1000eps(state):
    run_async(state.store.initialize())


@when("the system processes and ingests the sustained batch workload")
def when_process_sustained_workload(state):
    now = datetime.now(UTC)
    rounds = 5
    batch_size = 1000
    total_events = rounds * batch_size

    async def _run():
        total_nodes = 0
        t0 = time.perf_counter()
        for r in range(rounds):
            raw_batch = [
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": (now + timedelta(seconds=r, milliseconds=i)).isoformat(),
                    "agent_id": f"agent-sustained-{i % 20}",
                    "action": "syscall_exec",
                    "target": f"/bin/test_{r}_{i}",
                    "metadata": {"round": r},
                    "risk_score": 0.2,
                }
                for i in range(batch_size)
            ]
            nodes = await state.collector.collect_and_store_batch(
                state.store, EventSource.KERNEL_SYSCALL, raw_batch
            )
            total_nodes += len(nodes)
        total_time = time.perf_counter() - t0
        state.throughput_rate = total_nodes / total_time
        assert total_nodes == total_events

    run_async(_run())


@then("the processing throughput should exceed 1000 events per second without errors")
def then_throughput_exceeds_1000eps(state):
    assert (
        state.throughput_rate >= 1000.0
    ), f"Throughput was {state.throughput_rate:.2f} eps, expected >= 1000"


# Scenario 4: behavioral fingerprint for a 1-hour window is computed in under 2 seconds
@given("an agent with 600 events across a 1-hour time window")
def given_agent_600_events(state):
    run_async(state.store.initialize())
    now = datetime.now(UTC)
    events = []
    for i in range(600):
        events.append(
            NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=3600 - (i * 6)),
                source=EventSource.TOOL_CALL,
                agent_id=state.agent_id,
                action=f"action_{i % 5}",
                target=f"target_{i % 3}",
                metadata={},
                risk_score=0.4,
            )
        )
    run_async(state.store.insert_events_batch(events))


@when("the behavioral fingerprint is computed after a warmup run")
def when_fingerprint_computed(state):
    now = datetime.now(UTC)

    async def _run():
        # Warmup
        await state.detector.fingerprint_agent(
            agent_id=state.agent_id, window=3600, end_time=now
        )
        t0 = time.perf_counter()
        fp = await state.detector.fingerprint_agent(
            agent_id=state.agent_id, window=3600, end_time=now
        )
        state.fingerprint_elapsed_s = time.perf_counter() - t0
        state.fingerprint_result = fp

    run_async(_run())


@then("the fingerprint calculation should complete in under 2 seconds and produce a valid 64-character hash")
def then_fingerprint_valid(state):
    assert len(state.fingerprint_result) == 64
    assert (
        state.fingerprint_elapsed_s < 2.0
    ), f"Fingerprint took {state.fingerprint_elapsed_s:.2f}s"


# Scenario 5: incremental fingerprint update computes in under 2 seconds for a 1-hour window
@given("an agent with existing behavioral fingerprint state")
def given_existing_fp_state(state):
    now = datetime.now(UTC)
    init_events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now - timedelta(seconds=100),
            source=EventSource.TOOL_CALL,
            agent_id=state.agent_id,
            action="init_action",
            target="init_target",
            metadata={},
            risk_score=0.2,
        )
    ]
    state.detector.update_fingerprint_incremental(
        agent_id=state.agent_id, new_events=init_events, window=3600
    )


@when("new events are incrementally added to the agent fingerprint")
def when_incremental_fp_added(state):
    now = datetime.now(UTC)
    new_events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=i),
            source=EventSource.TOOL_CALL,
            agent_id=state.agent_id,
            action=f"new_op_{i}",
            target=f"target_{i}",
            metadata={},
            risk_score=0.3,
        )
        for i in range(10)
    ]
    t0 = time.perf_counter()
    state.incremental_fp_result = state.detector.update_fingerprint_incremental(
        agent_id=state.agent_id, new_events=new_events, window=3600
    )
    state.incremental_fp_elapsed_s = time.perf_counter() - t0


@then("the incremental update should complete in under 2 seconds and produce an updated hash")
def then_incremental_fp_valid(state):
    assert len(state.incremental_fp_result) == 64
    assert (
        state.incremental_fp_elapsed_s < 2.0
    ), f"Incremental update took {state.incremental_fp_elapsed_s:.2f}s"
