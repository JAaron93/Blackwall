"""BDD Step Definitions for Event Stream Collector (`tests/features/event_stream_collector.feature`)."""

from datetime import UTC, datetime
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.collector import EventStreamCollector
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.validators import validate_uuid_v4_format
from tests.step_defs.async_utils import run_async

scenarios("../features/event_stream_collector.feature")


class CollectorBDDState:
    def __init__(self):
        self.collector = EventStreamCollector(
            reconnect_max_attempts=3,
            reconnect_backoff_base=0.01,
        )
        self.raw_event = None
        self.normalized_event = None
        self.pillar_raw_events = {}
        self.pillar_normalized_events = {}
        self.stream_factory = None
        self.attempts_count = 0
        self.collected_events = []


@pytest.fixture
def collector_state():
    return CollectorBDDState()


# Scenario 1 steps
@given("a raw kernel syscall event payload")
def given_raw_kernel_syscall_event(collector_state):
    collector_state.raw_event = {
        "syscall": "sys_execve",
        "target": "/bin/bash",
        "agent_id": "agent-kernel-bdd",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@when("the event stream collector normalizes the event for KERNEL_SYSCALL")
def when_normalize_kernel_event(collector_state):
    collector_state.normalized_event = collector_state.collector.normalize_event(
        EventSource.KERNEL_SYSCALL, collector_state.raw_event
    )


@then("the normalized event source should be KERNEL_SYSCALL")
def then_source_is_kernel(collector_state):
    assert collector_state.normalized_event.source == EventSource.KERNEL_SYSCALL


@then("the normalized event timestamp should be in UTC timezone")
def then_timestamp_is_utc(collector_state):
    assert collector_state.normalized_event.timestamp.tzinfo is not None
    assert collector_state.normalized_event.timestamp.tzinfo == UTC


@then("the normalized event ID should be a valid UUID v4")
def then_event_id_is_uuid_v4(collector_state):
    assert validate_uuid_v4_format(collector_state.normalized_event.event_id)


# Scenario 2 steps
@given("raw event payloads for all five pillar sources")
def given_raw_events_all_pillars(collector_state):
    now_str = datetime.now(UTC).isoformat()
    collector_state.pillar_raw_events = {
        EventSource.KERNEL_SYSCALL: {
            "syscall": "sys_clone",
            "target": "process",
            "agent_id": "agent-p1",
            "timestamp": now_str,
        },
        EventSource.TOOL_CALL: {
            "tool_name": "bash_exec",
            "target": "ls -la",
            "agent_id": "agent-p2",
            "timestamp": now_str,
        },
        EventSource.IDENTITY_ACCESS: {
            "action": "token_grant",
            "target": "vault",
            "agent_id": "agent-p3",
            "timestamp": now_str,
        },
        EventSource.PIPELINE_EXECUTION: {
            "action": "pipeline_run",
            "target": "build_job",
            "agent_id": "agent-p4",
            "timestamp": now_str,
        },
        EventSource.FORENSIC_ALERT: {
            "action": "anomaly_alert",
            "target": "auth_log",
            "agent_id": "agent-p5",
            "timestamp": now_str,
        },
    }


@when("the event stream collector normalizes each raw event for its pillar source")
def when_normalize_all_pillars(collector_state):
    for source, raw_ev in collector_state.pillar_raw_events.items():
        collector_state.pillar_normalized_events[source] = (
            collector_state.collector.normalize_event(source, raw_ev)
        )


@then("each normalized event source matches its corresponding EventSource enum value")
def then_each_source_matches_enum(collector_state):
    for expected_source, norm_ev in collector_state.pillar_normalized_events.items():
        assert norm_ev.source == expected_source


# Scenario 3 steps
@given('a raw event payload with agent ID "agent-007" and metadata')
def given_raw_event_with_agent_id(collector_state):
    collector_state.raw_event = {
        "action": "read_secret",
        "target": "vault_path",
        "agent_id": "agent-007",
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": {"env": "production", "client": "test"},
    }


@when("the event stream collector normalizes the event")
def when_normalize_event_general(collector_state):
    collector_state.normalized_event = collector_state.collector.normalize_event(
        EventSource.TOOL_CALL, collector_state.raw_event
    )


@then("the normalized event metadata should contain ingested_at and pillar_source")
def then_metadata_enriched(collector_state):
    meta = collector_state.normalized_event.metadata
    assert "ingested_at" in meta
    assert meta["pillar_source"] == EventSource.TOOL_CALL.value
    assert meta["env"] == "production"


@then('the normalized event agent_id should be "agent-007"')
def then_agent_id_matches(collector_state):
    assert collector_state.normalized_event.agent_id == "agent-007"


# Scenario 4 steps
@given("a failing stream factory that succeeds on retry")
def given_failing_stream_factory(collector_state):
    collector_state.attempts_count = 0

    def stream_factory():
        collector_state.attempts_count += 1
        if collector_state.attempts_count == 1:
            raise ConnectionError("Pillar stream connection lost")

        async def event_generator():
            yield {
                "syscall": "sys_execve",
                "target": "/usr/bin/python",
                "agent_id": "agent-reconnect-bdd",
                "timestamp": datetime.now(UTC).isoformat(),
            }

        return event_generator()

    collector_state.stream_factory = stream_factory


@when("collecting events with reconnect enabled for KERNEL_SYSCALL")
def when_collect_with_reconnect(collector_state):
    async def _collect():
        events = []
        async for ev in collector_state.collector.collect_with_reconnect(
            EventSource.KERNEL_SYSCALL, collector_state.stream_factory
        ):
            events.append(ev)
        return events

    collector_state.collected_events = run_async(_collect())


@then("events should be successfully collected after reconnect attempt")
def then_reconnect_success(collector_state):
    assert len(collector_state.collected_events) == 1
    assert collector_state.collected_events[0].agent_id == "agent-reconnect-bdd"
    assert collector_state.attempts_count == 2
