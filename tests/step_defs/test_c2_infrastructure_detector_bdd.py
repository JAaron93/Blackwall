"""BDD Step Definitions for C2 Infrastructure Detector (`tests/features/c2_infrastructure_detector.feature`)."""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    C2Evidence,
)
from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
from tests.step_defs.async_utils import run_async

scenarios("../features/c2_infrastructure_detector.feature")


class C2BDDState:
    def __init__(self):
        self.detector = C2InfrastructureDetector()
        self.url = None
        self.classification = None
        self.agent_id = None
        self.target_url = None
        self.time_window = None
        self.evidence_list = []
        self.beaconing_result = None
        self.persistence_indicators = []


@pytest.fixture
def c2_state():
    return C2BDDState()


# Scenario 1: a Pastebin URL is classified as a known C2 endpoint
@given(parsers.parse('a URL string "{url}"'))
def given_url_string(c2_state, url):
    c2_state.url = url


@when("the C2 detector classifies the endpoint")
def when_classify_endpoint(c2_state):
    c2_state.classification = run_async(
        c2_state.detector.classify_endpoint(c2_state.url)
    )


@then(parsers.parse('the classification result should be "{expected}"'))
def then_classification_result(c2_state, expected):
    assert c2_state.classification == expected


# Scenario 2: an agent accessing a C2 endpoint generates C2Evidence with the endpoint in c2_endpoints
@given(parsers.parse('an agent "{agent_id}" accessing a C2 endpoint "{endpoint}"'))
def given_agent_accessing_c2_endpoint(c2_state, agent_id, endpoint):
    c2_state.agent_id = agent_id
    c2_state.target_url = endpoint
    now = datetime.now(timezone.utc)
    c2_state.time_window = (now - timedelta(minutes=5), now + timedelta(minutes=5))

    evt = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action="http_request",
        target=endpoint,
        risk_score=0.8,
    )
    c2_state.detector.record_event(evt)


@when(parsers.parse('the C2 detector detects C2 establishment for "{agent_id}" over the time window'))
def when_detect_c2_establishment(c2_state, agent_id):
    c2_state.evidence_list = run_async(
        c2_state.detector.detect_c2_establishment(agent_id, c2_state.time_window)
    )


@then(parsers.parse('C2 evidence should be generated containing "{endpoint}" in c2_endpoints'))
def then_c2_evidence_contains_endpoint(c2_state, endpoint):
    assert len(c2_state.evidence_list) >= 1
    evidence = c2_state.evidence_list[0]
    assert isinstance(evidence, C2Evidence)
    assert endpoint in evidence.c2_endpoints


# Scenario 3: periodic connections at regular intervals are identified as beaconing
@given(parsers.parse('an agent "{agent_id}" making periodic connections to "{endpoint}" at regular {interval:d} second intervals'))
def given_agent_periodic_connections(c2_state, agent_id, endpoint, interval):
    c2_state.agent_id = agent_id
    c2_state.target_url = endpoint
    base_time = datetime.now(timezone.utc)
    c2_state.time_window = (base_time - timedelta(seconds=10), base_time + timedelta(seconds=100))

    for i in range(4):
        evt = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=base_time + timedelta(seconds=i * interval),
            source=EventSource.TOOL_CALL,
            agent_id=agent_id,
            action="beacon",
            target=endpoint,
            risk_score=0.5,
        )
        c2_state.detector.record_event(evt)


@when(parsers.parse('the C2 detector detects beaconing for "{agent_id}" and endpoint "{endpoint}"'))
def when_detect_beaconing(c2_state, agent_id, endpoint):
    c2_state.beaconing_result = run_async(
        c2_state.detector.detect_beaconing(agent_id, endpoint, c2_state.time_window)
    )


@then("the beaconing detection result should be true")
def then_beaconing_result_true(c2_state):
    assert c2_state.beaconing_result is True


# Scenario 4: a process that recreates itself after termination is identified as a persistence indicator
@given(parsers.parse('an agent "{agent_id}" executing a process with action "{action}" and target "{target}"'))
def given_agent_executing_process(c2_state, agent_id, action, target):
    c2_state.agent_id = agent_id
    now = datetime.now(timezone.utc)
    c2_state.time_window = (now - timedelta(minutes=5), now + timedelta(minutes=5))

    evt = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.PIPELINE_EXECUTION,
        agent_id=agent_id,
        action=action,
        target=target,
        risk_score=0.7,
    )
    c2_state.detector.record_event(evt)


@when(parsers.parse('the C2 detector detects persistence indicators for "{agent_id}" over the time window'))
def when_detect_persistence_indicators(c2_state, agent_id):
    c2_state.persistence_indicators = run_async(
        c2_state.detector.detect_persistence_indicators(agent_id, c2_state.time_window)
    )


@then(parsers.parse('the persistence indicators should contain "{indicator}"'))
def then_persistence_indicators_contain(c2_state, indicator):
    assert indicator in c2_state.persistence_indicators


# Scenario 5: C2 evidence includes cross-pillar correlation between Pillar 1 network events and tool calls
@given(parsers.parse('an agent "{agent_id}" with a Pillar 1 network syscall event targeting "{target}"'))
def given_agent_pillar1_syscall(c2_state, agent_id, target):
    c2_state.agent_id = agent_id
    now = datetime.now(timezone.utc)
    if c2_state.time_window is None:
        c2_state.time_window = (now - timedelta(minutes=5), now + timedelta(minutes=5))

    evt = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action="sys_connect",
        target=target,
        risk_score=0.9,
    )
    c2_state.detector.record_event(evt)


@given(parsers.parse('the agent "{agent_id}" with a tool call event targeting "{target}"'))
def given_agent_tool_call(c2_state, agent_id, target):
    now = datetime.now(timezone.utc)
    if c2_state.time_window is None:
        c2_state.time_window = (now - timedelta(minutes=5), now + timedelta(minutes=5))

    evt = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action="http_get",
        target=target,
        risk_score=0.8,
    )
    c2_state.detector.record_event(evt)


@then("C2 evidence should include cross-pillar correlation between Pillar 1 network events and tool calls")
def then_c2_evidence_includes_cross_pillar(c2_state):
    assert len(c2_state.evidence_list) >= 1
    evidence = c2_state.evidence_list[0]
    expected_msg = "Cross-pillar correlation between Pillar 1 network syscalls and tool calls"
    assert expected_msg in evidence.persistence_indicators
