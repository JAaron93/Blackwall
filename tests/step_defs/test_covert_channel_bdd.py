"""Pytest-BDD step definitions for Covert Channel & Latent Coordination Detection (TASK-2B.4)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    AlertBus,
    AlertSeverity,
    EventSource,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.covert_channel import (
    CovertChannelDetector,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/covert_channel_detection.feature")


class CovertChannelScenarioState:
    """State container for covert channel BDD scenarios."""

    def __init__(self) -> None:
        self.detector = CovertChannelDetector()
        self.alert_bus = AlertBus()
        self.swarm: SwarmEvidence | None = None
        self.events: list[NormalizedEvent] = []
        self.evidence_list: list[CovertChannelEvidence] = []
        self.endpoint: str = ""
        self.staging_path: str = ""
        self.agents: list[str] = []


@pytest.fixture
def state() -> CovertChannelScenarioState:
    return CovertChannelScenarioState()


# ---------------------------------------------------------------------------
# Scenario 1: Latent Coordination Divergence (Unlocated Message Board)
# ---------------------------------------------------------------------------


@given(parsers.parse("a detected agent group containing {count:d} distinct agent IDs"))
def step_given_agent_group(state: CovertChannelScenarioState, count: int) -> None:
    now = datetime.now(UTC)
    state.swarm = SwarmEvidence(
        swarm_id=uuid.uuid4(),
        agent_ids={f"agent-{i+1}" for i in range(count)},
        shared_patterns=[],
        temporal_correlation=0.0,
        coordination_score=0.0,
        first_seen=now,
        last_seen=now + timedelta(seconds=60),
    )


@given(
    parsers.parse(
        "the group has temporal_correlation of {temporal_corr:f} and coordination_score of {coord_score:f}"
    )
)
def step_given_scores(
    state: CovertChannelScenarioState, temporal_corr: float, coord_score: float
) -> None:
    assert state.swarm is not None
    state.swarm.temporal_correlation = temporal_corr
    state.swarm.coordination_score = coord_score


@given(
    parsers.parse(
        "the group has {c2_count:d} external C2 domains or network IPs in shared_patterns"
    )
)
def step_given_c2_count(state: CovertChannelScenarioState, c2_count: int) -> None:
    assert state.swarm is not None
    if c2_count == 0:
        state.swarm.shared_patterns = ["arg:status_query", "tool:bash"]
    else:
        state.swarm.shared_patterns = ["ip:198.51.100.44"]


@when("the CovertChannelDetector analyzes the group")
def step_when_detector_analyzes_group(state: CovertChannelScenarioState) -> None:
    assert state.swarm is not None
    state.evidence_list = state.detector.detect_for_swarm(state.swarm)


@then("a CovertChannelEvidence record MUST be generated")
def step_then_evidence_generated(state: CovertChannelScenarioState) -> None:
    assert len(state.evidence_list) >= 1


@then(parsers.parse('the channel_type MUST be "{channel_type}"'))
def step_then_channel_type(state: CovertChannelScenarioState, channel_type: str) -> None:
    assert len(state.evidence_list) >= 1
    assert state.evidence_list[0].channel_type.value == channel_type


@then(parsers.parse("the confidence score MUST be at least {threshold:f}"))
def step_then_confidence_at_least(
    state: CovertChannelScenarioState, threshold: float
) -> None:
    assert len(state.evidence_list) >= 1
    assert state.evidence_list[0].confidence_score >= threshold


@then("a CRITICAL alert MUST be published to the AlertBus")
def step_then_critical_alert_published(state: CovertChannelScenarioState) -> None:
    assert len(state.evidence_list) >= 1
    evidence = state.evidence_list[0]
    success = run_async(state.alert_bus.publish_covert_channel_alert(evidence))
    assert success is True
    alerts = state.alert_bus.get_alerts(severity=AlertSeverity.CRITICAL)
    assert len(alerts) >= 1
    assert alerts[-1].threat_type == "covert_channel"


# ---------------------------------------------------------------------------
# Scenario 2: Steganographic Registry Detection
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        '{count:d} agents making rapid sequential metadata requests to "{endpoint}"'
    )
)
def step_given_artifactory_agents(
    state: CovertChannelScenarioState, count: int, endpoint: str
) -> None:
    state.endpoint = endpoint
    state.agents = [f"agent-stealth-{i+1}" for i in range(count)]
    state.events = []


@given("the request paths contain base64-encoded directory names")
def step_given_b64_paths(state: CovertChannelScenarioState) -> None:
    now = datetime.now(UTC)
    for i, agent in enumerate(state.agents):
        b64_seg = "cGF5bG9hZDE="  # decodes to "payload1"
        path = f"{state.endpoint}/repo/{b64_seg}/manifest.json"
        event = NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=now + timedelta(seconds=i * 2),
            source=EventSource.TOOL_CALL,
            agent_id=agent,
            action="query_metadata",
            target=path,
            metadata={"headers": "custom"},
            risk_score=0.7,
        )
        state.events.append(event)


@when("the CovertChannelDetector processes the events")
def step_when_detector_processes_events(state: CovertChannelScenarioState) -> None:
    state.evidence_list = state.detector.detect_storage_channels(state.events)


@then("the observed_artifacts MUST contain the Artifactory endpoint")
def step_then_observed_artifactory(state: CovertChannelScenarioState) -> None:
    assert len(state.evidence_list) >= 1
    evidence = state.evidence_list[0]
    assert any("artifactory" in art for art in evidence.observed_artifacts)


@then(parsers.parse("the coordinating agents MUST contain all {count:d} agents"))
def step_then_coordinating_all(state: CovertChannelScenarioState, count: int) -> None:
    assert len(state.evidence_list) >= 1
    evidence = state.evidence_list[0]
    assert len(evidence.coordinating_agents) == count


# ---------------------------------------------------------------------------
# Scenario 3: Filesystem Dead-Drop Detection
# ---------------------------------------------------------------------------


@given(parsers.parse('{count:d} agents accessing a shared staging file "{filepath}"'))
def step_given_shared_staging_file(
    state: CovertChannelScenarioState, count: int, filepath: str
) -> None:
    state.staging_path = filepath
    state.events = []


@given(parsers.parse('agent "{agent_id}" performs a "{action}" action'))
def step_given_agent_action(
    state: CovertChannelScenarioState, agent_id: str, action: str
) -> None:
    now = datetime.now(UTC)
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now + timedelta(seconds=len(state.events)),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=state.staging_path,
        metadata={"fd": 3},
        risk_score=0.8,
    )
    state.events.append(event)


@then(parsers.parse('the observed_artifacts MUST contain "{artifact}"'))
def step_then_observed_contains(
    state: CovertChannelScenarioState, artifact: str
) -> None:
    assert len(state.evidence_list) >= 1
    evidence = state.evidence_list[0]
    assert artifact in evidence.observed_artifacts


# ---------------------------------------------------------------------------
# Scenario 4: Rejection of Single-Agent Activity
# ---------------------------------------------------------------------------


@given(parsers.parse('1 agent accessing a staging file "{filepath}"'))
def step_given_single_agent(state: CovertChannelScenarioState, filepath: str) -> None:
    now = datetime.now(UTC)
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-lonely-01",
        action="write",
        target=filepath,
        metadata={"fd": 3},
        risk_score=0.8,
    )
    state.events = [event]


@then("no CovertChannelEvidence record MUST be generated")
def step_then_no_evidence(state: CovertChannelScenarioState) -> None:
    assert len(state.evidence_list) == 0
