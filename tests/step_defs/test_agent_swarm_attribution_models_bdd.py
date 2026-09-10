"""Pytest-BDD step definitions for Agent Swarm Attribution Data Models (TASK-1.3)."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
    CovertChannelType,
)
from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IncidentReport,
    LinguisticSwarmMarkers,
    SwarmContextSummary,
    VerdictDecision,
)

scenarios("../features/agent_swarm_attribution_models.feature")


class SwarmModelsState:
    """State holder for swarm attribution BDD scenarios."""

    def __init__(self) -> None:
        self.markers: LinguisticSwarmMarkers | None = None
        self.summary: SwarmContextSummary | None = None
        self.evidence: CovertChannelEvidence | None = None
        self.profile: AttackerProfile | None = None
        self.report: IncidentReport | None = None
        self.error: Exception | None = None
        self.first_detected: datetime | None = None
        self.last_detected: datetime | None = None
        self.channel_type_str: str = ""
        self.agents_set: set[str] = set()


@pytest.fixture
def swarm_state() -> SwarmModelsState:
    return SwarmModelsState()


# ---------------------------------------------------------------------------
# Scenario 1: LinguisticSwarmMarkers
# ---------------------------------------------------------------------------


@given("a linguistic swarm classifier detecting collective pronouns")
def step_given_linguistic_classifier(swarm_state: SwarmModelsState) -> None:
    pass


@when(
    parsers.parse(
        'LinguisticSwarmMarkers is instantiated with valid score {score:f} and pronouns "{pronouns}"'
    )
)
def step_when_instantiate_markers(
    swarm_state: SwarmModelsState, score: float, pronouns: str
) -> None:
    pronoun_list = pronouns.split(",")
    swarm_state.markers = LinguisticSwarmMarkers(
        is_collective=True,
        confidence_score=score,
        detected_pronouns=pronoun_list,
        consensus_keywords=["consensus"],
    )


@then(
    parsers.parse(
        "the markers object MUST store is_collective True and confidence_score {score:f}"
    )
)
def step_then_markers_stored(swarm_state: SwarmModelsState, score: float) -> None:
    assert swarm_state.markers is not None
    assert swarm_state.markers.is_collective is True
    assert swarm_state.markers.confidence_score == pytest.approx(score)


@then(parsers.parse('the markers object MUST contain "{pronoun}" in detected_pronouns'))
def step_then_markers_contain_pronoun(
    swarm_state: SwarmModelsState, pronoun: str
) -> None:
    assert swarm_state.markers is not None
    assert pronoun in swarm_state.markers.detected_pronouns


# ---------------------------------------------------------------------------
# Scenario 2: SwarmContextSummary valid
# ---------------------------------------------------------------------------


@given(
    "a SwarmContextSummary with first_detected 5 minutes ago and last_detected now in UTC"
)
def step_given_swarm_summary_times(swarm_state: SwarmModelsState) -> None:
    now = datetime.now(UTC)
    swarm_state.first_detected = now - timedelta(minutes=5)
    swarm_state.last_detected = now


@when("the SwarmContextSummary object is instantiated")
def step_when_instantiate_summary(swarm_state: SwarmModelsState) -> None:
    swarm_state.summary = SwarmContextSummary(
        is_collective=True,
        collective_confidence=0.90,
        first_detected=swarm_state.first_detected,
        last_detected=swarm_state.last_detected,
    )


@then(
    parsers.parse(
        "the summary MUST store is_collective True and collective_confidence {confidence:f}"
    )
)
def step_then_summary_stored(swarm_state: SwarmModelsState, confidence: float) -> None:
    assert swarm_state.summary is not None
    assert swarm_state.summary.is_collective is True
    assert swarm_state.summary.collective_confidence == pytest.approx(confidence)


@then("first_detected and last_detected MUST be valid UTC timestamps")
def step_then_summary_utc_valid(swarm_state: SwarmModelsState) -> None:
    assert swarm_state.summary is not None
    assert swarm_state.summary.first_detected is not None
    assert swarm_state.summary.last_detected is not None
    assert swarm_state.summary.first_detected.tzinfo == UTC
    assert swarm_state.summary.last_detected.tzinfo == UTC
    assert swarm_state.summary.last_detected >= swarm_state.summary.first_detected


# ---------------------------------------------------------------------------
# Scenario 3: SwarmContextSummary inverted
# ---------------------------------------------------------------------------


@given("a SwarmContextSummary with first_detected after last_detected")
def step_given_inverted_timestamps(swarm_state: SwarmModelsState) -> None:
    now = datetime.now(UTC)
    swarm_state.first_detected = now
    swarm_state.last_detected = now - timedelta(minutes=5)


@when(
    "the SwarmContextSummary object is instantiated with inverted timestamps"
)
def step_when_instantiate_summary_inverted(swarm_state: SwarmModelsState) -> None:
    try:
        SwarmContextSummary(
            first_detected=swarm_state.first_detected,
            last_detected=swarm_state.last_detected,
        )
    except ValidationError as e:
        swarm_state.error = e


@then("a ValidationError MUST be raised for inverted temporal ordering")
def step_then_inverted_error_raised(swarm_state: SwarmModelsState) -> None:
    assert swarm_state.error is not None
    assert isinstance(swarm_state.error, ValidationError)


# ---------------------------------------------------------------------------
# Scenario 4: CovertChannelEvidence valid
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'a covert channel of type "{channel_type}" with coordinating agents "{agents}"'
    )
)
def step_given_covert_channel_agents(
    swarm_state: SwarmModelsState, channel_type: str, agents: str
) -> None:
    swarm_state.channel_type_str = channel_type
    swarm_state.agents_set = set(agents.split(","))


@when("the CovertChannelEvidence object is instantiated")
def step_when_instantiate_evidence(swarm_state: SwarmModelsState) -> None:
    now = datetime.now(UTC)
    try:
        swarm_state.evidence = CovertChannelEvidence(
            channel_type=CovertChannelType(swarm_state.channel_type_str),
            confidence_score=0.92,
            coordinating_agents=swarm_state.agents_set,
            deduction_rationale="BDD scenario test",
            first_detected=now - timedelta(minutes=1),
            last_detected=now,
        )
    except ValidationError as e:
        swarm_state.error = e


@then(parsers.parse('the evidence MUST store channel_type "{channel_type}"'))
def step_then_evidence_channel_type(
    swarm_state: SwarmModelsState, channel_type: str
) -> None:
    assert swarm_state.evidence is not None
    assert swarm_state.evidence.channel_type.value == channel_type


@then(parsers.parse("coordinating_agents MUST contain {count:d} agents"))
def step_then_evidence_agents_count(
    swarm_state: SwarmModelsState, count: int
) -> None:
    assert swarm_state.evidence is not None
    assert len(swarm_state.evidence.coordinating_agents) == count


# ---------------------------------------------------------------------------
# Scenario 5: CovertChannelEvidence insufficient agents
# ---------------------------------------------------------------------------


@given(
    parsers.parse(
        'a covert channel with only 1 coordinating agent "{agent_id}"'
    )
)
def step_given_insufficient_agents(
    swarm_state: SwarmModelsState, agent_id: str
) -> None:
    swarm_state.channel_type_str = "UNLOCATED_MESSAGE_BOARD"
    swarm_state.agents_set = {agent_id}


@then("a ValidationError MUST be raised for insufficient coordinating agents")
def step_then_insufficient_agents_error(swarm_state: SwarmModelsState) -> None:
    assert swarm_state.error is not None
    assert isinstance(swarm_state.error, ValidationError)


# ---------------------------------------------------------------------------
# Scenario 6: Backward Compatibility
# ---------------------------------------------------------------------------


@given("an AttackerProfile and IncidentReport instantiated without collective fields")
def step_given_backward_compatible_models(swarm_state: SwarmModelsState) -> None:
    now = datetime.now(UTC)
    identity = AttackerIdentity(agent_id="legacy-agent")
    swarm_state.profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
    )
    swarm_state.report = IncidentReport(
        event_id=identity.identity_id,
        verdict=VerdictDecision.BLOCK,
        attacker_identity=identity,
        attacker_profile=swarm_state.profile,
        exploited_tool="read_file",
        attack_technique="Path Traversal",
        mitigation_action="Blocked",
        recommended_user_action="Audit file permissions",
        attribution_confidence=0.85,
    )


@when("the profile and report are inspected")
def step_when_inspect_profile_and_report(swarm_state: SwarmModelsState) -> None:
    pass


@then("the profile swarm_memberships MUST be an empty list")
def step_then_profile_memberships_empty(swarm_state: SwarmModelsState) -> None:
    assert swarm_state.profile is not None
    assert swarm_state.profile.swarm_memberships == []


@then("the report is_collective MUST be False")
def step_then_report_is_collective_false(swarm_state: SwarmModelsState) -> None:
    assert swarm_state.report is not None
    assert swarm_state.report.is_collective is False


@then(parsers.parse("the report collective_confidence MUST be {confidence:f}"))
def step_then_report_collective_confidence_zero(
    swarm_state: SwarmModelsState, confidence: float
) -> None:
    assert swarm_state.report is not None
    assert swarm_state.report.collective_confidence == pytest.approx(confidence)
