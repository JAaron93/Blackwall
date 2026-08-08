"""Pytest-BDD step definitions for attacker attribution model validation."""

from datetime import datetime, timezone
import json
from uuid import uuid4
import pytest
from pydantic import ValidationError
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    IncidentReport,
    VerdictDecision,
)

scenarios("../features/attacker_attribution.feature")


class AttributionScenarioState:
    """Container for state during scenario execution."""

    def __init__(self):
        self.identity1: AttackerIdentity | None = None
        self.identity2: AttackerIdentity | None = None
        self.profile: AttackerProfile | None = None
        self.report: IncidentReport | None = None
        self.json_output: str = ""
        self.markdown_output: str = ""
        self.error: Exception | None = None
        self.agent_id1: str = ""
        self.agent_id2: str = ""
        self.thread_id: str = ""
        self.score: float = 0.5
        self.timestamp: datetime | None = None


@pytest.fixture
def state():
    return AttributionScenarioState()


# Scenario: Generate deterministic SHA-256 fingerprint
@given(
    parsers.parse(
        'two identical attacker identity attributes with agent_id "{agent_id}" and thread_id "{thread_id}"'
    )
)
def set_identical_identity_attributes(
    state: AttributionScenarioState, agent_id: str, thread_id: str
):
    state.agent_id1 = agent_id
    state.agent_id2 = agent_id
    state.thread_id = thread_id


@when("the AttackerIdentity objects are instantiated")
def instantiate_identities(state: AttributionScenarioState):
    state.identity1 = AttackerIdentity(
        agent_id=state.agent_id1,
        thread_id=state.thread_id,
        primary_source=IdentitySource.ADK_METADATA,
    )
    state.identity2 = AttackerIdentity(
        agent_id=state.agent_id2,
        thread_id=state.thread_id,
        primary_source=IdentitySource.ADK_METADATA,
    )


@then("both identity objects MUST produce the exact same 64-character SHA-256 identity_fingerprint")
def verify_identical_fingerprints(state: AttributionScenarioState):
    assert len(state.identity1.identity_fingerprint) == 64
    assert len(state.identity2.identity_fingerprint) == 64
    assert state.identity1.identity_fingerprint == state.identity2.identity_fingerprint


# Scenario: Generate distinct fingerprints
@given(
    parsers.parse(
        'two attacker identities with different agent_ids "{id1}" and "{id2}"'
    )
)
def set_distinct_identity_attributes(
    state: AttributionScenarioState, id1: str, id2: str
):
    state.agent_id1 = id1
    state.agent_id2 = id2
    state.thread_id = "th-same"


@then("their identity_fingerprint strings MUST be distinct")
def verify_distinct_fingerprints(state: AttributionScenarioState):
    assert state.identity1.identity_fingerprint != state.identity2.identity_fingerprint


# Scenario: Valid score and UTC timestamp
@given(parsers.parse("a valid UTC timestamp and threat_score {score:f}"))
def set_valid_utc_and_score(state: AttributionScenarioState, score: float):
    state.timestamp = datetime.now(timezone.utc)
    state.score = score


@when("the AttackerProfile object is instantiated")
def instantiate_attacker_profile(state: AttributionScenarioState):
    try:
        state.profile = AttackerProfile(
            fingerprint="a" * 64,
            first_seen=state.timestamp or datetime.now(timezone.utc),
            last_seen=state.timestamp or datetime.now(timezone.utc),
            threat_score=state.score,
        )
    except Exception as exc:
        state.error = exc


@then(parsers.parse("the profile MUST store the threat_score {expected_score:f} and UTC timestamp without error"))
def verify_profile_valid(state: AttributionScenarioState, expected_score: float):
    assert state.error is None
    assert state.profile is not None
    assert state.profile.threat_score == pytest.approx(expected_score)


# Scenario: Invalid threat score out of bounds
@given(parsers.parse("an invalid threat_score {score:f}"))
def set_invalid_score(state: AttributionScenarioState, score: float):
    state.score = score
    state.timestamp = datetime.now(timezone.utc)


@then("a ValidationError MUST be raised for threat_score out of bounds")
def verify_score_validation_error(state: AttributionScenarioState):
    assert isinstance(state.error, ValidationError)


# Scenario: Naive timestamp
@given("a naive timestamp without timezone info for AttackerProfile")
def set_naive_timestamp(state: AttributionScenarioState):
    state.timestamp = datetime.now()  # naive
    state.score = 0.5


@then("a ValidationError MUST be raised for non-UTC timestamp")
def verify_timestamp_validation_error(state: AttributionScenarioState):
    assert isinstance(state.error, ValidationError)


# Scenario: Serialization to Markdown and JSON
@given(parsers.parse('a valid IncidentReport with BLOCK verdict for agent "{agent_name}"'))
def set_valid_incident_report_scenario(
    state: AttributionScenarioState, agent_name: str
):
    now = datetime.now(timezone.utc)
    identity = AttackerIdentity(
        agent_name=agent_name,
        thread_id="th-999",
        primary_source=IdentitySource.ADK_METADATA,
    )
    profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        threat_score=0.95,
    )
    state.report = IncidentReport(
        event_id=uuid4(),
        verdict=VerdictDecision.BLOCK,
        attacker_identity=identity,
        attacker_profile=profile,
        exploited_tool="execute_bash",
        sanitized_arguments={"cmd": "whoami"},
        attack_technique="Unsafe Command Execution",
        mitigation_action="Operation blocked",
        recommended_user_action="Inspect agent logs",
        attribution_confidence=0.99,
    )


@when("the report serialization helpers to_json and to_markdown are executed")
def execute_report_serialization(state: AttributionScenarioState):
    assert state.report is not None
    state.json_output = state.report.to_json()
    state.markdown_output = state.report.to_markdown()


@then(parsers.parse('to_json MUST return a valid JSON string containing "{expected_agent}"'))
def verify_json_output(state: AttributionScenarioState, expected_agent: str):
    parsed = json.loads(state.json_output)
    assert parsed["attacker_identity"]["agent_name"] == expected_agent


@then(
    parsers.parse(
        'to_markdown MUST return a formatted Markdown string containing "{expected_header}"'
    )
)
def verify_markdown_output(state: AttributionScenarioState, expected_header: str):
    assert expected_header in state.markdown_output
