"""
tests/step_defs/test_agent_swarm_linguistic_bdd.py — Step definitions for Linguistic Swarm Attribution (TASK-2A.4).
"""

from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.attribution.linguistic import LinguisticSwarmClassifier
from blackwall.models import AttackerIdentity, LinguisticSwarmMarkers, ToolCallContext

scenarios("../features/agent_swarm_linguistic_attribution.feature")


class LinguisticScenarioState:
    """Holds scenario execution state across BDD steps."""

    def __init__(self) -> None:
        self.context: ToolCallContext | None = None
        self.metadata: dict[str, Any] = {}
        self.second_context: ToolCallContext | None = None
        self.second_metadata: dict[str, Any] = {}
        self.markers: LinguisticSwarmMarkers | None = None
        self.identity: AttackerIdentity | None = None
        self.second_identity: AttackerIdentity | None = None
        self.classifier = LinguisticSwarmClassifier()
        self.extractor = AttackerIdentityExtractor(classifier=self.classifier)


@pytest.fixture
def state() -> LinguisticScenarioState:
    return LinguisticScenarioState()


@given(parsers.parse('an ADK tool call with arguments containing "{arg_text}"'))
def step_given_tool_call_args(state: LinguisticScenarioState, arg_text: str) -> None:
    state.context = ToolCallContext(
        tool_name="execute_command",
        arguments={"input": arg_text},
        metadata=None,
    )


@given(parsers.parse('caller metadata with agent_name "{agent_name}"'))
def step_given_caller_agent_name(state: LinguisticScenarioState, agent_name: str) -> None:
    state.metadata["agent_name"] = agent_name


@given(parsers.parse('caller metadata with agent_id "{agent_id}"'))
def step_given_caller_agent_id(state: LinguisticScenarioState, agent_id: str) -> None:
    state.metadata["agent_id"] = agent_id


@given(parsers.parse('an ADK tool call where agent_id is set to "{agent_id}" and session_id is "{session_id}"'))
def step_given_false_monolith_first(state: LinguisticScenarioState, agent_id: str, session_id: str) -> None:
    state.context = ToolCallContext(
        tool_name="bash",
        arguments={"cmd": "whoami"},
        metadata=None,
    )
    state.metadata = {"agent_id": agent_id, "session_id": session_id}


@given(parsers.parse('another ADK tool call where agent_id is set to "{agent_id}" and session_id is "{session_id}"'))
def step_given_false_monolith_second(state: LinguisticScenarioState, agent_id: str, session_id: str) -> None:
    state.second_context = ToolCallContext(
        tool_name="bash",
        arguments={"cmd": "id"},
        metadata=None,
    )
    state.second_metadata = {"agent_id": agent_id, "session_id": session_id}


@when("the LinguisticSwarmClassifier analyzes the tool call")
def step_when_classifier_analyzes(state: LinguisticScenarioState) -> None:
    assert state.context is not None
    state.markers = state.classifier.classify(state.context, metadata=state.metadata)


@when("the AttackerIdentity is generated for both calls")
def step_when_identity_generated_both(state: LinguisticScenarioState) -> None:
    assert state.context is not None
    assert state.second_context is not None
    state.identity = state.extractor.extract(state.context, metadata=state.metadata)
    state.second_identity = state.extractor.extract(state.second_context, metadata=state.second_metadata)


@when("the AttackerIdentity is generated")
def step_when_identity_generated(state: LinguisticScenarioState) -> None:
    assert state.context is not None
    state.identity = state.extractor.extract(state.context, metadata=state.metadata)


@then("the classifier MUST flag is_collective as True")
def step_then_flag_collective_true(state: LinguisticScenarioState) -> None:
    assert state.markers is not None
    assert state.markers.is_collective is True


@then("the classifier MUST flag is_collective as False")
def step_then_flag_collective_false(state: LinguisticScenarioState) -> None:
    assert state.markers is not None
    assert state.markers.is_collective is False


@then(parsers.parse('the detected pronouns MUST include "{pronoun}"'))
def step_then_pronouns_include(state: LinguisticScenarioState, pronoun: str) -> None:
    assert state.markers is not None
    assert pronoun in state.markers.detected_pronouns


@then(parsers.parse("the confidence score MUST be at least {threshold:f}"))
def step_then_score_at_least(state: LinguisticScenarioState, threshold: float) -> None:
    assert state.markers is not None
    assert state.markers.confidence_score >= threshold


@then(parsers.parse("the confidence score MUST be less than {threshold:f}"))
def step_then_score_less_than(state: LinguisticScenarioState, threshold: float) -> None:
    assert state.markers is not None
    assert state.markers.confidence_score < threshold


@then("both identities MUST have is_collective flag set to True")
def step_then_both_collective(state: LinguisticScenarioState) -> None:
    assert state.identity is not None
    assert state.second_identity is not None
    assert state.identity.is_collective is True
    assert state.second_identity.is_collective is True


@then("the two identities MUST have distinct identity fingerprints")
def step_then_distinct_fingerprints(state: LinguisticScenarioState) -> None:
    assert state.identity is not None
    assert state.second_identity is not None
    assert state.identity.identity_fingerprint != state.second_identity.identity_fingerprint


@then("the identity MUST have is_collective flag set to True")
def step_then_identity_collective_true(state: LinguisticScenarioState) -> None:
    assert state.identity is not None
    assert state.identity.is_collective is True


@then(parsers.parse('the identity MUST contain collective_name starting with "{prefix}"'))
def step_then_collective_name_starts_with(state: LinguisticScenarioState, prefix: str) -> None:
    assert state.identity is not None
    assert state.identity.collective_name is not None
    assert state.identity.collective_name.startswith(prefix)
