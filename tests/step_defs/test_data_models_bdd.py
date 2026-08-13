"""BDD Step Definitions for Advanced Threat Detection Data Models (`tests/features/data_models.feature`)."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, List, Set

import pytest
from pydantic import ValidationError
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
    SwarmEvidence,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/data_models.feature")


class DataModelsBDDState:
    def __init__(self) -> None:
        self.raw_event_id: str | None = None
        self.raw_timestamp: datetime | None = None
        self.normalized_event: NormalizedEvent | None = None
        self.invalid_risk_scores: List[float] = []
        self.risk_score_exceptions: List[Exception] = []
        self.insufficient_node_lists: List[List[AttackNode]] = []
        self.attack_path_exceptions: List[Exception] = []
        self.insufficient_agent_sets: List[Set[str]] = []
        self.swarm_evidence_exceptions: List[Exception] = []


@pytest.fixture
def state() -> DataModelsBDDState:
    return DataModelsBDDState()


# Scenario 1: NormalizedEvent creation validates UUID v4 string parsing and UTC timezone-aware timestamp
@given("a request to create a NormalizedEvent with valid string UUID v4 and ISO UTC timestamp")
def given_valid_event_parameters(state: DataModelsBDDState) -> None:
    state.raw_event_id = "c56a4180-65aa-42ec-a945-5fd21dec0538"
    state.raw_timestamp = datetime.now(timezone.utc)


@when("the NormalizedEvent is instantiated")
def when_normalized_event_instantiated(state: DataModelsBDDState) -> None:
    async def _create_event() -> NormalizedEvent:
        return NormalizedEvent(
            event_id=state.raw_event_id,
            timestamp=state.raw_timestamp,
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-bdd-01",
            action="execve",
            target="/usr/bin/python3",
            metadata={"pid": 1234},
            risk_score=0.5,
        )

    state.normalized_event = run_async(_create_event())


@then("the event_id is parsed into a valid UUID v4 object")
def then_event_id_valid_uuid_v4(state: DataModelsBDDState) -> None:
    assert state.normalized_event is not None
    assert isinstance(state.normalized_event.event_id, uuid.UUID)
    assert str(state.normalized_event.event_id) == "c56a4180-65aa-42ec-a945-5fd21dec0538"
    assert state.normalized_event.event_id.version == 4


@then("the timestamp is timezone-aware and set to UTC")
def then_timestamp_is_utc(state: DataModelsBDDState) -> None:
    assert state.normalized_event is not None
    assert state.normalized_event.timestamp.tzinfo is not None
    assert state.normalized_event.timestamp.utcoffset() == timedelta(0)


# Scenario 2: risk_score outside [0.0, 1.0] is rejected with a validation error
@given("risk scores outside the range 0.0 to 1.0")
def given_invalid_risk_scores(state: DataModelsBDDState) -> None:
    state.invalid_risk_scores = [-0.1, -1.0, 1.01, 2.5]


@when("NormalizedEvent instances are created with invalid risk scores")
def when_create_events_with_invalid_scores(state: DataModelsBDDState) -> None:
    async def _instantiate_invalid_events() -> List[Exception]:
        exceptions: List[Exception] = []
        for score in state.invalid_risk_scores:
            try:
                NormalizedEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    source=EventSource.KERNEL_SYSCALL,
                    agent_id="agent-bdd-01",
                    action="execve",
                    target="/bin/bash",
                    risk_score=score,
                )
            except ValidationError as exc:
                exceptions.append(exc)
        return exceptions

    state.risk_score_exceptions = run_async(_instantiate_invalid_events())


@then("a ValidationError is raised for each invalid risk score")
def then_validation_error_raised(state: DataModelsBDDState) -> None:
    assert len(state.risk_score_exceptions) == len(state.invalid_risk_scores)
    for exc in state.risk_score_exceptions:
        assert isinstance(exc, ValidationError)


# Scenario 3: AttackPath with fewer than 2 nodes is rejected with a validation error
@given("an AttackPath with fewer than 2 nodes")
def given_attack_path_fewer_than_2_nodes(state: DataModelsBDDState) -> None:
    # 0 nodes and 1 node lists
    single_event = NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-bdd-02",
        action="connect",
        target="10.0.0.1:443",
        risk_score=0.4,
    )
    single_node = AttackNode(node_id=single_event.event_id, event=single_event)
    state.insufficient_node_lists = [[], [single_node]]


@when("the AttackPath is instantiated")
def when_attack_path_instantiated(state: DataModelsBDDState) -> None:
    async def _instantiate_invalid_paths() -> List[Exception]:
        exceptions: List[Exception] = []
        now = datetime.now(timezone.utc)
        for nodes in state.insufficient_node_lists:
            try:
                AttackPath(
                    path_id=uuid.uuid4(),
                    agent_id="agent-bdd-02",
                    nodes=nodes,
                    start_time=now,
                    end_time=now,
                    risk_score=0.5,
                    correlation_score=0.8,
                )
            except ValidationError as exc:
                exceptions.append(exc)
        return exceptions

    state.attack_path_exceptions = run_async(_instantiate_invalid_paths())


@then("a ValidationError is raised indicating minimum nodes requirement")
def then_validation_error_minimum_nodes(state: DataModelsBDDState) -> None:
    assert len(state.attack_path_exceptions) == len(state.insufficient_node_lists)
    for exc in state.attack_path_exceptions:
        assert isinstance(exc, ValidationError)
        assert "nodes" in str(exc).lower() or "at least 2" in str(exc).lower()


# Scenario 4: SwarmEvidence with fewer than 2 agent_ids is rejected with a validation error
@given("a SwarmEvidence with fewer than 2 agent IDs")
def given_swarm_evidence_fewer_than_2_agent_ids(state: DataModelsBDDState) -> None:
    state.insufficient_agent_sets = [set(), {"agent-solitary-01"}]


@when("the SwarmEvidence is instantiated")
def when_swarm_evidence_instantiated(state: DataModelsBDDState) -> None:
    async def _instantiate_invalid_swarms() -> List[Exception]:
        exceptions: List[Exception] = []
        now = datetime.now(timezone.utc)
        for agent_set in state.insufficient_agent_sets:
            try:
                SwarmEvidence(
                    swarm_id=uuid.uuid4(),
                    agent_ids=agent_set,
                    temporal_correlation=0.9,
                    coordination_score=0.85,
                    first_seen=now,
                    last_seen=now,
                )
            except ValidationError as exc:
                exceptions.append(exc)
        return exceptions

    state.swarm_evidence_exceptions = run_async(_instantiate_invalid_swarms())


@then("a ValidationError is raised indicating minimum agent IDs requirement")
def then_validation_error_minimum_agent_ids(state: DataModelsBDDState) -> None:
    assert len(state.swarm_evidence_exceptions) == len(state.insufficient_agent_sets)
    for exc in state.swarm_evidence_exceptions:
        assert isinstance(exc, ValidationError)
        assert "agent_ids" in str(exc).lower() or "at least 2" in str(exc).lower()
