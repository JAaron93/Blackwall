"""Pytest-BDD step definitions for security contract validation guardrails."""

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, List
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.validators import (
    validate_min_items,
    validate_non_empty_string,
    validate_semver_format,
    validate_temporal_sequence,
    validate_utc_datetime,
    validate_uuid_v4_format,
)

scenarios("../features/security_contract_validators.feature")


class ValidatorState:
    """Container for state during scenario execution."""

    def __init__(self):
        self.input_version: str = ""
        self.output_version: str = ""
        self.input_dt: datetime | None = None
        self.output_dt: datetime | None = None
        self.input_uuid: str = ""
        self.output_uuid: str = ""
        self.input_str: str = ""
        self.output_str: str = ""
        self.input_collection: List[Any] = []
        self.output_collection: List[Any] = []
        self.start_dt: datetime | None = None
        self.end_dt: datetime | None = None
        self.error: Exception | None = None


@pytest.fixture
def state():
    return ValidatorState()


# Semver steps
@given(parsers.parse('a version string "{version_str}"'))
def set_version_string(state: ValidatorState, version_str: str):
    state.input_version = version_str


@when("the semver validation helper is executed")
def execute_semver_validation(state: ValidatorState):
    try:
        state.output_version = validate_semver_format(state.input_version)
    except Exception as exc:
        state.error = exc


@then(parsers.parse('the validated version string should be "{expected_str}"'))
def verify_validated_version(state: ValidatorState, expected_str: str):
    assert state.error is None
    assert state.output_version == expected_str


@then(parsers.parse('a ValueError should be raised with "{expected_msg}"'))
def verify_value_error(state: ValidatorState, expected_msg: str):
    assert isinstance(state.error, ValueError)
    assert expected_msg in str(state.error)


# UTC datetime steps
@given("a timezone-aware UTC datetime")
def set_utc_datetime(state: ValidatorState):
    state.input_dt = datetime.now(timezone.utc)


@when("the UTC datetime validation helper is executed")
def execute_utc_datetime_validation(state: ValidatorState):
    try:
        state.output_dt = validate_utc_datetime(state.input_dt)
    except Exception as exc:
        state.error = exc


@then("the validated datetime should match the UTC input")
def verify_utc_datetime(state: ValidatorState):
    assert state.error is None
    assert state.output_dt == state.input_dt


@given("a naive datetime without timezone info")
def set_naive_datetime(state: ValidatorState):
    state.input_dt = datetime.now(timezone.utc).replace(tzinfo=None)


@given("a non-UTC timezone-aware datetime")
def set_non_utc_datetime(state: ValidatorState):
    est = timezone(timedelta(hours=-5))
    state.input_dt = datetime.now(est)


# UUID v4 steps
@given("a valid UUID v4 string")
def set_valid_uuid_v4(state: ValidatorState):
    state.input_uuid = str(uuid.uuid4())


@given(parsers.parse('an invalid UUID string "{invalid_uuid}"'))
def set_invalid_uuid(state: ValidatorState, invalid_uuid: str):
    state.input_uuid = invalid_uuid


@when("the UUID v4 validation helper is executed")
def execute_uuid_v4_validation(state: ValidatorState):
    try:
        state.output_uuid = validate_uuid_v4_format(state.input_uuid)
    except Exception as exc:
        state.error = exc


@then("the validated UUID string should match the input")
def verify_uuid_v4_match(state: ValidatorState):
    assert state.error is None
    assert state.output_uuid == state.input_uuid


# Non-empty string steps
@given(parsers.parse('a non-empty string "{input_str}"'))
def set_non_empty_string(state: ValidatorState, input_str: str):
    state.input_str = input_str


@given(parsers.parse('an empty string "{input_str}"'))
def set_empty_string(state: ValidatorState, input_str: str):
    state.input_str = input_str


@when("the non-empty string validation helper is executed")
def execute_non_empty_string_validation(state: ValidatorState):
    try:
        state.output_str = validate_non_empty_string(state.input_str, field_name="field")
    except Exception as exc:
        state.error = exc


@then(parsers.parse('the validated string should be "{expected_str}"'))
def verify_validated_string(state: ValidatorState, expected_str: str):
    assert state.error is None
    assert state.output_str == expected_str


# Min items steps
@given(parsers.parse("a collection with {count:d} items"))
def set_collection_count(state: ValidatorState, count: int):
    state.input_collection = list(range(count))


@when(parsers.parse("the min items validation helper is executed with min size {min_size:d}"))
def execute_min_items_validation(state: ValidatorState, min_size: int):
    try:
        state.output_collection = validate_min_items(state.input_collection, min_items=min_size, field_name="collection")
    except Exception as exc:
        state.error = exc


@then(parsers.parse("the validated collection should contain {count:d} items"))
def verify_collection_count(state: ValidatorState, count: int):
    assert state.error is None
    assert len(state.output_collection) == count


# Temporal sequence steps
@given("a valid UTC start time and a later UTC end time")
def set_valid_temporal_times(state: ValidatorState):
    now = datetime.now(timezone.utc)
    state.start_dt = now
    state.end_dt = now + timedelta(minutes=10)


@given("a valid UTC start time and an earlier UTC end time")
def set_invalid_temporal_times(state: ValidatorState):
    now = datetime.now(timezone.utc)
    state.start_dt = now
    state.end_dt = now - timedelta(minutes=10)


@when("the temporal sequence validation helper is executed")
def execute_temporal_sequence_validation(state: ValidatorState):
    try:
        validate_temporal_sequence(state.start_dt, state.end_dt, start_name="start_time", end_name="end_time")
    except Exception as exc:
        state.error = exc


@then("the temporal sequence validation succeeds without error")
def verify_temporal_sequence_success(state: ValidatorState):
    assert state.error is None
