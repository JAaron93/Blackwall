"""Pytest-BDD step definitions for security contract validation guardrails."""

from datetime import datetime, timedelta, timezone
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.validators import validate_semver_format, validate_utc_datetime

scenarios("../features/security_contract_validators.feature")


class ValidatorState:
    """Container for state during scenario execution."""

    def __init__(self):
        self.input_version: str = ""
        self.output_version: str = ""
        self.input_dt: datetime | None = None
        self.output_dt: datetime | None = None
        self.error: Exception | None = None


@pytest.fixture
def state():
    return ValidatorState()


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
