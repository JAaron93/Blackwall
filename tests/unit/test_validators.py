"""Unit tests for centralized validation helpers in src/blackwall/validators.py."""

from datetime import datetime, timezone, timedelta
import uuid
import pytest

from blackwall.validators import (
    ensure_uuid_v4,
    utc_now,
    validate_min_items,
    validate_non_empty_string,
    validate_semver_format,
    validate_temporal_sequence,
    validate_utc_datetime,
    validate_uuid_v4_format,
)


def test_validate_semver_format_valid():
    """Verify valid semver strings pass validation."""
    assert validate_semver_format("1.0.0") == "1.0.0"
    assert validate_semver_format("0.1.0") == "0.1.0"
    assert validate_semver_format("12.34.56") == "12.34.56"


def test_validate_semver_format_invalid():
    """Verify invalid semver strings raise ValueError."""
    with pytest.raises(ValueError, match="semantic versioning format"):
        validate_semver_format("1.0")

    with pytest.raises(ValueError, match="semantic versioning format"):
        validate_semver_format("v1.0.0")

    with pytest.raises(ValueError, match="semantic versioning format"):
        validate_semver_format("1.0.0-alpha")


def test_validate_utc_datetime_valid():
    """Verify timezone-aware UTC datetime objects pass validation."""
    now_utc = datetime.now(timezone.utc)
    assert validate_utc_datetime(now_utc) == now_utc


def test_validate_utc_datetime_invalid_naive():
    """Verify naive datetime objects raise ValueError."""
    naive_dt = datetime.now()
    with pytest.raises(ValueError, match="UTC timezone-aware"):
        validate_utc_datetime(naive_dt)


def test_validate_utc_datetime_invalid_non_utc():
    """Verify non-UTC timezone-aware datetime objects raise ValueError."""
    est = timezone(timedelta(hours=-5))
    non_utc_dt = datetime.now(est)
    with pytest.raises(ValueError, match="UTC timezone-aware"):
        validate_utc_datetime(non_utc_dt)


def test_utc_now():
    """Verify utc_now returns timezone-aware UTC datetime."""
    now = utc_now()
    assert isinstance(now, datetime)
    assert now.tzinfo is timezone.utc


def test_validate_uuid_v4_format_valid():
    """Verify valid UUID v4 strings pass validation and return UUID object."""
    raw_v4 = uuid.uuid4()
    valid_uuid_str = str(raw_v4)
    res_str = validate_uuid_v4_format(valid_uuid_str)
    assert isinstance(res_str, uuid.UUID)
    assert res_str == raw_v4

    res_obj = validate_uuid_v4_format(raw_v4)
    assert isinstance(res_obj, uuid.UUID)
    assert res_obj == raw_v4


def test_validate_uuid_v4_format_invalid():
    """Verify invalid UUID strings or non-v4 UUIDs raise ValueError."""
    invalid_uuid_str = "not-a-uuid"
    with pytest.raises(ValueError, match="Invalid UUID v4 format"):
        validate_uuid_v4_format(invalid_uuid_str)

    uuid_v1_str = str(uuid.uuid1())
    with pytest.raises(ValueError, match="must be a valid UUID v4"):
        validate_uuid_v4_format(uuid_v1_str)

    uuid_v1_obj = uuid.uuid1()
    with pytest.raises(ValueError, match="must be a valid UUID v4"):
        validate_uuid_v4_format(uuid_v1_obj)


def test_ensure_uuid_v4():
    """Verify ensure_uuid_v4 returns original UUID if valid v4, or generates new v4 UUID if invalid or None."""
    valid_v4_obj = uuid.uuid4()
    valid_v4_str = str(valid_v4_obj)

    assert ensure_uuid_v4(valid_v4_str) == valid_v4_obj
    assert ensure_uuid_v4(valid_v4_obj) == valid_v4_obj

    new_from_invalid = ensure_uuid_v4("bad-uuid")
    assert isinstance(new_from_invalid, uuid.UUID)
    assert new_from_invalid.version == 4

    new_from_none = ensure_uuid_v4(None)
    assert isinstance(new_from_none, uuid.UUID)
    assert new_from_none.version == 4


def test_validate_non_empty_string():
    """Verify validate_non_empty_string accepts valid strings and rejects empty/whitespace strings."""
    assert validate_non_empty_string("agent-1", "agent_id") == "agent-1"

    with pytest.raises(ValueError, match="agent_id must not be empty"):
        validate_non_empty_string("", "agent_id")

    with pytest.raises(ValueError, match="agent_id must not be empty"):
        validate_non_empty_string("   ", "agent_id")


def test_validate_min_items():
    """Verify validate_min_items validates minimum collection length."""
    assert validate_min_items([1, 2], min_items=2) == [1, 2]
    assert validate_min_items({"a", "b", "c"}, min_items=2) == {"a", "b", "c"}

    with pytest.raises(ValueError, match="collection must contain at least 2 items"):
        validate_min_items([1], min_items=2)


def test_validate_temporal_sequence():
    """Verify validate_temporal_sequence enforces end_time >= start_time for UTC datetimes."""
    now_utc = datetime.now(timezone.utc)
    later_utc = now_utc + timedelta(seconds=10)

    validate_temporal_sequence(now_utc, later_utc)
    validate_temporal_sequence(now_utc, now_utc)

    earlier_utc = now_utc - timedelta(seconds=5)
    with pytest.raises(
        ValueError, match="end_time must be greater than or equal to start_time"
    ):
        validate_temporal_sequence(now_utc, earlier_utc)
