"""Unit tests for centralized validation helpers in src/blackwall/validators.py."""

from datetime import datetime, timezone, timedelta
import pytest

from blackwall.validators import (
    utc_now,
    validate_semver_format,
    validate_utc_datetime,
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
