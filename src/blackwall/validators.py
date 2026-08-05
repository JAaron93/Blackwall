"""Centralized validation and utility helpers for Blackwall."""

from datetime import datetime, timezone
import re


def validate_semver_format(v: str) -> str:
    """Validate that a string follows the MAJOR.MINOR.PATCH semantic versioning format."""
    if not re.match(r"^\d+\.\d+\.\d+$", v):
        raise ValueError(
            "Version must be in MAJOR.MINOR.PATCH semantic versioning format"
        )
    return v


def validate_utc_datetime(v: datetime) -> datetime:
    """Validate that a datetime object is timezone-aware and set to UTC."""
    if v.tzinfo is None or v.utcoffset() != timezone.utc.utcoffset(v):
        raise ValueError("timestamp must be UTC timezone-aware")
    return v


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)
