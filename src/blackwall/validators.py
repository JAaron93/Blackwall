"""Centralized validation and utility helpers for Blackwall."""

from datetime import datetime, timezone
import json
import re
from typing import Any, Collection, Optional, TypeVar, Union
from uuid import UUID, uuid4

T = TypeVar("T", bound=Collection[Any])


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


def validate_uuid_v4_format(v: Any, field_name: str = "event_id") -> UUID:
    """Validate that a string or UUID is a valid UUID v4 format and return UUID instance."""
    if isinstance(v, UUID):
        if v.version != 4:
            raise ValueError(f"{field_name} must be a valid UUID v4")
        return v
    try:
        parsed = UUID(str(v))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"Invalid UUID v4 format for {field_name}: {v}") from exc

    if parsed.version != 4:
        raise ValueError(f"{field_name} must be a valid UUID v4")
    return parsed


def ensure_uuid_v4(v: Any = None) -> UUID:
    """Return valid UUID v4 instance if input is valid UUID v4, otherwise generate a new UUID v4 instance."""
    if v is not None:
        try:
            return validate_uuid_v4_format(v)
        except ValueError:
            pass
    return uuid4()


def validate_non_empty_string(v: str, field_name: str = "string") -> str:
    """Validate that a string is not empty or whitespace only."""
    if not v or not v.strip():
        raise ValueError(f"{field_name} must not be empty")
    return v


def validate_min_items(
    v: T,
    min_items: int = 2,
    field_name: str = "collection",
    custom_msg: Optional[str] = None,
) -> T:
    """Validate that a collection contains at least min_items elements."""
    if len(v) < min_items:
        msg = custom_msg or f"{field_name} must contain at least {min_items} items"
        raise ValueError(msg)
    return v


def validate_temporal_sequence(
    start_time: datetime,
    end_time: datetime,
    start_name: str = "start_time",
    end_name: str = "end_time",
    custom_msg: Optional[str] = None,
) -> None:
    """Validate that end_time >= start_time for UTC-aware datetimes."""
    validate_utc_datetime(start_time)
    validate_utc_datetime(end_time)
    if end_time < start_time:
        msg = custom_msg or f"{end_name} must be greater than or equal to {start_name}"
        raise ValueError(msg)


def parse_json_safely(v: Optional[Union[str, bytes]], default: Any = None) -> Any:
    """Safely parse a JSON string or bytes object, returning a default fallback on error or empty input."""
    if v is None:
        return default
    if isinstance(v, (str, bytes)):
        s = v.decode("utf-8") if isinstance(v, bytes) else v
        if not s.strip():
            return default
        try:
            return json.loads(s)
        except Exception:
            return default
    return default


def format_iso_datetime(v: Optional[datetime] = None) -> str:
    """Format a timezone-aware UTC datetime (or current UTC time if None) to an ISO 8601 string."""
    dt = v if v is not None else utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def parse_iso_datetime(
    v: Optional[Union[str, datetime]], default: Optional[datetime] = None
) -> Optional[datetime]:
    """Parse an ISO 8601 string or datetime into a UTC timezone-aware datetime object."""
    if v is None:
        return default
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc) if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        if not v.strip():
            return default
        try:
            dt = datetime.fromisoformat(v)
            return dt.astimezone(timezone.utc) if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return default
    return default


def compute_word_intersection_match_quality(query_text: str, candidate_text: str) -> float:
    """Compute word-level intersection match quality between a query text and candidate text."""
    query_words = set(re.findall(r"\w+", query_text.lower()))
    candidate_words = set(re.findall(r"\w+", candidate_text.lower()))
    if not query_words or not candidate_words:
        return 0.0
    intersection = query_words & candidate_words
    min_len = min(len(query_words), len(candidate_words))
    return len(intersection) / max(min_len, 1)

