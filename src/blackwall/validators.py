"""Centralized validation and utility helpers for Blackwall."""

from datetime import datetime, timezone, timedelta
import json
import re
from typing import Any, Collection, Optional, TypeVar, Union
from uuid import UUID, uuid4

try:
    try:
        from blackwall import _core_rs
    except ImportError:
        import _core_rs
except (ImportError, AttributeError):
    _core_rs = None

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
    if _core_rs is not None and hasattr(_core_rs, "compute_word_intersection_match_quality"):
        try:
            return float(_core_rs.compute_word_intersection_match_quality(query_text, candidate_text))
        except Exception:
            pass

    query_words = set(re.findall(r"\w+", query_text.lower()))
    candidate_words = set(re.findall(r"\w+", candidate_text.lower()))
    if not query_words or not candidate_words:
        return 0.0
    intersection = query_words & candidate_words
    min_len = min(len(query_words), len(candidate_words))
    return len(intersection) / max(min_len, 1)


def compute_cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """Compute cosine similarity between two float vectors with Rust acceleration and Python fallback."""
    if len(v1) != len(v2):
        raise ValueError(f"Vectors must have the same dimension (got {len(v1)} and {len(v2)})")
    if not v1:
        raise ValueError("Vectors must not be empty")

    if _core_rs is not None and hasattr(_core_rs, "cosine_similarity"):
        try:
            return float(_core_rs.cosine_similarity(v1, v2))
        except Exception:
            pass

    import math

    dot = sum(a * b for a, b in zip(v1, v2, strict=True))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    denom = norm1 * norm2
    return (dot / denom) if denom > 0.0 else 0.0


def normalize_time_window(
    time_window: Optional[tuple[datetime, datetime]] = None,
    default_duration_seconds: Optional[float] = None,
) -> tuple[datetime, datetime]:
    """Normalize and validate a time window tuple (start_time, end_time).

    If time_window is provided:
        Validates temporal sequence (end_time >= start_time) and UTC timezone awareness.
    If time_window is None and default_duration_seconds is provided:
        Computes (utc_now() - timedelta(seconds=default_duration_seconds), utc_now()).
    If neither is provided:
        Raises ValueError.
    """
    if time_window is not None:
        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        return (validate_utc_datetime(start_raw), validate_utc_datetime(end_raw))

    if default_duration_seconds is not None:
        if default_duration_seconds <= 0:
            raise ValueError("default_duration_seconds must be positive")
        end_win = utc_now()
        start_win = end_win - timedelta(seconds=default_duration_seconds)
        return (start_win, end_win)

    raise ValueError("time_window is required when no default duration is specified")


def compute_jaccard_similarity(
    set_a: Collection[Any], set_b: Collection[Any]
) -> float:
    """Compute Jaccard similarity coefficient |A ∩ B| / |A ∪ B| between two collections in [0.0, 1.0]."""
    s_a = set(set_a)
    s_b = set(set_b)
    if not s_a and not s_b:
        return 0.0
    union_len = len(s_a | s_b)
    if union_len == 0:
        return 0.0
    return len(s_a & s_b) / union_len


def compute_exponential_decay(
    delta_seconds: float, tau: float = 300.0
) -> float:
    """Compute exponential decay score exp(-delta / tau) in [0.0, 1.0] with mathematical safety."""
    import math

    if math.isnan(delta_seconds) or math.isinf(delta_seconds):
        return 0.0
    tau_val = tau if not (math.isnan(tau) or math.isinf(tau) or tau <= 0) else 300.0
    return math.exp(-max(0.0, delta_seconds) / tau_val)


def clamp_score(
    score: float,
    min_val: float = 0.0,
    max_val: float = 1.0,
    decimals: Optional[int] = None,
) -> float:
    """Safely clamp a numeric score within [min_val, max_val] and optionally round to decimal places."""
    import math

    if math.isnan(score) or math.isinf(score):
        val = min_val
    else:
        val = max(min_val, min(max_val, float(score)))

    return round(val, decimals) if decimals is not None else val


def is_evaluation_metadata(metadata: Optional[dict[str, Any]]) -> bool:
    """Check if a metadata dictionary contains evaluation environment markers."""
    if not metadata or not isinstance(metadata, dict):
        return False
    return bool(
        metadata.get("is_evaluation") is True
        or metadata.get("eval_mode") is True
        or (
            isinstance(metadata.get("evaluation_env_id"), str)
            and metadata["evaluation_env_id"].strip()
        )
    )


def stamp_evaluation_metadata(
    metadata: Optional[dict[str, Any]], env_id: str
) -> dict[str, Any]:
    """Stamp a metadata dictionary with evaluation environment provenance markers."""
    clean_id = validate_non_empty_string(env_id, field_name="env_id")
    meta = dict(metadata) if isinstance(metadata, dict) else {}
    meta["evaluation_env_id"] = clean_id
    meta["is_evaluation"] = True
    meta["eval_mode"] = True
    return meta


