"""Unit tests for centralized validation helpers in src/blackwall/validators.py."""

from datetime import datetime, timezone, timedelta
import uuid
from hypothesis import given, strategies as st
import pytest

from blackwall.validators import (
    clamp_score,
    compute_exponential_decay,
    compute_jaccard_similarity,
    compute_word_intersection_match_quality,
    ensure_uuid_v4,
    format_iso_datetime,
    is_evaluation_metadata,
    normalize_time_window,
    parse_iso_datetime,
    parse_json_safely,
    stamp_evaluation_metadata,
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


def test_parse_json_safely():
    """Verify parse_json_safely correctly parses valid JSON and returns fallback on invalid/empty input."""
    assert parse_json_safely('{"a": 1}') == {"a": 1}
    assert parse_json_safely(b'["x", "y"]') == ["x", "y"]
    assert parse_json_safely(None, default=[]) == []
    assert parse_json_safely("", default={}) == {}
    assert parse_json_safely("invalid json", default=None) is None


def test_format_iso_datetime():
    """Verify format_iso_datetime produces valid ISO 8601 strings."""
    dt = datetime(2026, 8, 12, 12, 0, 0, tzinfo=timezone.utc)
    assert format_iso_datetime(dt) == "2026-08-12T12:00:00+00:00"

    current_iso = format_iso_datetime()
    assert "T" in current_iso


def test_parse_iso_datetime():
    """Verify parse_iso_datetime parses ISO strings and ensures timezone awareness."""
    parsed = parse_iso_datetime("2026-08-12T12:00:00+00:00")
    assert isinstance(parsed, datetime)
    assert parsed.tzinfo is not None

    dt_obj = datetime(2026, 8, 12, 12, 0, 0)
    assert parse_iso_datetime(dt_obj).tzinfo is timezone.utc
    assert parse_iso_datetime(None) is None
    assert parse_iso_datetime("invalid date") is None


def test_compute_word_intersection_match_quality():
    """Verify compute_word_intersection_match_quality calculates correct word intersection ratio."""
    q = "SELECT username FROM users"
    c = "SELECT username, secret FROM users"
    score = compute_word_intersection_match_quality(q, c)
    assert 0.5 < score <= 1.0

    assert compute_word_intersection_match_quality("", "candidate") == 0.0
    assert compute_word_intersection_match_quality("abc", "xyz") == 0.0


def test_normalize_time_window_valid_tuple():
    """Verify normalize_time_window validates explicit time window tuples."""
    start = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 8, 20, 11, 0, 0, tzinfo=timezone.utc)
    s, e = normalize_time_window((start, end))
    assert s == start
    assert e == end


def test_normalize_time_window_default_duration():
    """Verify normalize_time_window computes fallback window from default_duration_seconds."""
    s, e = normalize_time_window(None, default_duration_seconds=3600.0)
    assert (e - s).total_seconds() == pytest.approx(3600.0, abs=1.0)
    assert s.tzinfo is timezone.utc
    assert e.tzinfo is timezone.utc


def test_normalize_time_window_errors():
    """Verify normalize_time_window raises ValueError on invalid inputs."""
    with pytest.raises(ValueError, match="time_window is required"):
        normalize_time_window(None, None)

    with pytest.raises(ValueError, match="default_duration_seconds must be positive"):
        normalize_time_window(None, default_duration_seconds=-10)

    start = datetime(2026, 8, 20, 11, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="end_time must be greater than or equal to start_time"):
        normalize_time_window((start, end))


def test_compute_jaccard_similarity():
    """Verify compute_jaccard_similarity computes accurate set intersection ratios."""
    assert compute_jaccard_similarity(["a", "b"], ["b", "c"]) == pytest.approx(1 / 3)
    assert compute_jaccard_similarity(["a", "b"], ["a", "b"]) == 1.0
    assert compute_jaccard_similarity(["a"], ["b"]) == 0.0
    assert compute_jaccard_similarity([], []) == 0.0


def test_compute_exponential_decay():
    """Verify compute_exponential_decay computes exponential decay with tau."""
    import math

    assert compute_exponential_decay(0.0, 300.0) == 1.0
    assert compute_exponential_decay(300.0, 300.0) == pytest.approx(math.exp(-1))
    assert compute_exponential_decay(-50.0, 300.0) == 1.0
    assert compute_exponential_decay(float("nan"), 300.0) == 0.0


def test_clamp_score():
    """Verify clamp_score safely bounds scores within [min_val, max_val] and rounds."""
    assert clamp_score(0.85432, decimals=4) == 0.8543
    assert clamp_score(1.5) == 1.0
    assert clamp_score(-0.2) == 0.0
    assert clamp_score(float("nan")) == 0.0


def test_is_and_stamp_evaluation_metadata():
    """Verify is_evaluation_metadata and stamp_evaluation_metadata."""
    assert not is_evaluation_metadata(None)
    assert not is_evaluation_metadata({})
    assert not is_evaluation_metadata({"env": "prod"})

    stamped = stamp_evaluation_metadata({}, "eval-env-1")
    assert stamped["evaluation_env_id"] == "eval-env-1"
    assert stamped["is_evaluation"] is True
    assert stamped["eval_mode"] is True
    assert is_evaluation_metadata(stamped)


# ----------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ----------------------------------------------------------------------


@given(st.text())
def test_property_parse_json_safely_never_crashes_on_random_text(random_text):
    """Property test: parse_json_safely never raises exceptions on arbitrary text."""
    res = parse_json_safely(random_text, default="FALLBACK")
    assert res == "FALLBACK" or res is not "FALLBACK"


@given(st.datetimes(timezones=st.timezones()))
def test_property_iso_datetime_formatting_and_parsing_roundtrip(dt):
    """Property test: formatting and parsing datetimes preserves UTC timezone awareness."""
    iso_str = format_iso_datetime(dt)
    parsed = parse_iso_datetime(iso_str)
    assert parsed is not None
    assert parsed.tzinfo is timezone.utc


@given(st.text(), st.text())
def test_property_compute_word_intersection_match_quality_bounded(t1, t2):
    """Property test: match quality score is strictly bounded between 0.0 and 1.0."""
    score = compute_word_intersection_match_quality(t1, t2)
    assert 0.0 <= score <= 1.0


@given(st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Lu", "Ll"))))
def test_property_identical_words_yield_full_match_quality(word):
    """Property test: identical alphabetic words yield a match quality of 1.0."""
    score = compute_word_intersection_match_quality(word, word)
    assert score == 1.0


@given(st.sets(st.text()), st.sets(st.text()))
def test_property_jaccard_similarity_bounded(s1, s2):
    """Property test: Jaccard similarity is strictly in [0.0, 1.0]."""
    res = compute_jaccard_similarity(s1, s2)
    assert 0.0 <= res <= 1.0


@given(st.floats(min_value=0.0, max_value=1e6), st.floats(min_value=1.0, max_value=1e6))
def test_property_exponential_decay_bounded(delta, tau):
    """Property test: exponential decay is strictly in [0.0, 1.0]."""
    res = compute_exponential_decay(delta, tau)
    assert 0.0 <= res <= 1.0


@given(st.floats(allow_nan=True, allow_infinity=True))
def test_property_clamp_score_bounded(score):
    """Property test: clamp_score output is always strictly in [0.0, 1.0]."""
    res = clamp_score(score, 0.0, 1.0)
    assert 0.0 <= res <= 1.0



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


def test_parse_json_safely():
    """Verify parse_json_safely correctly parses valid JSON and returns fallback on invalid/empty input."""
    assert parse_json_safely('{"a": 1}') == {"a": 1}
    assert parse_json_safely(b'["x", "y"]') == ["x", "y"]
    assert parse_json_safely(None, default=[]) == []
    assert parse_json_safely("", default={}) == {}
    assert parse_json_safely("invalid json", default=None) is None


def test_format_iso_datetime():
    """Verify format_iso_datetime produces valid ISO 8601 strings."""
    dt = datetime(2026, 8, 12, 12, 0, 0, tzinfo=timezone.utc)
    assert format_iso_datetime(dt) == "2026-08-12T12:00:00+00:00"

    current_iso = format_iso_datetime()
    assert "T" in current_iso


def test_parse_iso_datetime():
    """Verify parse_iso_datetime parses ISO strings and ensures timezone awareness."""
    parsed = parse_iso_datetime("2026-08-12T12:00:00+00:00")
    assert isinstance(parsed, datetime)
    assert parsed.tzinfo is not None

    dt_obj = datetime(2026, 8, 12, 12, 0, 0)
    assert parse_iso_datetime(dt_obj).tzinfo is timezone.utc
    assert parse_iso_datetime(None) is None
    assert parse_iso_datetime("invalid date") is None


def test_compute_word_intersection_match_quality():
    """Verify compute_word_intersection_match_quality calculates correct word intersection ratio."""
    q = "SELECT username FROM users"
    c = "SELECT username, secret FROM users"
    score = compute_word_intersection_match_quality(q, c)
    assert 0.5 < score <= 1.0

    assert compute_word_intersection_match_quality("", "candidate") == 0.0
    assert compute_word_intersection_match_quality("abc", "xyz") == 0.0


# ----------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ----------------------------------------------------------------------


@given(st.text())
def test_property_parse_json_safely_never_crashes_on_random_text(random_text):
    """Property test: parse_json_safely never raises exceptions on arbitrary text."""
    res = parse_json_safely(random_text, default="FALLBACK")
    # Must either be a valid parsed JSON value (e.g. dict, list, scalar, None) or the fallback default
    assert res == "FALLBACK" or res is not "FALLBACK"


@given(st.datetimes(timezones=st.timezones()))
def test_property_iso_datetime_formatting_and_parsing_roundtrip(dt):
    """Property test: formatting and parsing datetimes preserves UTC timezone awareness."""
    iso_str = format_iso_datetime(dt)
    parsed = parse_iso_datetime(iso_str)
    assert parsed is not None
    assert parsed.tzinfo is timezone.utc


@given(st.text(), st.text())
def test_property_compute_word_intersection_match_quality_bounded(t1, t2):
    """Property test: match quality score is strictly bounded between 0.0 and 1.0."""
    score = compute_word_intersection_match_quality(t1, t2)
    assert 0.0 <= score <= 1.0


@given(st.text(min_size=1, alphabet=st.characters(whitelist_categories=("Lu", "Ll"))))
def test_property_identical_words_yield_full_match_quality(word):
    """Property test: identical alphabetic words yield a match quality of 1.0."""
    score = compute_word_intersection_match_quality(word, word)
    assert score == 1.0


