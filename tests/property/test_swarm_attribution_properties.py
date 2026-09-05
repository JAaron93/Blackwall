"""Hypothesis property-based tests for Swarm Attribution Models (TASK-1.2).

Verifies invariants:
1. Confidence score boundary validation ([0.0, 1.0]).
2. Minimal coordinating agent set lengths (N >= 2).
3. Timezone-aware UTC datetime enforcement.
4. Temporal sequence ordering (last_detected >= first_detected).
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
    CovertChannelType,
)
from blackwall.models import (
    AttackerProfile,
    LinguisticSwarmMarkers,
    SwarmContextSummary,
)

# ---------------------------------------------------------------------------
# Property 1: Score Boundary Validation ([0.0, 1.0])
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(score=st.floats(min_value=0.0, max_value=1.0))
def test_property_valid_confidence_scores_accepted(score: float):
    """Property: All confidence scores in [0.0, 1.0] must be valid across all models."""
    markers = LinguisticSwarmMarkers(confidence_score=score)
    assert 0.0 <= markers.confidence_score <= 1.0

    summary = SwarmContextSummary(collective_confidence=score)
    assert 0.0 <= summary.collective_confidence <= 1.0

    now = datetime.now(UTC)
    evidence = CovertChannelEvidence(
        channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
        confidence_score=score,
        coordinating_agents={"agent-1", "agent-2"},
        deduction_rationale="Hypothesis score test",
        first_detected=now,
        last_detected=now,
    )
    assert 0.0 <= evidence.confidence_score <= 1.0

    profile = AttackerProfile(
        fingerprint="d" * 64,
        first_seen=now,
        last_seen=now,
        collective_confidence=score,
    )
    assert 0.0 <= profile.collective_confidence <= 1.0


@settings(max_examples=50)
@given(
    invalid_score=st.one_of(
        st.floats(max_value=-0.0001, allow_nan=False, allow_infinity=False),
        st.floats(min_value=1.0001, max_value=1e6, allow_nan=False, allow_infinity=False),
    )
)
def test_property_out_of_bounds_confidence_scores_rejected(invalid_score: float):
    """Property: Any confidence score strictly < 0.0 or > 1.0 must raise ValidationError."""
    with pytest.raises(ValidationError):
        LinguisticSwarmMarkers(confidence_score=invalid_score)

    with pytest.raises(ValidationError):
        SwarmContextSummary(collective_confidence=invalid_score)

    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
            confidence_score=invalid_score,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Hypothesis invalid score test",
            first_detected=now,
            last_detected=now,
        )

    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="d" * 64,
            first_seen=now,
            last_seen=now,
            collective_confidence=invalid_score,
        )


# ---------------------------------------------------------------------------
# Property 2: Coordinating Agents Set Cardinality (N >= 2)
# ---------------------------------------------------------------------------


@settings(max_examples=40)
@given(
    agents=st.sets(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=30),
        min_size=2,
        max_size=10,
    )
)
def test_property_coordinating_agents_valid_cardinality(agents: set[str]):
    """Property: CovertChannelEvidence accepts any agent set with cardinality >= 2."""
    now = datetime.now(UTC)
    evidence = CovertChannelEvidence(
        channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
        confidence_score=0.9,
        coordinating_agents=agents,
        deduction_rationale="Valid cardinality test",
        first_detected=now,
        last_detected=now,
    )
    assert len(evidence.coordinating_agents) >= 2


@settings(max_examples=40)
@given(
    invalid_agents=st.sets(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=30),
        max_size=1,
    )
)
def test_property_coordinating_agents_invalid_cardinality(invalid_agents: set[str]):
    """Property: CovertChannelEvidence rejects any agent set with cardinality < 2."""
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
            confidence_score=0.9,
            coordinating_agents=invalid_agents,
            deduction_rationale="Invalid cardinality test",
            first_detected=now,
            last_detected=now,
        )


# ---------------------------------------------------------------------------
# Property 3: Timezone-Aware UTC Datetime Enforcement
# ---------------------------------------------------------------------------


@settings(max_examples=30)
@given(
    offset_hours=st.one_of(
        st.integers(min_value=-12, max_value=-1),
        st.integers(min_value=1, max_value=14),
    )
)
def test_property_non_utc_timezones_rejected(offset_hours: int):
    """Property: Non-UTC timezone offsets must raise ValidationError."""
    non_utc_tz = timezone(timedelta(hours=offset_hours))
    non_utc_dt = datetime(2026, 9, 4, 12, 0, 0, tzinfo=non_utc_tz)
    utc_dt = datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC)

    # SwarmContextSummary
    with pytest.raises(ValidationError):
        SwarmContextSummary(first_detected=non_utc_dt, last_detected=utc_dt)

    with pytest.raises(ValidationError):
        SwarmContextSummary(first_detected=utc_dt, last_detected=non_utc_dt)

    # CovertChannelEvidence
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
            confidence_score=0.85,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Non-UTC test",
            first_detected=non_utc_dt,
            last_detected=utc_dt,
        )


# ---------------------------------------------------------------------------
# Property 4: Temporal Sequence Ordering (last_detected >= first_detected)
# ---------------------------------------------------------------------------


@settings(max_examples=40)
@given(
    delta_seconds=st.integers(min_value=0, max_value=86400 * 365),
)
def test_property_temporal_ordering_valid(delta_seconds: int):
    """Property: last_detected >= first_detected must always pass validation."""
    first = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    last = first + timedelta(seconds=delta_seconds)

    summary = SwarmContextSummary(first_detected=first, last_detected=last)
    assert summary.last_detected >= summary.first_detected

    evidence = CovertChannelEvidence(
        channel_type=CovertChannelType.STEGANOGRAPHIC_REGISTRY,
        confidence_score=0.8,
        coordinating_agents={"agent-a", "agent-b"},
        deduction_rationale="Ordering property test",
        first_detected=first,
        last_detected=last,
    )
    assert evidence.last_detected >= evidence.first_detected


@settings(max_examples=40)
@given(
    delta_seconds=st.integers(min_value=1, max_value=86400 * 365),
)
def test_property_temporal_ordering_inverted_rejected(delta_seconds: int):
    """Property: last_detected < first_detected must always raise ValidationError."""
    first = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    last = first - timedelta(seconds=delta_seconds)

    with pytest.raises(ValidationError):
        SwarmContextSummary(first_detected=first, last_detected=last)

    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.STEGANOGRAPHIC_REGISTRY,
            confidence_score=0.8,
            coordinating_agents={"agent-a", "agent-b"},
            deduction_rationale="Ordering inverted test",
            first_detected=first,
            last_detected=last,
        )
