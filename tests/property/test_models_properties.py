"""Property-based tests for Advanced Threat Detection data models.

Uses Hypothesis to verify properties 3, 4, 5, 10, 11, 26, and 27 across generated inputs.
"""

from datetime import datetime, timezone, timedelta
import uuid

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
    SwarmEvidence,
)

# Strategies
valid_uuid4_st = st.uuids(version=4)
utc_datetime_st = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 1, 1),
    timezones=st.just(timezone.utc),
)
non_empty_str_st = st.text(min_size=1).filter(lambda s: bool(s.strip()))
valid_risk_score_st = st.floats(min_value=0.0, max_value=1.0)
event_source_st = st.sampled_from(EventSource)


@st.composite
def normalized_event_st(draw):
    return NormalizedEvent(
        event_id=draw(valid_uuid4_st),
        timestamp=draw(utc_datetime_st),
        source=draw(event_source_st),
        agent_id=draw(non_empty_str_st),
        action=draw(non_empty_str_st),
        target=draw(non_empty_str_st),
        metadata={},
        risk_score=draw(valid_risk_score_st),
    )


@st.composite
def attack_node_st(draw):
    return AttackNode(
        node_id=draw(valid_uuid4_st),
        event=draw(normalized_event_st()),
    )


# Property 3: Normalized Event UUID Validity
@settings(max_examples=100)
@given(valid_uuid=valid_uuid4_st)
def test_property_3_normalized_event_uuid_validity(valid_uuid):
    """Property 3: For any created Normalized_Event, event_id SHALL be a valid UUID v4."""
    event = NormalizedEvent(
        event_id=valid_uuid,
        timestamp=datetime.now(timezone.utc),
        source=EventSource.KERNEL_SYSCALL,
        agent_id="agent-01",
        action="execve",
        target="/usr/bin/test",
        risk_score=0.5,
    )
    assert isinstance(event.event_id, uuid.UUID)
    assert event.event_id.version == 4


@settings(max_examples=100)
@given(invalid_str=st.text().filter(lambda s: not _is_valid_uuid4(s)))
def test_property_3_normalized_event_uuid_rejection(invalid_str):
    """Property 3 rejection: Invalid UUID strings must fail validation."""
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=invalid_str,
            timestamp=datetime.now(timezone.utc),
            source=EventSource.KERNEL_SYSCALL,
            agent_id="agent-01",
            action="execve",
            target="/usr/bin/test",
            risk_score=0.5,
        )


def _is_valid_uuid4(val: str) -> bool:
    try:
        parsed = uuid.UUID(val)
        return parsed.version == 4
    except Exception:
        return False


# Property 4: Normalized Event Timestamp Timezone
@settings(max_examples=100)
@given(ts=utc_datetime_st)
def test_property_4_normalized_event_timestamp_valid(ts):
    """Property 4: For any created Normalized_Event, timestamp SHALL be UTC timezone-aware."""
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=ts,
        source=EventSource.TOOL_CALL,
        agent_id="agent-01",
        action="read",
        target="file.txt",
        risk_score=0.2,
    )
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)


# Property 5: Risk Score Bounds
@settings(max_examples=100)
@given(score=valid_risk_score_st)
def test_property_5_normalized_event_risk_score_valid(score):
    """Property 5: For any created Normalized_Event, risk_score SHALL be in [0.0, 1.0]."""
    event = NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source=EventSource.IDENTITY_ACCESS,
        agent_id="agent-01",
        action="login",
        target="system",
        risk_score=score,
    )
    assert 0.0 <= event.risk_score <= 1.0


@settings(max_examples=100)
@given(
    invalid_score=st.one_of(
        st.floats(max_value=-0.0001),
        st.floats(min_value=1.0001),
    )
)
def test_property_5_normalized_event_risk_score_invalid(invalid_score):
    """Property 5 rejection: Out-of-bounds risk_score values must fail validation."""
    with pytest.raises(ValidationError):
        NormalizedEvent(
            event_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.IDENTITY_ACCESS,
            agent_id="agent-01",
            action="login",
            target="system",
            risk_score=invalid_score,
        )


# Property 10: Attack Path Minimum Node Validation
@settings(max_examples=100)
@given(node=attack_node_st(), path_id=valid_uuid4_st)
def test_property_10_attack_path_min_nodes(node, path_id):
    """Property 10: Attack_Path with fewer than 2 nodes SHALL be rejected."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=path_id,
            agent_id="agent-01",
            nodes=[node],
            start_time=now,
            end_time=now + timedelta(seconds=1),
            risk_score=0.5,
            correlation_score=0.5,
        )


# Property 11: Attack Path Temporal Validity
@settings(max_examples=100)
@given(
    nodes=st.lists(attack_node_st(), min_size=2, max_size=5),
    start=utc_datetime_st,
    offset_sec=st.integers(min_value=0, max_value=3600),
    path_id=valid_uuid4_st,
)
def test_property_11_attack_path_temporal_validity(nodes, start, offset_sec, path_id):
    """Property 11: For any Attack_Path, end_time SHALL be >= start_time."""
    end = start + timedelta(seconds=offset_sec)
    path = AttackPath(
        path_id=path_id,
        agent_id="agent-01",
        nodes=nodes,
        start_time=start,
        end_time=end,
        risk_score=0.5,
        correlation_score=0.5,
    )
    assert path.end_time >= path.start_time


@settings(max_examples=100)
@given(
    nodes=st.lists(attack_node_st(), min_size=2, max_size=5),
    start=utc_datetime_st,
    offset_sec=st.integers(min_value=1, max_value=3600),
    path_id=valid_uuid4_st,
)
def test_property_11_attack_path_temporal_invalidity(nodes, start, offset_sec, path_id):
    """Property 11 rejection: end_time < start_time must fail validation."""
    end = start - timedelta(seconds=offset_sec)
    with pytest.raises(ValidationError):
        AttackPath(
            path_id=path_id,
            agent_id="agent-01",
            nodes=nodes,
            start_time=start,
            end_time=end,
            risk_score=0.5,
            correlation_score=0.5,
        )


# Property 26: Swarm Evidence Agent Count Validation
@settings(max_examples=100)
@given(
    agents=st.sets(non_empty_str_st, min_size=2, max_size=10), swarm_id=valid_uuid4_st
)
def test_property_26_swarm_evidence_agent_count_valid(agents, swarm_id):
    """Property 26: Swarm_Evidence agent_ids set SHALL contain at least 2 distinct agent identifiers."""
    now = datetime.now(timezone.utc)
    evidence = SwarmEvidence(
        swarm_id=swarm_id,
        agent_ids=agents,
        temporal_correlation=0.8,
        coordination_score=0.85,
        first_seen=now,
        last_seen=now + timedelta(minutes=10),
    )
    assert len(evidence.agent_ids) >= 2


@settings(max_examples=100)
@given(agents=st.sets(non_empty_str_st, max_size=1), swarm_id=valid_uuid4_st)
def test_property_26_swarm_evidence_agent_count_invalid(agents, swarm_id):
    """Property 26 rejection: Swarm_Evidence with fewer than 2 agents must fail validation."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        SwarmEvidence(
            swarm_id=swarm_id,
            agent_ids=agents,
            temporal_correlation=0.8,
            coordination_score=0.85,
            first_seen=now,
            last_seen=now + timedelta(minutes=10),
        )


# Property 27: Swarm Evidence Correlation Threshold Validation
@settings(max_examples=100)
@given(corr=st.floats(min_value=0.0, max_value=1.0), swarm_id=valid_uuid4_st)
def test_property_27_swarm_evidence_correlation_threshold_bounds(corr, swarm_id):
    """Property 27: For any valid Swarm_Evidence, temporal_correlation SHALL be in [0.0, 1.0]."""
    now = datetime.now(timezone.utc)
    evidence = SwarmEvidence(
        swarm_id=swarm_id,
        agent_ids={"agent-1", "agent-2"},
        temporal_correlation=corr,
        coordination_score=0.8,
        first_seen=now,
        last_seen=now + timedelta(minutes=10),
    )
    assert 0.0 <= evidence.temporal_correlation <= 1.0
