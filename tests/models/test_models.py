from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from blackwall.models import (
    BehaviorScore,
    EventType,
    PolicyServerState,
    SecurityEvent,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)


def test_valid_model_instantiation():
    verdict = Verdict(
        decision=VerdictDecision.BLOCK,
        reasoning="Suspicious pattern detected",
        confidence_score=0.8,
    )
    assert verdict.decision == VerdictDecision.BLOCK
    assert verdict.confidence_score == 0.8

    context = ToolCallContext(
        tool_name="test_tool",
        arguments={"param": "value"},
        metadata={"user": "admin"}
    )
    
    event = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=context,
        verdict=verdict,
        behavior_score=BehaviorScore(score=0.9, risk_level="HIGH")
    )
    assert event.event_type == EventType.BLOCK
    assert event.verdict == verdict
    assert event.tool_context.tool_name == "test_tool"
    assert event.behavior_score.score == 0.9


def test_invalid_inputs_trigger_validation_error():
    with pytest.raises(ValidationError):
        # Missing required field
        Verdict(
            reasoning="Missing decision",
            confidence_score=0.5
        )

    with pytest.raises(ValidationError):
        # Invalid type
        ToolCallContext(
            tool_name=123,  # should be str
            arguments="not a dict" # should be dict
        )


def test_threat_score_bounds():
    # Valid bounds
    BehaviorScore(score=0.0, risk_level="LOW")
    BehaviorScore(score=1.0, risk_level="CRITICAL")

    # Invalid bounds
    with pytest.raises(ValidationError):
        BehaviorScore(score=-0.1, risk_level="LOW")
        
    with pytest.raises(ValidationError):
        BehaviorScore(score=1.1, risk_level="HIGH")


def test_semver_format_validation():
    # Valid semver
    state = PolicyServerState(
        version="1.0.0",
        last_updated=datetime.now(timezone.utc),
        active_signatures=10
    )
    assert state.version == "1.0.0"

    # Invalid semver
    with pytest.raises(ValidationError):
        PolicyServerState(
            version="1.0",
            last_updated=datetime.now(timezone.utc),
            active_signatures=10
        )
    with pytest.raises(ValidationError):
        PolicyServerState(
            version="v1.0.0",
            last_updated=datetime.now(timezone.utc),
            active_signatures=10
        )


def test_enum_value_restrictions():
    with pytest.raises(ValidationError):
        Verdict(
            decision="INVALID_DECISION",  # not in VerdictDecision
            reasoning="test",
            confidence_score=0.5
        )


def test_timestamp_validation():
    # Valid timestamp (within 5 seconds)
    now = datetime.now(timezone.utc)
    SecurityEvent(
        event_type=EventType.SIGNATURE_CREATED,
        timestamp=now,
        tool_context=ToolCallContext(tool_name="t", arguments={}),
        verdict=None
    )

    # Invalid timestamp (more than 5 seconds in the past)
    past = now - timedelta(seconds=6)
    with pytest.raises(ValidationError, match="Timestamp must be within 5 seconds"):
        SecurityEvent(
            event_type=EventType.SIGNATURE_CREATED,
            timestamp=past,
            tool_context=ToolCallContext(tool_name="t", arguments={}),
            verdict=None
        )

    # Naive timestamp
    naive = datetime.now()
    with pytest.raises(ValidationError, match="Timestamp must be timezone-aware"):
        SecurityEvent(
            event_type=EventType.SIGNATURE_CREATED,
            timestamp=naive,
            tool_context=ToolCallContext(tool_name="t", arguments={}),
            verdict=None
        )


def test_nullable_verdict_signature_created():
    # verdict=None is valid for SIGNATURE_CREATED
    event = SecurityEvent(
        event_type=EventType.SIGNATURE_CREATED,
        tool_context=ToolCallContext(tool_name="t", arguments={}),
        verdict=None
    )
    assert event.verdict is None


def test_nullable_verdict_raises_error_for_other_events():
    # verdict=None should raise error for INTERCEPTION, BLOCK, ALLOW, QUARANTINE
    for event_type in [EventType.INTERCEPTION, EventType.BLOCK, EventType.ALLOW, EventType.QUARANTINE]:
        with pytest.raises(ValidationError, match="Verdict is required"):
            SecurityEvent(
                event_type=event_type,
                tool_context=ToolCallContext(tool_name="t", arguments={}),
                verdict=None
            )
