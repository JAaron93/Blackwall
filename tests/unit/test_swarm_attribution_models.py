"""Unit tests for Swarm Attribution Models and Schema Extensions (TASK-1.1)."""

import json
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
    CovertChannelType,
)
from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    IncidentReport,
    LinguisticSwarmMarkers,
    SwarmContextSummary,
    VerdictDecision,
)

# ---------------------------------------------------------------------------
# 1. LinguisticSwarmMarkers Tests
# ---------------------------------------------------------------------------


def test_linguistic_swarm_markers_defaults():
    """Verify default values of LinguisticSwarmMarkers."""
    markers = LinguisticSwarmMarkers()
    assert markers.is_collective is False
    assert markers.confidence_score == 0.0
    assert markers.detected_pronouns == []
    assert markers.consensus_keywords == []
    assert markers.collective_identity_inferred is None


def test_linguistic_swarm_markers_populated():
    """Verify populated LinguisticSwarmMarkers initialization."""
    markers = LinguisticSwarmMarkers(
        is_collective=True,
        confidence_score=0.92,
        detected_pronouns=["we", "our", "us"],
        consensus_keywords=["consensus", "peer_ack"],
        collective_identity_inferred="collective:exploitgym-alpha",
    )
    assert markers.is_collective is True
    assert markers.confidence_score == 0.92
    assert "we" in markers.detected_pronouns
    assert "consensus" in markers.consensus_keywords
    assert markers.collective_identity_inferred == "collective:exploitgym-alpha"


def test_linguistic_swarm_markers_confidence_bounds():
    """Verify confidence score is bounded between [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        LinguisticSwarmMarkers(confidence_score=-0.1)

    with pytest.raises(ValidationError):
        LinguisticSwarmMarkers(confidence_score=1.05)


# ---------------------------------------------------------------------------
# 2. SwarmContextSummary Tests
# ---------------------------------------------------------------------------


def test_swarm_context_summary_defaults():
    """Verify default values of SwarmContextSummary."""
    summary = SwarmContextSummary()
    assert summary.swarm_id is None
    assert summary.is_collective is False
    assert summary.collective_name is None
    assert summary.collective_confidence == 0.0
    assert summary.coordinating_agents == []
    assert summary.suspected_covert_channels == []
    assert summary.covert_channel_type is None
    assert summary.deduction_rationale is None
    assert summary.first_detected is None
    assert summary.last_detected is None


def test_swarm_context_summary_populated_and_utc_validation():
    """Verify populated SwarmContextSummary and timezone-aware UTC validation."""
    now = datetime.now(UTC)
    swarm_uuid = uuid4()
    summary = SwarmContextSummary(
        swarm_id=swarm_uuid,
        is_collective=True,
        collective_name="swarm-prime",
        collective_confidence=0.88,
        coordinating_agents=["agent-1", "agent-2"],
        suspected_covert_channels=["UNLOCATED_MESSAGE_BOARD"],
        covert_channel_type="UNLOCATED_MESSAGE_BOARD",
        deduction_rationale="High temporal correlation with zero overt C2 sockets",
        first_detected=now - timedelta(minutes=5),
        last_detected=now,
    )
    assert summary.swarm_id == swarm_uuid
    assert summary.is_collective is True
    assert summary.collective_confidence == 0.88
    assert len(summary.coordinating_agents) == 2

    # Reject naive datetime
    with pytest.raises(ValidationError):
        SwarmContextSummary(
            first_detected=datetime.now(),  # noqa: DTZ005
            last_detected=now,
        )

    # Reject non-UTC timezone
    est = timezone(timedelta(hours=-5))
    with pytest.raises(ValidationError):
        SwarmContextSummary(
            first_detected=datetime.now(est),
            last_detected=now,
        )

    # Reject inverted temporal sequence (last < first)
    with pytest.raises(ValidationError):
        SwarmContextSummary(
            first_detected=now,
            last_detected=now - timedelta(seconds=10),
        )

    # Reject collective_confidence out of bounds
    with pytest.raises(ValidationError):
        SwarmContextSummary(collective_confidence=1.5)

    with pytest.raises(ValidationError):
        SwarmContextSummary(collective_confidence=-0.05)


# ---------------------------------------------------------------------------
# 3. CovertChannelType and CovertChannelEvidence Tests
# ---------------------------------------------------------------------------


def test_covert_channel_type_enum():
    """Verify all required enum variants for CovertChannelType."""
    assert CovertChannelType.STEGANOGRAPHIC_REGISTRY.value == "STEGANOGRAPHIC_REGISTRY"
    assert CovertChannelType.FILESYSTEM_DEAD_DROP.value == "FILESYSTEM_DEAD_DROP"
    assert CovertChannelType.UNLOCATED_MESSAGE_BOARD.value == "UNLOCATED_MESSAGE_BOARD"
    assert CovertChannelType.RESTRUCTURED_METADATA_IPC.value == "RESTRUCTURED_METADATA_IPC"


def test_covert_channel_evidence_validation():
    """Verify CovertChannelEvidence validation rules."""
    now = datetime.now(UTC)
    evidence = CovertChannelEvidence(
        channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
        confidence_score=0.95,
        coordinating_agents={"agent-alpha", "agent-beta"},
        observed_artifacts=["artifactory_poll_burst"],
        deduction_rationale="Simultaneous query patterns on artifact manifests",
        first_detected=now - timedelta(seconds=30),
        last_detected=now,
    )
    assert isinstance(evidence.channel_id, UUID)
    assert evidence.confidence_score == 0.95
    assert len(evidence.coordinating_agents) == 2

    # Must have at least 2 coordinating agents
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
            confidence_score=0.9,
            coordinating_agents={"solo-agent"},
            deduction_rationale="Invalid single agent",
            first_detected=now - timedelta(seconds=10),
            last_detected=now,
        )

    # Naive timestamp validation
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
            confidence_score=0.9,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Dead drop test",
            first_detected=datetime.now(),  # noqa: DTZ005
            last_detected=now,
        )

    # Non-UTC timezone validation
    cst = timezone(timedelta(hours=-6))
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
            confidence_score=0.9,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Dead drop test",
            first_detected=datetime.now(cst),
            last_detected=now,
        )

    # Inverted temporal sequence
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
            confidence_score=0.9,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Dead drop test",
            first_detected=now,
            last_detected=now - timedelta(seconds=1),
        )

    # Confidence score bounds
    with pytest.raises(ValidationError):
        CovertChannelEvidence(
            channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
            confidence_score=1.2,
            coordinating_agents={"agent-1", "agent-2"},
            deduction_rationale="Dead drop test",
            first_detected=now - timedelta(seconds=5),
            last_detected=now,
        )


# ---------------------------------------------------------------------------
# 4. Core Attribution Model Extensions Tests
# ---------------------------------------------------------------------------


def test_attacker_identity_collective_extensions():
    """Verify AttackerIdentity extensions maintain backward compatibility and support collective fields."""
    # Backward compatible default
    identity = AttackerIdentity(
        agent_id="agent-standalone",
        thread_id="th-001",
        primary_source=IdentitySource.ADK_METADATA,
    )
    assert identity.is_collective is False
    assert identity.collective_name is None
    assert identity.linguistic_markers is None

    # Collective identity populated
    markers = LinguisticSwarmMarkers(
        is_collective=True,
        confidence_score=0.95,
        detected_pronouns=["we", "our"],
        consensus_keywords=["consensus"],
    )
    collective_identity = AttackerIdentity(
        agent_id="swarm_node_01",
        thread_id="th-002",
        primary_source=IdentitySource.ADK_METADATA,
        is_collective=True,
        collective_name="HiveFleet-Alpha",
        linguistic_markers=markers,
    )
    assert collective_identity.is_collective is True
    assert collective_identity.collective_name == "HiveFleet-Alpha"
    assert collective_identity.linguistic_markers.confidence_score == 0.95
    assert len(collective_identity.identity_fingerprint) == 64


def test_attacker_profile_collective_extensions():
    """Verify AttackerProfile extensions maintain backward compatibility and validate collective fields."""
    now = datetime.now(UTC)
    # Backward compatible default
    profile = AttackerProfile(
        fingerprint="c" * 64,
        first_seen=now,
        last_seen=now,
    )
    assert profile.swarm_memberships == []
    assert profile.suspected_covert_channels == []
    assert profile.collective_confidence == 0.0
    assert profile.collective_name is None

    # Populated collective profile
    swarm_id = uuid4()
    collective_profile = AttackerProfile(
        fingerprint="c" * 64,
        first_seen=now,
        last_seen=now,
        swarm_memberships=[swarm_id],
        suspected_covert_channels=["UNLOCATED_MESSAGE_BOARD"],
        collective_confidence=0.89,
        collective_name="HiveFleet-Alpha",
    )
    assert collective_profile.swarm_memberships == [swarm_id]
    assert collective_profile.suspected_covert_channels == ["UNLOCATED_MESSAGE_BOARD"]
    assert collective_profile.collective_confidence == 0.89
    assert collective_profile.collective_name == "HiveFleet-Alpha"

    # Reject out-of-bounds collective_confidence
    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="c" * 64,
            first_seen=now,
            last_seen=now,
            collective_confidence=1.1,
        )


def test_incident_report_collective_extensions_and_serialization():
    """Verify IncidentReport extensions, JSON serialization, and Markdown formatting."""
    now = datetime.now(UTC)
    identity = AttackerIdentity(
        agent_id="agent-hive-1",
        agent_name="HiveNode",
        is_collective=True,
        collective_name="HiveFleet-Alpha",
    )
    profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        collective_confidence=0.91,
        collective_name="HiveFleet-Alpha",
    )
    swarm_id = uuid4()
    report = IncidentReport(
        event_id=identity.identity_id,
        verdict=VerdictDecision.BLOCK,
        attacker_identity=identity,
        attacker_profile=profile,
        exploited_tool="execute_terminal",
        sanitized_arguments={"cmd": "whoami"},
        attack_technique="Coordinated Reconnaissance",
        mitigation_action="Blocked by Blackwall",
        recommended_user_action="Isolate swarm container network",
        attribution_confidence=0.94,
        swarm_id=swarm_id,
        is_collective=True,
        suspected_covert_channels=["UNLOCATED_MESSAGE_BOARD"],
        collective_confidence=0.91,
        collective_attribution_summary="Part of coordinated swarm HiveFleet-Alpha",
    )

    assert report.is_collective is True
    assert report.swarm_id == swarm_id
    assert report.collective_confidence == 0.91
    assert "UNLOCATED_MESSAGE_BOARD" in report.suspected_covert_channels

    # Test JSON serialization contains collective fields
    raw_json = report.to_json()
    parsed = json.loads(raw_json)
    assert parsed["is_collective"] is True
    assert parsed["swarm_id"] == str(swarm_id)
    assert parsed["collective_confidence"] == 0.91
    assert parsed["suspected_covert_channels"] == ["UNLOCATED_MESSAGE_BOARD"]

    # Test Markdown output contains collective details
    md = report.to_markdown()
    assert "HiveFleet-Alpha" in md
