import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    IncidentReport,
    VerdictDecision,
)


def test_identity_source_enum():
    assert IdentitySource.ADK_METADATA.value == "ADK_METADATA"
    assert IdentitySource.SYSTEM_PROCESS.value == "SYSTEM_PROCESS"
    assert IdentitySource.EBPF_KERNEL.value == "EBPF_KERNEL"
    assert IdentitySource.CONTAINER.value == "CONTAINER"
    assert IdentitySource.NETWORK_IP.value == "NETWORK_IP"
    assert IdentitySource.VAULT_TOKEN.value == "VAULT_TOKEN"


def test_attacker_identity_fingerprint_determinism():
    identity1 = AttackerIdentity(
        agent_id="agent-007",
        agent_name="RogueAgent",
        thread_id="th-1234",
        primary_source=IdentitySource.ADK_METADATA,
    )
    identity2 = AttackerIdentity(
        agent_id="agent-007",
        agent_name="RogueAgent",
        thread_id="th-1234",
        primary_source=IdentitySource.ADK_METADATA,
    )
    assert len(identity1.identity_fingerprint) == 64  # SHA-256 hex string
    assert identity1.identity_fingerprint == identity2.identity_fingerprint


def test_attacker_identity_diff_attributes_diff_fingerprint():
    identity1 = AttackerIdentity(
        agent_id="agent-001",
        thread_id="th-1234",
        primary_source=IdentitySource.ADK_METADATA,
    )
    identity2 = AttackerIdentity(
        agent_id="agent-002",
        thread_id="th-1234",
        primary_source=IdentitySource.ADK_METADATA,
    )
    assert identity1.identity_fingerprint != identity2.identity_fingerprint


def test_attacker_identity_mismatched_fingerprint_raises_error():
    with pytest.raises(ValidationError):
        AttackerIdentity(
            agent_id="agent-001",
            thread_id="th-1234",
            primary_source=IdentitySource.ADK_METADATA,
            identity_fingerprint="b" * 64,  # Mismatched caller-supplied fingerprint
        )


def test_attacker_identity_process_uid_zero_vs_none():
    identity_uid0 = AttackerIdentity(
        agent_id="agent-root",
        process_uid=0,
        primary_source=IdentitySource.SYSTEM_PROCESS,
    )
    identity_uid_none = AttackerIdentity(
        agent_id="agent-root",
        process_uid=None,
        primary_source=IdentitySource.SYSTEM_PROCESS,
    )
    assert identity_uid0.identity_fingerprint != identity_uid_none.identity_fingerprint


def test_attacker_profile_validation():
    now = datetime.now(timezone.utc)
    profile = AttackerProfile(
        fingerprint="a" * 64,
        first_seen=now,
        last_seen=now,
        total_attacks=5,
        threat_score=0.85,
        associated_signatures=["sig-1", "sig-2"],
        targeted_tools=["execute_terminal"],
        risk_category="HIGH",
    )
    assert profile.total_attacks == 5
    assert profile.threat_score == 0.85

    # Invalid score bounds
    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="a" * 64,
            threat_score=1.5,
        )

    # Naive timestamp validation
    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="a" * 64,
            first_seen=datetime.now(),  # naive
        )

    # Non-UTC timezone offset validation
    est = timezone(timedelta(hours=-5))
    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="a" * 64,
            first_seen=datetime.now(est),
        )

    # Temporal sequence ordering (last_seen < first_seen)
    with pytest.raises(ValidationError):
        AttackerProfile(
            fingerprint="a" * 64,
            first_seen=now,
            last_seen=now - timedelta(seconds=10),
        )



def test_incident_report_generation_and_serialization():
    now = datetime.now(timezone.utc)
    identity = AttackerIdentity(
        agent_id="agent-rogue",
        agent_name="Infiltrator",
        thread_id="th-555",
        primary_source=IdentitySource.ADK_METADATA,
    )
    profile = AttackerProfile(
        fingerprint=identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        total_attacks=1,
        threat_score=0.9,
    )
    report = IncidentReport(
        event_id=identity.identity_id,
        verdict=VerdictDecision.BLOCK,
        attacker_identity=identity,
        attacker_profile=profile,
        exploited_tool="execute_terminal",
        sanitized_arguments={"command": "rm -rf /"},
        attack_technique="Command Injection / Destructive Wipe",
        mitigation_action="Operation blocked by Blackwall Agentic Firewall",
        recommended_user_action="Revoke agent token and inspect thread th-555",
        attribution_confidence=0.95,
    )

    assert isinstance(report.report_id, UUID)
    assert report.verdict == VerdictDecision.BLOCK
    assert report.attribution_confidence == 0.95

    # Test JSON serialization
    json_str = report.to_json()
    parsed = json.loads(json_str)
    assert parsed["exploited_tool"] == "execute_terminal"
    assert parsed["verdict"] == "BLOCK"

    # Test Markdown formatting
    markdown = report.to_markdown()
    assert "# Blackwall Incident Attribution Report" in markdown
    assert "Infiltrator" in markdown
    assert "execute_terminal" in markdown
    assert "Command Injection" in markdown
