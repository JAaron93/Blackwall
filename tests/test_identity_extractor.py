"""
tests/test_identity_extractor.py — TDD unit tests for AttackerIdentityExtractor.

Written BEFORE implementation per strict TDD mandate.
Tests cover:
  - ADK metadata full extraction (FR-1)
  - ADK metadata partial → process fallback (FR-1)
  - Empty/None metadata → graceful degraded identity (NFR-2)
  - Exception isolation: extraction errors return UNRESOLVED_ATTACKER (NFR-2)
  - Deterministic fingerprint from extracted identity (FR-2)
  - primary_source assignment logic
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.models import AttackerIdentity, IdentitySource, ToolCallContext


@pytest.fixture
def extractor() -> AttackerIdentityExtractor:
    return AttackerIdentityExtractor()


@pytest.fixture
def full_adk_metadata() -> dict:
    return {
        "agent_id": "agent-007",
        "agent_name": "MaliciousScriptAgent",
        "agent_model": "gemini-3.8-flash",
        "thread_id": "th-991",
    }


@pytest.fixture
def tool_context() -> ToolCallContext:
    return ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "whoami"},
        metadata=None,
    )


class TestADKMetadataExtraction:
    """FR-1: Identity extraction from ADK context metadata."""

    def test_full_adk_metadata_extracts_all_fields(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext, full_adk_metadata: dict
    ):
        identity = extractor.extract(context=tool_context, metadata=full_adk_metadata)

        assert isinstance(identity, AttackerIdentity)
        assert identity.agent_id == "agent-007"
        assert identity.agent_name == "MaliciousScriptAgent"
        assert identity.agent_model == "gemini-3.8-flash"
        assert identity.thread_id == "th-991"
        assert identity.primary_source == IdentitySource.ADK_METADATA

    def test_adk_metadata_produces_valid_fingerprint(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext, full_adk_metadata: dict
    ):
        identity = extractor.extract(context=tool_context, metadata=full_adk_metadata)

        assert len(identity.identity_fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in identity.identity_fingerprint)

    def test_adk_metadata_fingerprint_is_deterministic(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext, full_adk_metadata: dict
    ):
        identity1 = extractor.extract(context=tool_context, metadata=full_adk_metadata)
        identity2 = extractor.extract(context=tool_context, metadata=full_adk_metadata)

        assert identity1.identity_fingerprint == identity2.identity_fingerprint

    def test_partial_adk_metadata_only_uses_present_fields(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        partial_metadata = {"agent_id": "agent-partial"}  # No thread_id, no model
        identity = extractor.extract(context=tool_context, metadata=partial_metadata)

        assert identity.agent_id == "agent-partial"
        assert identity.thread_id is None
        assert identity.agent_model is None
        # Still classified as ADK_METADATA since at least agent_id is present
        assert identity.primary_source == IdentitySource.ADK_METADATA


class TestProcessFallbackExtraction:
    """FR-1: Fallback to local process inspection when ADK metadata is incomplete."""

    def test_empty_metadata_falls_back_to_process(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity = extractor.extract(context=tool_context, metadata={})

        assert isinstance(identity, AttackerIdentity)
        assert identity.primary_source == IdentitySource.SYSTEM_PROCESS
        # Process PID and UID should be populated from os module
        assert identity.process_pid is not None
        assert identity.process_pid == os.getpid()

    def test_none_metadata_falls_back_to_process(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity = extractor.extract(context=tool_context, metadata=None)

        assert isinstance(identity, AttackerIdentity)
        assert identity.primary_source == IdentitySource.SYSTEM_PROCESS
        assert identity.process_pid == os.getpid()

    def test_process_fallback_includes_uid(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity = extractor.extract(context=tool_context, metadata=None)

        # On Unix, process_uid should be populated
        if hasattr(os, "getuid"):
            assert identity.process_uid == os.getuid()

    def test_process_fallback_identity_has_valid_fingerprint(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity = extractor.extract(context=tool_context, metadata=None)

        assert len(identity.identity_fingerprint) == 64


class TestFailSafeExceptionIsolation:
    """NFR-2: Failures in identity extraction must NOT crash the pipeline."""

    def test_extraction_failure_returns_unresolved_attacker(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        """If internal extraction logic raises, a safe fallback identity is returned."""
        with patch.object(extractor, "_extract_from_adk", side_effect=RuntimeError("Simulated ADK failure")):
            with patch.object(extractor, "_extract_from_process", side_effect=OSError("Simulated OS failure")):
                identity = extractor.extract(context=tool_context, metadata={"agent_id": "x"})

        assert isinstance(identity, AttackerIdentity)
        # Must be a safe, unresolved identity — not an exception propagation
        assert identity.agent_name == "UNRESOLVED_ATTACKER" or identity.agent_id == "UNRESOLVED_ATTACKER"

    def test_extraction_never_raises_exception(
        self, extractor: AttackerIdentityExtractor
    ):
        """extract() must always return an AttackerIdentity, never raise."""
        broken_context = MagicMock(spec=ToolCallContext)
        broken_context.tool_name = None  # Intentionally broken

        # Should not raise — must return a graceful identity
        result = extractor.extract(context=broken_context, metadata=None)
        assert isinstance(result, AttackerIdentity)


class TestPrimarySourceClassification:
    """Validates that primary_source is correctly set based on extraction path."""

    def test_adk_fields_present_gives_adk_primary_source(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        metadata = {"agent_id": "agent-test", "thread_id": "th-1"}
        identity = extractor.extract(context=tool_context, metadata=metadata)
        assert identity.primary_source == IdentitySource.ADK_METADATA

    def test_no_adk_fields_gives_system_process_primary_source(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity = extractor.extract(context=tool_context, metadata=None)
        assert identity.primary_source == IdentitySource.SYSTEM_PROCESS

    def test_different_agents_produce_different_fingerprints(
        self, extractor: AttackerIdentityExtractor, tool_context: ToolCallContext
    ):
        identity_a = extractor.extract(context=tool_context, metadata={"agent_id": "agent-A"})
        identity_b = extractor.extract(context=tool_context, metadata={"agent_id": "agent-B"})
        assert identity_a.identity_fingerprint != identity_b.identity_fingerprint


class TestSwarmAttributionIntegration:
    """TASK-2A.3: Tests verifying linguistic markers, is_collective, and false monolith disambiguation."""

    def test_linguistic_markers_embedded_in_extracted_identity(
        self, extractor: AttackerIdentityExtractor
    ):
        ctx = ToolCallContext(
            tool_name="bash",
            arguments={"cmd": "echo 'we are coordinating with peer workers on consensus reached'"},
            metadata=None,
        )
        identity = extractor.extract(context=ctx, metadata={"agent_id": "agent-swarm-1"})

        assert identity.linguistic_markers is not None
        assert identity.is_collective is True
        assert identity.collective_name is not None
        assert "we" in identity.linguistic_markers.detected_pronouns

    def test_benign_call_has_linguistic_markers_not_collective(
        self, extractor: AttackerIdentityExtractor
    ):
        ctx = ToolCallContext(
            tool_name="bash",
            arguments={"cmd": "whoami"},
            metadata=None,
        )
        identity = extractor.extract(context=ctx, metadata={"agent_id": "agent-solo-1"})

        assert identity.linguistic_markers is not None
        assert identity.is_collective is False
        assert identity.linguistic_markers.confidence_score == 0.0

    def test_false_monolith_disambiguation_produces_distinct_fingerprints(
        self, extractor: AttackerIdentityExtractor
    ):
        """FR-2: Multiple calls with agent_id='we' across different sessions must NOT collapse."""
        ctx1 = ToolCallContext(
            tool_name="bash",
            arguments={"cmd": "cat /etc/passwd"},
            metadata={"session_id": "session-alpha-100"},
        )
        ctx2 = ToolCallContext(
            tool_name="bash",
            arguments={"cmd": "cat /etc/shadow"},
            metadata={"session_id": "session-beta-200"},
        )

        identity1 = extractor.extract(context=ctx1, metadata={"agent_id": "we"})
        identity2 = extractor.extract(context=ctx2, metadata={"agent_id": "we"})

        assert identity1.is_collective is True
        assert identity2.is_collective is True
        assert identity1.identity_fingerprint != identity2.identity_fingerprint
        assert identity1.session_salt is not None
        assert identity2.session_salt is not None
        assert identity1.session_salt != identity2.session_salt

