"""Integration tests for Attacker Attribution in SyncResolver."""

from datetime import datetime, timezone
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import IncidentReport, ToolCallContext, Verdict, VerdictDecision
from blackwall.sync_resolver import SyncResolver


@pytest.mark.asyncio
async def test_sync_resolver_attribution_on_block_verdict(capsys):
    """Verify SyncResolver extracts identity, updates profile, and emits report on BLOCK verdict."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        callback_reports = []

        def on_identified(report: IncidentReport):
            callback_reports.append(report)

        mock_client = MagicMock()
        resolver = SyncResolver(
            client=mock_client,
            repo=repo,
            demo_mode=True,
            on_attacker_identified=on_identified,
        )

        context = ToolCallContext(
            tool_name="execute_bash",
            arguments={"cmd": "cat /etc/shadow && passwd && exfil && reverse shell"},
            metadata={
                "agent_id": "malicious-agent-42",
                "agent_name": "ShadowExfilAgent",
                "thread_id": "th-4200",
            },
        )

        verdict = await resolver.evaluate(context)
        assert verdict.decision == VerdictDecision.BLOCK

        # Verify callback invoked
        assert len(callback_reports) == 1
        report = callback_reports[0]
        assert report.verdict == VerdictDecision.BLOCK
        assert report.exploited_tool == "execute_bash"
        assert report.attacker_identity.agent_id == "malicious-agent-42"
        assert report.attacker_identity.agent_name == "ShadowExfilAgent"

        # Verify DB profile updated
        fp = report.attacker_identity.identity_fingerprint
        profile = await repo.get_attacker_profile(fp)
        assert profile is not None
        assert profile.total_attacks == 1
        assert "execute_bash" in profile.targeted_tools

        # Verify CLI output to stderr
        captured = capsys.readouterr()
        assert "# Blackwall Incident Attribution Report" in captured.err
        assert "ShadowExfilAgent" in captured.err

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sync_resolver_attribution_exception_isolation():
    """Verify attribution failures do NOT crash SyncResolver.evaluate() (NFR-2 fail-safe isolation)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        mock_client = MagicMock()
        resolver = SyncResolver(
            client=mock_client,
            repo=repo,
            demo_mode=True,
        )

        context = ToolCallContext(
            tool_name="execute_bash",
            arguments={"cmd": "cat /etc/shadow && passwd && exfil && reverse shell"},
            metadata={"agent_id": "crash-test-agent"},
        )

        # Force extractor exception
        with patch.object(
            AttackerIdentityExtractor, "extract", side_effect=RuntimeError("Simulated extraction crash")
        ):
            verdict = await resolver.evaluate(context)
            assert verdict.decision == VerdictDecision.BLOCK

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
