"""Integration tests for Attacker Attribution in SyncResolver."""

import ast
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.attribution.provider import SQLiteSwarmContextProvider
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import (
    IncidentReport,
    SwarmContextSummary,
    ToolCallContext,
    VerdictDecision,
)
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
        await resolver.flush_background_tasks()

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
            AttackerIdentityExtractor,
            "extract",
            side_effect=RuntimeError("Simulated extraction crash"),
        ):
            verdict = await resolver.evaluate(context)
            assert verdict.decision == VerdictDecision.BLOCK

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


async def _seed_swarm_context(repo, collective_name="collective:track4-swarm"):
    """Seeds a swarm context containing agent-99 for resolver tests."""
    now = datetime.now(timezone.utc)
    context = SwarmContextSummary(
        is_collective=True,
        collective_name=collective_name,
        collective_confidence=0.88,
        coordinating_agents=["agent-99", "agent-100"],
        suspected_covert_channels=["board-101"],
        covert_channel_type="UNLOCATED_MESSAGE_BOARD",
        deduction_rationale="high correlation without C2",
        first_detected=now,
        last_detected=now,
    )
    return await repo.upsert_swarm_context(context)


def _swarm_block_context():
    return ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "cat /etc/shadow && passwd && exfil && reverse shell"},
        metadata={
            "agent_id": "agent-99",
            "agent_name": "SwarmWorker-99",
            "thread_id": "th-9900",
        },
    )


@pytest.mark.asyncio
async def test_sync_resolver_enriches_block_with_swarm_context():
    """TASK-4.1: BLOCK verdicts resolve swarm lineage and enrich profile+report."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()
        seeded = await _seed_swarm_context(repo)

        callback_reports = []
        resolver = SyncResolver(
            client=MagicMock(),
            repo=repo,
            demo_mode=True,
            on_attacker_identified=callback_reports.append,
        )
        assert isinstance(resolver.swarm_provider, SQLiteSwarmContextProvider)

        verdict = await resolver.evaluate(_swarm_block_context())
        assert verdict.decision == VerdictDecision.BLOCK
        await resolver.flush_background_tasks()

        assert len(callback_reports) == 1
        report = callback_reports[0]
        assert report.swarm_id == seeded.swarm_id
        assert report.is_collective is True
        assert report.suspected_covert_channels == ["board-101"]
        assert report.collective_confidence == 0.88

        profile = await repo.get_attacker_profile(
            report.attacker_identity.identity_fingerprint
        )
        assert profile is not None
        assert seeded.swarm_id in profile.swarm_memberships
        assert profile.suspected_covert_channels == ["board-101"]

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sync_resolver_explicit_provider_injection():
    """TASK-4.1: injected providers (e.g. Enterprise) enrich reports without repo lineage."""

    async def _resolve(agent_id, fingerprint):
        now = datetime.now(timezone.utc)
        return SwarmContextSummary(
            is_collective=True,
            collective_name="collective:injected",
            collective_confidence=0.91,
            coordinating_agents=[agent_id or "agent-99"],
            suspected_covert_channels=["board-injected"],
            first_detected=now,
            last_detected=now,
        )

    class _StubProvider:
        async def resolve_swarm_context(self, agent_id, fingerprint):
            return await _resolve(agent_id, fingerprint)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        callback_reports = []
        resolver = SyncResolver(
            client=MagicMock(),
            repo=repo,
            demo_mode=True,
            on_attacker_identified=callback_reports.append,
            swarm_provider=_StubProvider(),
        )

        verdict = await resolver.evaluate(_swarm_block_context())
        assert verdict.decision == VerdictDecision.BLOCK
        await resolver.flush_background_tasks()

        assert len(callback_reports) == 1
        assert callback_reports[0].collective_confidence == 0.91
        assert callback_reports[0].suspected_covert_channels == ["board-injected"]

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sync_resolver_swarm_provider_failure_isolated():
    """TASK-4.1: provider explosions must not break verdict delivery (NFR-2)."""

    class _ExplodingProvider:
        async def resolve_swarm_context(self, agent_id, fingerprint):
            raise RuntimeError("provider down")

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        callback_reports = []
        resolver = SyncResolver(
            client=MagicMock(),
            repo=repo,
            demo_mode=True,
            on_attacker_identified=callback_reports.append,
            swarm_provider=_ExplodingProvider(),
        )

        verdict = await resolver.evaluate(_swarm_block_context())
        assert verdict.decision == VerdictDecision.BLOCK
        await resolver.flush_background_tasks()

        assert len(callback_reports) == 1
        assert callback_reports[0].swarm_id is None
        assert callback_reports[0].is_collective is False

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sync_resolver_swarm_enrichment_latency_sla():
    """TASK-4.1: background swarm enrichment completes within 5ms (warmup first)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()
        await _seed_swarm_context(repo)

        resolver = SyncResolver(client=MagicMock(), repo=repo, demo_mode=True)
        context = _swarm_block_context()

        # Warmup (Rule 1): pool init + page cache before timing.
        verdict = await resolver.evaluate(context)
        assert verdict.decision == VerdictDecision.BLOCK
        await resolver.flush_background_tasks()

        samples = []
        for _ in range(3):
            t0 = time.perf_counter()
            await resolver._process_attribution(context, verdict)
            samples.append((time.perf_counter() - t0) * 1000.0)
        assert min(samples) < 5.0, f"Enrichment SLA breached: {samples}"

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_sync_resolver_core_has_zero_enterprise_imports():
    """TASK-4.1: resolver wiring preserves Core/Enterprise decoupling (NFR-3)."""
    src_root = Path(__file__).resolve().parents[1] / "src" / "blackwall"
    for module_path in (
        src_root / "sync_resolver.py",
        src_root / "attribution" / "provider.py",
    ):
        tree = ast.parse(module_path.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        assert not any("enterprise" in name or name == "asyncpg" for name in imports), (
            f"{module_path} must not import Enterprise/asyncpg"
        )
