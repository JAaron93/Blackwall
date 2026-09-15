"""Unit tests for SwarmContextProvider protocol & providers (TASK-3.2, TDD)."""

import ast
import inspect
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from blackwall.attribution.provider import (
    SQLiteSwarmContextProvider,
    SwarmContextProvider,
)
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import SwarmContextSummary


def _make_swarm_context(**overrides):
    now = datetime.now(timezone.utc)
    kwargs = {
        "swarm_id": uuid4(),
        "is_collective": True,
        "collective_name": "collective:provider-swarm",
        "collective_confidence": 0.9,
        "coordinating_agents": ["agent-99", "agent-100"],
        "suspected_covert_channels": ["board-9"],
        "covert_channel_type": "UNLOCATED_MESSAGE_BOARD",
        "deduction_rationale": "high correlation without C2",
        "first_detected": now,
        "last_detected": now,
    }
    kwargs.update(overrides)
    return SwarmContextSummary(**kwargs)


def _temp_repo():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return tmp.name


@pytest.mark.asyncio
async def test_provider_protocol_signature():
    """TASK-3.2: protocol exposes async resolve_swarm_context returning a summary."""
    assert hasattr(SwarmContextProvider, "resolve_swarm_context")
    assert inspect.iscoroutinefunction(SQLiteSwarmContextProvider.resolve_swarm_context)
    assert isinstance(SQLiteSwarmContextProvider(_temp_repo()), SwarmContextProvider)


@pytest.mark.asyncio
async def test_sqlite_provider_resolves_local_context():
    """TASK-3.2: SQLite provider retrieves contexts stored in SQLiteThreatRepository."""
    db_path = _temp_repo()
    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        context = _make_swarm_context()
        await repo.upsert_swarm_context(context)
        provider = SQLiteSwarmContextProvider(repo)

        resolved = await provider.resolve_swarm_context(
            agent_id="agent-99", fingerprint="f" * 64
        )
        assert resolved is not None
        assert resolved.swarm_id == context.swarm_id
        assert resolved.collective_name == "collective:provider-swarm"
        assert resolved.suspected_covert_channels == ["board-9"]
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sqlite_provider_returns_none_on_miss():
    """TASK-3.2: unknown agents resolve to None without raising."""
    db_path = _temp_repo()
    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        provider = SQLiteSwarmContextProvider(repo)
        resolved = await provider.resolve_swarm_context(
            agent_id="ghost", fingerprint="0" * 64
        )
        assert resolved is None
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_sqlite_provider_failsafe_on_repository_error():
    """TASK-3.2: repository exceptions degrade gracefully to None (NFR-2)."""

    class ExplodingRepository:
        async def find_swarm_by_agent_or_fingerprint(self, agent_id, fingerprint):
            raise RuntimeError("boom")

    provider = SQLiteSwarmContextProvider(ExplodingRepository())
    resolved = await provider.resolve_swarm_context(
        agent_id="agent-99", fingerprint="f" * 64
    )
    assert resolved is None


@pytest.mark.asyncio
async def test_sqlite_provider_lookup_latency_sla():
    """TASK-3.2: provider lookups complete in < 15ms (NFR-4)."""
    db_path = _temp_repo()
    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.upsert_swarm_context(_make_swarm_context())
        provider = SQLiteSwarmContextProvider(repo)

        # Warmup (Rule 1, testing_and_hygiene.md): bypass cold pool/page-cache
        # overhead before timing; best-of-3 tolerates shared-CI scheduling noise.
        await provider.resolve_swarm_context(agent_id="agent-99", fingerprint="f" * 64)

        samples = []
        for _ in range(3):
            t0 = time.perf_counter()
            await provider.resolve_swarm_context(
                agent_id="agent-99", fingerprint="f" * 64
            )
            samples.append((time.perf_counter() - t0) * 1000.0)
        best_ms = min(samples)
        assert best_ms < 15.0, f"Provider SLA breached: samples={samples}"
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_core_provider_has_zero_enterprise_dependencies():
    """TASK-3.2: Core provider never imports Enterprise or asyncpg (NFR-3)."""
    src_root = Path(__file__).resolve().parents[2] / "src" / "blackwall"
    for module_path in (
        src_root / "attribution" / "provider.py",
        src_root / "db" / "repository.py",
    ):
        tree = ast.parse(module_path.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        assert not any("enterprise" in name or name == "asyncpg" for name in imports), (
            f"{module_path} must not import Enterprise/asyncpg: {sorted(imports)}"
        )


@pytest.mark.asyncio
async def test_enterprise_provider_adapts_attack_graph_store():
    """TASK-3.2: Enterprise provider maps AttackGraphStore nodes to summaries."""
    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )
    from blackwall.enterprise.advanced_threat_detection.enums import EventSource
    from blackwall.enterprise.advanced_threat_detection.models import (
        AttackNode,
        NormalizedEvent,
    )

    now = datetime.now(timezone.utc)
    swarm_id = uuid4()
    node = AttackNode(
        node_id=uuid4(),
        event=NormalizedEvent(
            event_id=uuid4(),
            timestamp=now,
            source=EventSource.TOOL_CALL,
            agent_id="agent-99",
            action="coordinate",
            target="swarm",
            metadata={
                "swarm_id": str(swarm_id),
                "collective_name": "collective:exploitgym-swarm-alpha",
                "collective_confidence": 0.88,
                "coordinating_agents": ["agent-99", "agent-100"],
                "suspected_covert_channels": ["board-alpha"],
                "covert_channel_type": "UNLOCATED_MESSAGE_BOARD",
                "deduction_rationale": "high correlation without C2",
            },
            risk_score=0.9,
        ),
        incoming_edges=[],
        outgoing_edges=[],
    )

    class FakeStore:
        async def query_nodes(self, agent_id=None, time_window=None, **kwargs):
            assert agent_id == "agent-99"
            return [node]

    provider = EnterpriseSwarmContextProvider(FakeStore())
    resolved = await provider.resolve_swarm_context(
        agent_id="agent-99", fingerprint="f" * 64
    )
    assert resolved is not None
    assert resolved.swarm_id == swarm_id
    assert resolved.collective_name == "collective:exploitgym-swarm-alpha"
    assert resolved.coordinating_agents == ["agent-99", "agent-100"]
    assert resolved.suspected_covert_channels == ["board-alpha"]
    assert isinstance(provider, SwarmContextProvider)


@pytest.mark.asyncio
async def test_enterprise_provider_returns_none_without_swarm_metadata():
    """TASK-3.2: Enterprise provider returns None when nodes carry no swarm lineage."""
    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )
    from blackwall.enterprise.advanced_threat_detection.enums import EventSource
    from blackwall.enterprise.advanced_threat_detection.models import (
        AttackNode,
        NormalizedEvent,
    )

    now = datetime.now(timezone.utc)
    node = AttackNode(
        node_id=uuid4(),
        event=NormalizedEvent(
            event_id=uuid4(),
            timestamp=now,
            source=EventSource.TOOL_CALL,
            agent_id="agent-99",
            action="read",
            target="file",
            metadata={},
            risk_score=0.1,
        ),
        incoming_edges=[],
        outgoing_edges=[],
    )

    class FakeStore:
        async def query_nodes(self, agent_id=None, time_window=None, **kwargs):
            return [node]

    provider = EnterpriseSwarmContextProvider(FakeStore())
    assert (
        await provider.resolve_swarm_context(agent_id="agent-99", fingerprint="x")
        is None
    )


@pytest.mark.asyncio
async def test_enterprise_provider_failsafe_on_store_error():
    """TASK-3.2: Enterprise store exceptions degrade gracefully to None (NFR-2)."""
    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )

    class ExplodingStore:
        async def query_nodes(self, *args, **kwargs):
            raise RuntimeError("store down")

    provider = EnterpriseSwarmContextProvider(ExplodingStore())
    assert (
        await provider.resolve_swarm_context(agent_id="agent-99", fingerprint="x")
        is None
    )


def _make_swarm_evidence(**overrides):
    """Builds detector-style SwarmEvidence for bridge fallback tests."""
    from blackwall.enterprise.advanced_threat_detection.enums import (
        CovertChannelType,
    )
    from blackwall.enterprise.advanced_threat_detection.models import (
        CovertChannelEvidence,
        SwarmEvidence,
    )

    now = datetime.now(timezone.utc)
    channel = CovertChannelEvidence(
        channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
        confidence_score=0.9,
        coordinating_agents={"agent-99", "agent-100"},
        observed_artifacts=["board-alpha"],
        deduction_rationale="high correlation without C2",
        first_detected=now,
        last_detected=now,
    )
    kwargs = {
        "swarm_id": uuid4(),
        "agent_ids": {"agent-99", "agent-100"},
        "shared_patterns": ["consensus reached"],
        "temporal_correlation": 0.88,
        "coordination_score": 0.85,
        "first_seen": now,
        "last_seen": now,
        "covert_channels": [channel],
    }
    kwargs.update(overrides)
    return SwarmEvidence(**kwargs)


@pytest.mark.asyncio
async def test_enterprise_provider_falls_back_to_evidence_lookup():
    """P1 regression: detector SwarmEvidence must stay reachable via the bridge."""
    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )

    evidence = _make_swarm_evidence()

    class MetadataFreeStore:
        async def query_nodes(self, agent_id=None, time_window=None, **kwargs):
            return []

    async def lookup(agent_id):
        assert agent_id == "agent-99"
        return [evidence]

    provider = EnterpriseSwarmContextProvider(
        MetadataFreeStore(), evidence_lookup=lookup
    )
    resolved = await provider.resolve_swarm_context(
        agent_id="agent-99", fingerprint="f" * 64
    )
    assert resolved is not None
    assert resolved.swarm_id == evidence.swarm_id
    assert sorted(resolved.coordinating_agents) == ["agent-100", "agent-99"]
    assert resolved.collective_confidence == 0.85
    assert resolved.suspected_covert_channels == [
        str(evidence.covert_channels[0].channel_id)
    ]
    assert resolved.covert_channel_type == "UNLOCATED_MESSAGE_BOARD"


@pytest.mark.asyncio
async def test_enterprise_provider_evidence_lookup_miss_returns_none():
    """P1 regression: empty evidence lookups still resolve to None."""

    async def lookup(agent_id):
        return []

    from blackwall.enterprise.advanced_threat_detection.bridge import (
        EnterpriseSwarmContextProvider,
    )

    class MetadataFreeStore:
        async def query_nodes(self, agent_id=None, time_window=None, **kwargs):
            return []

    provider = EnterpriseSwarmContextProvider(
        MetadataFreeStore(), evidence_lookup=lookup
    )
    assert (
        await provider.resolve_swarm_context(agent_id="agent-99", fingerprint="x")
        is None
    )
