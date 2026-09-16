"""Unit tests for SQLite Attacker Profile persistence in SQLiteThreatRepository."""

from datetime import datetime, timedelta, timezone
import os
import tempfile
import time
import pytest

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IdentitySource,
    SwarmContextSummary,
)


@pytest.mark.asyncio
async def test_attacker_profile_table_initialization():
    """Verify attacker_profiles table is created during initialization."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        async with repo.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='attacker_profiles';"
            )
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == "attacker_profiles"
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_upsert_and_get_attacker_profile():
    """Verify upserting a new AttackerProfile inserts it correctly and get_attacker_profile fetches it."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        now = datetime.now(timezone.utc)
        identity = AttackerIdentity(
            agent_id="test-agent-01",
            agent_name="TestAttacker",
            thread_id="th-100",
            primary_source=IdentitySource.ADK_METADATA,
        )
        fp = identity.identity_fingerprint

        profile = AttackerProfile(
            fingerprint=fp,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.85,
            targeted_tools=["execute_bash"],
            associated_signatures=["sig-001"],
            risk_category="HIGH",
        )

        saved = await repo.upsert_attacker_profile(profile)
        assert saved.fingerprint == fp
        assert saved.total_attacks == 1
        assert saved.threat_score == 0.85

        fetched = await repo.get_attacker_profile(fp)
        assert fetched is not None
        assert fetched.fingerprint == fp
        assert fetched.total_attacks == 1
        assert fetched.threat_score == 0.85
        assert fetched.targeted_tools == ["execute_bash"]
        assert fetched.associated_signatures == ["sig-001"]

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_upsert_attacker_profile_increments_attack_count_and_merges_tools():
    """Verify upserting an existing profile updates attack count, last_seen, and tool lists."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        now = datetime.now(timezone.utc)
        fp = "a" * 64
        initial_profile = AttackerProfile(
            fingerprint=fp,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.50,
            targeted_tools=["read_file"],
            associated_signatures=["sig-001"],
        )
        await repo.upsert_attacker_profile(initial_profile)

        # Subsequent attack
        second_profile = AttackerProfile(
            fingerprint=fp,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.90,
            targeted_tools=["execute_bash"],
            associated_signatures=["sig-002"],
        )
        updated = await repo.upsert_attacker_profile(second_profile)
        assert updated.total_attacks == 2
        assert updated.threat_score == 0.90
        assert "read_file" in updated.targeted_tools
        assert "execute_bash" in updated.targeted_tools
        assert "sig-001" in updated.associated_signatures
        assert "sig-002" in updated.associated_signatures

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_attacker_profile_upsert_latency_sla():
    """Verify upsert operation meets < 5ms SLA execution budget."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        now = datetime.now(timezone.utc)
        profile = AttackerProfile(
            fingerprint="b" * 64,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.75,
            targeted_tools=["run_command"],
        )

        # Warmup (Rule 1, testing_and_hygiene.md): bypass cold WAL/pool overhead.
        await repo.upsert_attacker_profile(profile)

        t0 = time.perf_counter()
        await repo.upsert_attacker_profile(profile)
        t1 = time.perf_counter()

        elapsed_ms = (t1 - t0) * 1000.0
        assert elapsed_ms < 5.0, (
            f"Upsert SLA breached: took {elapsed_ms:.2f}ms (expected < 5ms)"
        )

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def _make_swarm_context(**overrides):
    """Build a SwarmContextSummary with valid UTC timestamps for tests."""
    now = datetime.now(timezone.utc)
    kwargs = {
        "is_collective": True,
        "collective_name": "collective:test-swarm",
        "collective_confidence": 0.85,
        "coordinating_agents": ["agent-99", "agent-100"],
        "suspected_covert_channels": ["board-1"],
        "covert_channel_type": "UNLOCATED_MESSAGE_BOARD",
        "deduction_rationale": "high correlation without C2",
        "first_detected": now,
        "last_detected": now,
    }
    kwargs.update(overrides)
    return SwarmContextSummary(**kwargs)


@pytest.mark.asyncio
async def test_swarm_context_table_initialization():
    """TASK-3.1: local_swarm_contexts table is created during initialization."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        async with repo.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='local_swarm_contexts';"
            )
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == "local_swarm_contexts"
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_attacker_profile_swarm_columns_self_healing():
    """TASK-3.1: legacy attacker_profiles tables gain swarm columns on initialize()."""
    import aiosqlite

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute(
                """
                CREATE TABLE attacker_profiles (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_attacks INTEGER NOT NULL DEFAULT 1,
                    threat_score REAL NOT NULL DEFAULT 0.5,
                    associated_signatures TEXT,
                    targeted_tools TEXT,
                    risk_category TEXT NOT NULL DEFAULT 'HIGH'
                );
                """
            )
            await conn.commit()

        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        async with repo.pool.connection() as conn:
            cursor = await conn.execute("PRAGMA table_info(attacker_profiles);")
            columns = {row[1] for row in await cursor.fetchall()}
        assert "swarm_memberships" in columns
        assert "suspected_covert_channels" in columns
        assert "collective_confidence" in columns
        assert "collective_name" in columns
        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_swarm_context_upsert_get_roundtrip():
    """TASK-3.1: upsert_swarm_context inserts and get_swarm_context fetches it."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        context = _make_swarm_context()
        saved = await repo.upsert_swarm_context(context)
        assert saved.collective_name == "collective:test-swarm"
        assert saved.coordinating_agents == ["agent-99", "agent-100"]
        assert saved.swarm_id is not None

        fetched = await repo.get_swarm_context(saved.swarm_id)
        assert fetched is not None
        assert fetched.swarm_id == saved.swarm_id
        assert fetched.collective_confidence == 0.85
        assert fetched.suspected_covert_channels == ["board-1"]

        missing = await repo.get_swarm_context("00000000-0000-4000-8000-000000000000")
        assert missing is None

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_find_swarm_by_agent_or_fingerprint():
    """TASK-3.1: find_swarm_by_agent_or_fingerprint resolves via agent and profile lineage."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        now = datetime.now(timezone.utc)
        context = _make_swarm_context()
        saved = await repo.upsert_swarm_context(context)

        by_agent = await repo.find_swarm_by_agent_or_fingerprint(
            agent_id="agent-99", fingerprint="f" * 64
        )
        assert by_agent is not None
        assert by_agent.swarm_id == saved.swarm_id

        profile = AttackerProfile(
            fingerprint="f" * 64,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.6,
            swarm_memberships=[saved.swarm_id],
            suspected_covert_channels=["board-1"],
            collective_confidence=0.85,
            collective_name="collective:test-swarm",
        )
        await repo.upsert_attacker_profile(profile)

        by_fingerprint = await repo.find_swarm_by_agent_or_fingerprint(
            agent_id="unknown-agent", fingerprint="f" * 64
        )
        assert by_fingerprint is not None
        assert by_fingerprint.swarm_id == saved.swarm_id

        fetched_profile = await repo.get_attacker_profile("f" * 64)
        assert fetched_profile is not None
        assert fetched_profile.swarm_memberships == [saved.swarm_id]
        assert fetched_profile.collective_name == "collective:test-swarm"

        unknown = await repo.find_swarm_by_agent_or_fingerprint(
            agent_id="ghost", fingerprint="0" * 64
        )
        assert unknown is None

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_swarm_context_crud_latency_sla():
    """TASK-3.1: swarm context CRUD operations meet the < 5ms SLA budget."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        # Warmup (Rule 1, testing_and_hygiene.md): bypass cold WAL/pool overhead.
        await repo.upsert_swarm_context(_make_swarm_context())

        context = _make_swarm_context()

        t0 = time.perf_counter()
        saved = await repo.upsert_swarm_context(context)
        t1 = time.perf_counter()
        assert (t1 - t0) * 1000.0 < 5.0, "upsert_swarm_context SLA breached"

        t0 = time.perf_counter()
        await repo.get_swarm_context(saved.swarm_id)
        t1 = time.perf_counter()
        assert (t1 - t0) * 1000.0 < 5.0, "get_swarm_context SLA breached"

        t0 = time.perf_counter()
        await repo.find_swarm_by_agent_or_fingerprint(
            agent_id="agent-99", fingerprint="f" * 64
        )
        t1 = time.perf_counter()
        assert (t1 - t0) * 1000.0 < 5.0, (
            "find_swarm_by_agent_or_fingerprint SLA breached"
        )

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


@pytest.mark.asyncio
async def test_find_swarm_prefers_most_recent_membership():
    """P1 regression: stale swarm memberships must not shadow the current swarm."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        now = datetime.now(timezone.utc)
        stale = await repo.upsert_swarm_context(
            _make_swarm_context(
                collective_name="collective:stale-swarm",
                first_detected=now - timedelta(hours=2),
                last_detected=now - timedelta(hours=2),
            )
        )
        current = await repo.upsert_swarm_context(
            _make_swarm_context(
                collective_name="collective:current-swarm",
                first_detected=now - timedelta(minutes=5),
                last_detected=now,
            )
        )

        profile = AttackerProfile(
            fingerprint="e" * 64,
            first_seen=now,
            last_seen=now,
            total_attacks=1,
            threat_score=0.6,
            swarm_memberships=[stale.swarm_id, current.swarm_id],
        )
        await repo.upsert_attacker_profile(profile)

        resolved = await repo.find_swarm_by_agent_or_fingerprint(
            agent_id="ghost", fingerprint="e" * 64
        )
        assert resolved is not None
        assert resolved.swarm_id == current.swarm_id
        assert resolved.collective_name == "collective:current-swarm"

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
