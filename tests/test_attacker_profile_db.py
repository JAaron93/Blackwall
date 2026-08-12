"""Unit tests for SQLite Attacker Profile persistence in SQLiteThreatRepository."""

from datetime import datetime, timezone
import os
import tempfile
import time
import pytest

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import AttackerIdentity, AttackerProfile, IdentitySource


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

        t0 = time.perf_counter()
        await repo.upsert_attacker_profile(profile)
        t1 = time.perf_counter()

        elapsed_ms = (t1 - t0) * 1000.0
        assert elapsed_ms < 5.0, f"Upsert SLA breached: took {elapsed_ms:.2f}ms (expected < 5ms)"

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
