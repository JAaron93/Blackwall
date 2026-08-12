"""Property-based tests for Attacker Identity and Profile persistence invariants."""

from datetime import datetime, timezone
import os
import tempfile
import asyncio
from hypothesis import given, settings, strategies as st
import pytest

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import AttackerIdentity, AttackerProfile, IdentitySource


# ---------------------------------------------------------------------------
# Property 1: Deterministic SHA-256 Identity Fingerprinting
# ---------------------------------------------------------------------------

@settings(max_examples=50)
@given(
    agent_id=st.text(min_size=1, max_size=50),
    agent_name=st.text(min_size=1, max_size=50),
    thread_id=st.text(min_size=1, max_size=50),
    uid=st.one_of(st.none(), st.integers(min_value=0, max_value=65535)),
)
def test_property_identity_fingerprint_determinism(agent_id, agent_name, thread_id, uid):
    """Property: Identical identity inputs MUST always yield identical 64-char SHA-256 fingerprints."""
    id1 = AttackerIdentity(
        agent_id=agent_id,
        agent_name=agent_name,
        thread_id=thread_id,
        process_uid=uid,
        primary_source=IdentitySource.ADK_METADATA,
    )
    id2 = AttackerIdentity(
        agent_id=agent_id,
        agent_name=agent_name,
        thread_id=thread_id,
        process_uid=uid,
        primary_source=IdentitySource.ADK_METADATA,
    )

    assert len(id1.identity_fingerprint) == 64
    assert id1.identity_fingerprint == id2.identity_fingerprint


@settings(max_examples=30)
@given(
    id1_agent=st.text(min_size=1, max_size=20),
    id2_agent=st.text(min_size=21, max_size=40),
)
def test_property_identity_fingerprint_uniqueness(id1_agent, id2_agent):
    """Property: Distinct agent IDs MUST yield distinct fingerprints."""
    if id1_agent == id2_agent:
        return

    identity1 = AttackerIdentity(agent_id=id1_agent, primary_source=IdentitySource.ADK_METADATA)
    identity2 = AttackerIdentity(agent_id=id2_agent, primary_source=IdentitySource.ADK_METADATA)

    assert identity1.identity_fingerprint != identity2.identity_fingerprint


# ---------------------------------------------------------------------------
# Property 2: Monotonic Attack Counter and Tool Union Invariants
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_property_profile_upsert_monotonicity_and_tool_union():
    """Property: Repeated upserts increment total_attacks monotonically and merge tools as a set union."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        fp = "c" * 64
        now = datetime.now(timezone.utc)
        tools = ["read_file", "execute_bash", "write_file", "query_db"]

        accumulated_tools = set()
        for i, tool in enumerate(tools, start=1):
            accumulated_tools.add(tool)
            prof = AttackerProfile(
                fingerprint=fp,
                first_seen=now,
                last_seen=now,
                total_attacks=1,
                threat_score=0.80,
                targeted_tools=[tool],
            )
            updated = await repo.upsert_attacker_profile(prof)
            assert updated.total_attacks == i
            assert set(updated.targeted_tools) == accumulated_tools

        fetched = await repo.get_attacker_profile(fp)
        assert fetched is not None
        assert fetched.total_attacks == len(tools)
        assert set(fetched.targeted_tools) == set(tools)

        await repo.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
