"""Property-based tests for AILMTracker using Hypothesis (Pillar 6 Task 10 / Properties 35-40)."""

from datetime import UTC, datetime, timedelta
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.enterprise.advanced_threat_detection import (
    AILMEvidence,
    AILMTracker,
    AttackGraphStore,
    PermissionGrant,
)


# Property 35: Permission Grant Recording
@pytest.mark.asyncio
@given(
    perm=st.sampled_from(["s3:GetObject", "db:Read", "sys:Execute", "k8s:GetSecrets"]),
    grantor=st.sampled_from(["admin", "auth_svc", "iam_role", "system"]),
    grantee=st.sampled_from(["agent-p35-1", "agent-p35-2", "agent-p35-3"]),
    scope=st.sampled_from(["user_space", "kernel_space", "internal_net", "sandbox"]),
)
@settings(max_examples=30)
async def test_property_35_permission_grant_recording(perm: str, grantor: str, grantee: str, scope: str):
    """Property 35: Permission grant SHALL be recorded with all required fields."""
    store = AttackGraphStore(in_memory=True)
    tracker = AILMTracker(store=store)
    now = datetime.now(UTC)

    grant = PermissionGrant(
        permission=perm,
        granted_by=grantor,
        granted_to=grantee,
        timestamp=now,
        scope=scope,
    )
    await tracker.track_permission_grant(grant)

    grants = await tracker.get_permission_grants(grantee)
    assert len(grants) >= 1
    recorded = grants[-1]
    assert recorded.permission == perm
    assert recorded.granted_by == grantor
    assert recorded.granted_to == grantee
    assert recorded.scope == scope


# Property 36: Permission Accumulation Detection
@pytest.mark.asyncio
@given(
    num_grants=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=30)
async def test_property_36_permission_accumulation_detection(num_grants: int):
    """Property 36: Accumulated permissions over time SHALL be detected in composed_permissions."""
    store = AttackGraphStore(in_memory=True)
    tracker = AILMTracker(store=store)
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    agent_id = "agent-p36"

    permissions = [f"perm_{i}" for i in range(num_grants)]
    for i, p in enumerate(permissions):
        g = PermissionGrant(
            permission=p,
            granted_by="service_role",
            granted_to=agent_id,
            timestamp=base_time + timedelta(seconds=i * 20),
            scope="user_space",
        )
        await tracker.track_permission_grant(g)

    time_win = (base_time, base_time + timedelta(seconds=300))
    evidences = await tracker.detect_permission_composition(agent_id, time_win)

    assert len(evidences) == 1
    ev = evidences[0]
    for p in permissions:
        assert p in ev.composed_permissions


# Property 37: Cross-Boundary Permission Detection
@pytest.mark.asyncio
@given(
    scope1=st.sampled_from(["user_space", "sandbox"]),
    scope2=st.sampled_from(["kernel_space", "external_net"]),
)
@settings(max_examples=30)
async def test_property_37_cross_boundary_permission_detection(scope1: str, scope2: str):
    """Property 37: Permissions spanning multiple trust boundaries SHALL be identified in boundary_crossings."""
    store = AttackGraphStore(in_memory=True)
    tracker = AILMTracker(store=store)
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    agent_id = "agent-p37"

    g1 = PermissionGrant(
        permission="read_data",
        granted_by="auth",
        granted_to=agent_id,
        timestamp=base_time,
        scope=scope1,
    )
    g2 = PermissionGrant(
        permission="write_data",
        granted_by="root",
        granted_to=agent_id,
        timestamp=base_time + timedelta(seconds=10),
        scope=scope2,
    )
    await tracker.track_permission_grant(g1)
    await tracker.track_permission_grant(g2)

    time_win = (base_time, base_time + timedelta(seconds=60))
    evidences = await tracker.detect_permission_composition(agent_id, time_win)

    assert len(evidences) == 1
    ev = evidences[0]
    assert len(ev.boundary_crossings) >= 1
    expected_transition = f"{scope1}->{scope2}"
    assert expected_transition in ev.boundary_crossings


# Property 38: Security Boundary Crossing Identification
@pytest.mark.asyncio
@given(
    ctx1=st.sampled_from(["user_space", "kernel_space", "sandbox", "host"]),
    ctx2=st.sampled_from(["user_space", "kernel_space", "sandbox", "host"]),
)
@settings(max_examples=30)
async def test_property_38_security_boundary_crossing_identification(ctx1: str, ctx2: str):
    """Property 38: identify_boundary_crossing SHALL return True iff contexts differ."""
    tracker = AILMTracker()
    is_crossing = await tracker.identify_boundary_crossing(ctx1, ctx2)

    if ctx1.strip().lower() != ctx2.strip().lower():
        assert is_crossing is True
    else:
        assert is_crossing is False


# Property 39: AILM Risk Level Computation
@given(
    composed_perms=st.sets(st.sampled_from(["read_log", "write_log", "root", "exfiltrate"]), min_size=0, max_size=4),
    crossings=st.lists(st.sampled_from(["u->k", "k->e", "s->h", "a->b"]), min_size=0, max_size=4),
)
def test_property_39_ailm_risk_level_computation(composed_perms: set[str], crossings: list[str]):
    """Property 39: compute_risk_level SHALL return a valid risk level string."""
    tracker = AILMTracker()
    risk_level = tracker.compute_risk_level(composed_perms, crossings)
    assert risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# Property 40: AILM Evidence Completeness
@pytest.mark.asyncio
@given(
    agent_id=st.sampled_from(["agent-1", "agent-2"]),
    num_grants=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=30)
async def test_property_40_ailm_evidence_completeness(agent_id: str, num_grants: int):
    """Property 40: AILMEvidence SHALL include non-null agent_id, composed_permissions, boundary_crossings, and risk_level."""
    tracker = AILMTracker()
    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    scopes = ["user_space", "kernel_space", "sandbox"]
    for i in range(num_grants):
        g = PermissionGrant(
            permission=f"perm_{i}",
            granted_by="admin",
            granted_to=agent_id,
            timestamp=base_time + timedelta(seconds=i * 10),
            scope=scopes[i % len(scopes)],
        )
        await tracker.track_permission_grant(g)

    time_win = (base_time, base_time + timedelta(seconds=100))
    evidences = await tracker.detect_permission_composition(agent_id, time_win)

    assert len(evidences) == 1
    ev = evidences[0]
    assert isinstance(ev, AILMEvidence)
    assert ev.agent_id == agent_id
    assert isinstance(ev.composed_permissions, set)
    assert isinstance(ev.boundary_crossings, list)
    assert ev.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
