"""Unit tests for AILMTracker component (Pillar 6 Task 10)."""

from datetime import UTC, datetime, timedelta
import uuid
import pytest

from blackwall.enterprise.advanced_threat_detection.models import (
    PermissionGrant,
    AILMEvidence,
)
from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


@pytest.fixture
def store():
    return AttackGraphStore(in_memory=True)


@pytest.fixture
def tracker(store):
    return AILMTracker(store=store)


@pytest.mark.asyncio
async def test_track_permission(tracker):
    now = datetime.now(UTC)
    grantor_id = str(uuid.uuid4())
    grantee_id = str(uuid.uuid4())
    grant = PermissionGrant(
        permission="s3:GetObject",
        granted_by=grantor_id,
        granted_to=grantee_id,
        timestamp=now,
        scope="arn:aws:s3:::sensitive-bucket/*",
    )
    await tracker.track_permission_grant(grant)

    grants = await tracker.get_permission_grants(grantee_id)
    assert len(grants) == 1
    assert grants[0].permission == "s3:GetObject"
    assert str(grants[0].granted_by) == grantor_id
    assert str(grants[0].granted_to) == grantee_id
    assert grants[0].scope == "arn:aws:s3:::sensitive-bucket/*"


@pytest.mark.asyncio
async def test_composition_detection(tracker):
    now = datetime.now(UTC)
    grantor_1 = str(uuid.uuid4())
    grantor_2 = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    g1 = PermissionGrant(
        permission="read_user_data",
        granted_by=grantor_1,
        granted_to=agent_id,
        timestamp=now - timedelta(seconds=100),
        scope="user_space",
    )
    g2 = PermissionGrant(
        permission="execute_kernel_cmd",
        granted_by=grantor_2,
        granted_to=agent_id,
        timestamp=now - timedelta(seconds=50),
        scope="kernel_space",
    )
    await tracker.track_permission_grant(g1)
    await tracker.track_permission_grant(g2)

    time_win = (now - timedelta(seconds=300), now + timedelta(seconds=10))
    evidences = await tracker.detect_permission_composition(agent_id, time_win)

    assert len(evidences) >= 1
    ev = evidences[0]
    assert isinstance(ev, AILMEvidence)
    assert ev.agent_id == agent_id
    assert "read_user_data" in ev.composed_permissions
    assert "execute_kernel_cmd" in ev.composed_permissions
    assert len(ev.boundary_crossings) >= 1


@pytest.mark.asyncio
async def test_boundary_crossing(tracker):
    is_crossing = await tracker.identify_boundary_crossing("user_space", "kernel_space")
    assert is_crossing is True

    is_same = await tracker.identify_boundary_crossing("user_space", "user_space")
    assert is_same is False


@pytest.mark.asyncio
async def test_risk_level(tracker):
    # Test LOW risk
    risk_low = tracker.compute_risk_level(
        composed_permissions={"read_log"},
        boundary_crossings=[],
    )
    assert risk_low == "LOW"

    # Test MEDIUM risk
    risk_med = tracker.compute_risk_level(
        composed_permissions={"read_log", "write_log"},
        boundary_crossings=["user_space->internal_api"],
    )
    assert risk_med == "MEDIUM"

    # Test HIGH risk
    risk_high = tracker.compute_risk_level(
        composed_permissions={"read_log", "admin_write"},
        boundary_crossings=["user_space->internal_api", "internal_api->sandbox"],
    )
    assert risk_high == "HIGH"

    # Test CRITICAL risk
    risk_crit = tracker.compute_risk_level(
        composed_permissions={"root", "exfiltrate"},
        boundary_crossings=[
            "user_space->internal_api",
            "internal_api->kernel_space",
            "kernel_space->external_net",
        ],
    )
    assert risk_crit == "CRITICAL"


@pytest.mark.asyncio
async def test_bounded_grant_retention_eviction():
    tracker = AILMTracker(max_grants_per_agent=3)
    now = datetime.now(UTC)
    grantor_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())

    for i in range(5):
        g = PermissionGrant(
            permission=f"perm_{i}",
            granted_by=grantor_id,
            granted_to=agent_id,
            timestamp=now + timedelta(seconds=i),
            scope="user_space",
        )
        await tracker.track_permission_grant(g)

    grants = await tracker.get_permission_grants(agent_id)
    assert len(grants) == 3
    # Verify oldest grants (perm_0, perm_1) were evicted
    perm_names = [g.permission for g in grants]
    assert perm_names == ["perm_2", "perm_3", "perm_4"]


@pytest.mark.asyncio
async def test_boundary_crossing_unrecognized_scopes(tracker):
    # Transition between unrecognized sub-scopes is not a trust boundary crossing
    is_crossing = await tracker.identify_boundary_crossing("internal_module_a", "internal_module_b")
    assert is_crossing is False

    # Transition from recognized boundary to unrecognized scope is identified as boundary crossing
    is_crossing_recognized = await tracker.identify_boundary_crossing("user_space", "internal_module_b")
    assert is_crossing_recognized is True


def test_max_grants_per_agent_type_validation():
    with pytest.raises(ValueError, match="max_grants_per_agent must be a positive integer"):
        AILMTracker(max_grants_per_agent=1.5)

    with pytest.raises(ValueError, match="max_grants_per_agent must be a positive integer"):
        AILMTracker(max_grants_per_agent=True)

    with pytest.raises(ValueError, match="max_grants_per_agent must be a positive integer"):
        AILMTracker(max_grants_per_agent=0)
