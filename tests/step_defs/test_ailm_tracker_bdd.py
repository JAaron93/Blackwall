"""BDD Step Definitions for AILM Tracker (`tests/features/ailm_tracker.feature`)."""

from datetime import UTC, datetime, timedelta
import uuid
import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection import (
    AILMEvidence,
    AILMTracker,
    PermissionGrant,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/ailm_tracker.feature")

# Deterministic UUID v4 mapping for BDD entity strings
AGENT_UUIDS = {
    "agent-bdd-1": str(uuid.UUID("11111111-1111-4111-8111-111111111111")),
    "agent-bdd-2": str(uuid.UUID("22222222-2222-4222-8222-222222222222")),
    "agent-bdd-3": str(uuid.UUID("33333333-3333-4333-8333-333333333333")),
    "agent-bdd-4": str(uuid.UUID("44444444-4444-4444-8444-444444444444")),
    "admin-user": str(uuid.UUID("99999999-9999-4999-8999-999999999999")),
    "auth_svc": str(uuid.UUID("88888888-8888-4888-8888-888888888888")),
    "admin_svc": str(uuid.UUID("77777777-7777-4777-8777-777777777777")),
    "auth": str(uuid.UUID("66666666-6666-4666-8666-666666666666")),
    "root": str(uuid.UUID("55555555-5555-4555-8555-555555555555")),
    "admin": str(uuid.UUID("44444444-4444-4444-8444-444444444444")),
}


def get_uuid_str(name: str) -> str:
    return AGENT_UUIDS.get(name, str(uuid.uuid4()))


class AILMBDDState:
    def __init__(self):
        self.tracker = AILMTracker()
        self.grant = None
        self.evidences = None
        self.base_time = datetime.now(UTC)


@pytest.fixture
def ailm_state():
    return AILMBDDState()


@given('a permission grant with permission "s3:GetObject", granted_by "admin-user", granted_to "agent-bdd-1", and scope "user_space"')
def given_grant(ailm_state):
    ailm_state.grant = PermissionGrant(
        permission="s3:GetObject",
        granted_by=get_uuid_str("admin-user"),
        granted_to=get_uuid_str("agent-bdd-1"),
        timestamp=ailm_state.base_time,
        scope="user_space",
    )


@when("the AILM tracker records the permission grant")
def when_record_grant(ailm_state):
    run_async(ailm_state.tracker.track_permission_grant(ailm_state.grant))


@then('the recorded grant should contain permission "s3:GetObject", granted_by "admin-user", granted_to "agent-bdd-1", and scope "user_space"')
def then_verify_recorded_grant(ailm_state):
    agent_id = get_uuid_str("agent-bdd-1")
    grants = run_async(ailm_state.tracker.get_permission_grants(agent_id))
    assert len(grants) == 1
    g = grants[0]
    assert g.permission == "s3:GetObject"
    assert str(g.granted_by) == get_uuid_str("admin-user")
    assert str(g.granted_to) == agent_id
    assert g.scope == "user_space"


@given('an agent "agent-bdd-2" with permission grant "read_db" at current time minus 200 seconds')
def given_grant_1(ailm_state):
    g1 = PermissionGrant(
        permission="read_db",
        granted_by=get_uuid_str("auth_svc"),
        granted_to=get_uuid_str("agent-bdd-2"),
        timestamp=ailm_state.base_time - timedelta(seconds=200),
        scope="user_space",
    )
    run_async(ailm_state.tracker.track_permission_grant(g1))


@given('the agent "agent-bdd-2" receiving permission grant "write_db" at current time minus 50 seconds')
def given_grant_2(ailm_state):
    g2 = PermissionGrant(
        permission="write_db",
        granted_by=get_uuid_str("admin_svc"),
        granted_to=get_uuid_str("agent-bdd-2"),
        timestamp=ailm_state.base_time - timedelta(seconds=50),
        scope="user_space",
    )
    run_async(ailm_state.tracker.track_permission_grant(g2))


@when('the AILM tracker detects permission composition for "agent-bdd-2" over a 300 second window')
def when_detect_composition_agent2(ailm_state):
    time_win = (
        ailm_state.base_time - timedelta(seconds=300),
        ailm_state.base_time + timedelta(seconds=10),
    )
    ailm_state.evidences = run_async(
        ailm_state.tracker.detect_permission_composition(get_uuid_str("agent-bdd-2"), time_win)
    )


@then('the AILM evidence should contain composed permissions "read_db" and "write_db"')
def then_verify_composed_perms(ailm_state):
    assert len(ailm_state.evidences) == 1
    ev = ailm_state.evidences[0]
    assert "read_db" in ev.composed_permissions
    assert "write_db" in ev.composed_permissions


@given('an agent "agent-bdd-3" with grant "read_user_data" in scope "user_space"')
def given_grant_scope_1(ailm_state):
    g1 = PermissionGrant(
        permission="read_user_data",
        granted_by=get_uuid_str("auth"),
        granted_to=get_uuid_str("agent-bdd-3"),
        timestamp=ailm_state.base_time - timedelta(seconds=100),
        scope="user_space",
    )
    run_async(ailm_state.tracker.track_permission_grant(g1))


@given('the agent "agent-bdd-3" with grant "kernel_exec" in scope "kernel_space"')
def given_grant_scope_2(ailm_state):
    g2 = PermissionGrant(
        permission="kernel_exec",
        granted_by=get_uuid_str("root"),
        granted_to=get_uuid_str("agent-bdd-3"),
        timestamp=ailm_state.base_time - timedelta(seconds=50),
        scope="kernel_space",
    )
    run_async(ailm_state.tracker.track_permission_grant(g2))


@when('the AILM tracker detects permission composition for "agent-bdd-3" over a 300 second window')
def when_detect_composition_agent3(ailm_state):
    time_win = (
        ailm_state.base_time - timedelta(seconds=300),
        ailm_state.base_time + timedelta(seconds=10),
    )
    ailm_state.evidences = run_async(
        ailm_state.tracker.detect_permission_composition(get_uuid_str("agent-bdd-3"), time_win)
    )


@then("the AILM evidence should identify at least 1 boundary crossing transition")
def then_verify_boundary_crossings(ailm_state):
    assert len(ailm_state.evidences) == 1
    ev = ailm_state.evidences[0]
    assert len(ev.boundary_crossings) >= 1
    assert "user_space->kernel_space" in ev.boundary_crossings


@given('an agent "agent-bdd-4" with grants crossing 3 security boundaries')
def given_grants_3_crossings(ailm_state):
    scopes = ["user_space", "internal_api", "kernel_space", "external_net"]
    agent_id = get_uuid_str("agent-bdd-4")
    admin_id = get_uuid_str("admin")
    for i, sc in enumerate(scopes):
        g = PermissionGrant(
            permission=f"perm_{i}",
            granted_by=admin_id,
            granted_to=agent_id,
            timestamp=ailm_state.base_time - timedelta(seconds=200 - i * 50),
            scope=sc,
        )
        run_async(ailm_state.tracker.track_permission_grant(g))


@when('the AILM tracker detects permission composition for "agent-bdd-4" over a 300 second window')
def when_detect_composition_agent4(ailm_state):
    time_win = (
        ailm_state.base_time - timedelta(seconds=300),
        ailm_state.base_time + timedelta(seconds=10),
    )
    ailm_state.evidences = run_async(
        ailm_state.tracker.detect_permission_composition(get_uuid_str("agent-bdd-4"), time_win)
    )


@then('the AILM evidence should have risk_level "CRITICAL"')
def then_verify_critical_risk(ailm_state):
    assert len(ailm_state.evidences) == 1
    ev = ailm_state.evidences[0]
    assert ev.risk_level == "CRITICAL"
