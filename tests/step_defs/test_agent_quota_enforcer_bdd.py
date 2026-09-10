"""BDD Step Definitions for Agent Quota Enforcer (`tests/features/agent_quota_enforcer.feature`)."""

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import AgentQuotaUsage
from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
    AgentQuotaEnforcer,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/agent_quota_enforcer.feature")


class AgentQuotaBDDState:
    """State holder for Agent Quota Enforcer BDD scenarios."""

    def __init__(self) -> None:
        self.alert_bus: AlertBus = AlertBus()
        self.enforcer: AgentQuotaEnforcer | None = None
        self.last_usage: AgentQuotaUsage | None = None
        self.last_enforced: bool | None = None
        self.target_agent_id: str | None = None


@pytest.fixture
def bdd_state() -> AgentQuotaBDDState:
    return AgentQuotaBDDState()


# Given steps
@given(parsers.parse("an Agent Quota Enforcer instance with limit {limit:d} tokens/sec and Alert Bus"))
def given_enforcer_standard(bdd_state: AgentQuotaBDDState, limit: int) -> None:
    bdd_state.enforcer = AgentQuotaEnforcer(
        alert_bus=bdd_state.alert_bus,
        token_burn_rate_limit=float(limit),
        request_velocity_limit=50.0,
        sliding_window_sec=60.0,
        quarantine_duration_sec=300.0,
    )


@given(parsers.parse("an Agent Quota Enforcer instance with request velocity limit {limit:d} calls/sec and Alert Bus"))
def given_enforcer_velocity(bdd_state: AgentQuotaBDDState, limit: int) -> None:
    bdd_state.enforcer = AgentQuotaEnforcer(
        alert_bus=bdd_state.alert_bus,
        token_burn_rate_limit=5000.0,
        request_velocity_limit=float(limit),
        sliding_window_sec=60.0,
        quarantine_duration_sec=300.0,
    )


@given(parsers.parse("an Agent Quota Enforcer instance with limit {limit:d} tokens/sec and critical multiplier {multiplier:f}"))
def given_enforcer_critical(bdd_state: AgentQuotaBDDState, limit: int, multiplier: float) -> None:
    bdd_state.enforcer = AgentQuotaEnforcer(
        alert_bus=bdd_state.alert_bus,
        token_burn_rate_limit=float(limit),
        critical_burn_rate_multiplier=multiplier,
        sliding_window_sec=60.0,
        quarantine_duration_sec=300.0,
    )


# When steps
@when(parsers.parse('agent "{agent_id}" consumes {tokens:d} tokens in 1 second'))
def when_agent_consumes_tokens(bdd_state: AgentQuotaBDDState, agent_id: str, tokens: int) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.target_agent_id = agent_id
    bdd_state.last_usage = run_async(
        bdd_state.enforcer.track_token_consumption(agent_id=agent_id, tokens_used=tokens, api_calls=1)
    )
    bdd_state.last_enforced = run_async(
        bdd_state.enforcer.enforce_quota_limits(agent_id=agent_id, auto_quarantine=True)
    )


@when(parsers.parse('agent "{agent_id}" executes {calls:d} API calls in 1 second'))
def when_agent_velocity_surge(bdd_state: AgentQuotaBDDState, agent_id: str, calls: int) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.target_agent_id = agent_id
    bdd_state.last_usage = run_async(
        bdd_state.enforcer.track_token_consumption(agent_id=agent_id, tokens_used=10, api_calls=calls)
    )
    bdd_state.last_enforced = run_async(
        bdd_state.enforcer.enforce_quota_limits(agent_id=agent_id, auto_quarantine=True)
    )


@when(parsers.parse('agent "{agent_id}" consumes {tokens:d} tokens with {calls:d} API call'))
def when_agent_benign_consumption(bdd_state: AgentQuotaBDDState, agent_id: str, tokens: int, calls: int) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.target_agent_id = agent_id
    bdd_state.last_usage = run_async(
        bdd_state.enforcer.track_token_consumption(agent_id=agent_id, tokens_used=tokens, api_calls=calls)
    )
    bdd_state.last_enforced = run_async(
        bdd_state.enforcer.enforce_quota_limits(agent_id=agent_id, auto_quarantine=True)
    )


@when(parsers.parse('agent "{agent_id}" consumes {tokens:d} tokens in a single burst'))
def when_agent_critical_burst(bdd_state: AgentQuotaBDDState, agent_id: str, tokens: int) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.target_agent_id = agent_id
    bdd_state.last_usage = run_async(
        bdd_state.enforcer.track_token_consumption(agent_id=agent_id, tokens_used=tokens, api_calls=5)
    )
    bdd_state.last_enforced = run_async(
        bdd_state.enforcer.enforce_quota_limits(agent_id=agent_id, auto_quarantine=True)
    )


@when(parsers.parse('agent "{agent_id}" is manually quarantined with reason "{reason}"'))
def when_manual_quarantine(bdd_state: AgentQuotaBDDState, agent_id: str, reason: str) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.target_agent_id = agent_id
    bdd_state.enforcer.quarantine_agent(agent_id=agent_id, duration_sec=300.0, reason=reason)


@when(parsers.parse('agent "{agent_id}" is unquarantined'))
def when_unquarantine(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    bdd_state.enforcer.unquarantine_agent(agent_id=agent_id)


# Then steps
@then("the quota enforcer flags the quota as exceeded")
def then_quota_flagged_exceeded(bdd_state: AgentQuotaBDDState) -> None:
    assert bdd_state.last_usage is not None
    assert bdd_state.last_usage.quota_exceeded is True
    assert bdd_state.last_enforced is True


@then(parsers.parse('agent "{agent_id}" is placed into quarantine'))
def then_agent_in_quarantine(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    assert bdd_state.enforcer.is_quarantined(agent_id) is True


@then(parsers.parse('a Denial of Wallet alert is emitted to the Alert Bus for "{agent_id}"'))
def then_dow_alert_emitted(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    alerts = bdd_state.alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id=agent_id)
    assert len(alerts) >= 1
    assert alerts[-1].agent_id == agent_id


@then("the quota enforcer detects the velocity surge")
def then_velocity_surge_detected(bdd_state: AgentQuotaBDDState) -> None:
    assert bdd_state.last_enforced is True


@then(parsers.parse('a Denial of Wallet alert with severity "{severity_a}" or "{severity_b}" is emitted for "{agent_id}"'))
def then_alert_severity_emitted(bdd_state: AgentQuotaBDDState, severity_a: str, severity_b: str, agent_id: str) -> None:
    alerts = bdd_state.alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id=agent_id)
    assert len(alerts) >= 1
    severities = {AlertSeverity(severity_a), AlertSeverity(severity_b)}
    assert alerts[-1].severity in severities


@then("the quota enforcer confirms the quota is not exceeded")
def then_quota_not_exceeded(bdd_state: AgentQuotaBDDState) -> None:
    assert bdd_state.last_usage is not None
    assert bdd_state.last_usage.quota_exceeded is False
    assert bdd_state.last_enforced is False


@then(parsers.parse('agent "{agent_id}" is not quarantined'))
def then_agent_not_quarantined(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    assert bdd_state.enforcer.is_quarantined(agent_id) is False


@then(parsers.parse('zero Denial of Wallet alerts are emitted for "{agent_id}"'))
def then_zero_alerts_emitted(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    alerts = bdd_state.alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id=agent_id)
    assert len(alerts) == 0


@then(parsers.parse('a CRITICAL severity alert is emitted to the Alert Bus for "{agent_id}"'))
def then_critical_dow_alert(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    alerts = bdd_state.alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id=agent_id)
    assert len(alerts) >= 1
    assert alerts[-1].severity == AlertSeverity.CRITICAL


@then(parsers.parse("the alert metadata contains total tokens consumed {tokens:d}"))
def then_alert_metadata_tokens(bdd_state: AgentQuotaBDDState, tokens: int) -> None:
    alerts = bdd_state.alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE")
    assert len(alerts) >= 1
    assert alerts[-1].metadata.get("tokens_consumed") == tokens


@then(parsers.parse('agent "{agent_id}" is verified as quarantined'))
def then_verified_quarantined(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    assert bdd_state.enforcer.is_quarantined(agent_id) is True


@then(parsers.parse('enforcing quota on "{agent_id}" immediately returns True'))
def then_enforce_returns_true(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    assert run_async(bdd_state.enforcer.enforce_quota_limits(agent_id)) is True


@then(parsers.parse('agent "{agent_id}" is no longer quarantined'))
def then_no_longer_quarantined(bdd_state: AgentQuotaBDDState, agent_id: str) -> None:
    assert bdd_state.enforcer is not None
    assert bdd_state.enforcer.is_quarantined(agent_id) is False
