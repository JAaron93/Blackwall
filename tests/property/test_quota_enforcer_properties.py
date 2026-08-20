"""Property-based tests for Agent Fleet Resource and Token Velocity Enforcement (Task 27).

Validates Properties 100, 101, 102, 103 against Requirements 25.1, 25.2, 25.3, 15.13.
"""

import asyncio
from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import AgentQuotaUsage
from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
    AgentQuotaEnforcer,
)

# Strategies
identifier_st = st.from_regex(r"[a-zA-Z0-9_-]{1,32}", fullmatch=True)
utc_datetime_st = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
    timezones=st.just(UTC),
)


@st.composite
def valid_agent_quota_usage(draw: st.DrawFn) -> AgentQuotaUsage:
    """Hypothesis strategy generating valid AgentQuotaUsage models."""
    agent_id = draw(identifier_st)
    window_start = draw(utc_datetime_st)
    tokens = draw(st.integers(min_value=0, max_value=1_000_000))
    calls = draw(st.integers(min_value=0, max_value=10_000))
    rate = draw(st.floats(min_value=0.0, max_value=100_000.0, allow_nan=False, allow_infinity=False))
    exceeded = draw(st.booleans())
    return AgentQuotaUsage(
        agent_id=agent_id,
        time_window_start=window_start,
        tokens_consumed=tokens,
        api_call_count=calls,
        token_burn_rate_per_sec=rate,
        quota_exceeded=exceeded,
    )


@given(usage=valid_agent_quota_usage())
@settings(max_examples=100, deadline=None)
def test_property_103_agent_quota_usage_model_acceptance(
    usage: AgentQuotaUsage,
) -> None:
    """Feature: blackwall-advanced-threat-detection, Property 103: Breach Defense Model Pydantic Validation - AgentQuotaUsage Acceptance.

    For all valid instantiated AgentQuotaUsage models, Pydantic validation succeeds
    with non-empty agent_id, UTC timezone-aware time_window_start, non-negative usage counts, and non-negative burn rates.
    """
    assert len(usage.agent_id.strip()) >= 1
    assert usage.time_window_start.tzinfo is not None
    assert usage.time_window_start.utcoffset() == timedelta(0)
    assert usage.tokens_consumed >= 0
    assert usage.api_call_count >= 0
    assert usage.token_burn_rate_per_sec >= 0.0
    assert isinstance(usage.quota_exceeded, bool)


@given(
    invalid_agent_id=st.sampled_from(["", "   ", "\t\n"]),
    invalid_tokens=st.integers(min_value=-10000, max_value=-1),
    invalid_calls=st.integers(min_value=-10000, max_value=-1),
    invalid_rate=st.floats(min_value=-10000.0, max_value=-0.001),
    naive_dt=st.datetimes(min_value=datetime(2020, 1, 1), max_value=datetime(2030, 12, 31)),
)
@settings(max_examples=50, deadline=None)
def test_property_103_agent_quota_usage_model_rejection(
    invalid_agent_id: str,
    invalid_tokens: int,
    invalid_calls: int,
    invalid_rate: float,
    naive_dt: datetime,
) -> None:
    """Feature: blackwall-advanced-threat-detection, Property 103: Breach Defense Model Pydantic Validation - AgentQuotaUsage Rejection.

    Invalid models with empty agent_id, negative counts, negative rates, or naive timestamps are rejected with ValidationError.
    """
    valid_dt = datetime.now(UTC)

    # Rejection: empty agent_id
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id=invalid_agent_id,
            time_window_start=valid_dt,
            tokens_consumed=100,
            api_call_count=1,
            token_burn_rate_per_sec=50.0,
            quota_exceeded=False,
        )

    # Rejection: negative tokens_consumed
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=valid_dt,
            tokens_consumed=invalid_tokens,
            api_call_count=1,
            token_burn_rate_per_sec=50.0,
            quota_exceeded=False,
        )

    # Rejection: negative api_call_count
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=valid_dt,
            tokens_consumed=100,
            api_call_count=invalid_calls,
            token_burn_rate_per_sec=50.0,
            quota_exceeded=False,
        )

    # Rejection: negative token_burn_rate_per_sec
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=valid_dt,
            tokens_consumed=100,
            api_call_count=1,
            token_burn_rate_per_sec=invalid_rate,
            quota_exceeded=False,
        )

    # Rejection: naive timestamp (no tzinfo)
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=naive_dt,
            tokens_consumed=100,
            api_call_count=1,
            token_burn_rate_per_sec=50.0,
            quota_exceeded=False,
        )

    # Rejection: non-UTC timezone timestamp (+05:00)
    non_utc_dt = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=non_utc_dt,
            tokens_consumed=100,
            api_call_count=1,
            token_burn_rate_per_sec=50.0,
            quota_exceeded=False,
        )


@given(
    agent=identifier_st,
    tokens=st.integers(min_value=0, max_value=5000),
    calls=st.integers(min_value=0, max_value=50),
    limit=st.floats(min_value=10.0, max_value=2000.0),
)
@settings(max_examples=100, deadline=None)
def test_property_100_token_consumption_rate_tracking(
    agent: str,
    tokens: int,
    calls: int,
    limit: float,
) -> None:
    """Feature: blackwall-advanced-threat-detection, Property 100: Token Consumption Rate Tracking.

    For any action executed by an agent, the Agent_Quota_Enforcer SHALL record token usage
    and compute the rolling burn rate per second, returning a valid AgentQuotaUsage record.
    """
    async def _run() -> None:
        enforcer = AgentQuotaEnforcer(
            token_burn_rate_limit=limit,
            sliding_window_sec=60.0,
        )
        usage = await enforcer.track_token_consumption(
            agent_id=agent,
            tokens_used=tokens,
            api_calls=calls,
        )

        assert usage.agent_id == agent
        assert usage.tokens_consumed == tokens
        assert usage.api_call_count == calls
        assert usage.token_burn_rate_per_sec >= 0.0
        assert isinstance(usage.quota_exceeded, bool)
        assert usage.time_window_start.tzinfo is not None

    asyncio.run(_run())


@given(
    agent=identifier_st,
    spike_tokens=st.integers(min_value=600, max_value=10000),
    limit=st.floats(min_value=50.0, max_value=500.0),
)
@settings(max_examples=100, deadline=None)
def test_property_101_velocity_limit_quarantine_trigger(
    agent: str,
    spike_tokens: int,
    limit: float,
) -> None:
    """Feature: blackwall-advanced-threat-detection, Property 101: Velocity Limit Quarantine Trigger.

    For any agent whose token burn rate or request velocity exceeds configured ceilings,
    the Agent_Quota_Enforcer SHALL trigger automated throttling or quarantine.
    """
    async def _run() -> None:
        enforcer = AgentQuotaEnforcer(
            token_burn_rate_limit=limit,
            quarantine_duration_sec=300.0,
        )

        # Ingest burst of tokens exceeding rate limit
        await enforcer.track_token_consumption(agent_id=agent, tokens_used=spike_tokens, api_calls=1)

        exceeded = await enforcer.enforce_quota_limits(agent_id=agent, auto_quarantine=True)
        assert exceeded is True
        assert enforcer.is_quarantined(agent) is True

    asyncio.run(_run())


@given(
    agent=identifier_st,
    spike_tokens=st.integers(min_value=1500, max_value=20000),
    limit=st.floats(min_value=100.0, max_value=500.0),
)
@settings(max_examples=100, deadline=None)
def test_property_102_quota_violation_alert_mapping(
    agent: str,
    spike_tokens: int,
    limit: float,
) -> None:
    """Feature: blackwall-advanced-threat-detection, Property 102: Quota Violation Alert Mapping.

    For any quota violation or velocity surge event, the Agent_Quota_Enforcer SHALL emit
    a Denial of Wallet alert to the Alert Bus with appropriate severity (HIGH or CRITICAL).
    """
    async def _run() -> None:
        alert_bus = AlertBus()
        enforcer = AgentQuotaEnforcer(
            alert_bus=alert_bus,
            token_burn_rate_limit=limit,
            critical_burn_rate_multiplier=2.0,
        )

        await enforcer.track_token_consumption(agent_id=agent, tokens_used=spike_tokens, api_calls=10)
        exceeded = await enforcer.enforce_quota_limits(agent_id=agent)
        assert exceeded is True

        alerts = alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id=agent)
        assert len(alerts) >= 1
        latest = alerts[-1]
        assert latest.agent_id == agent
        assert latest.threat_type == "DENIAL_OF_WALLET_SURGE"
        assert "Denial of Wallet" in latest.title
        assert latest.metadata["tokens_consumed"] == spike_tokens
        assert latest.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}

    asyncio.run(_run())
