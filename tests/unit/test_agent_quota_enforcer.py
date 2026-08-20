"""Unit tests for AgentQuotaEnforcer (Pillar 6 Task 27)."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import AgentQuotaUsage
from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
    AgentQuotaEnforcer,
)


@pytest.mark.asyncio
async def test_token_tracking() -> None:
    """Test recording token usage and calculating rolling burn rates."""
    enforcer = AgentQuotaEnforcer(
        token_burn_rate_limit=500.0,
        request_velocity_limit=50.0,
        sliding_window_sec=60.0,
    )

    now = datetime.now(UTC)
    usage = await enforcer.track_token_consumption(
        agent_id="agent_alpha",
        tokens_used=150,
        api_calls=1,
        timestamp=now,
    )

    assert isinstance(usage, AgentQuotaUsage)
    assert usage.agent_id == "agent_alpha"
    assert usage.tokens_consumed == 150
    assert usage.api_call_count == 1
    assert usage.token_burn_rate_per_sec >= 0.0
    assert not usage.quota_exceeded
    assert usage.time_window_start.tzinfo is not None

    # Track second event
    usage2 = await enforcer.track_token_consumption(
        agent_id="agent_alpha",
        tokens_used=200,
        api_calls=2,
    )
    assert usage2.tokens_consumed == 350
    assert usage2.api_call_count == 3


@pytest.mark.asyncio
async def test_velocity_enforcement() -> None:
    """Test velocity limit enforcement and quarantine triggers."""
    alert_bus = AlertBus(max_retries=1)
    enforcer = AgentQuotaEnforcer(
        alert_bus=alert_bus,
        token_burn_rate_limit=500.0,
        request_velocity_limit=10.0,
        sliding_window_sec=60.0,
        quarantine_duration_sec=10.0,
    )

    # Within limits
    await enforcer.track_token_consumption("agent_beta", tokens_used=100, api_calls=1)
    is_exceeded = await enforcer.enforce_quota_limits("agent_beta")
    assert not is_exceeded
    assert not enforcer.is_quarantined("agent_beta")

    # Exceed token burn rate
    await enforcer.track_token_consumption("agent_beta", tokens_used=1000, api_calls=1)
    is_exceeded_spike = await enforcer.enforce_quota_limits("agent_beta")
    assert is_exceeded_spike
    assert enforcer.is_quarantined("agent_beta")

    # While quarantined, enforce returns True immediately
    assert await enforcer.enforce_quota_limits("agent_beta")


@pytest.mark.asyncio
async def test_dow_alerts() -> None:
    """Test Denial of Wallet alert publishing on quota violations."""
    alert_bus = AlertBus(max_retries=1)
    enforcer = AgentQuotaEnforcer(
        alert_bus=alert_bus,
        token_burn_rate_limit=200.0,
        critical_burn_rate_multiplier=2.0,
        sliding_window_sec=60.0,
    )

    # Trigger critical spike (> 400 tokens/sec)
    await enforcer.track_token_consumption("agent_rogue", tokens_used=800, api_calls=5)
    await enforcer.enforce_quota_limits("agent_rogue")

    alerts = alert_bus.get_alerts(threat_type="DENIAL_OF_WALLET_SURGE", agent_id="agent_rogue")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.agent_id == "agent_rogue"
    assert "Denial of Wallet" in alert.title
    assert alert.metadata["tokens_consumed"] == 800


@pytest.mark.asyncio
async def test_quarantine_lifecycle() -> None:
    """Test manual quarantine, automatic expiration, and unquarantine."""
    enforcer = AgentQuotaEnforcer(
        quarantine_duration_sec=0.1,  # Short duration for test
    )

    assert not enforcer.is_quarantined("agent_test")
    enforcer.quarantine_agent("agent_test", duration_sec=0.1, reason="Test quarantine")
    assert enforcer.is_quarantined("agent_test")

    # Usage when quarantined
    usage = enforcer.get_usage("agent_test")
    assert usage is not None
    assert usage.quota_exceeded

    # Manual unquarantine
    assert enforcer.unquarantine_agent("agent_test")
    assert not enforcer.is_quarantined("agent_test")

    # Quarantine and wait for auto-expiry
    enforcer.quarantine_agent("agent_test", duration_sec=0.05)
    time.sleep(0.06)
    assert not enforcer.is_quarantined("agent_test")


@pytest.mark.asyncio
async def test_sliding_window_eviction() -> None:
    """Test sliding window eviction of old usage records."""
    enforcer = AgentQuotaEnforcer(
        sliding_window_sec=0.05,
    )

    await enforcer.track_token_consumption("agent_slide", tokens_used=100, api_calls=1)
    usage1 = enforcer.get_usage("agent_slide")
    assert usage1 is not None
    assert usage1.tokens_consumed == 100

    time.sleep(0.06)
    usage2 = enforcer.get_usage("agent_slide")
    assert usage2 is None


@pytest.mark.asyncio
async def test_parameter_validation() -> None:
    """Test invalid parameter rejection across constructor and methods."""
    # Invalid constructor params
    with pytest.raises(ValueError, match="token_burn_rate_limit must be a float greater than 0.0"):
        AgentQuotaEnforcer(token_burn_rate_limit=-10.0)

    with pytest.raises(ValueError, match="token_burn_rate_limit must be a float greater than 0.0"):
        AgentQuotaEnforcer(token_burn_rate_limit=0.0)

    with pytest.raises(ValueError, match="token_burn_rate_limit must be a float greater than 0.0"):
        AgentQuotaEnforcer(token_burn_rate_limit=True)  # type: ignore

    with pytest.raises(ValueError, match="request_velocity_limit must be a float greater than 0.0"):
        AgentQuotaEnforcer(request_velocity_limit=-1.0)

    with pytest.raises(ValueError, match="sliding_window_sec must be a float greater than 0.0"):
        AgentQuotaEnforcer(sliding_window_sec=0.0)

    with pytest.raises(ValueError, match="quarantine_duration_sec must be a float greater than 0.0"):
        AgentQuotaEnforcer(quarantine_duration_sec=-5.0)

    with pytest.raises(ValueError, match="critical_burn_rate_multiplier must be a float >= 1.0"):
        AgentQuotaEnforcer(critical_burn_rate_multiplier=0.5)

    enforcer = AgentQuotaEnforcer()

    # Empty agent ID
    with pytest.raises(ValueError, match="agent_id"):
        await enforcer.track_token_consumption("", tokens_used=10)

    with pytest.raises(ValueError, match="agent_id"):
        await enforcer.track_token_consumption("   ", tokens_used=10)

    # Negative tokens or calls
    with pytest.raises(ValueError, match="tokens_used must be a non-negative integer"):
        await enforcer.track_token_consumption("agent_1", tokens_used=-5)

    with pytest.raises(ValueError, match="tokens_used must be a non-negative integer"):
        await enforcer.track_token_consumption("agent_1", tokens_used=True)  # type: ignore

    with pytest.raises(ValueError, match="api_calls must be a non-negative integer"):
        await enforcer.track_token_consumption("agent_1", tokens_used=10, api_calls=-1)

    # Naive timestamp
    naive_dt = datetime.now()  # Naive
    with pytest.raises(ValueError, match="timezone-aware"):
        await enforcer.track_token_consumption("agent_1", tokens_used=10, timestamp=naive_dt)

    # AgentQuotaUsage model validation
    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="",
            time_window_start=datetime.now(UTC),
            tokens_consumed=10,
            api_call_count=1,
            token_burn_rate_per_sec=10.0,
            quota_exceeded=False,
        )

    with pytest.raises(ValidationError):
        AgentQuotaUsage(
            agent_id="agent_1",
            time_window_start=datetime.now(UTC),
            tokens_consumed=-1,
            api_call_count=1,
            token_burn_rate_per_sec=10.0,
            quota_exceeded=False,
        )
