"""Agent Quota Enforcer for Fleet Resource and Token Velocity Enforcement (Pillar 6 Task 27).

Provides real-time token consumption tracking, rolling burn rate computation per second,
API request velocity limit enforcement, automated throttling/quarantine, and Denial of Wallet (DoW) alerts.
"""

import collections
import logging
import time
from datetime import UTC, datetime
from typing import Optional
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import (
    AgentQuotaUsage,
    Alert,
)
from blackwall.validators import (
    validate_non_empty_string,
    validate_utc_datetime,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.quota_enforcer")


class AgentQuotaEnforcer:
    """Enterprise resource and token velocity enforcer protecting against Denial of Wallet (DoW) attacks."""

    def __init__(
        self,
        alert_bus: Optional[AlertBus] = None,
        token_burn_rate_limit: float = 500.0,
        request_velocity_limit: float = 50.0,
        sliding_window_sec: float = 60.0,
        quarantine_duration_sec: float = 300.0,
        critical_burn_rate_multiplier: float = 2.0,
    ) -> None:
        if (
            isinstance(token_burn_rate_limit, bool)
            or not isinstance(token_burn_rate_limit, (int, float))
            or token_burn_rate_limit <= 0.0
        ):
            raise ValueError("token_burn_rate_limit must be a float greater than 0.0")

        if (
            isinstance(request_velocity_limit, bool)
            or not isinstance(request_velocity_limit, (int, float))
            or request_velocity_limit <= 0.0
        ):
            raise ValueError("request_velocity_limit must be a float greater than 0.0")

        if (
            isinstance(sliding_window_sec, bool)
            or not isinstance(sliding_window_sec, (int, float))
            or sliding_window_sec <= 0.0
        ):
            raise ValueError("sliding_window_sec must be a float greater than 0.0")

        if (
            isinstance(quarantine_duration_sec, bool)
            or not isinstance(quarantine_duration_sec, (int, float))
            or quarantine_duration_sec <= 0.0
        ):
            raise ValueError("quarantine_duration_sec must be a float greater than 0.0")

        if (
            isinstance(critical_burn_rate_multiplier, bool)
            or not isinstance(critical_burn_rate_multiplier, (int, float))
            or critical_burn_rate_multiplier < 1.0
        ):
            raise ValueError("critical_burn_rate_multiplier must be a float >= 1.0")

        self.alert_bus = alert_bus
        self.token_burn_rate_limit = float(token_burn_rate_limit)
        self.request_velocity_limit = float(request_velocity_limit)
        self.sliding_window_sec = float(sliding_window_sec)
        self.quarantine_duration_sec = float(quarantine_duration_sec)
        self.critical_burn_rate_multiplier = float(critical_burn_rate_multiplier)

        # In-memory sliding windows: agent_id -> deque of (mono_ts, tokens, api_calls, utc_dt)
        self._agent_windows: dict[str, collections.deque[tuple[float, int, int, datetime]]] = {}
        # Quarantined agents: agent_id -> (expiry_mono_ts, reason)
        self._quarantined_agents: dict[str, tuple[float, str]] = {}

    def _evict_stale_records(self, agent_id: str, current_mono: float) -> None:
        """Evict records outside the sliding window for a given agent."""
        if agent_id not in self._agent_windows:
            return

        window = self._agent_windows[agent_id]
        cutoff = current_mono - self.sliding_window_sec
        while window and window[0][0] < cutoff:
            window.popleft()

        if not window:
            self._agent_windows.pop(agent_id, None)

    def is_quarantined(self, agent_id: str) -> bool:
        """Check whether an agent is currently quarantined, automatically expiring stale quarantines."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        if clean_id not in self._quarantined_agents:
            return False

        expiry_mono, _reason = self._quarantined_agents[clean_id]
        if time.monotonic() >= expiry_mono:
            del self._quarantined_agents[clean_id]
            logger.info("Quarantine expired for agent %s", clean_id)
            return False

        return True

    def quarantine_agent(
        self,
        agent_id: str,
        duration_sec: Optional[float] = None,
        reason: str = "Token burn rate or velocity quota exceeded",
    ) -> None:
        """Place an agent into temporary quarantine."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        duration = self.quarantine_duration_sec if duration_sec is None else float(duration_sec)
        if duration <= 0.0:
            raise ValueError("duration_sec must be positive")

        expiry_mono = time.monotonic() + duration
        self._quarantined_agents[clean_id] = (expiry_mono, reason)
        logger.warning(
            "Agent %s quarantined for %.1fs (Reason: %s)",
            clean_id,
            duration,
            reason,
        )

    def unquarantine_agent(self, agent_id: str) -> bool:
        """Release an agent from quarantine early. Returns True if was quarantined."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        if clean_id in self._quarantined_agents:
            del self._quarantined_agents[clean_id]
            logger.info("Agent %s released from quarantine", clean_id)
            return True
        return False

    async def track_token_consumption(
        self,
        agent_id: str,
        tokens_used: int,
        api_calls: int = 1,
        timestamp: Optional[datetime] = None,
    ) -> AgentQuotaUsage:
        """Record token usage and api call count for an agent and compute rolling burn rate."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")

        if isinstance(tokens_used, bool) or not isinstance(tokens_used, int) or tokens_used < 0:
            raise ValueError("tokens_used must be a non-negative integer")

        if isinstance(api_calls, bool) or not isinstance(api_calls, int) or api_calls < 0:
            raise ValueError("api_calls must be a non-negative integer")

        if timestamp is not None:
            utc_dt = validate_utc_datetime(timestamp)
        else:
            utc_dt = datetime.now(UTC)

        now_mono = time.monotonic()

        if clean_id not in self._agent_windows:
            self._agent_windows[clean_id] = collections.deque()

        window = self._agent_windows[clean_id]
        window.append((now_mono, tokens_used, api_calls, utc_dt))
        self._evict_stale_records(clean_id, now_mono)

        # Re-fetch active window
        active_window = self._agent_windows.get(clean_id, collections.deque())
        total_tokens = sum(item[1] for item in active_window)
        total_calls = sum(item[2] for item in active_window)

        if active_window:
            oldest_mono = active_window[0][0]
            window_start_dt = active_window[0][3]
            elapsed_sec = max(1.0, now_mono - oldest_mono)
        else:
            window_start_dt = utc_dt
            elapsed_sec = 1.0

        burn_rate = total_tokens / elapsed_sec
        call_rate = total_calls / elapsed_sec

        quota_exceeded = (
            burn_rate > self.token_burn_rate_limit
            or call_rate > self.request_velocity_limit
            or self.is_quarantined(clean_id)
        )

        return AgentQuotaUsage(
            agent_id=clean_id,
            time_window_start=window_start_dt,
            tokens_consumed=total_tokens,
            api_call_count=total_calls,
            token_burn_rate_per_sec=burn_rate,
            quota_exceeded=quota_exceeded,
        )

    async def enforce_quota_limits(
        self,
        agent_id: str,
        auto_quarantine: bool = True,
    ) -> bool:
        """Check whether an agent exceeds velocity or token caps; trigger throttling/quarantine and alert.
        
        Returns True if quota limits are exceeded or agent is quarantined, False otherwise.
        """
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        now_mono = time.monotonic()

        # Check if already quarantined
        if self.is_quarantined(clean_id):
            return True

        self._evict_stale_records(clean_id, now_mono)
        window = self._agent_windows.get(clean_id)
        if not window:
            return False

        total_tokens = sum(item[1] for item in window)
        total_calls = sum(item[2] for item in window)
        oldest_mono = window[0][0]
        elapsed_sec = max(1.0, now_mono - oldest_mono)

        burn_rate = total_tokens / elapsed_sec
        call_rate = total_calls / elapsed_sec

        burn_exceeded = burn_rate > self.token_burn_rate_limit
        call_exceeded = call_rate > self.request_velocity_limit

        if burn_exceeded or call_exceeded:
            reason = []
            if burn_exceeded:
                reason.append(
                    f"token burn rate {burn_rate:.1f} tokens/sec > limit {self.token_burn_rate_limit:.1f}"
                )
            if call_exceeded:
                reason.append(
                    f"API call rate {call_rate:.1f} calls/sec > limit {self.request_velocity_limit:.1f}"
                )
            full_reason = "; ".join(reason)

            if auto_quarantine:
                self.quarantine_agent(
                    clean_id,
                    duration_sec=self.quarantine_duration_sec,
                    reason=f"Quota exceeded: {full_reason}",
                )

            # Publish Denial of Wallet alert
            if self.alert_bus is not None:
                is_critical = (
                    burn_rate >= (self.token_burn_rate_limit * self.critical_burn_rate_multiplier)
                    or call_rate >= (self.request_velocity_limit * 2.0)
                )
                severity = AlertSeverity.CRITICAL if is_critical else AlertSeverity.HIGH
                alert_id = uuid4()
                alert = Alert(
                    alert_id=alert_id,
                    timestamp=datetime.now(UTC),
                    severity=severity,
                    threat_type="DENIAL_OF_WALLET_SURGE",
                    title=f"Denial of Wallet surge detected for agent {clean_id}",
                    description=(
                        f"Agent {clean_id} triggered Denial of Wallet defense. {full_reason}. "
                        f"Total tokens in window: {total_tokens}, total API calls: {total_calls}."
                    ),
                    agent_id=clean_id,
                    metadata={
                        "agent_id": clean_id,
                        "tokens_consumed": total_tokens,
                        "api_call_count": total_calls,
                        "token_burn_rate_per_sec": burn_rate,
                        "call_rate_per_sec": call_rate,
                        "token_burn_rate_limit": self.token_burn_rate_limit,
                        "request_velocity_limit": self.request_velocity_limit,
                        "quarantined": auto_quarantine,
                    },
                )
                await self.alert_bus.publish(alert)

            return True

        return False

    def get_usage(self, agent_id: str) -> Optional[AgentQuotaUsage]:
        """Get current rolling usage stats for an agent without appending new records."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        now_mono = time.monotonic()
        self._evict_stale_records(clean_id, now_mono)

        window = self._agent_windows.get(clean_id)
        if not window:
            if self.is_quarantined(clean_id):
                return AgentQuotaUsage(
                    agent_id=clean_id,
                    time_window_start=datetime.now(UTC),
                    tokens_consumed=0,
                    api_call_count=0,
                    token_burn_rate_per_sec=0.0,
                    quota_exceeded=True,
                )
            return None

        total_tokens = sum(item[1] for item in window)
        total_calls = sum(item[2] for item in window)
        oldest_mono = window[0][0]
        window_start_dt = window[0][3]
        elapsed_sec = max(1.0, now_mono - oldest_mono)

        burn_rate = total_tokens / elapsed_sec
        call_rate = total_calls / elapsed_sec

        quota_exceeded = (
            burn_rate > self.token_burn_rate_limit
            or call_rate > self.request_velocity_limit
            or self.is_quarantined(clean_id)
        )

        return AgentQuotaUsage(
            agent_id=clean_id,
            time_window_start=window_start_dt,
            tokens_consumed=total_tokens,
            api_call_count=total_calls,
            token_burn_rate_per_sec=burn_rate,
            quota_exceeded=quota_exceeded,
        )

    def reset_quota(self, agent_id: str) -> None:
        """Clear recorded usage and quarantine state for an agent."""
        clean_id = validate_non_empty_string(agent_id, field_name="agent_id")
        self._agent_windows.pop(clean_id, None)
        self._quarantined_agents.pop(clean_id, None)
