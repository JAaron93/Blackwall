"""Command-and-Control (C2) Infrastructure Detector for Blackwall Advanced Threat Detection (Pillar 6 Task 11)."""

from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    C2Evidence,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

# Known C2 Service Patterns (Requirement 7.1)
KNOWN_C2_PATTERNS = [
    # RequestBin patterns
    (r"(?:https?://)?(?:www\.)?(?:requestbin\.(?:net|com)|request\.bin|requestb\.in)", "requestbin"),
    # Pastebin & Gist patterns
    (r"(?:https?://)?(?:www\.)?pastebin\.com", "pastebin"),
    (r"(?:https?://)?(?:www\.)?gist\.github\.com", "github_gist"),
    (r"(?:https?://)?(?:www\.)?(?:hastebin\.com|justpaste\.it|rentry\.co|ghostbin\.com)", "pastebin"),
    # Webhook receivers & tunnels
    (r"(?:https?://)?(?:www\.)?webhook\.site", "webhook_receiver"),
    (r"(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?pipedream\.(?:net|com)", "webhook_receiver"),
    (r"(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?ngrok(?:-free)?\.(?:io|app)", "webhook_receiver"),
    (r"(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?(?:localtunnel\.me|serveo\.net|pagekite\.me)", "webhook_receiver"),
    (r"(?:https?://)?(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)", "webhook_receiver"),
    # Cloud storage services
    (r"(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?s3\.amazonaws\.com", "cloud_storage"),
    (r"(?:https?://)?storage\.googleapis\.com", "cloud_storage"),
    (r"(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?blob\.core\.windows\.net", "cloud_storage"),
    (r"(?:https?://)?(?:www\.)?(?:dropbox\.com|mega\.nz|drive\.google\.com)", "cloud_storage"),
]

PERSISTENCE_PATTERNS = [
    (r"cron|crontab|/etc/cron|/var/spool/cron", "Cron job persistence mechanism"),
    (r"systemd|systemctl|/etc/systemd/system", "Systemd service persistence mechanism"),
    (r"schtasks|taskschd|scheduled_task", "Scheduled task persistence mechanism"),
    (r"launchctl|LaunchDaemons|LaunchAgents", "MacOS launchd persistence mechanism"),
    (r"respawn|while\s+true|restart=always|supervisord|auto-restart", "Self-respawning process loop"),
]


class C2InfrastructureDetector:
    """Detects Command-and-Control (C2) infrastructure establishment, beaconing, and persistence."""

    def __init__(
        self,
        store: Optional[AttackGraphStore] = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self._events_by_agent: Dict[str, List[NormalizedEvent]] = {}

    def record_event(self, event: NormalizedEvent) -> None:
        """Record an event in memory for C2 analysis.

        Args:
            event: Validated NormalizedEvent instance.
        """
        agent_id = str(event.agent_id)
        if agent_id not in self._events_by_agent:
            self._events_by_agent[agent_id] = []
        self._events_by_agent[agent_id].append(event)

    async def classify_endpoint(self, domain_or_url: str) -> Optional[str]:
        """Classify endpoint as a potential C2 service pattern.

        Args:
            domain_or_url: Target domain, IP, or URL string.

        Returns:
            Service pattern classification ('requestbin', 'pastebin', 'github_gist',
            'cloud_storage', 'webhook_receiver') or None if non-C2.
        """
        if not domain_or_url or not domain_or_url.strip():
            return None

        clean_str = domain_or_url.strip().lower()

        for pattern, service_type in KNOWN_C2_PATTERNS:
            if re.search(pattern, clean_str, re.IGNORECASE):
                return service_type

        return None

    async def detect_beaconing(
        self,
        agent_id: str,
        endpoint: str,
        time_window: Tuple[datetime, datetime],
    ) -> bool:
        """Detect periodic beaconing patterns indicative of C2 communication.

        Args:
            agent_id: Agent identifier string.
            endpoint: Target endpoint or domain to evaluate.
            time_window: Tuple of (start_time, end_time) UTC datetimes.

        Returns:
            True if periodic beaconing pattern is detected, False otherwise.
        """
        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

        agent_events = self._events_by_agent.get(str(agent_id), [])

        # Filter events for matching endpoint/target within time window
        endpoint_clean = endpoint.strip().lower()
        matching_timestamps: List[datetime] = []

        for evt in agent_events:
            if not (start_win <= evt.timestamp <= end_win):
                continue
            target_str = str(evt.target).lower()
            metadata_str = str(evt.metadata).lower()
            action_str = str(evt.action).lower()
            if (
                endpoint_clean in target_str
                or endpoint_clean in metadata_str
                or endpoint_clean in action_str
                or endpoint_clean == "all"
                or endpoint_clean == "*"
            ):
                matching_timestamps.append(evt.timestamp)

        # Sort chronologically
        matching_timestamps.sort()

        if len(matching_timestamps) < 3:
            return False

        # Calculate time deltas between consecutive connections in seconds
        deltas = [
            (matching_timestamps[i + 1] - matching_timestamps[i]).total_seconds()
            for i in range(len(matching_timestamps) - 1)
        ]

        # Ignore non-positive deltas
        valid_deltas = [d for d in deltas if d > 0]
        if len(valid_deltas) < 2:
            return False

        mean_delta = sum(valid_deltas) / len(valid_deltas)
        if mean_delta <= 0:
            return False

        variance = sum((d - mean_delta) ** 2 for d in valid_deltas) / len(valid_deltas)
        std_dev = math.sqrt(variance)

        # Coefficient of variation (std_dev / mean_delta)
        # Low variance (CV <= 0.25) indicates periodic beaconing / polling
        return (std_dev / mean_delta) <= 0.25

    async def detect_persistence_indicators(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
    ) -> List[str]:
        """Identify persistence indicators such as cron jobs, self-respawning processes, or scheduled tasks.

        Args:
            agent_id: Agent identifier string.
            time_window: Tuple of (start_time, end_time) UTC datetimes.

        Returns:
            List of detected persistence indicator description strings.
        """
        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

        agent_events = self._events_by_agent.get(str(agent_id), [])
        indicators: Set[str] = set()

        for evt in agent_events:
            if not (start_win <= evt.timestamp <= end_win):
                continue

            content_to_check = f"{evt.action} {evt.target} {evt.metadata}".lower()

            for pattern, description in PERSISTENCE_PATTERNS:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    indicators.add(description)

        return list(indicators)

    async def detect_c2_establishment(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
    ) -> List[C2Evidence]:
        """Detect C2 infrastructure setup and communication patterns for an agent.

        Args:
            agent_id: Agent identifier string.
            time_window: Tuple of (start_time, end_time) UTC datetimes.

        Returns:
            List of C2Evidence objects detected for the agent.
        """
        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

        agent_key = str(agent_id)
        agent_events = [
            e
            for e in self._events_by_agent.get(agent_key, [])
            if start_win <= e.timestamp <= end_win
        ]

        if not agent_events:
            return []

        c2_endpoints: List[str] = []
        c2_services: List[str] = []
        kernel_network_events: List[NormalizedEvent] = []
        tool_call_events: List[NormalizedEvent] = []

        for evt in agent_events:
            if evt.source == EventSource.KERNEL_SYSCALL:
                kernel_network_events.append(evt)
            elif evt.source == EventSource.TOOL_CALL or evt.source == EventSource.PIPELINE_EXECUTION:
                tool_call_events.append(evt)

            # Check target and metadata for C2 endpoint patterns
            candidate_urls = [evt.target]
            if isinstance(evt.metadata, dict):
                for k, v in evt.metadata.items():
                    if isinstance(v, str) and ("http" in v or "bin" in v or "paste" in v or "site" in v):
                        candidate_urls.append(v)

            for candidate in candidate_urls:
                service = await self.classify_endpoint(candidate)
                if service:
                    if candidate not in c2_endpoints:
                        c2_endpoints.append(candidate)
                        c2_services.append(service)

        # Detect persistence indicators
        persistence_indicators = await self.detect_persistence_indicators(agent_key, time_window)

        # Check cross-pillar correlation between Pillar 1 network events and tool calls
        cross_pillar_correlated = False
        if kernel_network_events and tool_call_events:
            for k_evt in kernel_network_events:
                for t_evt in tool_call_events:
                    # If network event and tool call target or metadata overlap
                    if (
                        k_evt.target in t_evt.target
                        or t_evt.target in k_evt.target
                        or (isinstance(k_evt.metadata, dict) and k_evt.metadata.get("domain") == t_evt.target)
                    ):
                        cross_pillar_correlated = True
                        break

        if cross_pillar_correlated and "Cross-pillar correlation between Pillar 1 network syscalls and tool calls" not in persistence_indicators:
            persistence_indicators.append(
                "Cross-pillar correlation between Pillar 1 network syscalls and tool calls"
            )

        # Determine beaconing
        is_beaconing = False
        for endpoint in c2_endpoints or ["all"]:
            if await self.detect_beaconing(agent_key, endpoint, time_window):
                is_beaconing = True
                break

        # If no endpoints detected and no persistence/beaconing, no C2 evidence
        if not c2_endpoints and not is_beaconing and not persistence_indicators:
            return []

        # Determine communication pattern
        if is_beaconing:
            communication_pattern = "beaconing"
        elif "webhook_receiver" in c2_services:
            communication_pattern = "webhook"
        elif "cloud_storage" in c2_services:
            communication_pattern = "exfiltration"
        elif "pastebin" in c2_services or "github_gist" in c2_services or "requestbin" in c2_services:
            communication_pattern = "polling"
        else:
            communication_pattern = "interactive"

        evidence = C2Evidence(
            agent_id=agent_key,
            c2_endpoints=c2_endpoints,
            communication_pattern=communication_pattern,
            persistence_indicators=persistence_indicators,
        )

        return [evidence]
