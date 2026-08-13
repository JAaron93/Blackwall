"""Command-and-Control (C2) Infrastructure Detector for Blackwall Advanced Threat Detection (Pillar 6 Task 11)."""

from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from uuid import UUID

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    C2Evidence,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

# Known C2 Hostname Domain Patterns (Requirement 7.1)
KNOWN_C2_HOST_PATTERNS = [
    # RequestBin patterns
    (r"^(?:[a-zA-Z0-9_-]+\.)?requestbin\.(?:net|com)$", "requestbin"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?requestb\.in$", "requestbin"),
    # Pastebin & Gist patterns
    (r"^(?:[a-zA-Z0-9_-]+\.)?pastebin\.com$", "pastebin"),
    (r"^gist\.github\.com$", "github_gist"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?(?:hastebin\.com|justpaste\.it|rentry\.co|ghostbin\.com)$", "pastebin"),
    # Webhook receivers & tunnels
    (r"^webhook\.site$", "webhook_receiver"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?pipedream\.(?:net|com)$", "webhook_receiver"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?ngrok(?:-free)?\.(?:io|app)$", "webhook_receiver"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?(?:localtunnel\.me|serveo\.net|pagekite\.me)$", "webhook_receiver"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?(?:discord(?:app)?\.com|hooks\.slack\.com)$", "webhook_receiver"),
    # Cloud storage services
    (r"^(?:[a-zA-Z0-9_-]+\.)?s3\.amazonaws\.com$", "cloud_storage"),
    (r"^storage\.googleapis\.com$", "cloud_storage"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?blob\.core\.windows\.net$", "cloud_storage"),
    (r"^(?:[a-zA-Z0-9_-]+\.)?(?:dropbox\.com|mega\.nz|drive\.google\.com)$", "cloud_storage"),
]

PERSISTENCE_PATTERNS = [
    (r"cron|crontab|/etc/cron|/var/spool/cron", "Cron job persistence mechanism"),
    (r"systemd|systemctl|/etc/systemd/system", "Systemd service persistence mechanism"),
    (r"schtasks|taskschd|scheduled_task", "Scheduled task persistence mechanism"),
    (r"launchctl|LaunchDaemons|LaunchAgents", "MacOS launchd persistence mechanism"),
    (r"respawn|while\s+true|restart=always|supervisord|auto-restart", "Self-respawning process loop"),
]

NETWORK_ACTION_KEYWORDS = {
    "connect", "sys_connect", "sendto", "sys_sendto", "socket", "bind",
    "accept", "recvfrom", "network_access", "http_request", "tcp_connect",
    "udp_send", "dns_query", "net_outbound"
}


def _extract_hostname_and_path(url_or_domain: str) -> Tuple[str, str]:
    """Extract host/domain and path from input string safely."""
    raw = url_or_domain.strip().lower()
    if not raw:
        return "", ""

    url_str = raw
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        parsed = urlparse(url_str)
        host = parsed.hostname or raw.split("/")[0].split(":")[0]
        path = parsed.path or ""
        return host.strip().lower(), path.strip().lower()
    except Exception:
        clean = raw.split("/")[0].split(":")[0]
        return clean.strip().lower(), ""


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
        """Classify endpoint as a potential C2 service pattern based on parsed hostname.

        Args:
            domain_or_url: Target domain, IP, or URL string.

        Returns:
            Service pattern classification ('requestbin', 'pastebin', 'github_gist',
            'cloud_storage', 'webhook_receiver') or None if non-C2.
        """
        if not domain_or_url or not domain_or_url.strip():
            return None

        host, path = _extract_hostname_and_path(domain_or_url)
        if not host:
            return None

        for pattern, service_type in KNOWN_C2_HOST_PATTERNS:
            if re.search(pattern, host, re.IGNORECASE):
                return service_type

        return None

    async def detect_beaconing(
        self,
        agent_id: str,
        endpoint: str,
        time_window: Tuple[datetime, datetime],
    ) -> bool:
        """Detect periodic beaconing patterns indicative of C2 communication to a specific endpoint.

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

        target_host, _ = _extract_hostname_and_path(endpoint)
        matching_timestamps: List[datetime] = []

        for evt in agent_events:
            if not (start_win <= evt.timestamp <= end_win):
                continue

            evt_target_host, _ = _extract_hostname_and_path(evt.target)
            metadata_host = ""
            if isinstance(evt.metadata, dict):
                meta_domain = evt.metadata.get("domain") or evt.metadata.get("host") or evt.metadata.get("endpoint", "")
                if isinstance(meta_domain, str) and meta_domain:
                    metadata_host, _ = _extract_hostname_and_path(meta_domain)

            # Match against specific target host or exact endpoint string
            if target_host and (
                target_host == evt_target_host or target_host == metadata_host or endpoint.strip().lower() == evt.target.strip().lower()
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

        valid_deltas = [d for d in deltas if d > 0]
        if len(valid_deltas) < 2:
            return False

        mean_delta = sum(valid_deltas) / len(valid_deltas)
        if mean_delta <= 0:
            return False

        variance = sum((d - mean_delta) ** 2 for d in valid_deltas) / len(valid_deltas)
        std_dev = math.sqrt(variance)

        # Coefficient of variation (std_dev / mean_delta <= 0.25 indicates regular periodic beaconing)
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
            # Restrict kernel network events strictly to genuine network syscall actions
            if evt.source == EventSource.KERNEL_SYSCALL:
                act_lower = evt.action.lower()
                is_net = (
                    act_lower in NETWORK_ACTION_KEYWORDS
                    or any(k in act_lower for k in ("connect", "socket", "network", "http", "dns", "send", "recv"))
                )
                if is_net:
                    kernel_network_events.append(evt)
            elif evt.source in (EventSource.TOOL_CALL, EventSource.PIPELINE_EXECUTION):
                tool_call_events.append(evt)

            # Extract candidate endpoints/URLs from target or metadata
            candidate_urls = [evt.target]
            if isinstance(evt.metadata, dict):
                for k, v in evt.metadata.items():
                    if isinstance(v, str) and ("http" in v or "bin" in v or "paste" in v or "site" in v or "storage" in v):
                        candidate_urls.append(v)

            for candidate in candidate_urls:
                service = await self.classify_endpoint(candidate)
                if service:
                    if candidate not in c2_endpoints:
                        c2_endpoints.append(candidate)
                        c2_services.append(service)

        # Detect persistence indicators
        persistence_indicators = await self.detect_persistence_indicators(agent_key, time_window)

        # Cross-pillar correlation between network syscalls (Pillar 1) and tool calls (Pillar 4)
        cross_pillar_correlated = False
        if kernel_network_events and tool_call_events:
            for k_evt in kernel_network_events:
                k_host, _ = _extract_hostname_and_path(k_evt.target)
                k_meta_host = ""
                if isinstance(k_evt.metadata, dict):
                    k_meta = k_evt.metadata.get("domain") or k_evt.metadata.get("host") or ""
                    if isinstance(k_meta, str) and k_meta:
                        k_meta_host, _ = _extract_hostname_and_path(k_meta)

                for t_evt in tool_call_events:
                    t_host, _ = _extract_hostname_and_path(t_evt.target)
                    t_meta_host = ""
                    if isinstance(t_evt.metadata, dict):
                        t_meta = t_evt.metadata.get("domain") or t_evt.metadata.get("host") or ""
                        if isinstance(t_meta, str) and t_meta:
                            t_meta_host, _ = _extract_hostname_and_path(t_meta)

                    # Correlate if non-empty matching network endpoints/hosts or exact targets
                    if (
                        (k_host and (k_host == t_host or k_host == t_meta_host))
                        or (k_meta_host and (k_meta_host == t_host or k_meta_host == t_meta_host))
                        or (k_evt.target and k_evt.target == t_evt.target)
                    ):
                        cross_pillar_correlated = True
                        break
                if cross_pillar_correlated:
                    break

        if cross_pillar_correlated and "Cross-pillar correlation between Pillar 1 network syscalls and tool calls" not in persistence_indicators:
            persistence_indicators.append(
                "Cross-pillar correlation between Pillar 1 network syscalls and tool calls"
            )

        # Determine beaconing per detected endpoint
        is_beaconing = False
        for endpoint in c2_endpoints:
            if await self.detect_beaconing(agent_key, endpoint, time_window):
                is_beaconing = True
                break

        # If no endpoints detected and no persistence/beaconing, return empty list
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
