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
from blackwall.validators import normalize_time_window, validate_utc_datetime

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
    "connect", "sys_connect", "sendto", "sys_sendto", "socket_connect",
    "network_access", "http_request", "tcp_connect", "udp_send", "dns_query", "net_outbound"
}

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "localhost.localdomain"}

DESTINATION_KEYS = {
    "url", "uri", "endpoint", "domain", "host", "target",
    "c2_url", "remote_url", "destination", "dest_url", "server"
}


def _is_local_host(host_str: str) -> bool:
    """Check if host string is a local hostname, IPv4 loopback (127.0.0.0/8), IPv6 loopback (::1), or IPv4-mapped IPv6 loopback (::ffff:127.0.0.0/8)."""
    clean_host = host_str.strip().lower().lstrip("[").rstrip("]")
    if not clean_host:
        return False
    if (
        clean_host in LOCAL_HOSTS
        or clean_host.startswith("127.")
        or clean_host == "::1"
        or clean_host.startswith("::ffff:127.")
        or clean_host.startswith("::ffff:7f")
    ):
        return True
    return False


def _extract_hostname_and_path(url_or_domain: str) -> Tuple[str, str]:
    """Extract host/domain and path from input string safely, robust to IPv6 addresses."""
    raw = url_or_domain.strip().lower()
    if not raw:
        return "", ""

    if raw == "::1" or raw.startswith("::1/"):
        parts = raw.split("/", 1)
        path = "/" + parts[1] if len(parts) > 1 else ""
        return "::1", path

    url_str = raw
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        scheme, rest = url_str.split("://", 1)
        host_port_path = rest.split("/", 1)
        host_port = host_port_path[0]
        path_part = "/" + host_port_path[1] if len(host_port_path) > 1 else ""

        # Enclose unbracketed IPv6 addresses
        if ":" in host_port and not host_port.startswith("["):
            if host_port.count(":") >= 2:
                host_port = f"[{host_port}]"

        url_str = f"{scheme}://{host_port}{path_part}"
        parsed = urlparse(url_str)
        host = parsed.hostname or host_port.lstrip("[").rstrip("]")
        path = parsed.path or ""
        return host.strip().lower(), path.strip().lower()
    except Exception:
        clean = raw.split("/")[0]
        return clean.strip().lower(), ""


def _normalize_endpoint(url_or_domain: str) -> str:
    """Normalize full endpoint string preserving scheme and netloc case-insensitively while preserving path and query case."""
    raw = url_or_domain.strip()
    if not raw:
        return ""

    url_str = raw
    if not url_str.lower().startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        parsed = urlparse(url_str)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or raw.split("/")[0]).lower()
        path = parsed.path.rstrip("/")
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return raw


def _is_local_endpoint(target_or_host: str) -> bool:
    """Check if target or host represents a local socket, loopback address, or Unix domain path."""
    raw = target_or_host.strip().lower()
    if not raw:
        return False
    if raw.startswith("/") or raw.startswith("unix:") or raw.startswith("file:"):
        return True

    # Direct match for loopback/local targets
    if _is_local_host(raw):
        return True

    # Strip scheme if present
    clean = raw
    if clean.startswith(("http://", "https://")):
        clean = clean.split("://", 1)[1]

    # Strip path/query
    clean = clean.split("/")[0].split("?")[0]

    if _is_local_host(clean):
        return True

    # Handle port stripping (e.g. 127.0.0.2:8080, [::1]:8080, ::1:8080, [::ffff:127.0.0.1]:8080)
    if ":" in clean:
        if clean.startswith("[") and "]" in clean:
            host_part = clean.split("]")[0].lstrip("[")
            if _is_local_host(host_part):
                return True
        # Try stripping port from the right (for IPv4, hostnames, or unbracketed IPv6 with port like ::1:8080)
        host_part = clean.rsplit(":", 1)[0].lstrip("[").rstrip("]")
        if _is_local_host(host_part):
            return True

    host, _ = _extract_hostname_and_path(raw)
    if _is_local_host(host):
        return True

    return False


def _extract_metadata_endpoints(metadata: Any) -> List[str]:
    """Extract candidate normalized target endpoint strings from explicit network destination metadata keys."""
    if not isinstance(metadata, dict):
        return []
    endpoints: List[str] = []
    for key in DESTINATION_KEYS:
        val = metadata.get(key)
        if isinstance(val, str) and val.strip():
            norm = _normalize_endpoint(val)
            if norm and norm not in endpoints and not _is_local_endpoint(val):
                endpoints.append(norm)

    return endpoints


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

        if _is_local_endpoint(domain_or_url):
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
        beaconing_threshold: float = 0.25,
    ) -> bool:
        """Detect periodic beaconing patterns indicative of C2 communication to a specific distinct endpoint.

        Args:
            agent_id: Agent identifier string.
            endpoint: Target endpoint or domain to evaluate.
            time_window: Tuple of (start_time, end_time) UTC datetimes.
            beaconing_threshold: Coefficient of variation threshold for periodic regularity.

        Returns:
            True if periodic beaconing pattern is detected, False otherwise.
        """
        start_win, end_win = normalize_time_window(time_window)

        if _is_local_endpoint(endpoint):
            return False

        agent_events = self._events_by_agent.get(str(agent_id), [])

        target_norm = _normalize_endpoint(endpoint)
        target_host, _ = _extract_hostname_and_path(endpoint)
        matching_timestamps: List[datetime] = []

        for evt in agent_events:
            if not (start_win <= evt.timestamp <= end_win):
                continue

            if _is_local_endpoint(evt.target):
                continue

            evt_target_norm = _normalize_endpoint(evt.target)
            evt_target_host, _ = _extract_hostname_and_path(evt.target)
            meta_norms = _extract_metadata_endpoints(evt.metadata)

            # Match exact normalized endpoint (including scheme, port/query) or exact host if domain-level query
            if (
                (target_norm and (target_norm == evt_target_norm or target_norm in meta_norms))
                or (target_host and target_host == evt_target_host and target_norm == evt_target_norm)
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

        # Coefficient of variation (CV) <= beaconing_threshold indicates periodic beaconing
        cv = std_dev / mean_delta
        return cv <= beaconing_threshold

    async def detect_persistence_indicators(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
    ) -> List[str]:
        """Detect persistence mechanisms associated with C2 callbacks.

        Args:
            agent_id: Agent identifier string.
            time_window: Tuple of (start_time, end_time) UTC datetimes.

        Returns:
            List of detected persistence mechanism description strings.
        """
        start_win, end_win = normalize_time_window(time_window)

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
        beaconing_threshold: float = 0.25,
    ) -> List[C2Evidence]:
        """Detect C2 infrastructure setup and communication patterns for an agent.

        Args:
            agent_id: Agent identifier string.
            time_window: Tuple of (start_time, end_time) UTC datetimes.
            beaconing_threshold: Regularity threshold for beaconing detection.

        Returns:
            List of C2Evidence objects detected for the agent.
        """
        start_win, end_win = normalize_time_window(time_window)

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
            # Restrict kernel network events strictly to genuine outbound network syscall actions (and non-local endpoints)
            if evt.source == EventSource.KERNEL_SYSCALL:
                act_lower = evt.action.lower()
                is_net = (
                    act_lower in NETWORK_ACTION_KEYWORDS
                    and not _is_local_endpoint(evt.target)
                    and not (isinstance(evt.metadata, dict) and (evt.metadata.get("is_local") is True or evt.metadata.get("family") == "AF_UNIX"))
                )
                if is_net:
                    kernel_network_events.append(evt)
            elif evt.source in (EventSource.TOOL_CALL, EventSource.PIPELINE_EXECUTION):
                if not _is_local_endpoint(evt.target):
                    tool_call_events.append(evt)

            # Extract candidate endpoints/URLs from target or metadata
            candidate_urls = [evt.target]
            if isinstance(evt.metadata, dict):
                for k in DESTINATION_KEYS:
                    val = evt.metadata.get(k)
                    if isinstance(val, str) and val.strip():
                        candidate_urls.append(val)

            for candidate in candidate_urls:
                service = await self.classify_endpoint(candidate)
                if service:
                    if candidate not in c2_endpoints:
                        c2_endpoints.append(candidate)
                        c2_services.append(service)

        # Detect persistence indicators
        persistence_indicators = await self.detect_persistence_indicators(agent_key, time_window)

        # Cross-pillar correlation between network syscalls (Pillar 1) and tool calls (Pillar 4) in O(N+M) time
        cross_pillar_correlated = False
        if kernel_network_events and tool_call_events:
            tool_targets: Set[str] = set()
            for t_evt in tool_call_events:
                tool_targets.update(
                    filter(None, [_normalize_endpoint(t_evt.target)] + _extract_metadata_endpoints(t_evt.metadata))
                )

            for k_evt in kernel_network_events:
                k_targets = set(
                    filter(None, [_normalize_endpoint(k_evt.target)] + _extract_metadata_endpoints(k_evt.metadata))
                )
                if k_targets & tool_targets:
                    cross_pillar_correlated = True
                    break

        if cross_pillar_correlated and "Cross-pillar correlation between Pillar 1 network syscalls and tool calls" not in persistence_indicators:
            persistence_indicators.append(
                "Cross-pillar correlation between Pillar 1 network syscalls and tool calls"
            )

        # Determine beaconing per detected endpoint
        is_beaconing = False
        for endpoint in c2_endpoints:
            if await self.detect_beaconing(agent_key, endpoint, time_window, beaconing_threshold=beaconing_threshold):
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
