"""Package Registry Monitor for Blackwall Advanced Threat Detection (Pillar 6 Task 13)."""

from datetime import datetime, timezone
import logging
import re
from typing import Any, AsyncIterable, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import uuid

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
    RegistryThreatEvidence,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.policy.models import PolicyConfig
from blackwall.validators import (
    ensure_uuid_v4,
    utc_now,
    validate_temporal_sequence,
    validate_utc_datetime,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.registry")

# Malformed Exploit Probing Regex Patterns (Requirement 9.2)
MALFORMED_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%2F|/etc/passwd|/etc/shadow|/win\.ini)", re.IGNORECASE),
        "Path traversal detected in package request",
    ),
    (
        re.compile(r"(?:__proto__|constructor\.prototype|Object\.prototype)", re.IGNORECASE),
        "Prototype pollution attempt detected in package payload or name",
    ),
    (
        re.compile(
            r"(?:;\s*(?:curl|wget|nc|sh|bash|cat|id|whoami|python|perl|eval|exec)|"
            r"\|\s*(?:curl|wget|nc|sh|bash|cat|id|whoami)|`[^`]+`|\$\([^)]+\))",
            re.IGNORECASE,
        ),
        "Command injection sequence detected in package query or semver",
    ),
    (
        re.compile(r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):", re.IGNORECASE),
        "Log4j/JNDI injection lookup pattern detected",
    ),
    (
        re.compile(r"(?:class\.module\.classLoader|classLoader|org\.springframework)", re.IGNORECASE),
        "Spring4Shell / ClassLoader manipulation probe detected",
    ),
    (
        re.compile(r"(?:'\s+or\s+'1'='1|union\s+select|select\s+.*\s+from)", re.IGNORECASE),
        "SQL injection attempt detected in package query",
    ),
    (
        re.compile(r"(?:%00|\\x00)", re.IGNORECASE),
        "Null byte injection detected in package request target",
    ),
]

# CVE Signature Mappings (Requirement 9.6)
CVE_SIGNATURES: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"\$\{jndi:", re.IGNORECASE),
        "CVE-2021-44228",  # Log4Shell
    ),
    (
        re.compile(r"(?:artifactory|jfrog|/etc/passwd|/etc/shadow|\.\./|\.\.%2f)", re.IGNORECASE),
        "CVE-2020-7980",  # JFrog Artifactory RCE / Path Traversal
    ),
    (
        re.compile(r"(?:__proto__|constructor\.prototype|Object\.prototype)", re.IGNORECASE),
        "CVE-2020-7774",  # npm prototype pollution
    ),
    (
        re.compile(r"(?:internal-|private-|@internal/|@corp/|dependency[-_]confusion)", re.IGNORECASE),
        "CVE-2021-38153",  # Dependency confusion / namespace shadowing
    ),
    (
        re.compile(r"(?:\.\.%2f|\.\.%2F|\.\./\.\./|/etc/passwd)", re.IGNORECASE),
        "CVE-2021-41773",  # Path traversal exploit
    ),
    (
        re.compile(r"(?:class\.module\.classLoader|classLoader|org\.springframework)", re.IGNORECASE),
        "CVE-2022-22965",  # Spring4Shell
    ),
]


def _infer_registry_type(url_or_target: str, metadata: Dict[str, Any]) -> str:
    """Infer package registry type (npm, PyPI, Artifactory, generic) from URL or metadata."""
    if metadata and "registry_type" in metadata and metadata["registry_type"]:
        return str(metadata["registry_type"])

    parsed = urlparse(url_or_target or "")
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    target_lower = (url_or_target or "").lower()

    if "artifactory" in hostname or "jfrog" in hostname or "artifactory" in path:
        return "Artifactory"
    elif hostname == "registry.npmjs.org" or hostname.endswith(".npmjs.org") or "npm" in hostname or "npm" in path:
        return "npm"
    elif hostname == "pypi.org" or hostname.endswith(".pypi.org") or hostname == "pypi.python.org" or "pypi" in hostname or "/simple/" in path or "python" in hostname:
        return "PyPI"
    elif hostname == "crates.io" or hostname.endswith(".crates.io") or "cargo" in hostname or "cargo" in path:
        return "Cargo"
    elif hostname == "rubygems.org" or hostname.endswith(".rubygems.org") or "rubygems" in hostname:
        return "RubyGems"
    elif "artifactory" in target_lower or "jfrog" in target_lower:
        return "Artifactory"
    elif "npm" in target_lower:
        return "npm"
    elif "pypi" in target_lower:
        return "PyPI"
    return "generic"



class PackageRegistryMonitor:
    """Monitors package registry proxy interactions for zero-day exploit probing and supply chain attacks."""

    def __init__(
        self,
        store: Optional[AttackGraphStore] = None,
        policy: Optional[PolicyConfig] = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self.policy = policy
        self._tracked_events: List[NormalizedEvent] = []

    async def monitor_registry_access(
        self,
        agent_id: str,
        registry_url: str,
        request_stream: Optional[AsyncIterable[Dict[str, Any]]] = None,
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream registry access events, normalizing heterogeneous requests into standard NormalizedEvent instances."""
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")

        clean_reg_url = registry_url.strip() if registry_url else "https://registry.npmjs.org"

        if request_stream is not None:
            async for req in request_stream:
                if not isinstance(req, dict):
                    continue

                try:
                    endpoint = str(req.get("endpoint") or req.get("path") or req.get("url") or "")
                    if endpoint.startswith("http://") or endpoint.startswith("https://"):
                        full_target = endpoint
                    else:
                        full_target = f"{clean_reg_url.rstrip('/')}/{endpoint.lstrip('/')}"

                    pkg_name = str(req.get("package_name") or req.get("package") or "")
                    if not pkg_name and "/" in endpoint:
                        pkg_name = endpoint.strip("/").split("/")[-1]

                    meta = dict(req)
                    inferred_type = _infer_registry_type(full_target, meta)
                    meta["registry_type"] = inferred_type
                    meta["package_name"] = pkg_name

                    action = str(req.get("action") or req.get("method") or "http_get").upper()
                    raw_ts = req.get("timestamp")
                    if isinstance(raw_ts, datetime):
                        try:
                            ts = validate_utc_datetime(raw_ts)
                        except Exception:
                            if raw_ts.tzinfo is None:
                                ts = raw_ts.replace(tzinfo=timezone.utc)
                            else:
                                ts = raw_ts.astimezone(timezone.utc)
                    elif isinstance(raw_ts, (int, float)):
                        ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
                    else:
                        ts = utc_now()

                    raw_score = req.get("risk_score", 0.4)
                    try:
                        score_val = float(raw_score)
                        risk_score = max(0.0, min(score_val, 1.0))
                    except (ValueError, TypeError):
                        risk_score = 0.4

                    event = NormalizedEvent(
                        event_id=ensure_uuid_v4(req.get("event_id")),
                        timestamp=ts,
                        source=EventSource.PIPELINE_EXECUTION,
                        agent_id=agent_id,
                        action=action,
                        target=full_target,
                        metadata=meta,
                        risk_score=risk_score,
                    )

                    self._tracked_events.append(event)
                    if self.store is not None:
                        await self.store.insert_event(event)

                    yield event
                except Exception as exc:
                    logger.warning("Skipping malformed registry record: %s (error: %s)", req, exc)
                    continue


    def correlate_cve(
        self,
        exploit_indicators: List[str],
        target_str: str = "",
        payload_str: str = "",
    ) -> List[str]:
        """Compare detected pattern and context against known CVE exploitation signatures."""
        cves: Set[str] = set()
        combined_text = f"{' '.join(exploit_indicators)} {target_str} {payload_str}"

        for pattern, cve_id in CVE_SIGNATURES:
            if pattern.search(combined_text):
                cves.add(cve_id)

        return sorted(cves)

    async def detect_exploit_probing(
        self,
        agent_id: Optional[str] = None,
        time_window: Optional[Tuple[datetime, datetime]] = None,
    ) -> List[RegistryThreatEvidence]:
        """Detect probing for package registry vulnerabilities, malformed requests, and unusual patterns."""
        start_w = None
        end_w = None
        if time_window is not None:
            start_raw, end_raw = time_window
            validate_temporal_sequence(
                start_raw, end_raw, start_name="start_time", end_name="end_time"
            )
            start_w = validate_utc_datetime(start_raw)
            end_w = validate_utc_datetime(end_raw)

        # Collect events from persistent store and tracked events
        candidate_events: List[NormalizedEvent] = []
        seen_event_ids: Set[uuid.UUID] = set()

        if self.store is not None:
            if hasattr(self.store, "query_nodes"):
                q_window = (start_w, end_w) if (start_w and end_w) else (
                    datetime(1970, 1, 1, tzinfo=timezone.utc),
                    datetime(2100, 1, 1, tzinfo=timezone.utc),
                )
                try:
                    store_nodes = await self.store.query_nodes(
                        agent_id=agent_id, time_window=q_window
                    )
                    for n in store_nodes:
                        if n.event.event_id not in seen_event_ids:
                            candidate_events.append(n.event)
                            seen_event_ids.add(n.event.event_id)
                except Exception as exc:
                    logger.debug("Failed querying store nodes: %s", exc)

            if hasattr(self.store, "_nodes"):
                for node in self.store._nodes.values():
                    if node.event.event_id not in seen_event_ids:
                        candidate_events.append(node.event)
                        seen_event_ids.add(node.event.event_id)

        for ev in self._tracked_events:
            if ev.event_id not in seen_event_ids:
                candidate_events.append(ev)
                seen_event_ids.add(ev.event_id)

        # Filter by agent_id and time_window
        filtered_events: List[NormalizedEvent] = []
        for ev in candidate_events:
            if agent_id and ev.agent_id != agent_id:
                continue
            if time_window is not None:
                if not (start_w <= ev.timestamp <= end_w):
                    continue
            filtered_events.append(ev)

        evidences: List[RegistryThreatEvidence] = []
        if not filtered_events:
            return evidences

        # 1. Per-event malformed request inspection
        events_by_pkg: Dict[Tuple[str, str], List[NormalizedEvent]] = {}
        status_404_by_agent_reg: Dict[Tuple[str, str], List[NormalizedEvent]] = {}

        for ev in filtered_events:
            target_str = str(ev.target or "")
            meta = ev.metadata if isinstance(ev.metadata, dict) else {}
            meta_str = str(meta)
            payload_str = str(meta.get("payload") or meta.get("query") or meta.get("body") or "")
            pkg_name = str(meta.get("package_name") or meta.get("package") or "")
            if not pkg_name:
                parsed = urlparse(target_str)
                path_parts = [p for p in parsed.path.split("/") if p]
                if path_parts:
                    pkg_name = path_parts[-1]
                else:
                    pkg_name = target_str

            reg_type = _infer_registry_type(target_str, meta)
            key = (reg_type, pkg_name)
            if key not in events_by_pkg:
                events_by_pkg[key] = []
            events_by_pkg[key].append(ev)

            status_code = meta.get("status_code")
            if status_code == 404 or "404" in ev.action:
                grp_key = (ev.agent_id, reg_type)
                if grp_key not in status_404_by_agent_reg:
                    status_404_by_agent_reg[grp_key] = []
                status_404_by_agent_reg[grp_key].append(ev)

            # Check malformed patterns
            combined_search_space = f"{target_str} {payload_str} {meta_str} {ev.action}"
            matched_indicators: List[str] = []

            for pattern, indicator_desc in MALFORMED_PATTERNS:
                if pattern.search(combined_search_space):
                    matched_indicators.append(f"{indicator_desc}: {pkg_name}")

            # Check internal scope on package registry
            if any(p in pkg_name.lower() or p in target_str.lower() for p in ("internal-", "private-", "@internal/", "@corp/")):
                matched_indicators.append(f"Internal scope probing on package registry: {pkg_name}")

            if matched_indicators:
                cve_candidates = self.correlate_cve(
                    matched_indicators, target_str=target_str, payload_str=payload_str
                )
                evidences.append(
                    RegistryThreatEvidence(
                        registry_type=reg_type,
                        package_name=pkg_name,
                        exploit_indicators=matched_indicators,
                        cve_candidates=cve_candidates,
                    )
                )

        # 2. Check for scoped unusual 404 scanning patterns (grouped by agent and registry type)
        for (grp_agent, grp_reg), ev_list in status_404_by_agent_reg.items():
            if len(ev_list) < 5:
                continue

            sorted_404s = sorted(ev_list, key=lambda e: e.timestamp)
            scanning_bursts: List[List[NormalizedEvent]] = []
            current_burst: List[NormalizedEvent] = []

            for ev in sorted_404s:
                if not current_burst:
                    current_burst.append(ev)
                else:
                    if (ev.timestamp - current_burst[0].timestamp).total_seconds() <= 300:
                        current_burst.append(ev)
                    else:
                        if len(current_burst) >= 5:
                            scanning_bursts.append(list(current_burst))
                        current_burst = [ev]
            if len(current_burst) >= 5:
                scanning_bursts.append(list(current_burst))

            for burst in scanning_bursts:
                distinct_pkgs = {
                    str(e.metadata.get("package_name") or e.target) for e in burst
                }
                scanning_indicator = [
                    f"Unusual scanning activity by agent '{grp_agent}': {len(burst)} consecutive 404 responses on {grp_reg} registry across {len(distinct_pkgs)} packages"
                ]
                cves = self.correlate_cve(scanning_indicator, target_str=burst[0].target)
                evidences.append(
                    RegistryThreatEvidence(
                        registry_type=grp_reg,
                        package_name=f"scanning-batch-{len(distinct_pkgs)}-pkgs",
                        exploit_indicators=scanning_indicator,
                        cve_candidates=cves,
                    )
                )

        return evidences

