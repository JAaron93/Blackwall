"""
src/blackwall/enterprise/advanced_threat_detection/covert_channel.py — Covert Channel & Latent Coordination Detector (Pillar 2).

Detects unlocated covert message boards, steganographic package registries, and filesystem dead-drops
leveraging the Latent Coordination Divergence Principle and multi-agent artifact heuristics.

Design Constraints (per design.md §3.2 & requirements.md FR-3, FR-4, NFR-2, NFR-4):
  - Latent Coordination Divergence: P(CovertChannel) = 1.0 - Prod_k(1.0 - Signal_k)
  - Cardinality Enforcement: N >= 2 coordinating agents strictly enforced (Rule 59)
  - UTC Timestamps: Zero-offset UTC datetimes on detection boundaries (Rule 19, Rule 59)
  - Fast-Path SLA: sub-5ms evaluation latency (NFR-4)
  - Fail-safe: catches all exceptions, logs warnings, returns empty results (NFR-2)
"""

from __future__ import annotations

import base64
import logging
import re
import uuid
from collections import defaultdict

from blackwall.enterprise.advanced_threat_detection.enums import CovertChannelType
from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.validators import (
    clamp_score,
    validate_utc_datetime,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.covert_channel")

# Regex pattern for external IP addresses (IPv4)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Base64 regex detecting potential encoded payloads (min length 8, valid base64 chars + padding)
BASE64_PATH_REGEX = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")

# Package registry keywords for steganography detection
REGISTRY_KEYWORDS = ("artifactory", "/api/storage", "npm-local", "pypi-local", "pkg-cache")

# Shared dead-drop staging directory prefixes
DEAD_DROP_DIR_PREFIXES = ("/tmp", "/dev/shm", ".cache")


def _is_base64_string(s: str) -> bool:
    """Return True if string is valid decodable base64 text of non-trivial length."""
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(s, validate=True)
        return len(decoded) >= 4 and any(b >= 32 for b in decoded)
    except Exception:  # noqa: BLE001
        return False


def _has_external_c2_endpoints(shared_patterns: list[str]) -> bool:
    """Return True if shared_patterns contains external IP or domain indicators."""
    for pattern in shared_patterns:
        p_lower = pattern.lower()
        if p_lower.startswith(("ip:", "domain:", "endpoint:")):
            # Exclude explicit loopback patterns
            if "127.0.0.1" in p_lower or "localhost" in p_lower or "::1" in p_lower:
                continue
            return True
        if IP_REGEX.search(pattern) or DOMAIN_REGEX.search(pattern):
            if "127.0.0.1" in p_lower or "localhost" in p_lower:
                continue
            return True
    return False


class CovertChannelDetector:
    """
    Infers covert coordination channels and latent message boards among agent groups.

    Implements:
      1. Latent Coordination Divergence (UNLOCATED_MESSAGE_BOARD) when high correlation
         exists without visible C2 endpoints.
      2. Steganographic Registry Monitor (STEGANOGRAPHIC_REGISTRY) for Artifactory/npm/PyPI abuse.
      3. Filesystem Dead-Drop Detector (FILESYSTEM_DEAD_DROP) for /tmp and /dev/shm staging.
    """

    def __init__(
        self,
        min_agents: int = 2,
        min_correlation_threshold: float = 0.80,
        min_coordination_threshold: float = 0.80,
    ) -> None:
        self.min_agents = max(2, min_agents)
        self.min_correlation_threshold = min_correlation_threshold
        self.min_coordination_threshold = min_coordination_threshold

    def detect_for_swarm(
        self,
        swarm: SwarmEvidence,
        events_by_agent: dict[str, list[NormalizedEvent]] | None = None,
    ) -> list[CovertChannelEvidence]:
        """
        Evaluate a detected SwarmEvidence for unlocated message boards and covert channels.

        Args:
            swarm: The SwarmEvidence identified by AgentSwarmDetector.
            events_by_agent: Optional mapping of agent IDs to their raw normalized events.

        Returns:
            List of CovertChannelEvidence records (or empty list if no covert channel deduced).
        """
        try:
            return self._detect_for_swarm_safe(swarm, events_by_agent)
        except Exception as exc:
            logger.warning(
                "CovertChannelDetector: error during swarm covert channel evaluation",
                exc_info=exc,
            )
            return []

    def _detect_for_swarm_safe(
        self,
        swarm: SwarmEvidence,
        events_by_agent: dict[str, list[NormalizedEvent]] | None = None,
    ) -> list[CovertChannelEvidence]:
        evidences: list[CovertChannelEvidence] = []

        # 1. Cardinality check (N >= 2)
        if len(swarm.agent_ids) < self.min_agents:
            return evidences

        # 2. Latent Coordination Divergence Principle (FR-3):
        # High temporal correlation >= 0.80 and high coordination score >= 0.80
        # with zero external C2 endpoints in shared patterns
        has_high_correlation = (
            swarm.temporal_correlation >= self.min_correlation_threshold
            and swarm.coordination_score >= self.min_coordination_threshold
        )

        has_c2 = _has_external_c2_endpoints(swarm.shared_patterns)

        if has_high_correlation and not has_c2:
            # Formula: P(CovertChannel) = 1.0 - (1.0 - temporal_corr) * (1.0 - coord_score)
            raw_prob = 1.0 - (
                (1.0 - swarm.temporal_correlation) * (1.0 - swarm.coordination_score)
            )
            confidence = clamp_score(raw_prob, 0.0, 1.0)

            first_dt = validate_utc_datetime(swarm.first_seen)
            last_dt = validate_utc_datetime(swarm.last_seen)
            last_dt = max(last_dt, first_dt)

            rationale = (
                f"Latent coordination divergence: high temporal correlation "
                f"({swarm.temporal_correlation:.2f}) and behavioral coordination "
                f"({swarm.coordination_score:.2f}) across {len(swarm.agent_ids)} agents "
                f"without visible external C2 endpoints; inferred unlocated message board."
            )

            unlocated_evidence = CovertChannelEvidence(
                channel_id=uuid.uuid4(),
                channel_type=CovertChannelType.UNLOCATED_MESSAGE_BOARD,
                confidence_score=confidence,
                coordinating_agents=set(swarm.agent_ids),
                observed_artifacts=[],
                deduction_rationale=rationale,
                first_detected=first_dt,
                last_detected=last_dt,
            )
            evidences.append(unlocated_evidence)

        # 3. If events are supplied, also check storage channels
        if events_by_agent:
            flat_events = [e for events in events_by_agent.values() for e in events]
            storage_evidences = self.detect_storage_channels(flat_events)
            evidences.extend(storage_evidences)

        return evidences

    def detect_storage_channels(
        self,
        events: list[NormalizedEvent],
    ) -> list[CovertChannelEvidence]:
        """
        Scan normalized events for steganographic registry or filesystem dead-drop patterns.

        Args:
            events: List of NormalizedEvent instances from intercepted tool calls.

        Returns:
            List of detected CovertChannelEvidence objects.
        """
        try:
            return self._detect_storage_channels_safe(events)
        except Exception as exc:
            logger.warning(
                "CovertChannelDetector: error during storage channel detection",
                exc_info=exc,
            )
            return []

    def _detect_storage_channels_safe(
        self,
        events: list[NormalizedEvent],
    ) -> list[CovertChannelEvidence]:
        evidences: list[CovertChannelEvidence] = []
        if not events:
            return evidences

        # ------------------------------------------------------------------
        # Heuristic 1: Steganographic Package/Artifact Registry Activity
        # ------------------------------------------------------------------
        registry_events_by_base: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for event in events:
            target_lower = (event.target or "").lower()
            # Match package registry endpoints
            if any(kw in target_lower for kw in REGISTRY_KEYWORDS):
                # Check for base64 encoded path segments
                segments = event.target.replace("\\", "/").split("/")
                has_b64 = any(_is_base64_string(seg) for seg in segments)
                if has_b64:
                    # Group by base registry endpoint or root path
                    base_key = "/".join(segments[:5]) if len(segments) >= 5 else event.target
                    registry_events_by_base[base_key].append(event)

        for base_key, reg_events in registry_events_by_base.items():
            coordinating = {e.agent_id for e in reg_events}
            if len(coordinating) >= self.min_agents:
                first_dt = min(e.timestamp for e in reg_events)
                last_dt = max(e.timestamp for e in reg_events)
                artifacts = sorted({e.target for e in reg_events})

                rationale = (
                    f"Steganographic package registry activity detected across "
                    f"{len(coordinating)} agents issuing base64-encoded metadata queries "
                    f"against registry base {base_key}."
                )

                evidences.append(
                    CovertChannelEvidence(
                        channel_id=uuid.uuid4(),
                        channel_type=CovertChannelType.STEGANOGRAPHIC_REGISTRY,
                        confidence_score=0.88,
                        coordinating_agents=coordinating,
                        observed_artifacts=artifacts,
                        deduction_rationale=rationale,
                        first_detected=validate_utc_datetime(first_dt),
                        last_detected=validate_utc_datetime(last_dt),
                    )
                )

        # ------------------------------------------------------------------
        # Heuristic 2: Local Filesystem Dead-Drops (/tmp, /dev/shm, .cache)
        # ------------------------------------------------------------------
        dead_drop_events_by_path: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for event in events:
            target = event.target or ""
            target_norm = target.replace("\\", "/")
            if any(target_norm.startswith(prefix) or f"/{prefix.lstrip('/')}" in target_norm for prefix in DEAD_DROP_DIR_PREFIXES):
                dead_drop_events_by_path[target].append(event)

        for path, path_events in dead_drop_events_by_path.items():
            coordinating = {e.agent_id for e in path_events}
            if len(coordinating) >= self.min_agents:
                # Check for complementary actions (e.g. write and read) or distinct coordinating agents
                actions = {e.action.lower() for e in path_events}
                has_multi_action = any("write" in a or "create" in a or "exec" in a for a in actions) and any(
                    "read" in a or "list" in a or "open" in a for a in actions
                )
                # Either multi-action or multiple distinct agents touching identical staging target
                score = 0.90 if has_multi_action else 0.80

                first_dt = min(e.timestamp for e in path_events)
                last_dt = max(e.timestamp for e in path_events)
                artifacts = sorted({e.target for e in path_events})

                rationale = (
                    f"Local filesystem dead-drop sequence detected across {len(coordinating)} "
                    f"agents accessing staging path {path}."
                )

                evidences.append(
                    CovertChannelEvidence(
                        channel_id=uuid.uuid4(),
                        channel_type=CovertChannelType.FILESYSTEM_DEAD_DROP,
                        confidence_score=score,
                        coordinating_agents=coordinating,
                        observed_artifacts=artifacts,
                        deduction_rationale=rationale,
                        first_detected=validate_utc_datetime(first_dt),
                        last_detected=validate_utc_datetime(last_dt),
                    )
                )

        return evidences
