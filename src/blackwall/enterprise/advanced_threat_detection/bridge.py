"""Enterprise swarm context provider (Pillar 3 bridge).

Adapts ``AttackGraphStore`` to the Core ``SwarmContextProvider`` protocol so
Enterprise swarm lineage can be injected at runtime into ``SyncResolver``
without Core ever importing from ``blackwall.enterprise``.
"""

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from blackwall.models import SwarmContextSummary
from blackwall.validators import clamp_score

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.bridge")

_SWARM_METADATA_KEYS = ("swarm_id", "collective_name", "coordinating_agents")


class EnterpriseSwarmContextProvider:
    """Protocol adapter resolving swarm lineage from the attack graph store."""

    def __init__(
        self,
        store: Any,
        lookback_hours: float = 1.0,
        limit: int = 100,
        evidence_lookup: Optional[Callable[[str], Awaitable[list[Any]]]] = None,
    ) -> None:
        self._store = store
        self._lookback = timedelta(hours=lookback_hours)
        self._limit = limit
        self._evidence_lookup = evidence_lookup

    async def resolve_swarm_context(
        self, agent_id: Optional[str], fingerprint: str
    ) -> Optional[SwarmContextSummary]:
        """Maps recent swarm-tagged attack graph nodes to a summary.

        Falls back to detector-produced ``SwarmEvidence`` (via the optional
        ``evidence_lookup``) when stored nodes carry no swarm metadata, so
        detector findings remain reachable. Returns None when the agent has
        no swarm lineage or on any failure (fail-safe NFR-2: callers fall
        back to individual attribution).
        """
        del fingerprint
        try:
            if not agent_id:
                return None
            now = datetime.now(timezone.utc)
            nodes = await self._store.query_nodes(
                agent_id=agent_id,
                time_window=(now - self._lookback, now),
                limit=self._limit,
            )
        except Exception as exc:
            logger.warning(
                "Enterprise swarm context lookup failed; falling back to "
                "individual attribution: %s",
                exc,
            )
            return None

        try:
            summary = self._summarize_nodes(agent_id, nodes or [])
            if summary is not None:
                return summary
            return await self._summarize_evidence(agent_id)
        except Exception as exc:
            logger.warning(
                "Enterprise swarm context mapping failed; falling back to "
                "individual attribution: %s",
                exc,
            )
            return None

    async def _summarize_evidence(self, agent_id: str) -> Optional[SwarmContextSummary]:
        """Maps detector SwarmEvidence to a summary (None when unreachable)."""
        if self._evidence_lookup is None:
            return None
        evidence_list = await self._evidence_lookup(agent_id)
        candidates = [
            evidence
            for evidence in evidence_list or []
            if agent_id in set(getattr(evidence, "agent_ids", None) or [])
        ]
        if not candidates:
            return None
        newest = max(
            candidates,
            key=lambda ev: getattr(ev, "last_seen", None)
            or datetime.min.replace(tzinfo=timezone.utc),
        )

        swarm_id: Optional[UUID] = None
        raw_swarm_id = getattr(newest, "swarm_id", None)
        if raw_swarm_id is not None:
            try:
                swarm_id = UUID(str(raw_swarm_id))
            except (ValueError, TypeError, AttributeError):
                swarm_id = None

        coordinating_agents = sorted(
            str(agent) for agent in (getattr(newest, "agent_ids", None) or [])
        )
        covert_channels = list(getattr(newest, "covert_channels", None) or [])
        suspected_channels = [str(ch.channel_id) for ch in covert_channels]
        channel_type = None
        if covert_channels:
            raw_type = getattr(covert_channels[0], "channel_type", None)
            channel_type = getattr(raw_type, "value", raw_type)
            channel_type = str(channel_type) if channel_type is not None else None
        try:
            confidence = float(getattr(newest, "coordination_score", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = clamp_score(confidence)

        return SwarmContextSummary(
            swarm_id=swarm_id,
            is_collective=True,
            collective_name=getattr(newest, "collective_name", None),
            collective_confidence=confidence,
            coordinating_agents=coordinating_agents,
            suspected_covert_channels=suspected_channels,
            covert_channel_type=channel_type,
            deduction_rationale=(
                f"Enterprise swarm evidence: {len(coordinating_agents)} agents, "
                f"coordination_score={confidence:.2f}"
            ),
            first_detected=getattr(newest, "first_seen", None),
            last_detected=getattr(newest, "last_seen", None),
        )

    def _summarize_nodes(
        self, agent_id: str, nodes: list[Any]
    ) -> Optional[SwarmContextSummary]:
        candidates = [
            node
            for node in nodes
            if any(key in (node.event.metadata or {}) for key in _SWARM_METADATA_KEYS)
        ]
        if not candidates:
            return None

        candidates.sort(key=lambda node: node.event.timestamp)
        newest_metadata = candidates[-1].event.metadata or {}

        swarm_id: Optional[UUID] = None
        raw_swarm_id = newest_metadata.get("swarm_id")
        if raw_swarm_id is not None:
            try:
                swarm_id = UUID(str(raw_swarm_id))
            except (ValueError, TypeError, AttributeError):
                swarm_id = None

        coordinating_agents = list(newest_metadata.get("coordinating_agents") or [])
        if agent_id not in coordinating_agents:
            coordinating_agents.append(agent_id)

        suspected_channels = list(
            newest_metadata.get("suspected_covert_channels") or []
        )
        try:
            confidence = float(newest_metadata.get("collective_confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = clamp_score(confidence)

        return SwarmContextSummary(
            swarm_id=swarm_id,
            is_collective=True,
            collective_name=newest_metadata.get("collective_name"),
            collective_confidence=confidence,
            coordinating_agents=coordinating_agents,
            suspected_covert_channels=suspected_channels,
            covert_channel_type=newest_metadata.get("covert_channel_type"),
            deduction_rationale=newest_metadata.get("deduction_rationale"),
            first_detected=candidates[0].event.timestamp,
            last_detected=candidates[-1].event.timestamp,
        )
