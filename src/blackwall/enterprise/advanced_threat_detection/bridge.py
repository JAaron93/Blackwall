"""Enterprise swarm context provider (Pillar 3 bridge).

Adapts ``AttackGraphStore`` to the Core ``SwarmContextProvider`` protocol so
Enterprise swarm lineage can be injected at runtime into ``SyncResolver``
without Core ever importing from ``blackwall.enterprise``.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from blackwall.models import SwarmContextSummary

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.bridge")

_SWARM_METADATA_KEYS = ("swarm_id", "collective_name", "coordinating_agents")


class EnterpriseSwarmContextProvider:
    """Protocol adapter resolving swarm lineage from the attack graph store."""

    def __init__(
        self, store: Any, lookback_hours: float = 1.0, limit: int = 100
    ) -> None:
        self._store = store
        self._lookback = timedelta(hours=lookback_hours)
        self._limit = limit

    async def resolve_swarm_context(
        self, agent_id: Optional[str], fingerprint: str
    ) -> Optional[SwarmContextSummary]:
        """Maps recent swarm-tagged attack graph nodes to a summary.

        Returns None when the agent has no swarm lineage or on any failure
        (fail-safe NFR-2: callers fall back to individual attribution).
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
            return self._summarize_nodes(agent_id, nodes or [])
        except Exception as exc:
            logger.warning(
                "Enterprise swarm context mapping failed; falling back to "
                "individual attribution: %s",
                exc,
            )
            return None

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
        confidence = max(0.0, min(1.0, confidence))

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
