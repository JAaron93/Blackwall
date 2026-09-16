"""Swarm context provider protocol (Blackwall Core, Pillar 3 bridge).

Defines the abstract asynchronous ``SwarmContextProvider`` protocol and the
Core ``SQLiteSwarmContextProvider`` backed by ``SQLiteThreatRepository``.

Strict tier isolation (NFR-3): this module relies solely on the Python
standard library and ``pydantic`` (transitively via ``blackwall.models``).
Zero C-extensions, zero ``asyncpg``, and zero imports from
``blackwall.enterprise`` are permitted here.
"""

import logging
from typing import Any, Optional, Protocol, runtime_checkable

from blackwall.models import SwarmContextSummary

logger = logging.getLogger("blackwall.attribution.provider")


@runtime_checkable
class SwarmContextProvider(Protocol):
    """Asynchronous protocol resolving active swarm lineage for an agent."""

    async def resolve_swarm_context(
        self, agent_id: Optional[str], fingerprint: str
    ) -> Optional[SwarmContextSummary]:
        """Returns the active swarm summary, or None when no lineage exists."""
        ...


class SQLiteSwarmContextProvider:
    """Core provider querying local swarm lineage from SQLite.

    Backed by ``SQLiteThreatRepository.find_swarm_by_agent_or_fingerprint()``.
    Any lookup failure degrades gracefully to ``None`` (fail-safe NFR-2) so
    callers fall back to standard individual attribution.
    """

    def __init__(self, repository: Any) -> None:
        self._repository = repository

    async def resolve_swarm_context(
        self, agent_id: Optional[str], fingerprint: str
    ) -> Optional[SwarmContextSummary]:
        try:
            return await self._repository.find_swarm_by_agent_or_fingerprint(
                agent_id, fingerprint
            )
        except Exception as exc:
            logger.warning(
                "Swarm context lookup failed; falling back to individual "
                "attribution: %s",
                exc,
            )
            return None
