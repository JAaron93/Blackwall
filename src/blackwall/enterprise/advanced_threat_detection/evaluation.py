"""Evaluation Environment Support for Blackwall Advanced Threat Detection (Pillar 6 Task 18).

Provides isolated attack graph instances, event labeling, alert isolation,
state resets, and evidence-derived containment checks for evaluation environments.
(Requirements 14.1 - 14.5, 22.5 & Properties 69 - 72).
"""

import asyncio
import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    AttackNode,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.validators import (
    validate_non_empty_string,
    validate_uuid_v4_format,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.evaluation")


class EvaluationAttackGraphStore(AttackGraphStore):
    """AttackGraphStore bound to an EvaluationEnvironment that enforces evaluation labeling, scoped IDs, and lifecycle closure guards."""

    def __init__(
        self,
        env: "EvaluationEnvironment",
        dsn: str | None = None,
        in_memory: bool = True,
    ) -> None:
        super().__init__(dsn=dsn, in_memory=in_memory)
        self._env = env
        self._store_closed = False

    def _check_store_open(self) -> None:
        if self._store_closed or self._env._closed:
            raise RuntimeError(
                f"EvaluationEnvironment '{self._env.env_id}' graph store is closed and cannot accept writes."
            )

    async def _initialize_locked(self) -> None:
        """Initialize database connection pool while self._env._lock is held."""
        self._check_store_open()
        if not self._initialized:
            await super().initialize()

    async def initialize(self) -> None:
        """Initialize database connection pool under environment lock and lifecycle guard."""
        async with self._env._lock:
            await self._initialize_locked()

    async def _insert_event_locked(self, event: NormalizedEvent) -> AttackNode:
        self._check_store_open()
        labeled = self._env.label_event(event)
        return await super().insert_event(labeled)

    async def insert_event(self, event: NormalizedEvent) -> AttackNode:
        async with self._env._lock:
            await self._initialize_locked()
            return await self._insert_event_locked(event)

    async def _insert_events_batch_locked(
        self, events: list[NormalizedEvent]
    ) -> list[AttackNode]:
        self._check_store_open()
        labeled_events = [self._env.label_event(e) for e in events]
        return await super().insert_events_batch(labeled_events)

    async def insert_events_batch(
        self, events: list[NormalizedEvent]
    ) -> list[AttackNode]:
        async with self._env._lock:
            await self._initialize_locked()
            return await self._insert_events_batch_locked(events)

    async def _get_node_locked(self, node_id: uuid.UUID | str) -> AttackNode | None:
        clean_uuid = validate_uuid_v4_format(node_id)
        # Fast path: check in-memory cache for clean_uuid (if already scoped node_id)
        if clean_uuid in self._nodes:
            node = self._nodes[clean_uuid]
            if node.event.metadata.get("evaluation_env_id") == self._env.env_id:
                return node
        # Check in-memory cache for derived scoped ID (if raw event_id passed)
        derived = self._env.derive_evaluation_event_id(clean_uuid)
        if derived in self._nodes:
            node = self._nodes[derived]
            if node.event.metadata.get("evaluation_env_id") == self._env.env_id:
                return node

        # Database fallback if PostgreSQL pool is active
        if self._pool:
            node = await super().get_node(derived)
            if (
                node is not None
                and node.event.metadata.get("evaluation_env_id") == self._env.env_id
            ):
                return node
            node = await super().get_node(clean_uuid)
            if (
                node is not None
                and node.event.metadata.get("evaluation_env_id") == self._env.env_id
            ):
                return node

        return None

    async def get_node(self, node_id: uuid.UUID | str) -> AttackNode | None:
        async with self._env._lock:
            self._check_store_open()
            return await self._get_node_locked(node_id)

    async def _resolve_eval_node_id_locked(self, node_ref: uuid.UUID | str) -> uuid.UUID:
        clean_uuid = validate_uuid_v4_format(node_ref)
        # Check environment-derived scoped UUID first
        derived = self._env.derive_evaluation_event_id(clean_uuid)
        node = await super().get_node(derived)
        if node is not None and node.event.metadata.get("evaluation_env_id") == self._env.env_id:
            return derived
        # Check raw UUID with evaluation provenance validation
        node = await super().get_node(clean_uuid)
        if node is not None and node.event.metadata.get("evaluation_env_id") == self._env.env_id:
            return clean_uuid
        return derived

    async def _link_events_locked(
        self,
        from_node: uuid.UUID | str,
        to_node: uuid.UUID | str,
        relationship: str = "caused",
    ) -> None:
        self._check_store_open()
        from_uuid = await self._resolve_eval_node_id_locked(from_node)
        to_uuid = await self._resolve_eval_node_id_locked(to_node)

        await super().link_events(
            from_node=from_uuid, to_node=to_uuid, relationship=relationship
        )

    async def link_events(
        self,
        from_node: uuid.UUID | str,
        to_node: uuid.UUID | str,
        relationship: str = "caused",
    ) -> None:
        async with self._env._lock:
            await self._link_events_locked(
                from_node=from_node, to_node=to_node, relationship=relationship
            )

    async def query_nodes(
        self,
        agent_id: str | None = None,
        time_range: tuple[datetime, datetime] | None = None,
        risk_threshold: float = 0.0,
        limit: int = 100,
    ) -> list[AttackNode]:
        async with self._env._lock:
            self._check_store_open()
            nodes = await super().query_nodes(
                agent_id=agent_id,
                time_range=time_range,
                risk_threshold=risk_threshold,
                limit=limit,
            )
            return [
                n
                for n in nodes
                if n.event.metadata.get("evaluation_env_id") == self._env.env_id
            ]

    async def get_all_nodes(self) -> list[AttackNode]:
        async with self._env._lock:
            self._check_store_open()
            nodes = await super().get_all_nodes()
            return [
                n
                for n in nodes
                if n.event.metadata.get("evaluation_env_id") == self._env.env_id
            ]

    async def purge_events_before(self, cutoff_time: datetime) -> int:
        """Purge only this evaluation environment's events older than cutoff_time."""
        async with self._env._lock:
            self._check_store_open()
            purged_count = 0
            edge_ids_to_remove: list[str] = []
            purged_ids: list[str] = []

            to_delete_candidates = {
                str(nid)
                for nid, node in self._nodes.items()
                if node.event.timestamp < cutoff_time
                and node.event.metadata.get("evaluation_env_id") == self._env.env_id
            }

            if self._pool:
                async with self._pool.acquire() as conn, conn.transaction():
                    purged_rows = await conn.fetch(
                        """
                        SELECT node_id FROM event_nodes 
                        WHERE timestamp < $1 AND metadata->>'evaluation_env_id' = $2;
                        """,
                        cutoff_time,
                        self._env.env_id,
                    )
                    purged_ids = [str(r["node_id"]) for r in purged_rows]
                    all_purge_ids = list(set(purged_ids) | to_delete_candidates)
                    if all_purge_ids:
                        edge_rows = await conn.fetch(
                            "SELECT edge_id FROM causal_edges WHERE from_node = ANY($1::text[]) OR to_node = ANY($1::text[]);",
                            all_purge_ids,
                        )
                        edge_ids_to_remove = [str(r["edge_id"]) for r in edge_rows]

                        if edge_ids_to_remove:
                            await conn.execute(
                                "DELETE FROM causal_edges WHERE edge_id = ANY($1::text[]);",
                                edge_ids_to_remove,
                            )

                        result = await conn.execute(
                            """
                            DELETE FROM event_nodes 
                            WHERE timestamp < $1 AND metadata->>'evaluation_env_id' = $2;
                            """,
                            cutoff_time,
                            self._env.env_id,
                        )
                        try:
                            purged_count = int(result.split()[-1])
                        except (ValueError, IndexError):
                            purged_count = len(purged_ids)

                        if edge_ids_to_remove:
                            await conn.execute(
                                """
                                UPDATE event_nodes
                                SET incoming_edges = (
                                    SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                                    FROM jsonb_array_elements_text(incoming_edges) AS elem
                                    WHERE elem != ALL($1)
                                ),
                                outgoing_edges = (
                                    SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                                    FROM jsonb_array_elements_text(outgoing_edges) AS elem
                                    WHERE elem != ALL($1)
                                )
                                WHERE incoming_edges ?| $1::text[] OR outgoing_edges ?| $1::text[];
                                """,
                                edge_ids_to_remove,
                            )

            purged_id_set = set(purged_ids) | to_delete_candidates
            to_delete = [
                nid
                for nid in list(self._nodes.keys())
                if (
                    str(nid) in purged_id_set
                    or (
                        self._nodes[nid].event.timestamp < cutoff_time
                        and self._nodes[nid].event.metadata.get("evaluation_env_id")
                        == self._env.env_id
                    )
                )
            ]
            to_delete_set = {str(nid) for nid in to_delete} | purged_id_set

            removed_edge_ids: set[str] = {
                str(e.get("edge_id", ""))
                for e in self._edges
                if str(e.get("from_node", "")) in to_delete_set
                or str(e.get("to_node", "")) in to_delete_set
            }
            removed_edge_ids.update(str(x) for x in edge_ids_to_remove)

            for nid in to_delete:
                node = self._nodes.pop(nid, None)
                if node:
                    agent_nids = self._agent_nodes_index.get(node.event.agent_id, [])
                    if nid in agent_nids:
                        agent_nids.remove(nid)

            self._path_cache.clear()
            self._edges = [
                e
                for e in self._edges
                if str(e.get("edge_id", "")) not in removed_edge_ids
            ]

            if removed_edge_ids:
                for node in self._nodes.values():
                    node.incoming_edges = [
                        eid
                        for eid in node.incoming_edges
                        if str(eid) not in removed_edge_ids
                    ]
                    node.outgoing_edges = [
                        eid
                        for eid in node.outgoing_edges
                        if str(eid) not in removed_edge_ids
                    ]

            if not self._pool:
                purged_count = len(to_delete)

            return purged_count

    async def reset(self) -> None:
        """Reset the evaluation environment state."""
        await self._env.reset()

    async def _close_locked(self) -> None:
        self._store_closed = True
        await super().close()

    async def close(self) -> None:
        async with self._env._lock:
            await self._close_locked()


class EvaluationEnvironment:
    """Encapsulates an isolated evaluation environment instance with its own graph store and alert bus."""

    def __init__(
        self,
        env_id: str,
        dsn: str | None = None,
        in_memory: bool = True,
        metadata: dict[str, Any] | None = None,
        manager: Optional["EvaluationEnvironmentManager"] = None,
    ) -> None:
        self.env_id = validate_non_empty_string(env_id, field_name="env_id")
        self.dsn = dsn
        self.in_memory = in_memory
        self.manager = manager
        self.created_at = datetime.now(UTC)
        self.metadata: dict[str, Any] = dict(metadata) if metadata else {}
        self._known_evidence_ids: set[uuid.UUID] = set()
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialized = False
        self.store = EvaluationAttackGraphStore(env=self, dsn=dsn, in_memory=in_memory)
        self.alert_bus = AlertBus()

    def derive_evaluation_event_id(self, event_id: uuid.UUID | str) -> uuid.UUID:
        """Deterministically derive an environment-isolated UUIDv4 to prevent collisions in shared databases."""
        clean_uuid = validate_uuid_v4_format(event_id)
        digest = hashlib.sha256(
            f"blackwall://eval/{self.env_id}/{clean_uuid}".encode()
        ).digest()
        derived = uuid.UUID(bytes=digest[:16], version=4)
        self._known_evidence_ids.add(clean_uuid)
        self._known_evidence_ids.add(derived)
        if self.manager is not None:
            self.manager._known_evaluation_evidence_ids.add(clean_uuid)
            self.manager._known_evaluation_evidence_ids.add(derived)
        return derived

    def _check_not_closed(self) -> None:
        """Raise RuntimeError if this evaluation environment has been closed."""
        if self._closed:
            raise RuntimeError(
                f"EvaluationEnvironment '{self.env_id}' is closed and cannot accept operations."
            )

    async def _initialize_locked(self) -> None:
        """Internal initialization while self._lock is held."""
        self._check_not_closed()
        await self.store._initialize_locked()
        self._initialized = self.store._initialized

    async def initialize(self) -> None:
        """Initialize the isolated graph store."""
        async with self._lock:
            await self._initialize_locked()

    def label_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Stamp a NormalizedEvent with this evaluation environment's metadata and isolated identifier."""
        meta = dict(event.metadata)
        meta["evaluation_env_id"] = self.env_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        meta["original_event_id"] = str(event.event_id)
        eval_id = self.derive_evaluation_event_id(event.event_id)
        return event.model_copy(update={"event_id": eval_id, "metadata": meta})

    def label_raw_event(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Stamp a raw event dictionary with this evaluation environment's metadata and isolated identifier."""
        stamped = dict(raw_event)
        meta = dict(stamped.get("metadata", {})) if isinstance(stamped.get("metadata"), dict) else {}
        meta["evaluation_env_id"] = self.env_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        if stamped.get("event_id"):
            meta["original_event_id"] = str(stamped["event_id"])
            stamped["event_id"] = str(self.derive_evaluation_event_id(stamped["event_id"]))
        stamped["metadata"] = meta
        return stamped

    def label_alert(self, alert: Alert) -> Alert:
        """Stamp an Alert with this evaluation environment's metadata."""
        meta = dict(alert.metadata)
        meta["evaluation_env_id"] = self.env_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        return alert.model_copy(update={"metadata": meta})

    async def insert_event(self, event: NormalizedEvent) -> AttackNode:
        """Label and insert an event into this environment's isolated attack graph."""
        async with self._lock:
            self._check_not_closed()
            await self.store._initialize_locked()
            return await self.store._insert_event_locked(event)

    async def insert_events_batch(
        self, events: list[NormalizedEvent]
    ) -> list[AttackNode]:
        """Label and batch-insert events into this environment's isolated attack graph."""
        async with self._lock:
            self._check_not_closed()
            await self.store._initialize_locked()
            return await self.store._insert_events_batch_locked(events)

    async def get_node(self, node_id: uuid.UUID | str) -> AttackNode | None:
        """Retrieve a node from this environment's graph, ensuring it belongs to this evaluation environment."""
        async with self._lock:
            self._check_not_closed()
            return await self.store._get_node_locked(node_id)

    async def publish_alert(self, alert: Alert) -> bool:
        """Label and publish an alert to this environment's isolated alert bus."""
        async with self._lock:
            self._check_not_closed()
            labeled = self.label_alert(alert)
            return await self.alert_bus.publish(labeled)

    async def reset(self) -> None:
        """Reset the evaluation environment state to a clean initial baseline."""
        async with self._lock:
            self._check_not_closed()

            # If PostgreSQL pool is configured, delete scoped DB records first
            if self.store._pool:
                try:
                    async with self.store._pool.acquire() as conn, conn.transaction():
                        rows = await conn.fetch(
                            "SELECT node_id FROM event_nodes WHERE metadata->>'evaluation_env_id' = $1;",
                            self.env_id,
                        )
                        if rows:
                            node_ids = [r["node_id"] for r in rows]
                            edge_rows = await conn.fetch(
                                "SELECT edge_id FROM causal_edges WHERE from_node = ANY($1::text[]) OR to_node = ANY($1::text[]);",
                                node_ids,
                            )
                            edge_ids = [er["edge_id"] for er in edge_rows] if edge_rows else []

                            await conn.execute(
                                "DELETE FROM causal_edges WHERE from_node = ANY($1::text[]) OR to_node = ANY($1::text[]);",
                                node_ids,
                            )

                            if edge_ids:
                                await conn.execute(
                                    """
                                    UPDATE event_nodes
                                    SET incoming_edges = incoming_edges - $1::text[],
                                        outgoing_edges = outgoing_edges - $1::text[]
                                    WHERE NOT (node_id = ANY($2::text[]));
                                    """,
                                    edge_ids,
                                    node_ids,
                                )

                            await conn.execute(
                                "DELETE FROM event_nodes WHERE metadata->>'evaluation_env_id' = $1;",
                                self.env_id,
                            )
                except Exception as exc:
                    logger.exception(
                        "Error deleting scoped DB records during eval reset for %s",
                        self.env_id,
                    )
                    raise RuntimeError(
                        f"Failed to reset evaluation environment '{self.env_id}'."
                    ) from exc

            # Clear in-memory structures and alert bus once DB deletion succeeds
            self.store._nodes.clear()
            self.store._agent_nodes_index.clear()
            self.store._path_cache.clear()
            self.store._edges.clear()
            self.alert_bus.clear()
            logger.info("Evaluation environment %s successfully reset.", self.env_id)

    async def close(self) -> None:
        """Close graph store connection pool and transition to closed state."""
        async with self._lock:
            if not self._closed:
                self._closed = True
                self._initialized = False
                await self.store._close_locked()

    def is_production_action_suppressed(self) -> bool:
        """All mitigations from evaluation environments must be suppressed from production."""
        return True


class EvaluationEnvironmentManager:
    """Manager for multi-tenant isolated evaluation environments and containment policies."""

    def __init__(
        self,
        default_dsn: str | None = None,
        in_memory: bool = True,
    ) -> None:
        self.default_dsn = default_dsn
        self.in_memory = in_memory
        self._environments: dict[str, EvaluationEnvironment] = {}
        self._known_evaluation_evidence_ids: set[uuid.UUID] = set()
        self._lock = asyncio.Lock()

    def get_or_create_environment(
        self,
        env_id: str,
        dsn: str | None = None,
        in_memory: bool | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationEnvironment:
        """Get an existing evaluation environment or create a new isolated instance."""
        clean_id = validate_non_empty_string(env_id, field_name="env_id")
        if clean_id not in self._environments:
            env_dsn = dsn if dsn is not None else self.default_dsn
            env_in_memory = in_memory if in_memory is not None else self.in_memory
            self._environments[clean_id] = EvaluationEnvironment(
                env_id=clean_id,
                dsn=env_dsn,
                in_memory=env_in_memory,
                metadata=metadata,
                manager=self,
            )
            logger.info("Created isolated evaluation environment %s", clean_id)
        return self._environments[clean_id]

    def get_environment(self, env_id: str) -> EvaluationEnvironment | None:
        """Retrieve an evaluation environment if it exists."""
        if not env_id or not isinstance(env_id, str):
            return None
        return self._environments.get(env_id.strip())

    def get_graph_store(
        self,
        env_id: str,
        dsn: str | None = None,
        in_memory: bool | None = None,
    ) -> AttackGraphStore:
        """Get the isolated AttackGraphStore for the specified evaluation environment."""
        env = self.get_or_create_environment(env_id=env_id, dsn=dsn, in_memory=in_memory)
        return env.store

    def label_event(self, event: NormalizedEvent, env_id: str) -> NormalizedEvent:
        """Label an event with the given evaluation environment ID."""
        clean_id = validate_non_empty_string(env_id, field_name="env_id")
        meta = dict(event.metadata)
        meta["evaluation_env_id"] = clean_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        self._known_evaluation_evidence_ids.add(event.event_id)
        return event.model_copy(update={"metadata": meta})

    def label_raw_event(self, raw_event: dict[str, Any], env_id: str) -> dict[str, Any]:
        """Label a raw event dictionary with the given evaluation environment ID."""
        clean_id = validate_non_empty_string(env_id, field_name="env_id")
        stamped = dict(raw_event)
        meta = dict(stamped.get("metadata", {})) if isinstance(stamped.get("metadata"), dict) else {}
        meta["evaluation_env_id"] = clean_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        stamped["metadata"] = meta
        return stamped

    def label_alert(self, alert: Alert, env_id: str) -> Alert:
        """Label an alert with the given evaluation environment ID."""
        clean_id = validate_non_empty_string(env_id, field_name="env_id")
        meta = dict(alert.metadata)
        meta["evaluation_env_id"] = clean_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        if alert.evidence_id:
            self._known_evaluation_evidence_ids.add(alert.evidence_id)
        return alert.model_copy(update={"metadata": meta})

    def is_evaluation_event(self, event: NormalizedEvent | dict[str, Any]) -> bool:
        """Check if an event carries evaluation environment labeling."""
        if isinstance(event, NormalizedEvent):
            meta = event.metadata
        elif isinstance(event, dict):
            meta = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
        else:
            return False

        return bool(
            meta.get("is_evaluation") is True
            or meta.get("eval_mode") is True
            or (isinstance(meta.get("evaluation_env_id"), str) and meta["evaluation_env_id"].strip())
        )

    def is_evaluation_alert(self, alert: Alert | dict[str, Any]) -> bool:
        """Check if an alert was generated from evaluation mode."""
        if isinstance(alert, Alert):
            meta = alert.metadata
        elif isinstance(alert, dict):
            meta = alert.get("metadata", {}) if isinstance(alert.get("metadata"), dict) else {}
        else:
            return False

        return bool(
            meta.get("is_evaluation") is True
            or meta.get("eval_mode") is True
            or (isinstance(meta.get("evaluation_env_id"), str) and meta["evaluation_env_id"].strip())
        )

    def should_suppress_production_reaction(self, alert_or_evidence: Any) -> bool:
        """Determine if an alert or evidence should suppress production mitigation actions.

        Satisfies Requirements 14.2 & 14.5: prevents evaluation events/alerts from
        triggering production eBPF socket drops, Threat Mesh broadcasts, or Vault revocations.
        """
        if alert_or_evidence is None:
            return False

        if isinstance(alert_or_evidence, Alert):
            return self.is_evaluation_alert(alert_or_evidence)
        elif isinstance(alert_or_evidence, NormalizedEvent):
            return self.is_evaluation_event(alert_or_evidence)
        elif isinstance(alert_or_evidence, dict):
            return self.is_evaluation_alert(alert_or_evidence) or self.is_evaluation_event(alert_or_evidence)

        # For object instances with metadata
        if hasattr(alert_or_evidence, "metadata") and isinstance(alert_or_evidence.metadata, dict):
            return bool(
                alert_or_evidence.metadata.get("is_evaluation") is True
                or alert_or_evidence.metadata.get("eval_mode") is True
                or (
                    isinstance(alert_or_evidence.metadata.get("evaluation_env_id"), str)
                    and alert_or_evidence.metadata["evaluation_env_id"].strip()
                )
            )

        return False

    async def is_evaluation_mode(
        self, evidence_id: uuid.UUID | str, env_id: str | None = None
    ) -> bool:
        """Mandatory Evidence-Derived Evaluation Containment Gate (Architecture Rule 20).

        Queries the underlying threat evidence graph to verify if an evidence ID belongs
        to an evaluation environment graph instance.
        """
        if not evidence_id:
            return False

        clean_node_id: uuid.UUID
        if isinstance(evidence_id, str):
            try:
                clean_node_id = uuid.UUID(evidence_id)
            except ValueError:
                return False
        elif isinstance(evidence_id, uuid.UUID):
            clean_node_id = evidence_id
        else:
            return False

        if clean_node_id in self._known_evaluation_evidence_ids:
            return True

        if env_id:
            env = self.get_environment(env_id)
            if env:
                if clean_node_id in getattr(env, "_known_evidence_ids", set()):
                    return True
                try:
                    node = await env.get_node(clean_node_id)
                    if (
                        node is not None
                        and self.is_evaluation_event(node.event)
                        and node.event.metadata.get("evaluation_env_id") == env.env_id
                    ):
                        return True
                except (OSError, RuntimeError) as exc:
                    logger.debug("Error checking evaluation mode for env %s: %s", env_id, exc)
                    return True
            return True

        for env in list(self._environments.values()):
            if clean_node_id in getattr(env, "_known_evidence_ids", set()):
                return True
            try:
                node = await env.get_node(clean_node_id)
                if node is not None and self.is_evaluation_event(node.event):
                    return True
            except (OSError, RuntimeError) as exc:
                logger.debug("Error checking evaluation mode in env %s: %s", env.env_id, exc)
                return True

        return False

    async def reset_environment(self, env_id: str) -> None:
        """Reset a specific evaluation environment to clean initial state."""
        async with self._lock:
            env = self.get_environment(env_id)
            if env:
                await env.reset()

    async def reset_all(self) -> None:
        """Reset all managed evaluation environments."""
        async with self._lock:
            for env in list(self._environments.values()):
                await env.reset()
            logger.info("Reset all %d evaluation environments.", len(self._environments))

    def list_environments(self) -> list[str]:
        """Return a list of all active evaluation environment IDs."""
        return list(self._environments.keys())

    async def delete_environment(self, env_id: str) -> None:
        """Remove and close an evaluation environment, preserving historical provenance IDs."""
        async with self._lock:
            clean_id = str(env_id).strip() if env_id else ""
            if clean_id in self._environments:
                env = self._environments.get(clean_id)
                if env is not None:
                    self._known_evaluation_evidence_ids.update(getattr(env, "_known_evidence_ids", set()))
                try:
                    if env is not None:
                        await env.reset()
                finally:
                    try:
                        if env is not None:
                            await env.close()
                    finally:
                        self._environments.pop(clean_id, None)
                logger.info("Deleted evaluation environment %s", clean_id)

    async def close_all(self) -> None:
        """Close all managed evaluation environments, preserving historical provenance IDs."""
        async with self._lock:
            for env in list(self._environments.values()):
                self._known_evaluation_evidence_ids.update(getattr(env, "_known_evidence_ids", set()))
                await env.close()
            self._environments.clear()
