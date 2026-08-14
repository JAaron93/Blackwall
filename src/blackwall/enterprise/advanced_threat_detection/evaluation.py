"""Evaluation Environment Support for Blackwall Advanced Threat Detection (Pillar 6 Task 18).

Provides isolated attack graph instances, event labeling, alert isolation,
state resets, and evidence-derived containment checks for evaluation environments.
(Requirements 14.1 - 14.5, 22.5 & Properties 69 - 72).
"""

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
from blackwall.validators import validate_non_empty_string

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.evaluation")


class EvaluationEnvironment:
    """Encapsulates an isolated evaluation environment instance with its own graph store and alert bus."""

    def __init__(
        self,
        env_id: str,
        dsn: str | None = None,
        in_memory: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.env_id = validate_non_empty_string(env_id, field_name="env_id")
        self.dsn = dsn
        self.in_memory = in_memory
        self.created_at = datetime.now(UTC)
        self.metadata: dict[str, Any] = dict(metadata) if metadata else {}
        self.store = AttackGraphStore(dsn=dsn, in_memory=in_memory)
        self.alert_bus = AlertBus()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the isolated graph store."""
        if not self._initialized:
            await self.store.initialize()
            self._initialized = True

    def label_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Stamp a NormalizedEvent with this evaluation environment's metadata."""
        meta = dict(event.metadata)
        meta["evaluation_env_id"] = self.env_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
        return event.model_copy(update={"metadata": meta})

    def label_raw_event(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Stamp a raw event dictionary with this evaluation environment's metadata."""
        stamped = dict(raw_event)
        meta = dict(stamped.get("metadata", {})) if isinstance(stamped.get("metadata"), dict) else {}
        meta["evaluation_env_id"] = self.env_id
        meta["is_evaluation"] = True
        meta["eval_mode"] = True
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
        await self.initialize()
        labeled = self.label_event(event)
        return await self.store.insert_event(labeled)

    async def insert_events_batch(
        self, events: list[NormalizedEvent]
    ) -> list[AttackNode]:
        """Label and batch-insert events into this environment's isolated attack graph."""
        await self.initialize()
        labeled_events = [self.label_event(e) for e in events]
        return await self.store.insert_events_batch(labeled_events)

    async def publish_alert(self, alert: Alert) -> bool:
        """Label and publish an alert to this environment's isolated alert bus."""
        labeled = self.label_alert(alert)
        return await self.alert_bus.publish(labeled)

    async def reset(self) -> None:
        """Reset the evaluation environment state to a clean initial baseline."""
        # Clear in-memory structures
        self.store._nodes.clear()
        self.store._agent_nodes_index.clear()
        self.store._path_cache.clear()
        self.store._edges.clear()

        # If PostgreSQL pool is configured, truncate tables
        if self.store._pool:
            try:
                async with self.store._pool.acquire() as conn:
                    await conn.execute("TRUNCATE TABLE causal_edges, event_nodes CASCADE;")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Error truncating DB tables during eval reset for %s: %s",
                    self.env_id,
                    exc,
                )

        # Clear alert bus history
        self.alert_bus.clear()
        logger.info("Evaluation environment %s successfully reset.", self.env_id)

    async def close(self) -> None:
        """Close graph store connection pool."""
        await self.store.close()

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

        if env_id:
            env = self.get_environment(env_id)
            if env:
                node = await env.store.get_node(clean_node_id)
                if node is not None:
                    return True
            return False

        for env in self._environments.values():
            node = await env.store.get_node(clean_node_id)
            if node is not None:
                return True

        return False

    async def reset_environment(self, env_id: str) -> None:
        """Reset a specific evaluation environment to clean initial state."""
        env = self.get_environment(env_id)
        if env:
            await env.reset()

    async def reset_all(self) -> None:
        """Reset all managed evaluation environments."""
        for env in self._environments.values():
            await env.reset()
        logger.info("Reset all %d evaluation environments.", len(self._environments))

    def list_environments(self) -> list[str]:
        """Return a list of all active evaluation environment IDs."""
        return list(self._environments.keys())

    async def delete_environment(self, env_id: str) -> None:
        """Remove and close an evaluation environment."""
        clean_id = str(env_id).strip() if env_id else ""
        if clean_id in self._environments:
            env = self._environments.pop(clean_id)
            await env.reset()
            await env.close()
            logger.info("Deleted evaluation environment %s", clean_id)

    async def close_all(self) -> None:
        """Close all managed evaluation environments."""
        for env in list(self._environments.values()):
            await env.close()
        self._environments.clear()
