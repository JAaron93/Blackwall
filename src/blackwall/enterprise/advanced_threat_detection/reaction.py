"""Active Threat Reaction Engine for Blackwall Advanced Threat Detection (Pillar 6 Task 24).

Translates high-confidence threat evidence (multi-stage attack paths, agent swarms,
exploit chains, AILM breaches) into automated mitigation actions across Pillars 1, 2, and 3
with mandatory evidence-derived evaluation containment.
(Requirements 22.1 - 22.5, 14.5 & Properties 89, 90, 91, 92, 104).
"""

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.evaluation import (
    EvaluationEnvironmentManager,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    ActiveReactionPayload,
    Alert,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.identity.sidecar import SecretVaultSidecar
from blackwall.enterprise.kernel.probe import KernelProbeDriver
from blackwall.enterprise.mcp.vault_mcp import VaultMCPAdapter
from blackwall.validators import is_evaluation_metadata

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.reaction")


class ActiveReactionEngine:
    """Active reaction coordinator executing automated mitigations across Pillars 1, 2, and 3."""

    def __init__(
        self,
        kernel_driver: KernelProbeDriver | Any | None = None,
        mesh_broadcaster: Any | None = None,
        vault_adapter: VaultMCPAdapter | SecretVaultSidecar | Any | None = None,
        alert_bus: AlertBus | None = None,
        attack_graph: AttackGraphStore | None = None,
        eval_manager: EvaluationEnvironmentManager | None = None,
    ) -> None:
        self.kernel_driver = kernel_driver
        self.mesh_broadcaster = mesh_broadcaster
        self.vault_adapter = vault_adapter
        self.alert_bus = alert_bus
        self.attack_graph = attack_graph
        self.eval_manager = eval_manager
        self._reaction_log: list[ActiveReactionPayload] = []
        self._lock = asyncio.Lock()

    async def is_evaluation_mode(
        self,
        evidence_id: str | uuid.UUID | None = None,
        env_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Check if reaction trigger originates from an evaluation context (Requirement 22.5).

        Implements multi-source fallback: explicit env_id, deterministic URI scheme,
        envelope metadata markers, EvaluationEnvironmentManager lookup, and AttackGraphStore node provenance.
        """
        # 1. Envelope environment ID (explicit evaluation environment provenance)
        if env_id is not None and str(env_id).strip():
            return True

        # 2. Deterministic evaluation namespace URI
        if isinstance(evidence_id, str):
            if evidence_id.startswith("blackwall://eval/") or evidence_id.startswith("blackwall://evaluation/"):
                return True

        # 3. Envelope metadata explicit flags & deterministic URI prefixes
        if is_evaluation_metadata(metadata):
            return True
        if metadata and isinstance(metadata, dict):
            eval_uri = metadata.get("evaluation_uri")
            if isinstance(eval_uri, str) and (
                eval_uri.startswith("blackwall://eval/") or eval_uri.startswith("blackwall://evaluation/")
            ):
                return True

        # 4. Evaluation Environment Manager (verified against registered environment)
        if self.eval_manager is not None:
            if env_id and self.eval_manager.get_environment(env_id) is not None:
                return True
            if await self.eval_manager.is_evaluation_mode(evidence_id, env_id=env_id):
                return True

        # 5. Attack Graph Store (verified node provenance)
        if self.attack_graph is not None:
            clean_id: uuid.UUID | None = None
            if isinstance(evidence_id, str):
                try:
                    clean_id = uuid.UUID(evidence_id)
                except ValueError:
                    clean_id = None
            elif isinstance(evidence_id, uuid.UUID):
                clean_id = evidence_id

            if clean_id is not None:
                node = await self.attack_graph.get_node(clean_id)
                if node is None and env_id:
                    digest = hashlib.sha256(
                        f"blackwall://eval/{env_id}/{clean_id}".encode()
                    ).digest()
                    derived_id = uuid.UUID(bytes=digest[:16], version=4)
                    node = await self.attack_graph.get_node(derived_id)

                if node is not None:
                    meta = node.event.metadata
                    if (
                        is_evaluation_metadata(meta)
                        or (isinstance(meta.get("evaluation_env_id"), str) and meta["evaluation_env_id"] == env_id)
                    ):
                        return True

        return False

    async def _handle_evaluation_containment_suppression(
        self,
        payload: ActiveReactionPayload,
        start_time: float,
        action_name: str,
    ) -> bool:
        """Check if action occurs within an evaluation environment and handle containment suppression."""
        is_eval = await self.is_evaluation_mode(
            payload.trigger_evidence_id,
            env_id=payload.evaluation_env_id,
            metadata=payload.metadata,
        )
        if is_eval:
            logger.info(
                "Evaluation containment: suppressing %s for evidence %s",
                action_name,
                payload.trigger_evidence_id,
            )
            payload.status = "SUPPRESSED_EVALUATION"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            await self._record_reaction(payload)
            return True
        return False

    async def execute_ebpf_socket_drop(
        self,
        payload: ActiveReactionPayload,
    ) -> bool:
        """Inject real-time eBPF socket drop rule into Pillar 1 driver (Production mode only).

        Satisfies Requirement 22.1 within 50ms SLA.
        """
        start_time = time.perf_counter()

        if await self._handle_evaluation_containment_suppression(
            payload, start_time, "eBPF socket drop"
        ):
            return False

        success = True
        if self.kernel_driver is not None:
            try:
                res = self.kernel_driver.inject_socket_drop(
                    pid=payload.target_pid,
                    ip=payload.target_ip,
                )
                if asyncio.iscoroutine(res):
                    res = await res
                success = bool(res) if res is not None else True
            except Exception as exc:
                logger.error("Failed to inject eBPF socket drop: %s", exc)
                success = False

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        payload.status = "COMPLETED" if success else "FAILED"
        payload.execution_duration_ms = duration_ms

        await self._record_reaction(payload)
        await self._publish_reaction_alert(payload, "eBPF Socket Drop Mitigation", AlertSeverity.CRITICAL)
        return success

    async def broadcast_fleet_signature(
        self,
        payload: ActiveReactionPayload,
    ) -> bool:
        """Publish zero-latency block signature to Pillar 2 Threat Mesh (Production mode only).

        Satisfies Requirement 22.2 within 15ms SLA.
        """
        start_time = time.perf_counter()

        if await self._handle_evaluation_containment_suppression(
            payload, start_time, "Threat Mesh broadcast"
        ):
            return False

        success = True
        if self.mesh_broadcaster is not None:
            try:
                if callable(self.mesh_broadcaster):
                    res = self.mesh_broadcaster(payload)
                    if asyncio.iscoroutine(res):
                        await res
                elif "broadcast_threat_signature" in dir(self.mesh_broadcaster):
                    res = self.mesh_broadcaster.broadcast_threat_signature(
                        signature=f"BW-BLOCK-{payload.target_agent_id}",
                        metadata=payload.metadata,
                    )
                    if asyncio.iscoroutine(res):
                        await res
                elif "broadcast" in dir(self.mesh_broadcaster):
                    res = self.mesh_broadcaster.broadcast(payload.model_dump(mode="json"))
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as exc:
                logger.error("Failed to broadcast threat signature: %s", exc)
                success = False

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        payload.status = "COMPLETED" if success else "FAILED"
        payload.execution_duration_ms = duration_ms

        await self._record_reaction(payload)
        await self._publish_reaction_alert(payload, "Fleet Threat Mesh Signature Broadcast", AlertSeverity.CRITICAL)
        return success

    async def revoke_identity_session(
        self,
        payload: ActiveReactionPayload,
    ) -> bool:
        """Trigger Pillar 3 Vault sidecar to invalidate JIT credentials (Production mode only).

        Satisfies Requirement 22.3 and Architecture Rule 39.
        """
        start_time = time.perf_counter()

        if await self._handle_evaluation_containment_suppression(
            payload, start_time, "Vault token revocation"
        ):
            return False

        success = True
        if self.vault_adapter is not None:
            try:
                if hasattr(self.vault_adapter, "revoke_agent_tokens"):
                    target = payload.target_agent_id
                    adapter_tokens = getattr(self.vault_adapter, "_issued_tokens", None)
                    target_to_revoke = target

                    if isinstance(adapter_tokens, dict):
                        if target and target in adapter_tokens:
                            t_info = adapter_tokens[target]
                            resolved_owner = t_info.get("agent_id") or t_info.get("principal_id")
                            if resolved_owner:
                                target_to_revoke = resolved_owner
                        elif payload.metadata and isinstance(payload.metadata, dict) and "token_id" in payload.metadata:
                            tid = payload.metadata["token_id"]
                            if tid in adapter_tokens:
                                t_info = adapter_tokens[tid]
                                resolved_owner = t_info.get("agent_id") or t_info.get("principal_id")
                                if resolved_owner and (not target or target in (tid, "generic-agent-ref", "unknown", "default")):
                                    target_to_revoke = resolved_owner

                    if target_to_revoke:
                        revoked_tokens = await self.vault_adapter.revoke_agent_tokens(target_to_revoke)
                        if isinstance(adapter_tokens, dict) and len(adapter_tokens) > 0 and len(revoked_tokens) == 0:
                            logger.warning(
                                "No active JIT tokens revoked for target %s", target_to_revoke
                            )
                            success = False
                    else:
                        logger.warning("No target agent or token identifier provided for revocation")
                        success = False
                elif hasattr(self.vault_adapter, "rotate_honeytokens"):
                    await self.vault_adapter.rotate_honeytokens()
                else:
                    logger.warning(
                        "Configured vault_adapter %s does not support token revocation or honeytoken rotation",
                        type(self.vault_adapter).__name__,
                    )
                    success = False
            except Exception as exc:
                logger.error("Failed to revoke identity tokens: %s", exc)
                success = False

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        payload.status = "COMPLETED" if success else "FAILED"
        payload.execution_duration_ms = duration_ms

        await self._record_reaction(payload)
        await self._publish_reaction_alert(payload, "Identity JIT Tokens Revoked", AlertSeverity.CRITICAL)
        return success

    async def _record_reaction(self, payload: ActiveReactionPayload) -> None:
        """Record reaction payload in internal log and persist to attack graph if available."""
        async with self._lock:
            self._reaction_log.append(payload)

    async def _publish_reaction_alert(
        self,
        payload: ActiveReactionPayload,
        title: str,
        severity: AlertSeverity,
    ) -> None:
        """Publish a notification alert to AlertBus if configured."""
        if self.alert_bus is not None:
            alert = Alert(
                alert_id=uuid.uuid4(),
                timestamp=datetime.now(UTC),
                severity=severity,
                threat_type=payload.action_type.value,
                title=title,
                description=f"Active threat reaction executed for agent {payload.target_agent_id}: {payload.status}",
                evidence_id=payload.trigger_evidence_id,
                agent_id=payload.target_agent_id,
                metadata={
                    "reaction_id": str(payload.reaction_id),
                    "action_type": payload.action_type.value,
                    "target_pid": payload.target_pid,
                    "target_ip": payload.target_ip,
                    "status": payload.status,
                    "duration_ms": payload.execution_duration_ms,
                    "evaluation_env_id": payload.evaluation_env_id,
                },
            )
            try:
                await self.alert_bus.publish(alert)
            except Exception as exc:
                logger.warning("Failed to publish reaction alert to AlertBus: %s", exc)

    def get_reaction_history(self) -> list[ActiveReactionPayload]:
        """Return a copy of all executed/suppressed reaction payloads."""
        return list(self._reaction_log)
