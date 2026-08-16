"""Active Threat Reaction Engine for Blackwall Advanced Threat Detection (Pillar 6 Task 24).

Translates high-confidence threat evidence into automated mitigation actions across:
- Pillar 1: Kernel eBPF socket and process drop injection (<50ms)
- Pillar 2: Threat Mesh zero-latency signature broadcast (<15ms)
- Pillar 3: Ephemeral Identity Sidecar / Vault JIT token revocation and honey-token rotation
with strict evidence-derived evaluation containment guards (Requirements 22.1 - 22.5, 14.5, 15.10;
Properties 89 - 92, 104).
"""

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.evaluation import (
    EvaluationEnvironmentManager,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    ActiveReactionPayload,
    Alert,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.validators import validate_uuid_v4_format

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.reaction")


class ActiveReactionEngine:
    """Automated Active Threat Reaction Engine coordinating mitigations across Pillars 1, 2, and 3."""

    def __init__(
        self,
        kernel_driver: Any | None = None,
        mesh_broadcaster: Any | None = None,
        vault_adapter: Any | None = None,
        eval_manager: EvaluationEnvironmentManager | None = None,
        graph_store: AttackGraphStore | None = None,
        alert_bus: AlertBus | None = None,
    ) -> None:
        self.kernel_driver = kernel_driver
        self.mesh_broadcaster = mesh_broadcaster
        self.vault_adapter = vault_adapter
        self.eval_manager = eval_manager
        self.graph_store = graph_store
        self.alert_bus = alert_bus

        self._reaction_history: list[ActiveReactionPayload] = []
        self._ebpf_drop_rules: list[dict[str, Any]] = []
        self._broadcasted_signatures: list[dict[str, Any]] = []
        self._revoked_identities: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    @property
    def reaction_history(self) -> list[ActiveReactionPayload]:
        """Return a copy of the executed reaction history."""
        return list(self._reaction_history)

    @property
    def ebpf_drop_rules(self) -> list[dict[str, Any]]:
        """Return recorded eBPF drop rules."""
        return list(self._ebpf_drop_rules)

    @property
    def broadcasted_signatures(self) -> list[dict[str, Any]]:
        """Return recorded broadcasted signatures."""
        return list(self._broadcasted_signatures)

    @property
    def revoked_identities(self) -> list[dict[str, Any]]:
        """Return recorded identity revocations."""
        return list(self._revoked_identities)

    async def is_evaluation_mode(
        self, evidence_id: uuid.UUID | str, env_id: str | None = None
    ) -> bool:
        """Mandatory Evidence-Derived Evaluation Containment Gate (Architecture Rule 20).

        Queries the evaluation environment manager and/or graph store to verify whether
        the trigger evidence originated in an evaluation environment.

        Fail-Safe Boundary: If an error or exception occurs during evaluation resolution,
        or if evidence is unresolved while an evaluation manager is configured, the check
        fails closed (returns True) to prevent unintended execution of production
        mitigations against unverified evaluation workloads.
        """
        if not evidence_id:
            return False

        if env_id and env_id.strip():
            return True

        if isinstance(evidence_id, str) and any(
            k in evidence_id.lower() for k in ("eval", "test", "sim", "mock", "synthetic")
        ):
            return True

        try:
            clean_evidence_uuid = validate_uuid_v4_format(evidence_id, field_name="evidence_id")
        except (ValueError, TypeError):
            return True

        if self.eval_manager is not None:
            try:
                if await self.eval_manager.is_evaluation_mode(clean_evidence_uuid, env_id=env_id):
                    return True
                for env in list(self.eval_manager._environments.values()):
                    try:
                        env_node = await env.store.get_node(clean_evidence_uuid)
                        if env_node is not None:
                            return True
                    except Exception:
                        return True
            except Exception as exc:
                logger.warning(
                    "Error querying evaluation manager for evidence %s; failing closed to contain: %s",
                    clean_evidence_uuid,
                    exc,
                )
                return True

        if self.graph_store is not None:
            try:
                node = await self.graph_store.get_node(clean_evidence_uuid)
                if node is not None:
                    meta = node.event.metadata
                    if (
                        meta.get("is_evaluation") is True
                        or meta.get("eval_mode") is True
                        or (isinstance(meta.get("evaluation_env_id"), str) and meta["evaluation_env_id"].strip())
                    ):
                        return True
            except Exception as exc:
                logger.warning(
                    "Error querying graph store for evaluation evidence %s; failing closed to contain: %s",
                    clean_evidence_uuid,
                    exc,
                )
                return True

        return False

    def _is_payload_eval_flagged(self, payload: ActiveReactionPayload) -> bool:
        """Check if the payload explicitly carries evaluation metadata."""
        if payload.evaluation_env_id and payload.evaluation_env_id.strip():
            return True
        meta = payload.metadata
        if (
            meta.get("is_evaluation") is True
            or meta.get("eval_mode") is True
            or (isinstance(meta.get("evaluation_env_id"), str) and meta["evaluation_env_id"].strip())
        ):
            return True
        return False

    async def execute_ebpf_socket_drop(
        self, payload: ActiveReactionPayload
    ) -> bool:
        """Inject real-time eBPF socket/PID drop rule into Pillar 1 Kernel Interception (<50ms SLA).

        Mandatory check: Queries is_evaluation_mode(payload.trigger_evidence_id);
        quashed immediately if evaluation mode is detected (Requirement 22.1 & 22.5).
        """
        start_time = time.perf_counter()
        is_eval = await self.is_evaluation_mode(payload.trigger_evidence_id)
        if is_eval or self._is_payload_eval_flagged(payload):
            payload.status = "SUPPRESSED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                "Suppressed production eBPF socket drop for reaction %s (evaluation containment).",
                payload.reaction_id,
            )
            return False

        # If kernel driver adapter is absent, fail immediately rather than falsely reporting success
        if self.kernel_driver is None:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                "Kernel driver adapter is absent; cannot inject eBPF socket drop for reaction %s.",
                payload.reaction_id,
            )
            return False

        # If neither PID nor IP target is specified, fail immediately
        if payload.target_pid is None and payload.target_ip is None:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                "Cannot inject socket drop for reaction %s: neither target_pid nor target_ip specified.",
                payload.reaction_id,
            )
            return False

        # Production execution path
        drop_rule = {
            "reaction_id": str(payload.reaction_id),
            "target_agent_id": payload.target_agent_id,
            "target_pid": payload.target_pid,
            "target_ip": payload.target_ip,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "ACTIVE",
        }

        applied = False
        try:
            if hasattr(self.kernel_driver, "inject_socket_drop"):
                res = self.kernel_driver.inject_socket_drop(
                    pid=payload.target_pid, ip=payload.target_ip
                )
                if asyncio.iscoroutine(res):
                    res = await res
                if res is False:
                    logger.error("Kernel driver rejected socket drop injection for PID %s / IP %s", payload.target_pid, payload.target_ip)
                    payload.status = "FAILED"
                    payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return False
                applied = True
            elif hasattr(self.kernel_driver, "drop_socket"):
                res = self.kernel_driver.drop_socket(
                    pid=payload.target_pid, ip=payload.target_ip
                )
                if asyncio.iscoroutine(res):
                    res = await res
                if res is False:
                    logger.error("Kernel driver rejected socket drop for PID %s / IP %s", payload.target_pid, payload.target_ip)
                    payload.status = "FAILED"
                    payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return False
                applied = True
            else:
                logger.error("Kernel driver lacks inject_socket_drop / drop_socket capability.")
                payload.status = "FAILED"
                payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
                return False
        except Exception as exc:
            logger.error("Error applying eBPF drop rule in kernel driver: %s", exc)
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            return False

        if not applied:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Kernel driver has no supported methods for drop injection.")
            return False

        async with self._lock:
            self._ebpf_drop_rules.append(drop_rule)

        payload.status = "SUCCESS"
        payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(
            "Injected eBPF socket drop for agent %s (PID: %s, IP: %s) in %.2fms.",
            payload.target_agent_id,
            payload.target_pid,
            payload.target_ip,
            payload.execution_duration_ms,
        )
        return True

    async def broadcast_fleet_signature(
        self, payload: ActiveReactionPayload
    ) -> bool:
        """Publish zero-latency block signature across Pillar 2 ZeroMQ Threat Mesh (<15ms SLA).

        Mandatory check: Queries is_evaluation_mode(payload.trigger_evidence_id);
        quashed immediately if evaluation mode is detected (Requirement 22.2 & 22.5).
        """
        start_time = time.perf_counter()
        is_eval = await self.is_evaluation_mode(payload.trigger_evidence_id)
        if is_eval or self._is_payload_eval_flagged(payload):
            payload.status = "SUPPRESSED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                "Suppressed Threat Mesh signature broadcast for reaction %s (evaluation containment).",
                payload.reaction_id,
            )
            return False

        # If mesh broadcaster adapter is absent, fail immediately rather than falsely reporting success
        if self.mesh_broadcaster is None:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                "Threat Mesh broadcaster adapter is absent; cannot broadcast signature for reaction %s.",
                payload.reaction_id,
            )
            return False

        # Production signature construction
        sig_id = f"sig_atd_{payload.target_agent_id}_{str(payload.reaction_id)[:8]}"
        signature = {
            "signature_id": sig_id,
            "reaction_id": str(payload.reaction_id),
            "target_agent_id": payload.target_agent_id,
            "target_pid": payload.target_pid,
            "target_ip": payload.target_ip,
            "pattern": f"agent:{payload.target_agent_id}",
            "threat_level": "CRITICAL",
            "timestamp": time.time(),
        }

        broadcasted = False
        try:
            if hasattr(self.mesh_broadcaster, "broadcast_signature"):
                res = self.mesh_broadcaster.broadcast_signature(signature)
                if asyncio.iscoroutine(res):
                    res = await res
                if res is False:
                    logger.error("Threat Mesh broadcaster rejected signature %s", sig_id)
                    payload.status = "FAILED"
                    payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return False
                broadcasted = True
            elif hasattr(self.mesh_broadcaster, "broadcast"):
                res = self.mesh_broadcaster.broadcast(signature)
                if asyncio.iscoroutine(res):
                    res = await res
                if res is False:
                    logger.error("Threat Mesh broadcaster rejected signature %s", sig_id)
                    payload.status = "FAILED"
                    payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return False
                broadcasted = True
        except Exception as exc:
            logger.error("Error broadcasting signature over Threat Mesh: %s", exc)
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            return False

        if not broadcasted:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Threat Mesh broadcaster has no supported broadcast methods.")
            return False

        async with self._lock:
            self._broadcasted_signatures.append(signature)

        payload.status = "SUCCESS"
        payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(
            "Broadcasted threat signature %s for agent %s in %.2fms.",
            sig_id,
            payload.target_agent_id,
            payload.execution_duration_ms,
        )
        return True

    async def revoke_identity_session(
        self, payload: ActiveReactionPayload
    ) -> bool:
        """Trigger Pillar 3 Ephemeral Identity Sidecar / Vault MCP to invalidate JIT credentials.

        Mandatory check: Queries is_evaluation_mode(payload.trigger_evidence_id);
        quashed immediately if evaluation mode is detected (Requirement 22.3 & 22.5).
        """
        start_time = time.perf_counter()
        is_eval = await self.is_evaluation_mode(payload.trigger_evidence_id)
        if is_eval or self._is_payload_eval_flagged(payload):
            payload.status = "SUPPRESSED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                "Suppressed Identity token revocation for reaction %s (evaluation containment).",
                payload.reaction_id,
            )
            return False

        # If vault adapter is absent, fail immediately rather than falsely reporting success
        if self.vault_adapter is None:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                "Vault MCP adapter is absent; cannot revoke credentials for reaction %s.",
                payload.reaction_id,
            )
            return False

        revocation_record = {
            "reaction_id": str(payload.reaction_id),
            "target_agent_id": payload.target_agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "REVOKED",
        }

        mitigated = False
        token_revoked = False
        honeytoken_rotated = False

        try:
            adapter = (
                self.vault_adapter.vault_adapter
                if hasattr(self.vault_adapter, "vault_adapter")
                else self.vault_adapter
            )

            if hasattr(adapter, "rotate_honeytokens"):
                res = adapter.rotate_honeytokens()
                if asyncio.iscoroutine(res):
                    res = await res
                if res is not False and res is not None:
                    honeytoken_rotated = True

            token_id = payload.metadata.get("token_id")
            token_ids = payload.metadata.get("token_ids")
            tokens_to_revoke: list[str] = []
            if token_id:
                tokens_to_revoke.append(token_id)
            if isinstance(token_ids, list):
                for tid in token_ids:
                    if tid and tid not in tokens_to_revoke:
                        tokens_to_revoke.append(tid)

            # Discover and include all active tokens belonging to the target agent
            if hasattr(adapter, "_issued_tokens"):
                for t_id, t_info in list(adapter._issued_tokens.items()):
                    if t_info.get("status") == "ACTIVE":
                        agent_matches = (
                            t_info.get("agent_id") == payload.target_agent_id
                            or t_info.get("principal_id") == payload.target_agent_id
                            or t_info.get("metadata", {}).get("agent_id") == payload.target_agent_id
                            or t_info.get("metadata", {}).get("principal_id") == payload.target_agent_id
                            or t_id == payload.target_agent_id
                        )
                        if agent_matches:
                            if t_id not in tokens_to_revoke:
                                tokens_to_revoke.append(t_id)

            if tokens_to_revoke and hasattr(adapter, "revoke_token"):
                all_tokens_successful = True
                for t_id in tokens_to_revoke:
                    if hasattr(adapter, "_issued_tokens") and t_id in adapter._issued_tokens:
                        if adapter._issued_tokens[t_id].get("status") == "REVOKED":
                            revocation_record.setdefault("revoked_token_ids", []).append(t_id)
                            revocation_record["revoked_token_id"] = t_id
                            continue
                    res = adapter.revoke_token(t_id)
                    if asyncio.iscoroutine(res):
                        res = await res
                    if res is not False and res is not None:
                        revocation_record.setdefault("revoked_token_ids", []).append(t_id)
                        revocation_record["revoked_token_id"] = t_id
                    else:
                        logger.error("Vault adapter rejected revocation of token: %s", t_id)
                        all_tokens_successful = False

                if all_tokens_successful and len(revocation_record.get("revoked_token_ids", [])) == len(tokens_to_revoke):
                    token_revoked = True
                else:
                    token_revoked = False

            is_honeytoken_target = bool(
                payload.metadata.get("is_honeytoken")
                or (isinstance(token_id, str) and token_id.startswith("BW_SYNTHETIC_"))
            )

            if tokens_to_revoke:
                mitigated = token_revoked
            else:
                mitigated = is_honeytoken_target and honeytoken_rotated

        except Exception as exc:
            logger.error("Error revoking identity credentials via Vault: %s", exc)
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            return False

        if not mitigated:
            payload.status = "FAILED"
            payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Vault adapter has no supported methods for identity revocation.")
            return False

        async with self._lock:
            self._revoked_identities.append(revocation_record)

        payload.status = "SUCCESS"
        payload.execution_duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(
            "Revoked identity credentials and rotated honey-tokens for agent %s in %.2fms.",
            payload.target_agent_id,
            payload.execution_duration_ms,
        )
        return True

    async def dispatch_reaction(
        self, payload: ActiveReactionPayload
    ) -> ActiveReactionPayload:
        """Route reaction payload to designated pillar mitigation handler and record execution logs (Requirement 22.4)."""
        if payload.action_type == ReactionActionType.EBPF_DROP:
            await self.execute_ebpf_socket_drop(payload)
        elif payload.action_type == ReactionActionType.MESH_SIGNATURE_BROADCAST:
            await self.broadcast_fleet_signature(payload)
        elif payload.action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS:
            await self.revoke_identity_session(payload)
        else:
            payload.status = "FAILED"

        async with self._lock:
            self._reaction_history.append(payload)

        # Log reaction execution record to Attack Graph Store (Requirement 22.4, Property 92)
        if self.graph_store is not None:
            try:
                reaction_event = NormalizedEvent(
                    event_id=payload.reaction_id,
                    timestamp=payload.timestamp,
                    source=EventSource.KERNEL_SYSCALL
                    if payload.action_type == ReactionActionType.EBPF_DROP
                    else EventSource.IDENTITY_ACCESS
                    if payload.action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS
                    else EventSource.TOOL_CALL,
                    agent_id=payload.target_agent_id,
                    action=f"active_reaction_{payload.action_type.value.lower()}",
                    target=str(payload.target_pid or payload.target_ip or payload.target_agent_id),
                    metadata={
                        "reaction_id": str(payload.reaction_id),
                        "trigger_evidence_id": str(payload.trigger_evidence_id),
                        "action_type": payload.action_type.value,
                        "status": payload.status,
                        "execution_duration_ms": payload.execution_duration_ms,
                        "evaluation_env_id": payload.evaluation_env_id,
                        **payload.metadata,
                    },
                    risk_score=0.9 if payload.status == "SUCCESS" else 0.1,
                )
                await self.graph_store.insert_event(reaction_event)
            except Exception as exc:
                logger.warning("Failed to log reaction event to attack graph store: %s", exc)

        # Publish notification alert to Alert Bus (Requirement 22.4, Property 92)
        if self.alert_bus is not None:
            try:
                audit_alert = Alert(
                    alert_id=uuid.uuid4(),
                    timestamp=datetime.now(UTC),
                    severity=AlertSeverity.CRITICAL
                    if payload.status == "SUCCESS"
                    else AlertSeverity.LOW,
                    threat_type="active_threat_reaction",
                    title=f"Active Reaction ({payload.action_type.value}): {payload.status}",
                    description=(
                        f"Active reaction {payload.reaction_id} ({payload.action_type.value}) "
                        f"dispatched for agent {payload.target_agent_id} with status '{payload.status}' "
                        f"in {payload.execution_duration_ms:.2f}ms."
                    ),
                    evidence_id=payload.trigger_evidence_id,
                    agent_id=payload.target_agent_id,
                    evidence=payload.model_dump(),
                    metadata={
                        "reaction_id": str(payload.reaction_id),
                        "action_type": payload.action_type.value,
                        "status": payload.status,
                        "evaluation_env_id": payload.evaluation_env_id,
                    },
                )
                await self.alert_bus.publish(audit_alert)
            except Exception as exc:
                logger.warning("Failed to publish reaction audit alert to Alert Bus: %s", exc)

        return payload

    async def react_to_alert(self, alert: Alert) -> list[ActiveReactionPayload]:
        """Automatically synthesize and dispatch mitigation actions for confirmed critical alerts."""
        payloads: list[ActiveReactionPayload] = []
        is_critical_or_high = alert.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)
        if not is_critical_or_high:
            return payloads

        evidence_id = alert.evidence_id or alert.alert_id
        target_agent = alert.agent_id or (alert.agent_ids[0] if alert.agent_ids else "unknown_agent")
        eval_env_id = alert.metadata.get("evaluation_env_id")
        target_pid = alert.evidence.get("pid") if isinstance(alert.evidence, dict) else None
        target_ip = alert.evidence.get("ip") or alert.evidence.get("remote_ip") if isinstance(alert.evidence, dict) else None

        threat_type = alert.threat_type.lower()

        # C2 infrastructure or zero-day exploit chain -> eBPF socket drop + fleet signature broadcast
        if "c2" in threat_type or "exploit_chain" in threat_type or "k8s" in threat_type:
            payloads.append(
                ActiveReactionPayload(
                    reaction_id=uuid.uuid4(),
                    trigger_evidence_id=evidence_id,
                    target_agent_id=target_agent,
                    target_pid=target_pid if isinstance(target_pid, int) and target_pid > 0 else None,
                    target_ip=str(target_ip) if target_ip else None,
                    action_type=ReactionActionType.EBPF_DROP,
                    evaluation_env_id=eval_env_id,
                )
            )
            payloads.append(
                ActiveReactionPayload(
                    reaction_id=uuid.uuid4(),
                    trigger_evidence_id=evidence_id,
                    target_agent_id=target_agent,
                    target_pid=target_pid if isinstance(target_pid, int) and target_pid > 0 else None,
                    target_ip=str(target_ip) if target_ip else None,
                    action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
                    evaluation_env_id=eval_env_id,
                )
            )

        # Agent swarm, AI-induced lateral movement (AILM), or credential theft -> Revoke identity tokens
        if "swarm" in threat_type or "ailm" in threat_type or "credential" in threat_type or "token" in threat_type:
            meta = dict(alert.metadata) if alert.metadata else {}
            token_id = (
                meta.get("token_id")
                or meta.get("token")
                or meta.get("target_token")
                or meta.get("credential_id")
            )
            token_ids = meta.get("token_ids")
            if not token_id and isinstance(alert.evidence, dict):
                token_id = (
                    alert.evidence.get("token_id")
                    or alert.evidence.get("token")
                    or alert.evidence.get("target_token")
                    or alert.evidence.get("credential_id")
                )
                if not token_ids:
                    token_ids = alert.evidence.get("token_ids")

            matching_tokens: list[str] = []
            if token_id:
                matching_tokens.append(token_id)
            if isinstance(token_ids, list):
                for tid in token_ids:
                    if tid and tid not in matching_tokens:
                        matching_tokens.append(tid)
            if self.vault_adapter is not None:
                adapter = (
                    self.vault_adapter.vault_adapter
                    if hasattr(self.vault_adapter, "vault_adapter")
                    else self.vault_adapter
                )
                if hasattr(adapter, "_issued_tokens"):
                    for t_id, t_info in list(adapter._issued_tokens.items()):
                        if t_info.get("status") == "ACTIVE":
                            agent_matches = (
                                t_info.get("agent_id") == target_agent
                                or t_info.get("principal_id") == target_agent
                                or t_info.get("metadata", {}).get("agent_id") == target_agent
                                or t_info.get("metadata", {}).get("principal_id") == target_agent
                                or t_id == target_agent
                            )
                            if agent_matches:
                                if t_id not in matching_tokens:
                                    matching_tokens.append(t_id)

            tok_meta = dict(meta)
            if matching_tokens:
                tok_meta["token_ids"] = matching_tokens
                tok_meta["token_id"] = matching_tokens[0]

            payloads.append(
                ActiveReactionPayload(
                    reaction_id=uuid.uuid4(),
                    trigger_evidence_id=evidence_id,
                    target_agent_id=target_agent,
                    action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
                    evaluation_env_id=eval_env_id,
                    metadata=tok_meta,
                )
            )

        executed: list[ActiveReactionPayload] = []
        for p in payloads:
            res = await self.dispatch_reaction(p)
            executed.append(res)

        return executed

    def clear(self) -> None:
        """Clear reaction history and recorded actions."""
        self._reaction_history.clear()
        self._ebpf_drop_rules.clear()
        self._broadcasted_signatures.clear()
        self._revoked_identities.clear()
