"""AlertBus and Real-Time Alert Generation for Blackwall Advanced Threat Detection (Pillar 6 Task 15)."""

import asyncio
import inspect
import logging
import uuid
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from blackwall.enterprise.advanced_threat_detection.enums import AlertSeverity
from blackwall.enterprise.advanced_threat_detection.models import (
    AILMEvidence,
    Alert,
    AttackPath,
    C2Evidence,
    ExploitChainEvidence,
    K8sThreatEvidence,
    RegistryThreatEvidence,
    SwarmEvidence,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.alert_bus")


class AlertBus:
    """Centralized asynchronous message bus and real-time alert generation coordinator."""

    def __init__(
        self,
        max_retries: int = 5,
        retry_delay: float = 0.01,
        history_capacity: int = 1000,
        batch_size: int = 100,
        flush_interval_seconds: float = 1.0,
    ) -> None:
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries <= 0:
            raise ValueError("max_retries must be a strictly positive integer")
        if isinstance(history_capacity, bool) or not isinstance(history_capacity, int) or history_capacity <= 0:
            raise ValueError("history_capacity must be a strictly positive integer")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("batch_size must be a strictly positive integer")
        if flush_interval_seconds <= 0:
            raise ValueError("flush_interval_seconds must be positive")

        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self._subscribers: list[Callable[[Alert], Any]] = []
        self._alerts: deque[Alert] = deque(maxlen=history_capacity)
        self._pending_alerts: deque[Alert] = deque()
        self._persistent_failures: list[dict[str, Any]] = []
        self._flush_task: asyncio.Task[Any] | None = None
        self._running = False
        self._lock = asyncio.Lock()
        self._flush_lock = asyncio.Lock()

    @property
    def persistent_failures(self) -> list[dict[str, Any]]:
        """Return recorded persistent alert delivery failures."""
        return list(self._persistent_failures)

    async def start(self) -> None:
        """Start background periodic flush timer if not already running."""
        async with self._lock:
            if self._running:
                return
            self._running = True
            if self.flush_interval_seconds > 0:
                self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def stop(self) -> None:
        """Stop background flush task and flush all remaining pending alerts."""
        self._running = False
        task = self._flush_task
        self._flush_task = None
        if task is not None and not task.done():
            try:
                task.cancel()
            except RuntimeError:
                pass
            try:
                if not task.get_loop().is_closed():
                    await task
            except (asyncio.CancelledError, RuntimeError, Exception):
                pass
        await self._flush_pending()

    async def _periodic_flush_loop(self) -> None:
        """Periodically flush buffered alerts at flush_interval_seconds."""
        try:
            while self._running:
                await asyncio.sleep(self.flush_interval_seconds)
                await self.flush()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def flush(self) -> bool:
        """Flush all pending alerts to subscribers in bounded batch chunks."""
        return await self._flush_pending()

    async def _flush_pending(self) -> bool:
        async with self._flush_lock:
            if not self._pending_alerts:
                return True
            all_ok = True
            while self._pending_alerts:
                chunk = []
                while self._pending_alerts and len(chunk) < self.batch_size:
                    chunk.append(self._pending_alerts.popleft())
                delivered_count = 0
                try:
                    for i, alert in enumerate(chunk):
                        delivery_task = asyncio.create_task(self._deliver_alert(alert))
                        try:
                            ok = await asyncio.shield(delivery_task)
                            if not ok:
                                all_ok = False
                            delivered_count = i + 1
                        except asyncio.CancelledError:
                            try:
                                await asyncio.wait_for(delivery_task, timeout=1.0)
                                delivered_count = i + 1
                            except (asyncio.TimeoutError, Exception):
                                delivery_task.cancel()
                            raise
                except (asyncio.CancelledError, Exception):
                    # Re-queue any undelivered alerts back to the front of _pending_alerts
                    undelivered = chunk[delivered_count:]
                    for alert_item in reversed(undelivered):
                        self._pending_alerts.appendleft(alert_item)
                    raise
            return all_ok

    def subscribe(self, handler: Callable[[Alert], Any]) -> None:
        """Register a synchronous or asynchronous alert subscriber handler."""
        if handler not in self._subscribers:
            self._subscribers.append(handler)

    def unsubscribe(self, handler: Callable[[Alert], Any]) -> None:
        """Remove a previously registered alert subscriber."""
        if handler in self._subscribers:
            self._subscribers.remove(handler)

    async def _deliver_alert(self, alert: Alert) -> bool:
        """Deliver a single alert to subscribers with retry resilience."""
        if not any(a.alert_id == alert.alert_id for a in self._alerts):
            self._alerts.append(alert)
        if not self._subscribers:
            return True

        all_success = True

        for subscriber in list(self._subscribers):
            delivered = False
            last_error: Exception | None = None

            for attempt in range(1, self.max_retries + 1):
                try:
                    if inspect.iscoroutinefunction(subscriber):
                        await subscriber(alert)
                    else:
                        result = subscriber(alert)
                        if inspect.iscoroutine(result):
                            await result
                    delivered = True
                    break
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    if attempt < self.max_retries and self.retry_delay > 0:
                        await asyncio.sleep(self.retry_delay)

            if not delivered:
                all_success = False
                error_msg = str(last_error) if last_error else "Unknown delivery failure"
                failure_record = {
                    "alert_id": str(alert.alert_id),
                    "error": error_msg,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "subscriber": getattr(subscriber, "__name__", str(subscriber)),
                }
                self._persistent_failures.append(failure_record)
                logger.critical(
                    "Persistent alert delivery failure for alert %s to subscriber %s after %d retries: %s",
                    alert.alert_id,
                    subscriber,
                    self.max_retries,
                    error_msg,
                )

        return all_success

    async def publish(self, alert: Alert) -> bool:
        """Publish an alert to all registered subscribers or buffer if batching is active."""
        if self._running and self.batch_size > 1 and self.flush_interval_seconds > 0:
            self._pending_alerts.append(alert)
            if len(self._pending_alerts) >= self.batch_size:
                return await self.flush()
            return True
        return await self._deliver_alert(alert)

    async def publish_batch(self, alerts: list[Alert]) -> bool:
        """Publish a batch of alerts in bounded chunk sizes up to batch_size."""
        if not alerts:
            return True
        if self._running and self.batch_size > 1 and self.flush_interval_seconds > 0:
            self._pending_alerts.extend(alerts)
            if len(self._pending_alerts) >= self.batch_size:
                return await self.flush()
            return True
        all_ok = True
        for i in range(0, len(alerts), self.batch_size):
            chunk = alerts[i : i + self.batch_size]
            for alert in chunk:
                ok = await self._deliver_alert(alert)
                if not ok:
                    all_ok = False
        return all_ok

    def get_alerts(
        self,
        severity: AlertSeverity | None = None,
        threat_type: str | None = None,
        agent_id: str | None = None,
    ) -> list[Alert]:
        """Retrieve stored alerts filtered by severity, threat_type, or agent_id."""
        filtered = list(self._alerts) + list(self._pending_alerts)
        if severity is not None:
            filtered = [a for a in filtered if a.severity == severity]
        if threat_type is not None:
            filtered = [a for a in filtered if a.threat_type == threat_type]
        if agent_id is not None:
            filtered = [
                a for a in filtered
                if a.agent_id == agent_id or agent_id in a.agent_ids
            ]
        return filtered

    def clear(self) -> None:
        """Clear all stored alerts and persistent failures."""
        self._alerts.clear()
        self._pending_alerts.clear()
        self._persistent_failures.clear()

    # ---------------------------------------------------------------------------
    # Severity Mapping Helpers (Requirements 10.1 - 10.7)
    # ---------------------------------------------------------------------------

    def map_swarm_severity(self, swarm: SwarmEvidence) -> AlertSeverity:
        """Map swarm detection evidence to alert severity (Requirement 10.1 -> CRITICAL)."""
        return AlertSeverity.CRITICAL

    def map_ailm_severity(self, ailm: AILMEvidence) -> AlertSeverity:
        """Map AILM evidence risk_level to alert severity (Requirement 10.2)."""
        risk = ailm.risk_level.upper() if isinstance(ailm.risk_level, str) else ""
        if risk == "CRITICAL":
            return AlertSeverity.CRITICAL
        elif risk == "HIGH":
            return AlertSeverity.HIGH
        elif risk == "MEDIUM":
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def map_exploit_chain_severity(self, chain: ExploitChainEvidence) -> AlertSeverity:
        """Map exploit chain novelty score to alert severity (Requirement 10.3)."""
        if chain.novelty_score >= 0.8:
            return AlertSeverity.CRITICAL
        elif chain.novelty_score >= 0.5:
            return AlertSeverity.HIGH
        elif chain.novelty_score >= 0.3:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def map_attack_path_severity(self, path: AttackPath) -> AlertSeverity:
        """Map attack path risk score to alert severity (Requirement 10.4)."""
        if path.risk_score >= 0.8:
            return AlertSeverity.CRITICAL
        elif path.risk_score >= 0.5:
            return AlertSeverity.HIGH
        elif path.risk_score >= 0.3:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def map_c2_severity(self, c2: C2Evidence) -> AlertSeverity:
        """Map C2 infrastructure evidence to alert severity (Requirement 10.5 -> CRITICAL)."""
        return AlertSeverity.CRITICAL

    def map_k8s_severity(self, k8s: K8sThreatEvidence) -> AlertSeverity:
        """Map Kubernetes threat type to alert severity (Requirement 10.6)."""
        tt = k8s.threat_type.lower()
        if tt in {"pod_token_theft", "token_theft", "fleet_spawning"}:
            return AlertSeverity.CRITICAL
        elif tt in {"secrets_exfiltration", "self_respawning_pod", "self_respawn", "privilege_escalation"}:
            return AlertSeverity.HIGH
        return AlertSeverity.MEDIUM

    def map_registry_severity(
        self,
        registry: RegistryThreatEvidence,
        exploit_confidence: float = 0.0,
    ) -> AlertSeverity:
        """Map package registry threat confidence to alert severity (Requirement 10.7)."""
        if exploit_confidence >= 0.8:
            return AlertSeverity.CRITICAL
        elif exploit_confidence >= 0.5:
            return AlertSeverity.HIGH
        elif exploit_confidence >= 0.3:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    # ---------------------------------------------------------------------------
    # Alert Generator Methods
    # ---------------------------------------------------------------------------

    def generate_swarm_alert(self, swarm: SwarmEvidence) -> Alert:
        """Generate an Alert for detected swarm activity (Requirement 10.1)."""
        agent_list = sorted(swarm.agent_ids)
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_swarm_severity(swarm),
            threat_type="swarm_detection",
            title=f"Agent Swarm Activity Detected ({len(agent_list)} agents)",
            description=(
                f"Coordinated agent swarm {swarm.swarm_id} detected with {len(agent_list)} agents "
                f"({', '.join(agent_list)}), coordination score {swarm.coordination_score:.2f}, "
                f"and temporal correlation {swarm.temporal_correlation:.2f}."
            ),
            evidence_id=swarm.swarm_id,
            agent_ids=agent_list,
            evidence=swarm.model_dump(),
        )

    def generate_ailm_alert(self, ailm: AILMEvidence) -> Alert:
        """Generate an Alert for AI-Induced Lateral Movement (Requirement 10.2)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_ailm_severity(ailm),
            threat_type="ailm",
            title=f"AI-Induced Lateral Movement: {ailm.agent_id}",
            description=(
                f"Agent {ailm.agent_id} executed lateral movement crossing "
                f"{len(ailm.boundary_crossings)} security boundaries with "
                f"{len(ailm.composed_permissions)} composed permissions (risk: {ailm.risk_level})."
            ),
            agent_id=ailm.agent_id,
            agent_ids=[ailm.agent_id],
            evidence=ailm.model_dump(),
        )

    def generate_exploit_chain_alert(self, chain: ExploitChainEvidence) -> Alert:
        """Generate an Alert for zero-day exploit chain sequences (Requirement 10.3)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_exploit_chain_severity(chain),
            threat_type="exploit_chain",
            title=f"Zero-Day Exploit Chain Detected ({len(chain.exploits)} stages)",
            description=(
                f"Exploit chain {chain.chain_id} detected with {len(chain.exploits)} stages, "
                f"novelty score {chain.novelty_score:.2f}, and confidence {chain.chaining_confidence:.2f}."
            ),
            evidence_id=chain.chain_id,
            evidence=chain.model_dump(),
        )

    def generate_attack_path_alert(self, path: AttackPath) -> Alert:
        """Generate an Alert for correlated multi-stage attack paths (Requirement 10.4)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_attack_path_severity(path),
            threat_type="attack_path",
            title=f"Multi-Stage Attack Path Correlated: {path.agent_id}",
            description=(
                f"Attack path {path.path_id} for agent {path.agent_id} with {len(path.nodes)} nodes, "
                f"risk score {path.risk_score:.2f}, and stages {path.attack_stages}."
            ),
            evidence_id=path.path_id,
            agent_id=path.agent_id,
            agent_ids=[path.agent_id],
            evidence=path.model_dump(),
        )

    def generate_c2_alert(self, c2: C2Evidence) -> Alert:
        """Generate an Alert for C2 infrastructure establishment (Requirement 10.5)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_c2_severity(c2),
            threat_type="c2_infrastructure",
            title=f"Command-and-Control Infrastructure Detected: {c2.agent_id}",
            description=(
                f"Agent {c2.agent_id} established C2 infrastructure with pattern '{c2.communication_pattern}' "
                f"targeting endpoints {c2.c2_endpoints}."
            ),
            agent_id=c2.agent_id,
            agent_ids=[c2.agent_id],
            evidence=c2.model_dump(),
        )

    def generate_k8s_alert(self, k8s: K8sThreatEvidence) -> Alert:
        """Generate an Alert for Kubernetes container threats (Requirement 10.6)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_k8s_severity(k8s),
            threat_type=f"k8s_{k8s.threat_type}",
            title=f"Kubernetes Threat ({k8s.threat_type}) in {k8s.namespace}/{k8s.pod_name}",
            description=(
                f"Kubernetes threat '{k8s.threat_type}' detected in namespace '{k8s.namespace}' "
                f"for pod '{k8s.pod_name}' using service account '{k8s.service_account}'."
            ),
            evidence=k8s.model_dump(),
        )

    def generate_registry_alert(
        self,
        registry: RegistryThreatEvidence,
        exploit_confidence: float = 0.0,
    ) -> Alert:
        """Generate an Alert for package registry probing or exploitation (Requirement 10.7)."""
        return Alert(
            alert_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            severity=self.map_registry_severity(registry, exploit_confidence=exploit_confidence),
            threat_type="package_registry",
            title=f"Package Registry Exploit Probing: {registry.registry_type}/{registry.package_name}",
            description=(
                f"Package registry exploit probing detected against {registry.registry_type} "
                f"for package '{registry.package_name}' (confidence: {exploit_confidence:.2f}, "
                f"CVE candidates: {registry.cve_candidates})."
            ),
            evidence=registry.model_dump(),
        )

    # ---------------------------------------------------------------------------
    # Convenience Publication Methods
    # ---------------------------------------------------------------------------

    async def publish_swarm_alert(self, swarm: SwarmEvidence) -> bool:
        """Generate and publish an alert for detected swarm activity."""
        alert = self.generate_swarm_alert(swarm)
        return await self.publish(alert)

    async def publish_ailm_alert(self, ailm: AILMEvidence) -> bool:
        """Generate and publish an alert for AILM events."""
        alert = self.generate_ailm_alert(ailm)
        return await self.publish(alert)

    async def publish_exploit_chain_alert(self, chain: ExploitChainEvidence) -> bool:
        """Generate and publish an alert for exploit chain sequences."""
        alert = self.generate_exploit_chain_alert(chain)
        return await self.publish(alert)

    async def publish_attack_path_alert(self, path: AttackPath) -> bool:
        """Generate and publish an alert for correlated attack paths."""
        alert = self.generate_attack_path_alert(path)
        return await self.publish(alert)

    async def publish_c2_alert(self, c2: C2Evidence) -> bool:
        """Generate and publish an alert for C2 infrastructure detection."""
        alert = self.generate_c2_alert(c2)
        return await self.publish(alert)

    async def publish_k8s_alert(self, k8s: K8sThreatEvidence) -> bool:
        """Generate and publish an alert for Kubernetes threats."""
        alert = self.generate_k8s_alert(k8s)
        return await self.publish(alert)

    async def publish_registry_alert(
        self,
        registry: RegistryThreatEvidence,
        exploit_confidence: float = 0.0,
    ) -> bool:
        """Generate and publish an alert for package registry threats."""
        alert = self.generate_registry_alert(registry, exploit_confidence=exploit_confidence)
        return await self.publish(alert)
