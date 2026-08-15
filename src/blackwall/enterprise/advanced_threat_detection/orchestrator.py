"""AdvancedThreatDetection main orchestrator component for Blackwall Pillar 6 (Task 21).

Wires EventStreamCollector, AttackGraphStore, AlertBus, SafeDetectionRunner,
ResourceThrottler, and all detection engines into a unified system entry point.
"""

import asyncio
from datetime import UTC, datetime, timedelta
import logging
from typing import Any, Callable, List, Optional, Tuple, Union
import uuid

from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
from blackwall.enterprise.advanced_threat_detection.collector import EventStreamCollector
from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.exploit import ExploitChainAnalyzer
from blackwall.enterprise.advanced_threat_detection.k8s import KubernetesDefenseLayer
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    AttackNode,
    AttackPath,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.registry import PackageRegistryMonitor
from blackwall.enterprise.advanced_threat_detection.resilience import (
    ResourceThrottler,
    SafeDetectionRunner,
)
from blackwall.enterprise.advanced_threat_detection.retrospective import (
    RetrospectiveAnalyzer,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.validators import utc_now, validate_utc_datetime

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.orchestrator")


class AdvancedThreatDetection:
    """Unified entry point and orchestrator for Blackwall Advanced Threat Detection (Pillar 6)."""

    def __init__(
        self,
        config: Optional[AdvancedThreatDetectionConfig] = None,
    ) -> None:
        self.config = config or AdvancedThreatDetectionConfig()
        self._running = False
        self._lock = asyncio.Lock()

        # Core subsystem infrastructure
        self.store = AttackGraphStore(
            dsn=self.config.database_url,
            in_memory=self.config.in_memory,
        )
        self.collector = EventStreamCollector(
            reconnect_max_attempts=self.config.reconnect_max_attempts,
            reconnect_backoff_base=self.config.reconnect_backoff_base,
        )
        self.alert_bus = AlertBus(
            history_capacity=self.config.event_buffer_size,
        )
        self.runner = SafeDetectionRunner(
            default_timeout_seconds=self.config.safe_execution_timeout,
        )
        self.throttler = ResourceThrottler(
            max_events_per_second=self.config.max_events_per_second,
            max_queue_size=self.config.event_buffer_size,
        )

        # Detection engines (wired conditionally per configuration)
        self.path_correlator: Optional[PathCorrelator] = (
            PathCorrelator(store=self.store)
            if self.config.enable_path_correlation
            else None
        )
        self.swarm_detector: Optional[AgentSwarmDetector] = (
            AgentSwarmDetector(
                store=self.store,
                default_window=int(self.config.temporal_window_seconds),
                default_min_agents=self.config.swarm_min_agents,
                default_correlation_threshold=self.config.swarm_correlation_threshold,
            )
            if self.config.enable_swarm_detection
            else None
        )
        self.exploit_analyzer: Optional[ExploitChainAnalyzer] = (
            ExploitChainAnalyzer(store=self.store)
            if self.config.enable_exploit_analysis
            else None
        )
        self.ailm_tracker: Optional[AILMTracker] = (
            AILMTracker(store=self.store)
            if self.config.enable_ailm_tracking
            else None
        )
        self.c2_detector: Optional[C2InfrastructureDetector] = (
            C2InfrastructureDetector(store=self.store)
            if self.config.enable_c2_detection
            else None
        )
        self.k8s_defense: Optional[KubernetesDefenseLayer] = (
            KubernetesDefenseLayer(store=self.store)
            if self.config.enable_k8s_defense
            else None
        )
        self.registry_monitor: Optional[PackageRegistryMonitor] = (
            PackageRegistryMonitor(store=self.store)
            if self.config.enable_registry_monitor
            else None
        )
        self.retrospective_analyzer: Optional[RetrospectiveAnalyzer] = (
            RetrospectiveAnalyzer(
                store=self.store,
                correlator=self.path_correlator,
                swarm_detector=self.swarm_detector,
            )
        )

    @property
    def is_running(self) -> bool:
        """Return boolean indicating if the orchestrator is currently running."""
        return self._running

    async def start(self) -> None:
        """Initialize store, start components, and verify connections."""
        async with self._lock:
            if self._running:
                return

            if not self.config.in_memory and self.config.database_url:
                try:
                    await self.store.initialize()
                except Exception as exc:
                    # Explicit connection error escalation without logging raw DSN (Rule 3)
                    logger.error(
                        "AdvancedThreatDetection failed to establish PostgreSQL connection: %s",
                        type(exc).__name__,
                    )
                    raise ValueError(
                        f"Database connection failed during orchestrator startup: {type(exc).__name__}"
                    ) from exc
            else:
                await self.store.initialize()

            self._running = True
            logger.info("AdvancedThreatDetection orchestrator started successfully")

    async def stop(self) -> None:
        """Gracefully shutdown orchestrator, close connections, and flush buffers."""
        async with self._lock:
            if not self._running:
                return

            self._running = False
            await self.store.close()
            logger.info("AdvancedThreatDetection orchestrator stopped")

    async def __aenter__(self) -> "AdvancedThreatDetection":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.stop()

    async def ingest_event(
        self,
        source_or_event: Union[EventSource, NormalizedEvent],
        raw_event: Optional[dict[str, Any]] = None,
    ) -> NormalizedEvent:
        """Ingest security event passively and non-blockingly into graph store and pipeline.

        Supports both (EventSource, raw_dict) and pre-normalized (NormalizedEvent) signatures.
        """
        if isinstance(source_or_event, NormalizedEvent):
            normalized = source_or_event
        else:
            if raw_event is None:
                raise ValueError("raw_event dictionary must be provided when source is EventSource")
            normalized = self.collector.normalize_event(source_or_event, raw_event)

        # Record throughput in throttler
        self.throttler.record_event()

        # Persist event in attack graph store
        await self.store.insert_event(normalized)

        # Feed auxiliary stateful detectors
        if self.c2_detector is not None:
            if normalized.agent_id not in self.c2_detector._events_by_agent:
                self.c2_detector._events_by_agent[normalized.agent_id] = []
            self.c2_detector._events_by_agent[normalized.agent_id].append(normalized)

        if self.k8s_defense is not None:
            target_str = (normalized.target or "").lower()
            if "k8s" in target_str or "kubernetes" in target_str or "secrets" in target_str or "pod" in target_str:
                await self.k8s_defense.track_k8s_api_access(normalized)

        return normalized

    async def correlate_agent_threats(
        self,
        agent_id: str,
        time_window: Optional[Tuple[datetime, datetime]] = None,
    ) -> List[Alert]:
        """Run all enabled detection engines safely for an agent within the specified time window."""
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")

        if time_window is not None:
            win_start, win_end = time_window
            win_start = validate_utc_datetime(win_start)
            win_end = validate_utc_datetime(win_end)
        else:
            win_end = utc_now()
            win_start = win_end - timedelta(seconds=self.config.temporal_window_seconds)

        new_alerts: List[Alert] = []

        # 1. Multi-Stage Attack Path Correlation
        if self.path_correlator is not None:
            max_d = self.throttler.get_analysis_depth(base_depth=10)
            paths: List[AttackPath] = await self.runner.run_safe(
                detector_name="path_correlator",
                coro=self.path_correlator.correlate_attack_paths(
                    agent_id=agent_id,
                    time_window=(win_start, win_end),
                    min_path_length=self.config.min_path_length,
                    max_depth=max_d,
                ),
                fallback=[],
            )
            for path in paths:
                if path.risk_score >= 0.3:
                    sev = self.alert_bus.map_attack_path_severity(path)
                    alert = Alert(
                        alert_id=uuid.uuid4(),
                        timestamp=utc_now(),
                        severity=sev,
                        threat_type="attack_path",
                        title=f"Multi-Stage Attack Path Detected ({len(path.nodes)} stages)",
                        description=f"Correlated attack path for agent {agent_id} with risk score {path.risk_score:.2f}",
                        evidence_id=path.path_id,
                        agent_id=agent_id,
                        evidence={
                            "risk_score": path.risk_score,
                            "correlation_score": path.correlation_score,
                            "attack_stages": path.attack_stages,
                            "node_count": len(path.nodes),
                        },
                    )
                    await self.alert_bus.publish(alert)
                    new_alerts.append(alert)

        # 2. Zero-Day Exploit Chain Analysis
        if self.exploit_analyzer is not None:
            chains = await self.runner.run_safe(
                detector_name="exploit_analyzer",
                coro=self.exploit_analyzer.detect_chains(
                    agent_id=agent_id,
                    time_window=(win_start, win_end),
                ),
                fallback=[],
            )
            for chain in chains:
                sev = self.alert_bus.map_exploit_chain_severity(chain)
                alert = Alert(
                    alert_id=uuid.uuid4(),
                    timestamp=utc_now(),
                    severity=sev,
                    threat_type="exploit_chain",
                    title=f"Exploit Chain Detected ({len(chain.exploits)} steps)",
                    description=f"Zero-day exploit sequence detected for agent {agent_id} (novelty: {chain.novelty_score:.2f})",
                    evidence_id=chain.chain_id,
                    agent_id=agent_id,
                    evidence={
                        "novelty_score": chain.novelty_score,
                        "chaining_confidence": chain.chaining_confidence,
                        "exploits": [str(cat.value) if hasattr(cat, "value") else str(cat) for _, cat in chain.exploits],
                    },
                )
                await self.alert_bus.publish(alert)
                new_alerts.append(alert)

        # 3. AI-Induced Lateral Movement (AILM)
        if self.ailm_tracker is not None:
            ailm_evidences = await self.runner.run_safe(
                detector_name="ailm_tracker",
                coro=self.ailm_tracker.detect_permission_composition(
                    agent_id=agent_id,
                    time_window=(win_start, win_end),
                ),
                fallback=[],
            )
            for ailm in ailm_evidences:
                if ailm.risk_level in ("HIGH", "CRITICAL"):
                    sev = self.alert_bus.map_ailm_severity(ailm)
                    alert = Alert(
                        alert_id=uuid.uuid4(),
                        timestamp=utc_now(),
                        severity=sev,
                        threat_type="ailm",
                        title=f"AI-Induced Lateral Movement Detected ({ailm.risk_level})",
                        description=f"Agent {agent_id} accumulated permissions across trust boundaries: {ailm.boundary_crossings}",
                        agent_id=agent_id,
                        evidence={
                            "risk_level": ailm.risk_level,
                            "composed_permissions": list(ailm.composed_permissions),
                            "boundary_crossings": ailm.boundary_crossings,
                        },
                    )
                    await self.alert_bus.publish(alert)
                    new_alerts.append(alert)

        # 4. Command-and-Control (C2) Detection
        if self.c2_detector is not None:
            c2_evidences = await self.runner.run_safe(
                detector_name="c2_detector",
                coro=self.c2_detector.detect_c2_establishment(
                    agent_id=agent_id,
                    time_window=(win_start, win_end),
                ),
                fallback=[],
            )
            for c2 in c2_evidences:
                sev = self.alert_bus.map_c2_severity(c2)
                alert = Alert(
                    alert_id=uuid.uuid4(),
                    timestamp=utc_now(),
                    severity=sev,
                    threat_type="c2_infrastructure",
                    title="C2 Infrastructure Establishment Detected",
                    description=f"Agent {agent_id} connected to C2 endpoints: {c2.c2_endpoints}",
                    agent_id=agent_id,
                    evidence={
                        "c2_endpoints": c2.c2_endpoints,
                        "communication_pattern": c2.communication_pattern,
                        "persistence_indicators": c2.persistence_indicators,
                    },
                )
                await self.alert_bus.publish(alert)
                new_alerts.append(alert)

        # 5. Kubernetes Container Defense Layer
        if self.k8s_defense is not None:
            k8s_evidences = await self.runner.run_safe(
                detector_name="k8s_defense",
                coro=self.k8s_defense.detect_pod_token_theft(
                    agent_id=agent_id,
                    time_window=(win_start, win_end),
                ),
                fallback=[],
            )
            for k8s in k8s_evidences:
                sev = self.alert_bus.map_k8s_severity(k8s)
                alert = Alert(
                    alert_id=uuid.uuid4(),
                    timestamp=utc_now(),
                    severity=sev,
                    threat_type="k8s_threat",
                    title=f"Kubernetes Container Threat: {k8s.threat_type}",
                    description=f"K8s threat detected in pod {k8s.pod_name} (namespace: {k8s.namespace})",
                    agent_id=agent_id,
                    evidence=k8s.evidence,
                )
                await self.alert_bus.publish(alert)
                new_alerts.append(alert)

        return new_alerts

    async def get_attack_graph(
        self,
        agent_id: Optional[str] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        risk_threshold: float = 0.0,
        limit: int = 100,
    ) -> List[AttackNode]:
        """Retrieve attack graph nodes matching specified query filters."""
        if time_range is not None:
            start_w, end_w = time_range
            start_w = validate_utc_datetime(start_w)
            end_w = validate_utc_datetime(end_w)
        else:
            start_w = datetime.min.replace(tzinfo=UTC)
            end_w = datetime.max.replace(tzinfo=UTC)

        nodes = await self.store.query_nodes(
            agent_id=agent_id,
            time_window=(start_w, end_w),
            limit=limit,
        )
        if risk_threshold > 0.0:
            nodes = [n for n in nodes if n.event.risk_score >= risk_threshold]
        return nodes

    def get_active_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        threat_type: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieve filtered active alerts from the AlertBus."""
        return self.alert_bus.get_alerts(
            severity=severity,
            threat_type=threat_type,
            agent_id=agent_id,
        )
