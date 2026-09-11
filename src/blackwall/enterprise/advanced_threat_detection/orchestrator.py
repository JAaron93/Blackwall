"""AdvancedThreatDetection main orchestrator component for Blackwall Pillar 6 (Task 21).

Wires EventStreamCollector, AttackGraphStore, AlertBus, SafeDetectionRunner,
ResourceThrottler, and all detection engines into a unified system entry point.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import logging
import re
from typing import Any, List, Optional, Tuple, Union
import uuid

from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
    InboundMethodType,
    InboundProtocolType,
    InjectionSourceType,
    ReactionActionType,
)
from blackwall.enterprise.advanced_threat_detection.evaluation import (
    EvaluationEnvironmentManager,
)
from blackwall.enterprise.advanced_threat_detection.covert_channel import (
    CovertChannelDetector,
)
from blackwall.enterprise.advanced_threat_detection.exploit import ExploitChainAnalyzer
from blackwall.enterprise.advanced_threat_detection.inbound_filter import (
    InboundProtocolFilter,
)
from blackwall.enterprise.advanced_threat_detection.k8s import KubernetesDefenseLayer
from blackwall.enterprise.advanced_threat_detection.models import (
    ActiveReactionPayload,
    AgentQuotaUsage,
    Alert,
    AttackNode,
    AttackPath,
    InboundProtocolMessage,
    NormalizedEvent,
    PromptInjectionEvidence,
    RegistryThreatEvidence,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.prompt_injection import (
    PromptInjectionScanner,
)
from blackwall.enterprise.advanced_threat_detection.quota_enforcer import (
    AgentQuotaEnforcer,
)
from blackwall.enterprise.advanced_threat_detection.reaction import (
    ActiveReactionEngine,
)
from blackwall.enterprise.advanced_threat_detection.registry import (
    PackageRegistryMonitor,
)
from blackwall.enterprise.advanced_threat_detection.resilience import (
    ResourceThrottler,
    SafeDetectionRunner,
)
from blackwall.enterprise.advanced_threat_detection.retrospective import (
    RetrospectiveAnalyzer,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.validators import normalize_time_window, utc_now, validate_utc_datetime

try:
    import psutil

    _PROCESS = psutil.Process()
except Exception:
    _PROCESS = None


def _get_current_memory_mb() -> float:
    """Return resident set size memory in MB if psutil is available."""
    if _PROCESS is not None:
        try:
            return _PROCESS.memory_info().rss / (1024.0 * 1024.0)
        except Exception:
            return 0.0
    return 0.0


@dataclass
class CorrelationCycleState:
    """State tracking for explicit agent correlation cycles."""

    last_activity: datetime
    completed: bool = False
    keys: set[tuple[Any, frozenset[str], datetime, datetime]] = field(
        default_factory=set
    )


logger = logging.getLogger(
    "blackwall.enterprise.advanced_threat_detection.orchestrator"
)


class AdvancedThreatDetection:
    """Unified entry point and orchestrator for Blackwall Advanced Threat Detection (Pillar 6)."""

    def __init__(
        self,
        config: Optional[AdvancedThreatDetectionConfig] = None,
        stream_factories: Optional[dict[EventSource, Callable[[], Any]]] = None,
        kernel_driver: Optional[Any] = None,
        mesh_broadcaster: Optional[Any] = None,
        vault_adapter: Optional[Any] = None,
        eval_manager: Optional[EvaluationEnvironmentManager] = None,
        active_reaction: Optional[ActiveReactionEngine] = None,
        inbound_filter: Optional[InboundProtocolFilter] = None,
        prompt_injection_scanner: Optional[PromptInjectionScanner] = None,
        quota_enforcer: Optional[AgentQuotaEnforcer] = None,
    ) -> None:
        self.config = config or AdvancedThreatDetectionConfig()
        self._running = False
        self._lock = asyncio.Lock()
        self._stream_factories: dict[EventSource, Callable[[], Any]] = dict(
            stream_factories or {}
        )
        self._stream_tasks: dict[EventSource, asyncio.Task[Any]] = {}
        self._stream_generations: dict[EventSource, int] = {}
        self.eval_manager = eval_manager

        # Core subsystem infrastructure configured per runtime config
        self.store = AttackGraphStore(
            dsn=self.config.database_url,
            in_memory=self.config.in_memory,
            min_pool_size=self.config.min_connections,
            max_pool_size=self.config.max_connections,
        )
        self.collector = EventStreamCollector(
            reconnect_max_attempts=self.config.reconnect_max_attempts,
            reconnect_backoff_base=self.config.reconnect_backoff_base,
        )
        self.alert_bus = AlertBus(
            history_capacity=self.config.event_buffer_size,
            batch_size=self.config.alert_batch_size,
            flush_interval_seconds=self.config.alert_flush_interval_seconds,
        )
        self.runner = SafeDetectionRunner(
            default_timeout_seconds=self.config.safe_execution_timeout,
        )
        self.throttler = ResourceThrottler(
            max_events_per_second=self.config.max_events_per_second,
            max_queue_size=self.config.event_buffer_size,
            max_memory_mb=self.config.max_memory_mb,
        )

        # Detection engines (wired conditionally per configuration)
        self.path_correlator: Optional[PathCorrelator] = (
            PathCorrelator(store=self.store)
            if self.config.enable_path_correlation
            else None
        )
        self.covert_channel_detector: Optional[CovertChannelDetector] = (
            CovertChannelDetector(min_agents=self.config.swarm_min_agents)
            if self.config.enable_swarm_detection
            else None
        )
        self.swarm_detector: Optional[AgentSwarmDetector] = (
            AgentSwarmDetector(
                store=self.store,
                default_window=int(self.config.temporal_window_seconds),
                default_min_agents=self.config.swarm_min_agents,
                default_correlation_threshold=self.config.swarm_correlation_threshold,
                covert_channel_detector=self.covert_channel_detector,
                alert_bus=self.alert_bus,
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
            AILMTracker(store=self.store) if self.config.enable_ailm_tracking else None
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

        # Breach Defense & Active Mitigation Engines (wired conditionally)
        self.active_reaction: Optional[ActiveReactionEngine] = (
            active_reaction
            if active_reaction is not None
            else (
                ActiveReactionEngine(
                    kernel_driver=kernel_driver,
                    mesh_broadcaster=mesh_broadcaster,
                    vault_adapter=vault_adapter,
                    alert_bus=self.alert_bus,
                    attack_graph=self.store,
                    eval_manager=self.eval_manager,
                )
                if self.config.enable_active_reaction
                else None
            )
        )
        self.inbound_filter: Optional[InboundProtocolFilter] = (
            inbound_filter
            if inbound_filter is not None
            else (
                InboundProtocolFilter(
                    alert_bus=self.alert_bus,
                    rate_limit_per_window=self.config.inbound_rate_limit,
                    sliding_window_sec=self.config.inbound_sliding_window_sec,
                    enforce_loopback=self.config.inbound_enforce_loopback,
                )
                if self.config.enable_inbound_filter
                else None
            )
        )
        self.prompt_injection_scanner: Optional[PromptInjectionScanner] = (
            prompt_injection_scanner
            if prompt_injection_scanner is not None
            else (
                PromptInjectionScanner(
                    alert_bus=self.alert_bus,
                    confidence_threshold=self.config.prompt_injection_confidence_threshold,
                    critical_confidence_threshold=self.config.prompt_injection_critical_threshold,
                    redaction_placeholder=self.config.prompt_injection_redaction_placeholder,
                )
                if self.config.enable_prompt_injection
                else None
            )
        )
        self.quota_enforcer: Optional[AgentQuotaEnforcer] = (
            quota_enforcer
            if quota_enforcer is not None
            else (
                AgentQuotaEnforcer(
                    alert_bus=self.alert_bus,
                    token_burn_rate_limit=self.config.quota_token_burn_rate_limit,
                    request_velocity_limit=self.config.quota_request_velocity_limit,
                    sliding_window_sec=self.config.quota_sliding_window_sec,
                    quarantine_duration_sec=self.config.quota_quarantine_duration_sec,
                )
                if self.config.enable_quota_enforcer
                else None
            )
        )
        self._published_covert_keys: dict[
            tuple[Any, frozenset[str], datetime, datetime], datetime
        ] = {}
        self._published_covert_cycles: dict[str, CorrelationCycleState] = {}

    @property
    def reaction_engine(self) -> Optional[ActiveReactionEngine]:
        """Alias property for active reaction engine."""
        return self.active_reaction

    @property
    def injection_scanner(self) -> Optional[PromptInjectionScanner]:
        """Alias property for prompt injection scanner."""
        return self.prompt_injection_scanner

    def register_pillar_stream(
        self,
        source: EventSource,
        stream_factory: Callable[[], Any],
    ) -> None:
        """Register a pillar event stream factory for automatic background collection."""
        self._stream_factories[source] = stream_factory
        if self._running:
            old_task = self._stream_tasks.get(source)
            self._stream_generations[source] = (
                self._stream_generations.get(source, 0) + 1
            )
            gen = self._stream_generations[source]
            if old_task and not old_task.done():
                old_task.cancel()
            task = asyncio.create_task(
                self._run_pillar_stream(source, stream_factory, gen)
            )
            self._stream_tasks[source] = task

    async def _run_pillar_stream(
        self,
        source: EventSource,
        stream_factory: Callable[[], Any],
        generation: int,
    ) -> None:
        """Continuously collect and ingest events from a registered pillar stream."""
        try:
            async for event in self.collector.collect_with_reconnect(
                source, stream_factory
            ):
                if (
                    not self._running
                    or self._stream_generations.get(source) != generation
                ):
                    break
                await self.ingest_event(event, source_generation=generation)
                if (
                    not self._running
                    or self._stream_generations.get(source) != generation
                ):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning(
                "Background collection for pillar stream %s terminated: %s",
                source,
                exc,
            )

    async def enforce_retention(self) -> int:
        """Purge events older than configured retention_period_days from attack graph store."""
        if self.config.retention_period_days <= 0:
            return 0
        cutoff = utc_now() - timedelta(days=self.config.retention_period_days)
        return await self.store.purge_events_before(cutoff)

    @property
    def is_running(self) -> bool:
        """Return boolean indicating if the orchestrator is currently running."""
        return self._running

    async def start(self) -> None:
        """Initialize store, start components, enforce retention, and start pillar collection."""
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

            # Enforce data retention policy upon startup
            if self.config.retention_period_days > 0:
                try:
                    await self.enforce_retention()
                except Exception as ret_exc:
                    logger.warning(
                        "Failed to enforce retention during startup: %s", ret_exc
                    )

            self._running = True

            # Start background alert bus flushing loop
            await self.alert_bus.start()

            # Start background collection tasks for all registered pillar streams
            for source, factory in self._stream_factories.items():
                if (
                    source in self._stream_tasks
                    and not self._stream_tasks[source].done()
                ):
                    self._stream_tasks[source].cancel()
                self._stream_generations[source] = (
                    self._stream_generations.get(source, 0) + 1
                )
                gen = self._stream_generations[source]
                task = asyncio.create_task(
                    self._run_pillar_stream(source, factory, gen)
                )
                self._stream_tasks[source] = task

            logger.info("AdvancedThreatDetection orchestrator started successfully")

    async def stop(self) -> None:
        """Gracefully shutdown orchestrator, close connections, and flush buffers."""
        async with self._lock:
            if not self._running:
                return

            self._running = False
            self._stream_generations.clear()

            # Cancel and await all active pillar collection streams
            tasks_to_cancel = [t for t in self._stream_tasks.values() if not t.done()]
            for task in tasks_to_cancel:
                try:
                    task.cancel()
                except RuntimeError:
                    pass
            if tasks_to_cancel:
                try:
                    active_tasks = [
                        t for t in tasks_to_cancel if not t.get_loop().is_closed()
                    ]
                    if active_tasks:
                        await asyncio.wait_for(
                            asyncio.gather(*active_tasks, return_exceptions=True),
                            timeout=2.0,
                        )
                except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                    pass
            self._stream_tasks.clear()

            await self.alert_bus.stop()
            await self.store.close()
            self._published_covert_keys.clear()
            self._published_covert_cycles.clear()
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
        source_generation: Optional[int] = None,
    ) -> NormalizedEvent:
        """Ingest security event passively and non-blockingly into graph store and pipeline.

        Supports both (EventSource, raw_dict) and pre-normalized (NormalizedEvent) signatures.
        """
        if isinstance(source_or_event, NormalizedEvent):
            normalized = source_or_event
        else:
            if raw_event is None:
                raise ValueError(
                    "raw_event dictionary must be provided when source is EventSource"
                )
            normalized = self.collector.normalize_event(source_or_event, raw_event)

        # Check generation ownership to prevent stale or superseded stream tasks from mutating state
        if source_generation is not None and (
            not self._running
            or self._stream_generations.get(normalized.source) != source_generation
        ):
            return normalized

        # Record throughput and evaluate resource throttling
        self.throttler.record_event()
        mem_mb = _get_current_memory_mb()
        if self.throttler.should_throttle(current_memory_mb=mem_mb):
            logger.warning(
                "AdvancedThreatDetection throttling active (rate=%.1f/s, memory=%.1fMB); dynamic analysis depth degradation will apply during correlation",
                self.throttler.current_rate(),
                mem_mb,
            )

        # Persist event in attack graph store
        await self.store.insert_event(normalized)

        # Feed auxiliary stateful detectors only if stream generation remains current
        if source_generation is not None and (
            not self._running
            or self._stream_generations.get(normalized.source) != source_generation
        ):
            return normalized

        if self.c2_detector is not None:
            if normalized.agent_id not in self.c2_detector._events_by_agent:
                self.c2_detector._events_by_agent[normalized.agent_id] = []
            self.c2_detector._events_by_agent[normalized.agent_id].append(normalized)

        if self.k8s_defense is not None:
            target_str = (normalized.target or "").lower()
            if (
                "k8s" in target_str
                or "kubernetes" in target_str
                or "secrets" in target_str
                or "pod" in target_str
            ):
                await self.k8s_defense.track_k8s_api_access(normalized)

        return normalized

    async def _publish_alerts(
        self, alerts: Sequence[Alert], target_list: List[Alert]
    ) -> List[Alert]:
        """Publish alerts matching minimum severity threshold via batch alert delivery."""
        sev_order = {
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4,
        }
        min_threshold = sev_order.get(self.config.alert_min_severity, 1)
        qualifying = [
            a for a in alerts if sev_order.get(a.severity, 1) >= min_threshold
        ]
        if qualifying:
            await self.alert_bus.publish_batch(qualifying)
            target_list.extend(qualifying)
        return qualifying

    async def _publish_alert(self, alert: Alert, target_list: List[Alert]) -> None:
        """Publish alert if it meets minimum severity threshold."""
        await self._publish_alerts([alert], target_list)

    async def correlate_agent_threats(
        self,
        agent_id: str,
        time_window: Optional[Tuple[datetime, datetime]] = None,
        cycle_id: str | None = None,
    ) -> List[Alert]:
        """Run all enabled detection engines safely for an agent within the specified time window."""
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")

        win_start, win_end = normalize_time_window(
            time_window, default_duration_seconds=self.config.temporal_window_seconds
        )

        mem_mb = _get_current_memory_mb()
        is_throttled = self.throttler.should_throttle(current_memory_mb=mem_mb)

        # When under severe resource pressure, adaptively degrade analysis window
        # for detection queries if no explicit time window was specified
        effective_start = win_start
        if is_throttled and time_window is None:
            degraded_secs = max(1.0, self.config.temporal_window_seconds * 0.5)
            effective_start = win_end - timedelta(seconds=degraded_secs)

        new_alerts: List[Alert] = []

        # 1. Multi-Stage Attack Path Correlation
        if self.path_correlator is not None:
            max_d = self.throttler.get_analysis_depth(
                base_depth=10, current_memory_mb=mem_mb
            )
            paths: List[AttackPath] = await self.runner.run_safe(
                detector_name="path_correlator",
                coro=self.path_correlator.correlate_attack_paths(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
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
                    await self._publish_alert(alert, new_alerts)
                    if (
                        sev == AlertSeverity.CRITICAL
                        and self.active_reaction is not None
                    ):
                        ebpf_payload = ActiveReactionPayload(
                            trigger_evidence_id=path.path_id,
                            target_agent_id=agent_id,
                            action_type=ReactionActionType.EBPF_DROP,
                            metadata={
                                "threat_type": "attack_path",
                                "risk_score": path.risk_score,
                            },
                        )
                        try:
                            await self.active_reaction.execute_ebpf_socket_drop(
                                ebpf_payload
                            )
                        except Exception as exc:
                            logger.error(
                                "Active reaction (eBPF drop) failed for attack_path %s: %s",
                                path.path_id,
                                exc,
                            )
                        mesh_payload = ActiveReactionPayload(
                            trigger_evidence_id=path.path_id,
                            target_agent_id=agent_id,
                            action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
                            metadata={
                                "threat_type": "attack_path",
                                "risk_score": path.risk_score,
                            },
                        )
                        try:
                            await self.active_reaction.broadcast_fleet_signature(
                                mesh_payload
                            )
                        except Exception as exc:
                            logger.error(
                                "Active reaction (mesh broadcast) failed for attack_path %s: %s",
                                path.path_id,
                                exc,
                            )

        # 2. Zero-Day Exploit Chain Analysis
        if self.exploit_analyzer is not None:
            chains = await self.runner.run_safe(
                detector_name="exploit_analyzer",
                coro=self.exploit_analyzer.detect_chains(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
                ),
                fallback=[],
            )
            for chain in chains:
                if (
                    chain.novelty_score >= self.config.exploit_novelty_threshold
                    or chain.chaining_confidence >= 0.5
                ):
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
                            "exploits": [
                                str(cat.value) if hasattr(cat, "value") else str(cat)
                                for _, cat in chain.exploits
                            ],
                        },
                    )
                    await self._publish_alert(alert, new_alerts)
                    if (
                        sev == AlertSeverity.CRITICAL
                        and self.active_reaction is not None
                    ):
                        ebpf_payload = ActiveReactionPayload(
                            trigger_evidence_id=chain.chain_id,
                            target_agent_id=agent_id,
                            action_type=ReactionActionType.EBPF_DROP,
                            metadata={
                                "threat_type": "exploit_chain",
                                "novelty_score": chain.novelty_score,
                            },
                        )
                        try:
                            await self.active_reaction.execute_ebpf_socket_drop(
                                ebpf_payload
                            )
                        except Exception as exc:
                            logger.error(
                                "Active reaction (eBPF drop) failed for exploit_chain %s: %s",
                                chain.chain_id,
                                exc,
                            )
                        mesh_payload = ActiveReactionPayload(
                            trigger_evidence_id=chain.chain_id,
                            target_agent_id=agent_id,
                            action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
                            metadata={
                                "threat_type": "exploit_chain",
                                "novelty_score": chain.novelty_score,
                            },
                        )
                        try:
                            await self.active_reaction.broadcast_fleet_signature(
                                mesh_payload
                            )
                        except Exception as exc:
                            logger.error(
                                "Active reaction (mesh broadcast) failed for exploit_chain %s: %s",
                                chain.chain_id,
                                exc,
                            )

        # 3. AI-Induced Lateral Movement (AILM)
        if self.ailm_tracker is not None:
            ailm_evidences = await self.runner.run_safe(
                detector_name="ailm_tracker",
                coro=self.ailm_tracker.detect_permission_composition(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
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
                    await self._publish_alert(alert, new_alerts)
                    if (
                        sev in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)
                        and self.active_reaction is not None
                    ):
                        vault_payload = ActiveReactionPayload(
                            trigger_evidence_id=alert.alert_id,
                            target_agent_id=agent_id,
                            action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
                            metadata={
                                "threat_type": "ailm",
                                "risk_level": ailm.risk_level,
                                "boundary_crossings": ailm.boundary_crossings,
                            },
                        )
                        try:
                            await self.active_reaction.revoke_identity_session(
                                vault_payload
                            )
                        except Exception as exc:
                            logger.error(
                                "Active reaction (vault revocation) failed for ailm agent %s: %s",
                                agent_id,
                                exc,
                            )

        # 4. Command-and-Control (C2) Detection
        if self.c2_detector is not None:
            c2_evidences = await self.runner.run_safe(
                detector_name="c2_detector",
                coro=self.c2_detector.detect_c2_establishment(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
                    beaconing_threshold=self.config.c2_beaconing_threshold,
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
                await self._publish_alert(alert, new_alerts)

        # 5. Kubernetes Container Defense Layer
        if self.k8s_defense is not None:
            # Token theft
            token_theft_evidences = await self.runner.run_safe(
                detector_name="k8s_defense_token_theft",
                coro=self.k8s_defense.detect_pod_token_theft(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
                ),
                fallback=[],
            )
            # Secrets exfiltration
            secrets_evidences = await self.runner.run_safe(
                detector_name="k8s_defense_secrets_exfiltration",
                coro=self.k8s_defense.detect_secrets_exfiltration(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
                    min_secret_reads=self.config.k8s_min_exfiltration_events,
                ),
                fallback=[],
            )
            for k8s in token_theft_evidences + secrets_evidences:
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
                await self._publish_alert(alert, new_alerts)

        # 6. Coordinated Multi-Agent Swarm Detection
        if self.swarm_detector is not None:
            swarms: List[SwarmEvidence] = await self.runner.run_safe(
                detector_name="swarm_detector",
                coro=self.swarm_detector.detect_swarms(
                    time_window=(effective_start, win_end),
                    min_agents=self.config.swarm_min_agents,
                    correlation_threshold=self.config.swarm_correlation_threshold,
                ),
                fallback=[],
            )
            for swarm in swarms:
                if agent_id in swarm.agent_ids:
                    sev = self.alert_bus.map_swarm_severity(swarm)
                    alert = Alert(
                        alert_id=uuid.uuid4(),
                        timestamp=utc_now(),
                        severity=sev,
                        threat_type="agent_swarm",
                        title=f"Coordinated Agent Swarm Detected ({len(swarm.agent_ids)} agents)",
                        description=f"Coordinated swarm behavior detected involving agent {agent_id} (coordination score: {swarm.coordination_score:.2f})",
                        evidence_id=swarm.swarm_id,
                        agent_id=agent_id,
                        agent_ids=list(swarm.agent_ids),
                        evidence={
                            "coordination_score": swarm.coordination_score,
                            "temporal_correlation": swarm.temporal_correlation,
                            "shared_patterns": swarm.shared_patterns,
                            "agent_ids": list(swarm.agent_ids),
                        },
                    )
                    await self._publish_alert(alert, new_alerts)
                    if (
                        sev == AlertSeverity.CRITICAL
                        and self.active_reaction is not None
                    ):
                        for aid in swarm.agent_ids:
                            ebpf_payload = ActiveReactionPayload(
                                trigger_evidence_id=swarm.swarm_id,
                                target_agent_id=aid,
                                action_type=ReactionActionType.EBPF_DROP,
                                metadata={
                                    "threat_type": "agent_swarm",
                                    "coordination_score": swarm.coordination_score,
                                },
                            )
                            try:
                                await self.active_reaction.execute_ebpf_socket_drop(
                                    ebpf_payload
                                )
                            except Exception as exc:
                                logger.error(
                                    "Active reaction (eBPF drop) failed for swarm agent %s: %s",
                                    aid,
                                    exc,
                                )
                            mesh_payload = ActiveReactionPayload(
                                trigger_evidence_id=swarm.swarm_id,
                                target_agent_id=aid,
                                action_type=ReactionActionType.MESH_SIGNATURE_BROADCAST,
                                metadata={
                                    "threat_type": "agent_swarm",
                                    "coordination_score": swarm.coordination_score,
                                },
                            )
                            try:
                                await self.active_reaction.broadcast_fleet_signature(
                                    mesh_payload
                                )
                            except Exception as exc:
                                logger.error(
                                    "Active reaction (mesh broadcast) failed for swarm agent %s: %s",
                                    aid,
                                    exc,
                                )
                            vault_payload = ActiveReactionPayload(
                                trigger_evidence_id=swarm.swarm_id,
                                target_agent_id=aid,
                                action_type=ReactionActionType.REVOKE_IDENTITY_TOKENS,
                                metadata={
                                    "threat_type": "agent_swarm",
                                    "coordination_score": swarm.coordination_score,
                                },
                            )
                            try:
                                await self.active_reaction.revoke_identity_session(
                                    vault_payload
                                )
                            except Exception as exc:
                                logger.error(
                                    "Active reaction (vault revocation) failed for swarm agent %s: %s",
                                    aid,
                                    exc,
                                )

                    # Publish covert channel alerts directly from this swarm's scoped evidence
                    for covert_channel in getattr(swarm, "covert_channels", []):
                        if agent_id in covert_channel.coordinating_agents:
                            dedup_key = (
                                covert_channel.channel_type,
                                frozenset(covert_channel.coordinating_agents),
                                covert_channel.first_detected,
                                covert_channel.last_detected,
                            )
                            now = utc_now()
                            cooldown = getattr(
                                self.config,
                                "covert_channel_dedup_cooldown_seconds",
                                30.0,
                            )
                            last_published = self._published_covert_keys.get(dedup_key)

                            # Suppress per-agent duplicates within one correlation cycle without suppressing subsequent detections of an ongoing channel
                            is_duplicate = False
                            if cycle_id is not None:
                                cycle_state = self._published_covert_cycles.get(
                                    cycle_id
                                )
                                if isinstance(cycle_state, CorrelationCycleState):
                                    cycle_state.last_activity = now
                                    is_duplicate = dedup_key in cycle_state.keys
                                elif isinstance(cycle_state, set):
                                    is_duplicate = dedup_key in cycle_state
                                elif (
                                    isinstance(cycle_state, tuple)
                                    and len(cycle_state) == 2
                                ):
                                    is_duplicate = dedup_key in cycle_state[1]
                            elif last_published is not None:
                                is_duplicate = (
                                    now - last_published
                                ).total_seconds() < cooldown

                            if not is_duplicate:
                                self._published_covert_keys[dedup_key] = now
                                if cycle_id is not None:
                                    # Evict completed cycles or cycles whose activity has timed out beyond cycle_ttl
                                    if len(self._published_covert_cycles) >= 100:
                                        cycle_ttl = max(
                                            300.0,
                                            self.config.temporal_window_seconds * 2,
                                        )
                                        expired_or_completed = []
                                        for (
                                            cid,
                                            state,
                                        ) in self._published_covert_cycles.items():
                                            if isinstance(state, CorrelationCycleState):
                                                if (
                                                    state.completed
                                                    or (
                                                        now - state.last_activity
                                                    ).total_seconds()
                                                    >= cycle_ttl
                                                ):
                                                    expired_or_completed.append(cid)
                                            elif (
                                                isinstance(state, tuple)
                                                and len(state) == 2
                                            ):
                                                if (
                                                    now - state[0]
                                                ).total_seconds() >= cycle_ttl:
                                                    expired_or_completed.append(cid)
                                        for cid in expired_or_completed:
                                            del self._published_covert_cycles[cid]

                                    cycle_state = self._published_covert_cycles.get(
                                        cycle_id
                                    )
                                    if isinstance(cycle_state, CorrelationCycleState):
                                        cycle_state.last_activity = now
                                        cycle_state.keys.add(dedup_key)
                                    elif isinstance(cycle_state, set):
                                        cycle_state.add(dedup_key)
                                    else:
                                        self._published_covert_cycles[cycle_id] = (
                                            CorrelationCycleState(
                                                last_activity=now,
                                                completed=False,
                                                keys={dedup_key},
                                            )
                                        )
                                covert_alert = (
                                    self.alert_bus.generate_covert_channel_alert(
                                        covert_channel
                                    )
                                )
                                await self._publish_alert(covert_alert, new_alerts)

                            # Evict expired dedup keys beyond 2x cooldown window to prevent memory leaks
                            if len(self._published_covert_keys) > 1000:
                                cutoff = now - timedelta(seconds=cooldown * 2)
                                self._published_covert_keys = {
                                    k: v
                                    for k, v in self._published_covert_keys.items()
                                    if v >= cutoff
                                }

        # 7. Package Registry Exploit Probing & Monitoring
        if self.registry_monitor is not None:
            reg_evidences: List[RegistryThreatEvidence] = await self.runner.run_safe(
                detector_name="registry_monitor",
                coro=self.registry_monitor.detect_exploit_probing(
                    agent_id=agent_id,
                    time_window=(effective_start, win_end),
                ),
                fallback=[],
            )
            unique_event_ids: set[str] = set()
            untracked_probes = 0
            for r in reg_evidences:
                if getattr(r, "event_ids", None):
                    unique_event_ids.update(r.event_ids)
                else:
                    count = getattr(r, "probing_event_count", None)
                    if count is not None and count > 0:
                        untracked_probes += count
                    else:
                        evidence_probes = 0
                        for ind in r.exploit_indicators:
                            m = re.search(r"(\d+)\s+consecutive\s+404\s+responses", ind)
                            if m:
                                evidence_probes += int(m.group(1))
                            else:
                                evidence_probes += 1
                        untracked_probes += max(evidence_probes, 1)

            total_probing_events = len(unique_event_ids) + untracked_probes

            # Threshold matches on total probing events count or known CVE detections
            if total_probing_events >= self.config.registry_min_probing_events or any(
                r.cve_candidates for r in reg_evidences
            ):
                for reg in reg_evidences:
                    conf = 0.85 if reg.cve_candidates else 0.5
                    sev = self.alert_bus.map_registry_severity(
                        reg, exploit_confidence=conf
                    )
                    alert = Alert(
                        alert_id=uuid.uuid4(),
                        timestamp=utc_now(),
                        severity=sev,
                        threat_type="registry_threat",
                        title=f"Package Registry Exploit Probing Detected ({reg.registry_type})",
                        description=f"Package registry exploit probing detected for agent {agent_id} on {reg.package_name}",
                        agent_id=agent_id,
                        evidence={
                            "registry_type": reg.registry_type,
                            "package_name": reg.package_name,
                            "exploit_indicators": reg.exploit_indicators,
                            "cve_candidates": reg.cve_candidates,
                        },
                    )
                    await self._publish_alert(alert, new_alerts)

        return new_alerts

    def complete_correlation_cycle(self, cycle_id: str) -> None:
        """Mark an explicit correlation cycle as completed, enabling safe deduplication eviction."""
        state = self._published_covert_cycles.get(cycle_id)
        if isinstance(state, CorrelationCycleState):
            state.completed = True
        self._published_covert_cycles.pop(cycle_id, None)

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

    async def inspect_and_sanitize_inbound_rpc(
        self,
        raw_data: str | bytes | dict[str, Any],
        sender_id: str,
        recipient_agent_id: str,
        protocol: InboundProtocolType = InboundProtocolType.MCP_SSE,
        headers: Optional[dict[str, Any]] = None,
        remote_addr: Optional[str] = None,
    ) -> Tuple[Optional[InboundProtocolMessage], Optional[dict[str, Any]]]:
        """Inspect headers, rate-limit, parse, and sanitize incoming RPC request."""
        if self.inbound_filter is None:
            if isinstance(raw_data, dict):
                method_val = raw_data.get("method", "tools/call")
                try:
                    m_type = InboundMethodType(method_val)
                except ValueError:
                    m_type = InboundMethodType.TOOLS_CALL
                return (
                    InboundProtocolMessage(
                        sender_id=sender_id,
                        recipient_agent_id=recipient_agent_id,
                        protocol=protocol,
                        method=m_type,
                        payload=raw_data,
                    ),
                    None,
                )
            return None, {"error": "Inbound filter not enabled"}

        # 1. Validate headers and origin — always enforced to prevent authorization bypass.
        # Callers that omit headers or remote_addr receive safe defaults: an empty headers dict
        # and an empty remote_addr string. The filter's loopback/origin rules then evaluate
        # those defaults, which ensures non-loopback callers cannot skip authorization by
        # simply omitting these optional parameters.
        _headers = headers if headers is not None else {}
        _remote_addr = remote_addr if remote_addr is not None else ""
        allowed = await self.inbound_filter.validate_headers_and_origin(
            headers=_headers, remote_addr=_remote_addr
        )
        if not allowed:
            return None, self.inbound_filter.synthesize_error_response(
                error_code=-32600, message="Unauthorized Origin or Host Header"
            )

        # 2. Enforce rate limiting
        within_limit = await self.inbound_filter.check_inbound_rate_limit(
            sender_id=sender_id
        )
        if not within_limit:
            return None, self.inbound_filter.synthesize_error_response(
                error_code=-32000, message="Inbound rate limit exceeded"
            )

        # 3. Parse and validate JSON-RPC
        msg, err = await self.inbound_filter.parse_and_validate_rpc(
            raw_data=raw_data,
            sender_id=sender_id,
            recipient_agent_id=recipient_agent_id,
            protocol=protocol,
        )
        if err is not None or msg is None:
            return None, err

        # 4. Sanitize parameters
        sanitized_msg = await self.inbound_filter.sanitize_incoming_rpc(msg)
        return sanitized_msg, None

    async def scan_payload_for_injection(
        self,
        content: str,
        source_type: InjectionSourceType,
        agent_id: Optional[str] = None,
    ) -> PromptInjectionEvidence:
        """Scan input payload for indirect prompt injection indicators and sanitize."""
        if self.prompt_injection_scanner is None:
            return PromptInjectionEvidence(
                scan_id=uuid.uuid4(),
                source_context=source_type,
                detected_patterns=["NO_SCANNER_CONFIGURED"],
                injection_confidence=0.0,
                sanitized_content=content,
            )
        return await self.prompt_injection_scanner.scan_payload(
            content=content,
            source_type=source_type,
            agent_id=agent_id,
        )

    async def track_agent_tokens(
        self,
        agent_id: str,
        tokens_used: int,
        api_calls: int = 1,
        timestamp: Optional[datetime] = None,
    ) -> Optional[AgentQuotaUsage]:
        """Record token consumption and compute rolling burn rate."""
        if self.quota_enforcer is None:
            return None
        return await self.quota_enforcer.track_token_consumption(
            agent_id=agent_id,
            tokens_used=tokens_used,
            api_calls=api_calls,
            timestamp=timestamp,
        )

    async def enforce_agent_velocity_limits(
        self,
        agent_id: str,
        auto_quarantine: bool = True,
    ) -> bool:
        """Enforce rate limits and quarantine for an agent. Returns True if exceeded or quarantined."""
        if self.quota_enforcer is None:
            return False
        return await self.quota_enforcer.enforce_quota_limits(
            agent_id=agent_id,
            auto_quarantine=auto_quarantine,
        )

    async def dispatch_threat_mitigation(
        self,
        payload: ActiveReactionPayload,
    ) -> bool:
        """Directly dispatch an active threat reaction mitigation across Pillars 1, 2, or 3."""
        if self.active_reaction is None:
            logger.warning(
                "ActiveReactionEngine not enabled; skipping reaction dispatch"
            )
            return False
        if payload.action_type == ReactionActionType.EBPF_DROP:
            return await self.active_reaction.execute_ebpf_socket_drop(payload)
        elif payload.action_type == ReactionActionType.MESH_SIGNATURE_BROADCAST:
            return await self.active_reaction.broadcast_fleet_signature(payload)
        elif payload.action_type == ReactionActionType.REVOKE_IDENTITY_TOKENS:
            return await self.active_reaction.revoke_identity_session(payload)
        return False
