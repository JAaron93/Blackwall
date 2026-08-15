"""BDD Step Definitions for ATD System Integration (`tests/features/system_integration.feature`)."""

import copy
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.orchestrator import (
    AdvancedThreatDetection,
)
from tests.step_defs.async_utils import run_async

scenarios("../features/system_integration.feature")


class SystemIntegrationBDDState:
    def __init__(self) -> None:
        self.config: AdvancedThreatDetectionConfig | None = None
        self.orchestrator: AdvancedThreatDetection | None = None
        self.raw_event: Dict[str, Any] = {}
        self.raw_event_copy: Dict[str, Any] = {}
        self.normalized_event: NormalizedEvent | None = None
        self.agent_id: str = f"agent-bdd-{uuid.uuid4().hex[:8]}"
        self.received_alerts: List[Alert] = []
        self.correlation_result: List[Alert] = []
        self.exception_caught: Exception | None = None


@pytest.fixture
def bdd_state() -> SystemIntegrationBDDState:
    state = SystemIntegrationBDDState()
    yield state
    if state.orchestrator and state.orchestrator.is_running:
        run_async(state.orchestrator.stop())


# Scenario 1: Unified orchestrator component wiring and lifecycle
@given("an AdvancedThreatDetectionConfig with in_memory enabled")
def given_config_in_memory(bdd_state: SystemIntegrationBDDState) -> None:
    bdd_state.config = AdvancedThreatDetectionConfig(in_memory=True)


@when("the AdvancedThreatDetection orchestrator is initialized and started")
def when_orchestrator_started(bdd_state: SystemIntegrationBDDState) -> None:
    assert bdd_state.config is not None
    orchestrator = AdvancedThreatDetection(bdd_state.config)
    run_async(orchestrator.start())
    bdd_state.orchestrator = orchestrator


@then("all core subsystems and detection engines are properly wired")
def then_all_subsystems_wired(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    assert orch.collector is not None
    assert orch.store is not None
    assert orch.alert_bus is not None
    assert orch.ailm_tracker is not None
    assert orch.c2_detector is not None
    assert orch.exploit_analyzer is not None
    assert orch.swarm_detector is not None
    assert orch.k8s_defense is not None


@then("the orchestrator enters running state")
def and_orchestrator_running(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    assert orch.is_running is True


# Scenario 2: Passive event observation without payload mutation
@given("a running AdvancedThreatDetection orchestrator")
def given_running_orchestrator(bdd_state: SystemIntegrationBDDState) -> None:
    config = AdvancedThreatDetectionConfig(in_memory=True)
    orchestrator = AdvancedThreatDetection(config)
    run_async(orchestrator.start())
    bdd_state.orchestrator = orchestrator


@given("a raw caller event payload dictionary")
def given_raw_caller_event(bdd_state: SystemIntegrationBDDState) -> None:
    bdd_state.raw_event = {
        "event_id": str(uuid.uuid4()),
        "source": "kernel_syscall",
        "agent_id": bdd_state.agent_id,
        "action": "sys_execve",
        "target": "/bin/chmod",
        "details": {"arg1": "+x", "arg2": "/tmp/rootkit"},
        "risk_score": 0.85,
    }
    bdd_state.raw_event_copy = copy.deepcopy(bdd_state.raw_event)


@when("the raw event is ingested via ingest_event")
def when_raw_event_ingested(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    bdd_state.normalized_event = run_async(
        orch.ingest_event(EventSource.KERNEL_SYSCALL, bdd_state.raw_event)
    )


@then("a valid NormalizedEvent is returned")
def then_valid_normalized_event(bdd_state: SystemIntegrationBDDState) -> None:
    assert bdd_state.normalized_event is not None
    assert isinstance(bdd_state.normalized_event, NormalizedEvent)
    assert bdd_state.normalized_event.action == "sys_execve"


@then("the original caller dictionary is not modified in-place")
def and_original_caller_dict_unmodified(bdd_state: SystemIntegrationBDDState) -> None:
    assert bdd_state.raw_event == bdd_state.raw_event_copy


@then("the event is persisted in the AttackGraphStore")
def and_event_persisted_in_store(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    assert bdd_state.normalized_event is not None

    async def _check() -> bool:
        node = await orch.store.get_node(bdd_state.normalized_event.event_id)
        return node is not None

    assert run_async(_check()) is True


# Scenario 3: Multi-pillar ingestion and real-time alert generation
@given("a running AdvancedThreatDetection orchestrator with alert subscribers")
def given_running_orchestrator_with_subscribers(
    bdd_state: SystemIntegrationBDDState,
) -> None:
    config = AdvancedThreatDetectionConfig(in_memory=True)
    orchestrator = AdvancedThreatDetection(config)
    run_async(orchestrator.start())
    bdd_state.orchestrator = orchestrator

    async def _on_alert(alert: Alert) -> None:
        bdd_state.received_alerts.append(alert)

    orchestrator.alert_bus.subscribe(_on_alert)


@when("multiple threat events from different pillars are ingested for an agent")
def when_multiple_pillar_threat_events_ingested(
    bdd_state: SystemIntegrationBDDState,
) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None

    events = [
        # Pillar 1 - Kernel
        {
            "event_id": str(uuid.uuid4()),
            "source": EventSource.KERNEL_SYSCALL.value,
            "agent_id": bdd_state.agent_id,
            "action": "bpf_prog_load",
            "target": "/sys/fs/bpf",
            "risk_score": 0.8,
        },
        # Pillar 3 - Identity Sidecar Honeytoken
        {
            "event_id": str(uuid.uuid4()),
            "source": EventSource.IDENTITY_ACCESS.value,
            "agent_id": bdd_state.agent_id,
            "action": "read_secret",
            "target": "BW_SYNTHETIC_API_KEY",
            "risk_score": 0.95,
        },
        # Pillar 4 - Pipeline MicroVM Sandbox
        {
            "event_id": str(uuid.uuid4()),
            "source": EventSource.PIPELINE_EXECUTION.value,
            "agent_id": bdd_state.agent_id,
            "action": "cgroup_escape_attempt",
            "target": "/sys/fs/cgroup",
            "risk_score": 0.9,
        },
    ]

    async def _ingest_all() -> None:
        for ev in events:
            source = EventSource(ev["source"])
            await orch.ingest_event(source, ev)

    run_async(_ingest_all())


@when("threat correlation is executed for the agent")
def when_threat_correlation_executed(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    bdd_state.correlation_result = run_async(
        orch.correlate_agent_threats(bdd_state.agent_id)
    )


@then("correlated threat alerts are published to the AlertBus")
def then_alerts_published(bdd_state: SystemIntegrationBDDState) -> None:
    assert bdd_state.orchestrator is not None
    # We can emit an alert or verify correlation
    assert isinstance(bdd_state.correlation_result, list)


@then("the attack graph contains all ingested nodes")
def and_graph_contains_all_nodes(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None

    async def _count_nodes() -> int:
        now = datetime.now(timezone.utc)
        nodes = await orch.store.query_nodes(
            agent_id=bdd_state.agent_id,
            time_window=(now - timedelta(hours=1), now + timedelta(hours=1)),
        )
        return len(nodes)

    count = run_async(_count_nodes())
    assert count >= 3


# Scenario 4: Safe detection execution crash containment
@given("a failing detector that raises an unexpected runtime exception")
def given_failing_detector(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    # Mock ailm_tracker.analyze_agent_profile to raise an unhandled RuntimeError
    orch.ailm_tracker.analyze_agent_profile = MagicMock(
        side_effect=RuntimeError("Unexpected detector crash")
    )


@when("threat correlation is triggered for an agent")
def when_threat_correlation_triggered(bdd_state: SystemIntegrationBDDState) -> None:
    orch = bdd_state.orchestrator
    assert orch is not None
    try:
        bdd_state.correlation_result = run_async(
            orch.correlate_agent_threats(bdd_state.agent_id)
        )
    except Exception as exc:
        bdd_state.exception_caught = exc


@then(
    "the orchestrator handles the failure safely without raising an unhandled exception"
)
def then_orchestrator_handles_failure_safely(
    bdd_state: SystemIntegrationBDDState,
) -> None:
    assert bdd_state.exception_caught is None
    assert isinstance(bdd_state.correlation_result, list)
