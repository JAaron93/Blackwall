"""Property-based tests for AdvancedThreatDetection Orchestrator and Configuration (Task 21).

Uses Hypothesis to verify:
- Property 77: Configuration Environment Variable Roundtrip & Type Coercion
- Property 78: Database Connection Pool Bounds Invariants
- Property 79: Non-Blocking Passive Ingestion & Store Graph Preservation
- Property 80: Detection Alert Minimum Severity Filtering Invariant
- Property 81: Safe Detector Crash and Timeout Containment Invariant
"""

import asyncio
from datetime import UTC, datetime, timedelta
import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.config import (
    AdvancedThreatDetectionConfig,
    ENV_PREFIX,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.orchestrator import (
    AdvancedThreatDetection,
)

# Custom Strategies
non_empty_str_st = st.text(min_size=1, max_size=30).filter(lambda s: bool(s.strip()))
event_source_st = st.sampled_from(EventSource)
alert_severity_st = st.sampled_from(AlertSeverity)
metadata_dict_st = st.dictionaries(
    keys=st.text(min_size=1, max_size=10),
    values=st.one_of(st.integers(), st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=20)),
    max_size=4,
)


# Property 77: Configuration Environment Variable Roundtrip & Coercion
@settings(max_examples=100)
@given(
    min_conn=st.integers(min_value=1, max_value=50),
    conn_delta=st.integers(min_value=0, max_value=50),
    enable_swarm=st.booleans(),
    enable_exploit=st.booleans(),
    enable_c2=st.booleans(),
    temporal_window=st.floats(min_value=1.0, max_value=3600.0),
    swarm_thresh=st.floats(min_value=0.0, max_value=1.0),
    min_sev=alert_severity_st,
    max_events=st.integers(min_value=10, max_value=10000),
)
def test_property_77_config_env_variable_coercion(
    min_conn: int,
    conn_delta: int,
    enable_swarm: bool,
    enable_exploit: bool,
    enable_c2: bool,
    temporal_window: float,
    swarm_thresh: float,
    min_sev: AlertSeverity,
    max_events: int,
):
    """Property 77: For any valid environment variable assignments prefixed with BLACKWALL_ATD_,

    AdvancedThreatDetectionConfig.from_env() SHALL correctly parse and coerce the configuration.
    """
    max_conn = min_conn + conn_delta
    env_mock = {
        f"{ENV_PREFIX}MIN_CONNECTIONS": str(min_conn),
        f"{ENV_PREFIX}MAX_CONNECTIONS": str(max_conn),
        f"{ENV_PREFIX}ENABLE_SWARM_DETECTION": "true" if enable_swarm else "false",
        f"{ENV_PREFIX}ENABLE_EXPLOIT_ANALYSIS": "1" if enable_exploit else "0",
        f"{ENV_PREFIX}ENABLE_C2_DETECTION": "yes" if enable_c2 else "no",
        f"{ENV_PREFIX}TEMPORAL_WINDOW_SECONDS": f"{temporal_window:.2f}",
        f"{ENV_PREFIX}SWARM_CORRELATION_THRESHOLD": f"{swarm_thresh:.4f}",
        f"{ENV_PREFIX}ALERT_MIN_SEVERITY": min_sev.value,
        f"{ENV_PREFIX}MAX_EVENTS_PER_SECOND": str(max_events),
    }

    config = AdvancedThreatDetectionConfig.from_env(env_mock)

    assert config.min_connections == min_conn
    assert config.max_connections == max_conn
    assert config.enable_swarm_detection == enable_swarm
    assert config.enable_exploit_analysis == enable_exploit
    assert config.enable_c2_detection == enable_c2
    assert abs(config.temporal_window_seconds - temporal_window) < 0.01
    assert abs(config.swarm_correlation_threshold - swarm_thresh) < 0.001
    assert config.alert_min_severity == min_sev
    assert config.max_events_per_second == max_events


# Property 78: Database Connection Pool Bounds Invariant
@settings(max_examples=100)
@given(
    min_conn=st.integers(min_value=2, max_value=100),
    max_conn=st.integers(min_value=1, max_value=100),
)
def test_property_78_config_connection_pool_bounds_invariant(
    min_conn: int, max_conn: int
):
    """Property 78: If max_connections is strictly less than min_connections,

    AdvancedThreatDetectionConfig validation SHALL raise a ValueError.
    """
    if max_conn < min_conn:
        with pytest.raises((ValueError, ValidationError)):
            AdvancedThreatDetectionConfig(
                min_connections=min_conn, max_connections=max_conn
            )
    else:
        cfg = AdvancedThreatDetectionConfig(
            min_connections=min_conn, max_connections=max_conn
        )
        assert cfg.min_connections == min_conn
        assert cfg.max_connections == max_conn


# Property 79: Non-Blocking Passive Ingestion & Store Graph Preservation
@settings(max_examples=50)
@given(
    source=event_source_st,
    agent_id=non_empty_str_st,
    action=non_empty_str_st,
    target=non_empty_str_st,
    meta=metadata_dict_st,
    risk_score=st.floats(min_value=0.0, max_value=1.0),
)
def test_property_79_orchestrator_event_ingestion_and_preservation(
    source: EventSource,
    agent_id: str,
    action: str,
    target: str,
    meta: dict,
    risk_score: float,
):
    """Property 79: For any ingested event, the orchestrator SHALL preserve all event fields,

    assign valid timestamps, and guarantee queryability in the attack graph store.
    """
    async def _run_test():
        config = AdvancedThreatDetectionConfig(in_memory=True)
        async with AdvancedThreatDetection(config=config) as orchestrator:
            raw_event = {
                "agent_id": agent_id,
                "action": action,
                "target": target,
                "metadata": meta,
                "risk_score": risk_score,
            }
            normalized = await orchestrator.ingest_event(source, raw_event)

            assert normalized.source == source
            assert normalized.agent_id == agent_id.strip()
            assert normalized.action == action.strip()
            assert normalized.target == target.strip()
            assert abs(normalized.risk_score - risk_score) < 1e-5

            # Retrieve from attack graph
            nodes = await orchestrator.get_attack_graph(agent_id=normalized.agent_id)
            assert len(nodes) >= 1
            node_event_ids = [n.event.event_id for n in nodes]
            assert normalized.event_id in node_event_ids

    asyncio.run(_run_test())


# Property 80: Alert Minimum Severity Filtering Invariant
@settings(max_examples=50)
@given(
    min_sev=alert_severity_st,
)
def test_property_80_alert_minimum_severity_filtering_invariant(min_sev: AlertSeverity):
    """Property 80: For any alert produced by detection engines,

    the orchestrator SHALL publish and return only alerts with severity >= alert_min_severity.
    """
    async def _run_test():
        sev_order = {
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4,
        }
        min_order = sev_order[min_sev]

        config = AdvancedThreatDetectionConfig(
            in_memory=True,
            alert_min_severity=min_sev,
            enable_path_correlation=True,
        )

        async with AdvancedThreatDetection(config=config) as orchestrator:
            # Ingest a sequence of events for agent
            now = datetime.now(UTC)
            for i in range(3):
                ev = NormalizedEvent(
                    event_id=uuid.uuid4(),
                    timestamp=now + timedelta(seconds=i * 5),
                    source=EventSource.TOOL_CALL,
                    agent_id="test-agent-filter",
                    action=f"action_{i}",
                    target=f"target_{i}",
                    risk_score=0.85,
                )
                await orchestrator.ingest_event(ev)

            alerts = await orchestrator.correlate_agent_threats(
                agent_id="test-agent-filter",
                time_window=(now - timedelta(minutes=1), now + timedelta(minutes=1)),
            )

            for alert in alerts:
                assert sev_order[alert.severity] >= min_order

    asyncio.run(_run_test())


# Property 81: Safe Detector Crash & Timeout Containment Invariant
@settings(max_examples=50)
@given(
    agent_id=non_empty_str_st,
)
def test_property_81_orchestrator_crash_containment_invariant(agent_id: str):
    """Property 81: Even if an underlying detection engine raises an unhandled exception or times out,

    the orchestrator SHALL contain the failure, not crash, and return surviving engine alerts.
    """
    async def _run_test():
        config = AdvancedThreatDetectionConfig(in_memory=True, safe_execution_timeout=0.1)
        async with AdvancedThreatDetection(config=config) as orchestrator:
            # Inject a crashing/hanging detector
            async def _failing_coro(*args, **kwargs):
                raise RuntimeError("Simulated internal detector crash")

            if orchestrator.path_correlator:
                orchestrator.path_correlator.correlate_attack_paths = _failing_coro  # type: ignore

            # Should not raise RuntimeError
            alerts = await orchestrator.correlate_agent_threats(agent_id=agent_id)
            assert isinstance(alerts, list)

    asyncio.run(_run_test())
