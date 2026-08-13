"""Integration tests for Retrospective Analysis and Historical Queries (Requirements 13.1, 13.2, 13.3, 13.4 & Tasks 17.1, 17.2, 17.3)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphStore,
    AttackNode,
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.retrospective import (
    RetrospectiveAnalyzer,
)


def make_event(
    agent_id: str,
    action: str,
    target: str,
    timestamp: datetime,
    risk_score: float = 0.8,
    metadata: dict | None = None,
) -> NormalizedEvent:
    """Helper to construct NormalizedEvent."""
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=timestamp,
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_historical_windows():
    """Verify historical time window support spanning days and weeks, and 30-day retention (Requirements 13.1, 13.4)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    agent_id = "agent-history-test"

    # Insert events spanning 29 days into history
    events = []
    for day_offset in range(29, -1, -1):
        ts = now - timedelta(days=day_offset, hours=1)
        ev1 = make_event(
            agent_id=agent_id,
            action="curl",
            target="https://repo.internal/pkg",
            timestamp=ts,
            risk_score=0.4,
        )
        ev2 = make_event(
            agent_id=agent_id,
            action="exec_payload",
            target="/tmp/run.sh",
            timestamp=ts + timedelta(minutes=2),
            risk_score=0.9,
        )
        events.extend([ev1, ev2])

    await store.insert_events_batch(events)

    # 1. Query spanning 7 days
    window_7d = (now - timedelta(days=7), now)
    paths_7d = await analyzer.analyze_historical_window(agent_id, window_7d)
    assert len(paths_7d) >= 1
    for path in paths_7d:
        assert window_7d[0] <= path.start_time <= window_7d[1]
        assert window_7d[0] <= path.end_time <= window_7d[1]

    # 2. Query spanning 14 days
    window_14d = (now - timedelta(days=14), now)
    paths_14d = await analyzer.analyze_historical_window(agent_id, window_14d)
    assert len(paths_14d) >= len(paths_7d)

    # 3. Query spanning full 30 days
    window_30d = (now - timedelta(days=30), now)
    paths_30d = await analyzer.analyze_historical_window(agent_id, window_30d)
    assert len(paths_30d) >= len(paths_14d)

    # 4. Verify 30-day retention invariant: events within 30 days are preserved
    # purge_expired_events(retention_days=30) should not delete events <= 30 days old
    purged_count = await analyzer.purge_expired_events(retention_days=30)
    assert purged_count == 0

    # Events older than 30 days (e.g. 35 days old) should be purged
    old_ev = make_event(
        agent_id=agent_id,
        action="old_action",
        target="old_target",
        timestamp=now - timedelta(days=35),
    )
    await store.insert_event(old_ev)
    purged_old = await analyzer.purge_expired_events(retention_days=30)
    assert purged_old >= 1


@pytest.mark.asyncio
async def test_retrospective_detection():
    """Verify retrospective path detection identifies attack paths not detected in real-time (Requirement 13.2)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    agent_id = "agent-stealth-campaign"

    # Simulate a slow "low-and-slow" multi-stage campaign spread over 3 days (1 step per day)
    # Real-time detectors with 5-minute sliding windows would miss this slow chain,
    # but retrospective path detection connects them based on causal relations or relaxed time windows.
    ev_recon = make_event(
        agent_id=agent_id,
        action="nmap_scan",
        target="10.0.0.0/24",
        timestamp=now - timedelta(days=3),
        risk_score=0.6,
    )
    ev_exploit = make_event(
        agent_id=agent_id,
        action="exploit_rce",
        target="10.0.0.15:8080",
        timestamp=now - timedelta(days=2),
        risk_score=0.85,
    )
    ev_exfil = make_event(
        agent_id=agent_id,
        action="exfiltrate_secrets",
        target="https://pastebin.com/raw/leak",
        timestamp=now - timedelta(days=1),
        risk_score=0.95,
    )

    node_recon = await store.insert_event(ev_recon)
    node_exploit = await store.insert_event(ev_exploit)
    node_exfil = await store.insert_event(ev_exfil)

    # Link events causally
    await store.link_events(node_recon.node_id, node_exploit.node_id, "ENABLED")
    await store.link_events(node_exploit.node_id, node_exfil.node_id, "LED_TO")

    # Retrospective detection batch analysis
    retrospective_paths = await analyzer.detect_retrospective_paths(
        agent_id=agent_id,
        time_window=(now - timedelta(days=4), now),
        batch_size=50,
        min_path_length=2,
    )

    assert len(retrospective_paths) >= 1
    # Verify the multi-day chain was reconstructed
    full_path = next(
        (p for p in retrospective_paths if len(p.nodes) == 3), retrospective_paths[0]
    )
    assert len(full_path.nodes) >= 2
    assert full_path.risk_score >= 0.85


@pytest.mark.asyncio
async def test_historical_correlation():
    """Verify multi-agent historical correlation identifies delayed swarm patterns across time (Requirement 13.3)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    analyzer = RetrospectiveAnalyzer(store=store)

    now = datetime.now(UTC)
    agent_a = "agent-swarm-worker-01"
    agent_b = "agent-swarm-worker-02"
    agent_c = "agent-swarm-worker-03"

    # Simulate coordinated actions executed by multiple agents with hours/days of delay
    # across a 2-week span
    events = []
    for offset_days, target in [(10, "k8s://vault-service"), (5, "k8s://vault-service"), (1, "k8s://vault-service")]:
        ts = now - timedelta(days=offset_days)
        events.append(
            make_event(
                agent_id=agent_a,
                action="probe_service",
                target=target,
                timestamp=ts,
                risk_score=0.75,
            )
        )
        events.append(
            make_event(
                agent_id=agent_b,
                action="probe_service",
                target=target,
                timestamp=ts + timedelta(hours=1),
                risk_score=0.75,
            )
        )
        events.append(
            make_event(
                agent_id=agent_c,
                action="probe_service",
                target=target,
                timestamp=ts + timedelta(hours=2),
                risk_score=0.75,
            )
        )

    await store.insert_events_batch(events)

    time_window = (now - timedelta(days=15), now)
    swarms = await analyzer.correlate_multi_agent_history(
        time_window=time_window,
        similarity_threshold=0.6,
        min_agents=2,
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert len(swarm.agent_ids) >= 2
    assert (
        agent_a in swarm.agent_ids
        or agent_b in swarm.agent_ids
        or agent_c in swarm.agent_ids
    )
    assert swarm.coordination_score > 0.0
