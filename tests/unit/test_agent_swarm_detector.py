"""Unit tests for AgentSwarmDetector (Blackwall Pillar 6 Task 7)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    AttackGraphStore,
    EventSource,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.policy.models import (
    AdvancedThreatDetectionPolicyConfig,
    EnvironmentRoleConfig,
    GlobalConfig,
    MCPServerConfig,
    MCPServersConfig,
    PolicyConfig,
    SwarmDetectorPolicyConfig,
    ThreatSignatureGraphConfig,
)


def create_event(
    agent_id: str = "agent-swarm-01",
    action: str = "exec",
    target: str = "/bin/bash",
    offset_seconds: float = 0.0,
    risk_score: float = 0.5,
    source: EventSource = EventSource.KERNEL_SYSCALL,
    metadata: dict | None = None,
    base_time: datetime | None = None,
) -> NormalizedEvent:
    """Helper to create a UTC-aware NormalizedEvent."""
    if base_time is None:
        base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        source=source,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {"ip": "192.168.1.100", "domain": "c2-domain.com"},
        risk_score=risk_score,
    )


@pytest.mark.asyncio
async def test_fingerprinting():
    """Verify behavioral fingerprint generation using action sequence hashing (Subtask 7.1 / Req 4.1)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    # Insert sequence of events for agent-1
    e1 = create_event(
        agent_id="agent-1",
        action="read_config",
        target="/etc/app.conf",
        offset_seconds=10,
        base_time=base_time,
    )
    e2 = create_event(
        agent_id="agent-1",
        action="spawn_proc",
        target="/bin/sh",
        offset_seconds=20,
        base_time=base_time,
    )
    e3 = create_event(
        agent_id="agent-1",
        action="connect_net",
        target="10.0.0.1:8080",
        offset_seconds=30,
        base_time=base_time,
    )

    await store.insert_event(e1)
    await store.insert_event(e2)
    await store.insert_event(e3)

    fp1 = await detector.fingerprint_agent(
        "agent-1", window=3600, end_time=base_time + timedelta(seconds=60)
    )
    fp1_again = await detector.fingerprint_agent(
        "agent-1", window=3600, end_time=base_time + timedelta(seconds=60)
    )

    assert isinstance(fp1, str)
    assert len(fp1) == 64  # SHA-256 hex string
    assert fp1 == fp1_again  # Deterministic / consistent

    # Different agent with different action sequence must produce different hash
    e4 = create_event(
        agent_id="agent-2",
        action="download",
        target="http://malicious.site",
        offset_seconds=15,
        base_time=base_time,
    )
    await store.insert_event(e4)
    fp2 = await detector.fingerprint_agent(
        "agent-2", window=3600, end_time=base_time + timedelta(seconds=60)
    )

    assert fp1 != fp2


@pytest.mark.asyncio
async def test_temporal_correlation():
    """Verify temporal correlation analysis and swarm detection thresholds (Subtask 7.2 / Reqs 4.2, 4.3)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    # Create 2 agents performing correlated actions closely in time
    for offset in [0, 5, 10, 15]:
        await store.insert_event(
            create_event(
                agent_id="agent-a",
                action="scan",
                target="192.168.1.1",
                offset_seconds=offset,
                base_time=base_time,
            )
        )
        await store.insert_event(
            create_event(
                agent_id="agent-b",
                action="scan",
                target="192.168.1.1",
                offset_seconds=offset + 1,
                base_time=base_time,
            )
        )

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(
        time_win, min_agents=2, correlation_threshold=0.75
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert isinstance(swarm, SwarmEvidence)
    assert swarm.agent_ids == {"agent-a", "agent-b"}
    assert swarm.temporal_correlation >= 0.75
    assert len(swarm.agent_ids) >= 2


@pytest.mark.asyncio
async def test_shared_infrastructure():
    """Verify shared IP, domain, and resource pattern detection across agents (Subtask 7.3 / Req 4.4)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    # Both agents share IP 192.168.1.50 and domain evil.c2.org in metadata/target
    e_a = create_event(
        agent_id="agent-x",
        action="exfil",
        target="evil.c2.org",
        metadata={"ip": "192.168.1.50", "domain": "evil.c2.org"},
        offset_seconds=5,
        base_time=base_time,
    )
    e_b = create_event(
        agent_id="agent-y",
        action="exfil",
        target="evil.c2.org",
        metadata={"ip": "192.168.1.50", "domain": "evil.c2.org"},
        offset_seconds=6,
        base_time=base_time,
    )

    await store.insert_event(e_a)
    await store.insert_event(e_b)

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(
        time_win, min_agents=2, correlation_threshold=0.5
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert len(swarm.shared_patterns) >= 1
    assert (
        "ip:192.168.1.50" in swarm.shared_patterns
        or "domain:evil.c2.org" in swarm.shared_patterns
    )


@pytest.mark.asyncio
async def test_shared_infrastructure_extraction_ipv6():
    """Verify shared IPv6 target extraction across agents in event target and metadata."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    # Both agents connect to public IPv6 endpoint in target
    e_a = create_event(
        agent_id="agent-ipv6-1",
        action="connect",
        target="connect [2607:f8b0:4005:805::200e]:8080",
        metadata={"endpoint": "https://[2607:f8b0:4005:805::200e]:8080/c2"},
        offset_seconds=5,
        base_time=base_time,
    )
    e_b = create_event(
        agent_id="agent-ipv6-2",
        action="connect",
        target="connect [2607:f8b0:4005:805::200e]:8080",
        metadata={"endpoint": "https://[2607:f8b0:4005:805::200e]:8080/c2"},
        offset_seconds=6,
        base_time=base_time,
    )

    await store.insert_event(e_a)
    await store.insert_event(e_b)

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(
        time_win, min_agents=2, correlation_threshold=0.5
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert "ip:2607:f8b0:4005:805::200e" in swarm.shared_patterns


@pytest.mark.asyncio
async def test_public_ipv6_target_suppresses_false_covert_channel_alert():
    """Verify that public IPv6 targets in events populate shared_patterns and suppress false UNLOCATED_MESSAGE_BOARD alerts."""
    from blackwall.enterprise.advanced_threat_detection.covert_channel import (
        CovertChannelDetector,
        CovertChannelType,
    )

    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    covert_detector = CovertChannelDetector(
        min_agents=2,
        min_correlation_threshold=0.5,
        min_coordination_threshold=0.5,
    )
    detector = AgentSwarmDetector(store=store, covert_channel_detector=covert_detector)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    # Coordinated agents communicating with a public IPv6 target
    for offset in [0, 5, 10]:
        await store.insert_event(
            create_event(
                agent_id="agent-ipv6-a",
                action="probe",
                target="connect [2607:f8b0:4005:805::200e]:8080",
                metadata={"protocol": "tcp"},
                offset_seconds=offset,
                base_time=base_time,
            )
        )
        await store.insert_event(
            create_event(
                agent_id="agent-ipv6-b",
                action="probe",
                target="connect [2607:f8b0:4005:805::200e]:8080",
                metadata={"protocol": "tcp"},
                offset_seconds=offset + 0.1,
                base_time=base_time,
            )
        )

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(
        time_win, min_agents=2, correlation_threshold=0.5
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert "ip:2607:f8b0:4005:805::200e" in swarm.shared_patterns
    # Verify covert channels do NOT include false UNLOCATED_MESSAGE_BOARD
    unlocated_alerts = [
        c
        for c in swarm.covert_channels
        if c.channel_type == CovertChannelType.UNLOCATED_MESSAGE_BOARD
    ]
    assert len(unlocated_alerts) == 0


@pytest.mark.asyncio
async def test_private_ipv6_target_does_not_suppress_covert_channel_alert():
    """Verify that private IPv6 targets (e.g. fe80::1) do NOT suppress UNLOCATED_MESSAGE_BOARD alerts."""
    from blackwall.enterprise.advanced_threat_detection.covert_channel import (
        CovertChannelDetector,
        CovertChannelType,
    )

    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    covert_detector = CovertChannelDetector(
        min_agents=2,
        min_correlation_threshold=0.5,
        min_coordination_threshold=0.5,
    )
    detector = AgentSwarmDetector(store=store, covert_channel_detector=covert_detector)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)

    for offset in [0, 5, 10]:
        await store.insert_event(
            create_event(
                agent_id="agent-priv-a",
                action="probe",
                target="connect [fe80::1]:8080",
                metadata={"protocol": "tcp"},
                offset_seconds=offset,
                base_time=base_time,
            )
        )
        await store.insert_event(
            create_event(
                agent_id="agent-priv-b",
                action="probe",
                target="connect [fe80::1]:8080",
                metadata={"protocol": "tcp"},
                offset_seconds=offset + 0.1,
                base_time=base_time,
            )
        )

    time_win = (base_time, base_time + timedelta(seconds=60))
    swarms = await detector.detect_swarms(
        time_win, min_agents=2, correlation_threshold=0.5
    )

    assert len(swarms) >= 1
    swarm = swarms[0]
    assert "ip:fe80::1" in swarm.shared_patterns
    unlocated_alerts = [
        c
        for c in swarm.covert_channels
        if c.channel_type == CovertChannelType.UNLOCATED_MESSAGE_BOARD
    ]
    assert len(unlocated_alerts) >= 1


@pytest.mark.asyncio
async def test_coordination_score():
    """Verify compute_coordination_score analysis and range [0.0, 1.0] (Subtask 7.4 / Reqs 4.5, 15.9)."""
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(store=store)

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    time_win = (base_time, base_time + timedelta(seconds=60))

    # Agents with identical actions at identical times -> high coordination score
    for offset in [0, 5, 10]:
        await store.insert_event(
            create_event(
                agent_id="agent-m",
                action="probe",
                target="target-srv",
                offset_seconds=offset,
                base_time=base_time,
            )
        )
        await store.insert_event(
            create_event(
                agent_id="agent-n",
                action="probe",
                target="target-srv",
                offset_seconds=offset,
                base_time=base_time,
            )
        )

    score = await detector.compute_coordination_score(["agent-m", "agent-n"], time_win)
    assert 0.0 <= score <= 1.0
    assert score >= 0.75


@pytest.mark.asyncio
async def test_policy_configuration_integration():
    """Verify AgentSwarmDetector inherits thresholds from PolicyConfig."""
    policy = PolicyConfig(
        version="1.0.0",
        global_config=GlobalConfig(
            threatThreshold=0.75,
            quarantineThreshold=0.5,
            enableStructuralGating=True,
            enableSemanticGating=True,
        ),
        environmentRoles={
            "sandbox": EnvironmentRoleConfig(
                allowedTools=[],
                blockedTools=[],
                requireSemanticReview=False,
                maxThreatScore=0.8,
            ),
            "production": EnvironmentRoleConfig(
                allowedTools=[],
                blockedTools=[],
                requireSemanticReview=True,
                maxThreatScore=0.5,
            ),
        },
        structuralRules=[],
        semanticGuidelines=[],
        mcpServers=MCPServersConfig(
            gti=MCPServerConfig(
                enabled=True, cacheEnabled=True, cacheTTL=3600, timeout=1000
            ),
            codebaseMemory=MCPServerConfig(
                enabled=True, cacheEnabled=True, cacheTTL=3600, timeout=1000
            ),
        ),
        threatSignatureGraph=ThreatSignatureGraphConfig(
            dbPath="./test.db",
            walMode=True,
            maxConnections=5,
            similarityThreshold=0.8,
            ttlSeconds=3600,
            maxSignatures=1000,
            embeddingDimension=768,
        ),
        advancedThreatDetection=AdvancedThreatDetectionPolicyConfig(
            swarmDetector=SwarmDetectorPolicyConfig(
                windowSeconds=1800,
                minAgents=3,
                correlationThreshold=0.6,
            )
        ),
    )

    detector = AgentSwarmDetector(policy=policy)
    assert detector.default_window == 1800
    assert detector.default_min_agents == 3
    assert detector.default_correlation_threshold == 0.6


@pytest.mark.asyncio
async def test_policy_configuration_default_omission():
    """Verify PolicyConfig provides default AdvancedThreatDetectionPolicyConfig when omitted."""
    policy = PolicyConfig(
        version="1.0.0",
        global_config=GlobalConfig(
            threatThreshold=0.75,
            quarantineThreshold=0.5,
            enableStructuralGating=True,
            enableSemanticGating=True,
        ),
        environmentRoles={
            "sandbox": EnvironmentRoleConfig(
                allowedTools=[],
                blockedTools=[],
                requireSemanticReview=False,
                maxThreatScore=0.8,
            ),
            "production": EnvironmentRoleConfig(
                allowedTools=[],
                blockedTools=[],
                requireSemanticReview=True,
                maxThreatScore=0.5,
            ),
        },
        structuralRules=[],
        semanticGuidelines=[],
        mcpServers=MCPServersConfig(
            gti=MCPServerConfig(
                enabled=True, cacheEnabled=True, cacheTTL=3600, timeout=1000
            ),
            codebaseMemory=MCPServerConfig(
                enabled=True, cacheEnabled=True, cacheTTL=3600, timeout=1000
            ),
        ),
        threatSignatureGraph=ThreatSignatureGraphConfig(
            dbPath="./test.db",
            walMode=True,
            maxConnections=5,
            similarityThreshold=0.8,
            ttlSeconds=3600,
            maxSignatures=1000,
            embeddingDimension=768,
        ),
    )

    assert policy.advancedThreatDetection is not None
    assert policy.advancedThreatDetection.swarmDetector.windowSeconds == 3600
    assert policy.advancedThreatDetection.swarmDetector.minAgents == 2
    assert policy.advancedThreatDetection.swarmDetector.correlationThreshold == 0.75

    detector = AgentSwarmDetector(policy=policy)
    assert detector.default_window == 3600
    assert detector.default_min_agents == 2
    assert detector.default_correlation_threshold == 0.75


@pytest.mark.asyncio
async def test_url_path_ip_is_not_extracted_as_shared_c2_pattern():
    """Verify that internal URLs with IP literals in their paths do not extract path IPs as shared patterns."""
    from blackwall.enterprise.advanced_threat_detection.swarm import _extract_all_ips

    # 1. Direct unit verification on _extract_all_ips
    url_target = "https://artifactory.internal/api/198.51.100.5/storage"
    assert _extract_all_ips(url_target) == set()

    res_target = "resource:https://artifactory.internal/api/198.51.100.5/storage"
    assert _extract_all_ips(res_target) == set()

    raw_path = "/api/198.51.100.5/storage"
    assert _extract_all_ips(raw_path) == set()

    # Legitimate IP endpoints are still extracted
    assert _extract_all_ips("https://198.51.100.5/api/storage") == {"198.51.100.5"}
    assert _extract_all_ips("https://[2607:f8b0:4005:805::200e]:8080/api") == {
        "2607:f8b0:4005:805::200e"
    }

    # 2. Integration verification via detect_swarms
    store = AttackGraphStore(in_memory=True)
    await store.initialize()
    detector = AgentSwarmDetector(
        store=store, default_min_agents=2, default_correlation_threshold=0.7
    )

    base_time = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    e1 = create_event(
        agent_id="agent-01",
        action="fetch",
        target="https://artifactory.internal/api/198.51.100.5/storage",
        offset_seconds=0.0,
        base_time=base_time,
        metadata={},
    )
    e2 = create_event(
        agent_id="agent-02",
        action="fetch",
        target="https://artifactory.internal/api/198.51.100.5/storage",
        offset_seconds=1.0,
        base_time=base_time,
        metadata={},
    )
    await store.insert_event(e1)
    await store.insert_event(e2)

    swarms = await detector.detect_swarms(
        time_window=(
            base_time - timedelta(minutes=5),
            base_time + timedelta(minutes=5),
        )
    )
    assert len(swarms) == 1
    # Must NOT have extracted "ip:198.51.100.5" into shared_patterns
    assert "ip:198.51.100.5" not in swarms[0].shared_patterns
