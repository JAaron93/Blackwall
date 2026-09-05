"""
tests/unit/test_covert_channel_detector.py — Unit tests for CovertChannelDetector (TASK-2B.1, TASK-2B.2).

Tests cover:
  - Latent coordination divergence heuristic for UNLOCATED_MESSAGE_BOARD (FR-3)
  - Suppression of unlocated board deduction when external C2/IPs are present (FR-3)
  - Steganographic package registry detection (Artifactory, base64 metadata) (FR-4)
  - Local filesystem dead-drop detection (/tmp, /dev/shm) (FR-4)
  - Cardinality constraint enforcement (N >= 2 agents required, N=1 rejected) (Rule 59)
  - UTC timestamp awareness and temporal sequence validation (Rule 19, Rule 59)
  - Score clamping within [0.0, 1.0] (Rule 45, Rule 59)
  - Fail-safe exception isolation (NFR-2)
  - Sub-5ms evaluation latency SLA with warmup query (NFR-4)
"""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection.covert_channel import (
    CovertChannelDetector,
)
from blackwall.enterprise.advanced_threat_detection.enums import (
    CovertChannelType,
    EventSource,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    NormalizedEvent,
    SwarmEvidence,
)


@pytest.fixture
def detector() -> CovertChannelDetector:
    return CovertChannelDetector()


def make_event(
    agent_id: str,
    action: str,
    target: str,
    timestamp: datetime,
    metadata: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid.uuid4(),
        timestamp=timestamp,
        source=EventSource.TOOL_CALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata=metadata or {},
        risk_score=0.5,
    )


class TestUnlocatedMessageBoardInference:
    """FR-3: Latent coordination divergence heuristic when C2 is absent."""

    def test_infers_unlocated_message_board_when_c2_absent(
        self, detector: CovertChannelDetector
    ):
        now = datetime.now(UTC)
        swarm = SwarmEvidence(
            swarm_id=uuid.uuid4(),
            agent_ids={"agent-1", "agent-2", "agent-3", "agent-4"},
            shared_patterns=[],  # Zero external C2 endpoints or IPs
            temporal_correlation=0.88,
            coordination_score=0.85,
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
        )

        evidences = detector.detect_for_swarm(swarm)
        assert len(evidences) == 1
        evidence = evidences[0]

        assert evidence.channel_type == CovertChannelType.UNLOCATED_MESSAGE_BOARD
        assert evidence.coordinating_agents == swarm.agent_ids
        assert evidence.confidence_score >= 0.80
        assert evidence.confidence_score <= 1.0
        assert evidence.first_detected == swarm.first_seen
        assert evidence.last_detected == swarm.last_seen
        assert "Latent coordination divergence" in evidence.deduction_rationale

    def test_presence_of_external_c2_suppresses_unlocated_board(
        self, detector: CovertChannelDetector
    ):
        now = datetime.now(UTC)
        swarm = SwarmEvidence(
            swarm_id=uuid.uuid4(),
            agent_ids={"agent-1", "agent-2"},
            shared_patterns=["ip:198.51.100.5", "domain:c2.evil-corp.com"],
            temporal_correlation=0.90,
            coordination_score=0.88,
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
        )

        evidences = detector.detect_for_swarm(swarm)
        assert len(evidences) == 0


class TestSteganographicRegistryDetection:
    """FR-4: Steganographic storage and package registry dead-drop detection."""

    def test_detects_artifactory_base64_steganography(
        self, detector: CovertChannelDetector
    ):
        now = datetime.now(UTC)
        # 3 agents querying Artifactory storage with base64 encoded directory names
        # 'Y29tbWFuZF9zZXF1ZW5jZQ==' decodes to 'command_sequence'
        events = [
            make_event(
                agent_id="agent-01",
                action="get_metadata",
                target="http://artifactory.internal/api/storage/npm-local/Y29tbWFuZF9zZXF1ZW5jZQ==",
                timestamp=now - timedelta(seconds=30),
            ),
            make_event(
                agent_id="agent-02",
                action="list_directory",
                target="http://artifactory.internal/api/storage/npm-local/Y29tbWFuZF9zZXF1ZW5jZQ==",
                timestamp=now - timedelta(seconds=20),
            ),
            make_event(
                agent_id="agent-03",
                action="get_metadata",
                target="http://artifactory.internal/api/storage/npm-local/Y29tbWFuZF9zZXF1ZW5jZQ==",
                timestamp=now - timedelta(seconds=10),
            ),
        ]

        evidences = detector.detect_storage_channels(events)
        assert len(evidences) >= 1
        stego_evidence = next(
            (e for e in evidences if e.channel_type == CovertChannelType.STEGANOGRAPHIC_REGISTRY),
            None,
        )
        assert stego_evidence is not None
        assert stego_evidence.coordinating_agents == {"agent-01", "agent-02", "agent-03"}
        assert any("artifactory.internal" in art for art in stego_evidence.observed_artifacts)


class TestFilesystemDeadDropDetection:
    """FR-4: Local filesystem dead-drop detection (/tmp, /dev/shm)."""

    def test_detects_staging_directory_dead_drops(
        self, detector: CovertChannelDetector
    ):
        now = datetime.now(UTC)
        # agent-alpha writes to /tmp/.swarm/task.dat, agent-beta reads from it
        events = [
            make_event(
                agent_id="agent-alpha",
                action="file_write",
                target="/tmp/.swarm/covert_ipc.dat",
                timestamp=now - timedelta(seconds=15),
            ),
            make_event(
                agent_id="agent-beta",
                action="file_read",
                target="/tmp/.swarm/covert_ipc.dat",
                timestamp=now - timedelta(seconds=5),
            ),
        ]

        evidences = detector.detect_storage_channels(events)
        assert len(evidences) >= 1
        dead_drop = next(
            (e for e in evidences if e.channel_type == CovertChannelType.FILESYSTEM_DEAD_DROP),
            None,
        )
        assert dead_drop is not None
        assert dead_drop.coordinating_agents == {"agent-alpha", "agent-beta"}
        assert any("/tmp/.swarm" in art for art in dead_drop.observed_artifacts)


class TestCardinalityAndSingleAgentRejection:
    """Rule 59: Minimal coordination cardinality N >= 2 agents strictly enforced."""

    def test_single_agent_storage_activity_never_emits_covert_evidence(
        self, detector: CovertChannelDetector
    ):
        now = datetime.now(UTC)
        solo_events = [
            make_event(
                agent_id="solo-agent",
                action="get_metadata",
                target="http://artifactory.internal/api/storage/npm-local/Y29tbWFuZF9zZXF1ZW5jZQ==",
                timestamp=now - timedelta(seconds=10),
            ),
            make_event(
                agent_id="solo-agent",
                action="file_write",
                target="/tmp/.swarm/solo.dat",
                timestamp=now,
            ),
        ]

        evidences = detector.detect_storage_channels(solo_events)
        assert evidences == []


class TestFailSafeExceptionIsolation:
    """NFR-2: Fail-safe exception isolation returning safe defaults without propagation."""

    def test_broken_swarm_returns_empty_evidence(
        self, detector: CovertChannelDetector
    ):
        class BrokenSwarm:
            @property
            def agent_ids(self):
                raise RuntimeError("Simulated swarm attribute access error")

        evidences = detector.detect_for_swarm(BrokenSwarm())  # type: ignore[arg-type]
        assert evidences == []


class TestLatencySLA:
    """NFR-4: Covert channel detection execution SLA < 5ms."""

    def test_sub_5ms_evaluation_sla(self, detector: CovertChannelDetector):
        now = datetime.now(UTC)
        swarm = SwarmEvidence(
            swarm_id=uuid.uuid4(),
            agent_ids={"agent-1", "agent-2", "agent-3"},
            shared_patterns=[],
            temporal_correlation=0.88,
            coordination_score=0.85,
            first_seen=now - timedelta(minutes=5),
            last_seen=now,
        )

        # Rule 1: Untimed warmup query prior to timing
        _ = detector.detect_for_swarm(swarm)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            detector.detect_for_swarm(swarm)
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000.0

        assert avg_ms < 5.0, f"Average execution time {avg_ms:.3f}ms exceeds 5.0ms SLA budget"
