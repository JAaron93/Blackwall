"""Unit tests for WeaveTraceSerializer (Subtask 22.3, Requirements 17 & 18)."""

import uuid
from datetime import UTC, datetime

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.weave_serializer import (
    WeaveTraceSerializer,
)


def test_serialize_event_sanitization() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event_id = uuid.uuid4()
    event = NormalizedEvent(
        event_id=event_id,
        agent_id="agent-007",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="execute_shell_command",
        target="/bin/bash -c 'cat /etc/shadow'",
        risk_score=0.95,
        metadata={
            "token": "secret_jwt_token",
            "api_key": "bw_synthetic_12345",
            "user_prompt": "run malicious command",
        },
    )

    serialized = WeaveTraceSerializer.serialize_event(event)
    assert serialized["event_id"] == str(event_id)
    assert serialized["agent_id"] == "agent-007"
    assert serialized["source"] == EventSource.KERNEL_SYSCALL.value
    assert serialized["risk_score"] == 0.95
    assert "2026-08-15" in serialized["timestamp"]

    # Invariant: payload, prompt, action, target, metadata must NOT be exported
    assert "action" not in serialized
    assert "target" not in serialized
    assert "metadata" not in serialized
    assert "user_prompt" not in serialized


def test_serialize_path_sanitization() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event1 = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="agent-01",
        timestamp=now,
        source=EventSource.IDENTITY_ACCESS,
        action="recon",
        target="network",
        risk_score=0.4,
    )
    event2 = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="agent-01",
        timestamp=now,
        source=EventSource.IDENTITY_ACCESS,
        action="exploit",
        target="db",
        risk_score=0.9,
    )

    node1 = AttackNode(node_id=uuid.uuid4(), event=event1)
    node2 = AttackNode(node_id=uuid.uuid4(), event=event2)

    path_id = uuid.uuid4()
    path = AttackPath(
        path_id=path_id,
        agent_id="agent-01",
        start_time=now,
        end_time=now,
        risk_score=0.88,
        attack_stages=["Reconnaissance", "Exploitation"],
        correlation_score=0.92,
        nodes=[node1, node2],
    )

    serialized = WeaveTraceSerializer.serialize_path(path)
    assert serialized["path_id"] == str(path_id)
    assert serialized["agent_id"] == "agent-01"
    assert serialized["risk_score"] == 0.88
    assert serialized["correlation_score"] == 0.92
    assert serialized["node_count"] == 2
    assert "nodes" not in serialized
    assert "Reconnaissance" in serialized["attack_stages"]


def test_serialize_swarm_sanitization() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    swarm_id = uuid.uuid4()
    swarm = SwarmEvidence(
        swarm_id=swarm_id,
        agent_ids={"agent-1", "agent-2", "agent-3"},
        temporal_correlation=0.85,
        coordination_score=0.91,
        first_seen=now,
        last_seen=now,
        shared_patterns=["pattern1"],
    )

    serialized = WeaveTraceSerializer.serialize_swarm(swarm)
    assert serialized["swarm_id"] == str(swarm_id)
    assert serialized["agent_ids"] == ["agent-1", "agent-2", "agent-3"]
    assert serialized["temporal_correlation"] == 0.85
    assert serialized["coordination_score"] == 0.91
    assert "2026-08-15" in serialized["first_seen"]


def test_mask_metadata_sensitive_keys() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    nested_event = NormalizedEvent(
        event_id=uuid.uuid4(),
        agent_id="nested-agent",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="raw_nested_exec",
        target="/raw/nested/path",
        risk_score=0.99,
        metadata={"inner_token": "secret"},
    )
    data = {
        "user": "alice",
        "api_key": "sk-12345678",
        "nested_event_payload": nested_event,
        "nested": {
            "password": "supersecret",
            "auth_token": "token-xyz",
            "private_cert": "-----BEGIN PRIVATE KEY-----",
            "safe_value": 42,
            "items": [
                {"secret_data": "shh"},
                {"id": 1, "credential_id": "cred-99"},
            ],
        },
    }

    masked = WeaveTraceSerializer.mask_metadata(data)
    assert masked["user"] == "alice"
    assert masked["api_key"] == "**REDACTED**"
    assert masked["nested"]["password"] == "**REDACTED**"
    assert masked["nested"]["auth_token"] == "**REDACTED**"
    assert masked["nested"]["private_cert"] == "**REDACTED**"
    assert masked["nested"]["safe_value"] == 42
    assert masked["nested"]["items"][0]["secret_data"] == "**REDACTED**"
    assert masked["nested"]["items"][1]["credential_id"] == "**REDACTED**"
    assert masked["nested"]["items"][1]["id"] == 1
    # Check nested event is properly sanitized into safe metadata dict without raw action/target
    assert isinstance(masked["nested_event_payload"], dict)
    assert masked["nested_event_payload"]["risk_score"] == 0.99
    assert "action" not in masked["nested_event_payload"]
    assert "target" not in masked["nested_event_payload"]


def test_enforce_size_limit() -> None:
    small_payload = {"key": "value"}
    res = WeaveTraceSerializer.enforce_size(small_payload, max_bytes=100)
    assert res == small_payload

    large_payload = {"key": "x" * 5000}
    res_large = WeaveTraceSerializer.enforce_size(large_payload, max_bytes=4096)
    assert res_large["_truncated"] is True
    assert res_large["_original_bytes"] > 4096
