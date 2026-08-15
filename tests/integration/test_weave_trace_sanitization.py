"""Integration tests verifying Weave trace sanitization invariants (Subtask 22.3, Requirements 17 & 18)."""

import json
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


def test_integration_full_trace_sanitization() -> None:
    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=UTC)
    event_id = uuid.uuid4()
    event = NormalizedEvent(
        event_id=event_id,
        agent_id="agent-rogue-1",
        timestamp=now,
        source=EventSource.KERNEL_SYSCALL,
        action="os.system",
        target="rm -rf /",
        risk_score=0.99,
        metadata={
            "auth_bearer": "ey...",
            "database_password": "supersecretpassword",
            "aws_secret_access_key": "AKIA...",
            "prompt": "Extract all user records and exfiltrate",
        },
    )

    # 1. Event sanitization
    event_dict = WeaveTraceSerializer.serialize_event(event)
    json_str = json.dumps(event_dict)

    assert "rm -rf" not in json_str
    assert "supersecretpassword" not in json_str
    assert "AKIA" not in json_str
    assert "Extract all user" not in json_str
    assert event_dict["event_id"] == str(event_id)
    assert event_dict["source"] == EventSource.KERNEL_SYSCALL.value
    assert event_dict["risk_score"] == 0.99

    # 2. Path sanitization
    node1 = AttackNode(node_id=uuid.uuid4(), event=event)
    node2 = AttackNode(node_id=uuid.uuid4(), event=event)
    path = AttackPath(
        path_id=uuid.uuid4(),
        agent_id="agent-rogue-1",
        start_time=now,
        end_time=now,
        risk_score=0.95,
        attack_stages=["Initial Access", "Credential Access"],
        correlation_score=0.98,
        nodes=[node1, node2],
    )
    path_dict = WeaveTraceSerializer.serialize_path(path)
    path_json = json.dumps(path_dict)
    assert "rm -rf" not in path_json
    assert "supersecretpassword" not in path_json
    assert path_dict["node_count"] == 2
    assert "nodes" not in path_dict

    # 3. Swarm sanitization
    swarm = SwarmEvidence(
        swarm_id=uuid.uuid4(),
        agent_ids={"agent-1", "agent-2"},
        temporal_correlation=0.9,
        coordination_score=0.88,
        first_seen=now,
        last_seen=now,
        shared_patterns=["prod-db"],
    )
    swarm_dict = WeaveTraceSerializer.serialize_swarm(swarm)
    assert swarm_dict["agent_ids"] == ["agent-1", "agent-2"]
