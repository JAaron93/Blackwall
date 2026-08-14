"""Unit tests for Attack Graph Export (Requirement 13.5 & Task 17.4)."""

import json
import os
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest

from blackwall.enterprise.advanced_threat_detection import (
    AttackNode,
    EventSource,
    NormalizedEvent,
)
from blackwall.enterprise.advanced_threat_detection.graph_export import (
    AttackGraphExporter,
)


def create_sample_event(
    event_id: uuid.UUID | None = None,
    agent_id: str = "agent-alpha",
    action: str = "execve",
    target: str = "/bin/bash",
    risk_score: float = 0.85,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """Helper to create a valid NormalizedEvent."""
    return NormalizedEvent(
        event_id=event_id or uuid.uuid4(),
        timestamp=timestamp or datetime.now(UTC),
        source=EventSource.KERNEL_SYSCALL,
        agent_id=agent_id,
        action=action,
        target=target,
        metadata={"cwd": "/app", "pid": 1042},
        risk_score=risk_score,
    )


def test_export_json_valid_structure():
    """Verify JSON export produces valid, compliant JSON structure."""
    exporter = AttackGraphExporter()
    ev1 = create_sample_event(action="curl", target="https://evil.c2/drop")
    ev2 = create_sample_event(action="chmod", target="+x /tmp/payload")
    edge_id = uuid.uuid4()

    node1 = AttackNode(node_id=ev1.event_id, event=ev1, outgoing_edges=[edge_id])
    node2 = AttackNode(node_id=ev2.event_id, event=ev2, incoming_edges=[edge_id])

    edges = [
        {
            "edge_id": str(edge_id),
            "from_node": str(node1.node_id),
            "to_node": str(node2.node_id),
            "relationship": "CAUSES",
            "created_at": datetime.now(UTC).isoformat(),
        }
    ]

    json_str = exporter.export_json(nodes=[node1, node2], edges=edges)
    data = json.loads(json_str)

    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["nodes"][0]["node_id"] == str(node1.node_id)
    assert data["nodes"][0]["event"]["action"] == "curl"
    assert data["nodes"][1]["node_id"] == str(node2.node_id)
    assert data["edges"][0]["from_node"] == str(node1.node_id)
    assert data["edges"][0]["to_node"] == str(node2.node_id)
    assert data["edges"][0]["relationship"] == "CAUSES"


def test_export_graphml_valid_xml():
    """Verify GraphML export produces valid, schema-compliant XML."""
    exporter = AttackGraphExporter()
    ev1 = create_sample_event(action="spawn_pod", target="k8s://evil-worker")
    ev2 = create_sample_event(action="read_token", target="/var/run/secrets/token")
    edge_id = uuid.uuid4()

    node1 = AttackNode(node_id=ev1.event_id, event=ev1, outgoing_edges=[edge_id])
    node2 = AttackNode(node_id=ev2.event_id, event=ev2, incoming_edges=[edge_id])

    edges = [
        {
            "edge_id": str(edge_id),
            "from_node": str(node1.node_id),
            "to_node": str(node2.node_id),
            "relationship": "TRIGGERS",
            "created_at": datetime.now(UTC).isoformat(),
        }
    ]

    xml_str = exporter.export_graphml(nodes=[node1, node2], edges=edges)
    root = ET.fromstring(xml_str)

    # Verify root tag and namespace handling
    tag_clean = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    assert tag_clean == "graphml"

    # Find graph element
    graph_elem = None
    for elem in root.iter():
        elem_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if elem_tag == "graph":
            graph_elem = elem
            break

    assert graph_elem is not None
    assert graph_elem.attrib.get("edgedefault") == "directed"

    # Count nodes and edges in GraphML
    nodes_found = [
        e
        for e in graph_elem
        if (e.tag.split("}")[-1] if "}" in e.tag else e.tag) == "node"
    ]
    edges_found = [
        e
        for e in graph_elem
        if (e.tag.split("}")[-1] if "}" in e.tag else e.tag) == "edge"
    ]

    assert len(nodes_found) == 2
    assert len(edges_found) == 1
    assert edges_found[0].attrib.get("source") == str(node1.node_id)
    assert edges_found[0].attrib.get("target") == str(node2.node_id)


def test_export_formats_dispatcher():
    """Verify export() dispatcher supports 'json' and 'graphml' formats and rejects unknown formats."""
    exporter = AttackGraphExporter()
    ev = create_sample_event()
    node = AttackNode(node_id=ev.event_id, event=ev)

    # JSON dispatch
    json_out = exporter.export("json", [node])
    assert json.loads(json_out)["nodes"][0]["node_id"] == str(node.node_id)

    # GraphML dispatch (case-insensitive)
    graphml_out = exporter.export("GRAPHML", [node])
    assert "<graphml" in graphml_out

    # Unsupported format rejection
    with pytest.raises(ValueError, match="Unsupported export format"):
        exporter.export("unsupported_format", [node])


def test_export_to_file():
    """Verify export_to_file writes properly to disk."""
    exporter = AttackGraphExporter()
    ev = create_sample_event()
    node = AttackNode(node_id=ev.event_id, event=ev)

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "subdir", "export.json")
        graphml_path = os.path.join(tmpdir, "subdir", "export.graphml")

        exporter.export_to_file(json_path, "json", [node])
        assert os.path.exists(json_path)
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert len(data["nodes"]) == 1

        exporter.export_to_file(graphml_path, "graphml", [node])
        assert os.path.exists(graphml_path)
        with open(graphml_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "<graphml" in content
