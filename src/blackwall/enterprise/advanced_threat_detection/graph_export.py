"""Attack Graph Exporter component for Blackwall Advanced Threat Detection (Pillar 6 Task 17.4)."""

import json
import os
import xml.etree.ElementTree as ET
from typing import Any
from uuid import UUID

from blackwall.enterprise.advanced_threat_detection.models import AttackNode


class AttackGraphExporter:
    """Exports attack graph structures (nodes and causal edges) into standard formats (JSON, GraphML)."""

    def export_json(
        self, nodes: list[AttackNode], edges: list[dict[str, Any]] | None = None
    ) -> str:
        """Export attack graph nodes and edges to standard structured JSON."""
        nodes_data = []
        for node in nodes:
            ev_dict = {
                "event_id": str(node.event.event_id),
                "timestamp": node.event.timestamp.isoformat(),
                "source": (
                    node.event.source.value
                    if hasattr(node.event.source, "value")
                    else str(node.event.source)
                ),
                "agent_id": node.event.agent_id,
                "action": node.event.action,
                "target": node.event.target,
                "metadata": node.event.metadata,
                "risk_score": float(node.event.risk_score),
            }
            nodes_data.append(
                {
                    "node_id": str(node.node_id),
                    "event": ev_dict,
                    "incoming_edges": [str(e) for e in node.incoming_edges],
                    "outgoing_edges": [str(e) for e in node.outgoing_edges],
                }
            )

        edges_data = []
        if edges:
            for edge in edges:
                edges_data.append(
                    {
                        "edge_id": str(edge.get("edge_id", "")),
                        "from_node": str(edge.get("from_node", "")),
                        "to_node": str(edge.get("to_node", "")),
                        "relationship": str(edge.get("relationship", "CONNECTED")),
                        "created_at": (
                            edge["created_at"].isoformat()
                            if hasattr(edge.get("created_at"), "isoformat")
                            else str(edge.get("created_at", ""))
                        ),
                    }
                )

        payload = {
            "version": "1.0",
            "format": "blackwall_attack_graph_json",
            "nodes": nodes_data,
            "edges": edges_data,
        }
        return json.dumps(payload, indent=2)

    def export_graphml(
        self, nodes: list[AttackNode], edges: list[dict[str, Any]] | None = None
    ) -> str:
        """Export attack graph nodes and edges to schema-compliant GraphML XML format."""
        graphml_ns = "http://graphml.graphdrawing.org/xmlns"
        ET.register_namespace("", graphml_ns)

        root = ET.Element(f"{{{graphml_ns}}}graphml")

        # Define node attribute keys
        key_defs = [
            ("d0", "node", "event_id", "string"),
            ("d1", "node", "timestamp", "string"),
            ("d2", "node", "source", "string"),
            ("d3", "node", "agent_id", "string"),
            ("d4", "node", "action", "string"),
            ("d5", "node", "target", "string"),
            ("d6", "node", "risk_score", "double"),
            ("d7", "edge", "relationship", "string"),
            ("d8", "edge", "created_at", "string"),
        ]

        for k_id, k_for, k_name, k_type in key_defs:
            k_elem = ET.SubElement(root, f"{{{graphml_ns}}}key")
            k_elem.attrib["id"] = k_id
            k_elem.attrib["for"] = k_for
            k_elem.attrib["attr.name"] = k_name
            k_elem.attrib["attr.type"] = k_type

        # Create directed graph container
        graph_elem = ET.SubElement(root, f"{{{graphml_ns}}}graph")
        graph_elem.attrib["id"] = "BlackwallAttackGraph"
        graph_elem.attrib["edgedefault"] = "directed"

        # Populate nodes
        for node in nodes:
            n_elem = ET.SubElement(graph_elem, f"{{{graphml_ns}}}node")
            n_elem.attrib["id"] = str(node.node_id)

            data_map = [
                ("d0", str(node.event.event_id)),
                ("d1", node.event.timestamp.isoformat()),
                (
                    "d2",
                    (
                        node.event.source.value
                        if hasattr(node.event.source, "value")
                        else str(node.event.source)
                    ),
                ),
                ("d3", str(node.event.agent_id)),
                ("d4", str(node.event.action)),
                ("d5", str(node.event.target)),
                ("d6", str(float(node.event.risk_score))),
            ]

            for key_id, value_text in data_map:
                d_elem = ET.SubElement(n_elem, f"{{{graphml_ns}}}data")
                d_elem.attrib["key"] = key_id
                d_elem.text = value_text

        # Populate edges
        if edges:
            for idx, edge in enumerate(edges):
                e_elem = ET.SubElement(graph_elem, f"{{{graphml_ns}}}edge")
                edge_id = str(edge.get("edge_id") or f"e{idx}")
                e_elem.attrib["id"] = edge_id
                e_elem.attrib["source"] = str(edge.get("from_node", ""))
                e_elem.attrib["target"] = str(edge.get("to_node", ""))

                d_rel = ET.SubElement(e_elem, f"{{{graphml_ns}}}data")
                d_rel.attrib["key"] = "d7"
                d_rel.text = str(edge.get("relationship", "CONNECTED"))

                d_created = ET.SubElement(e_elem, f"{{{graphml_ns}}}data")
                d_created.attrib["key"] = "d8"
                created_val = edge.get("created_at")
                d_created.text = (
                    created_val.isoformat()
                    if hasattr(created_val, "isoformat")
                    else str(created_val or "")
                )

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def export(
        self,
        format: str,
        nodes: list[AttackNode],
        edges: list[dict[str, Any]] | None = None,
    ) -> str:
        """Dispatcher to export nodes and edges according to requested format ('json' or 'graphml')."""
        fmt_lower = format.strip().lower()
        if fmt_lower == "json":
            return self.export_json(nodes, edges)
        if fmt_lower == "graphml":
            return self.export_graphml(nodes, edges)
        raise ValueError(
            f"Unsupported export format '{format}'. Supported formats: 'json', 'graphml'"
        )

    def export_to_file(
        self,
        filepath: str,
        format: str,
        nodes: list[AttackNode],
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        """Export graph structure to a file on disk."""
        content = self.export(format, nodes, edges)
        dir_path = os.path.dirname(filepath)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
