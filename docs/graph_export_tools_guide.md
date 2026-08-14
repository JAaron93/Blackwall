# Blackwall Attack Graph Export: External Tools Guide

This guide details how to consume, analyze, and visualize Blackwall Attack Graph exports ([`AttackGraphExporter`](file:///Users/pretermodernist/.gemini/antigravity/worktrees/Blackwall/implement_blackwall_seventeen_advanced/src/blackwall/enterprise/advanced_threat_detection/graph_export.py)) using external graph analysis and visualization tools: **NetworkX**, **Gephi**, and **Cytoscape / Cytoscape.js**.

---

## 1. Overview of Export Formats

Blackwall Advanced Threat Detection (Pillar 6 Task 17) supports two primary graph export formats via `AttackGraphExporter`:

| Format | Extension | Target Consumers | Characteristics |
| :--- | :--- | :--- | :--- |
| **GraphML XML** | `.graphml` / `.xml` | NetworkX, Gephi, Cytoscape Desktop | Schema-compliant directed XML (`<graph edgedefault="directed">`) with strongly-typed node/edge attributes (`risk_score`, `timestamp`, `agent_id`, `source`, `action`, `target`, `relationship`). |
| **Structured JSON** | `.json` | Cytoscape.js, D3.js, REST APIs | Normalized JSON payload with `nodes` and `edges` arrays, perfect for web frontends and microservices. |

```python
from blackwall.enterprise.advanced_threat_detection import RetrospectiveAnalyzer, AttackGraphExporter

# Export from RetrospectiveAnalyzer
retro_analyzer = RetrospectiveAnalyzer(store=store)
graphml_data = await retro_analyzer.export_attack_graph(format="graphml")
json_data = await retro_analyzer.export_attack_graph(format="json")

# Or direct export to file
exporter = AttackGraphExporter()
exporter.export_to_file("incident_attack_graph.graphml", format="graphml", nodes=nodes, edges=edges)
```

---

## 2. Tool-by-Tool Guide & Recommendations

### 🐍 1. NetworkX — Programmatic Automation & Headless Analysis

**Best for**: Automated Python scripts, CI/CD security quality gates, offline topological analysis, centrality metrics, and feeding graphs into downstream ML models.

#### How to Use with Blackwall GraphML:
NetworkX provides native 1-line support for reading Blackwall GraphML exports:

```python
import networkx as nx

# Read directly from file
G = nx.read_graphml("incident_attack_graph.graphml")

# Or parse directly from string
G = nx.parse_graphml(graphml_data)

# Access node attributes (typed automatically)
for node_id, data in G.nodes(data=True):
    print(f"Node {node_id} | Agent: {data.get('agent_id')} | Risk: {data.get('risk_score')}")

# Run graph algorithms
print("Is Directed Acyclic Graph (DAG):", nx.is_directed_acyclic_graph(G))
print("Topological Generations / Stages:", list(nx.topological_generations(G)))
print("Node Degree Centrality:", nx.degree_centrality(G))
```

#### Key Advantages:
- **Zero GUI Overhead**: Runs headlessly in containers, CLI tools, and automated pipelines.
- **Rich Algorithm Library**: Shortest paths, sub-graph extraction, connected components, and cycle detection.
- **Typed Attributes**: `risk_score` is automatically read as a `float`, preserving numeric accuracy.

---

### 🎨 2. Gephi — Visual Forensics & SOC Incident Investigation

**Best for**: Desktop visual exploration, incident triage, timeline animations, clustering multi-agent swarms, and generating publication-quality diagrams for security reports.

#### How to Use with Blackwall GraphML:
1. Open **Gephi** (desktop application).
2. Go to **File -> Open...** and select your `.graphml` export.
3. In the Import Report dialog, choose **Graph Type: Directed** and click **OK**.
4. In the **Appearance** panel:
   - **Nodes -> Color -> Ranking**: Select `risk_score` with a color ramp ($0.0 \to \text{Green}$, $1.0 \to \text{Red}$).
   - **Nodes -> Size -> Ranking**: Scale node size proportionally to `risk_score` or In-Degree.
   - **Nodes -> Color -> Partition**: Partition by `agent_id` or `source` to identify multi-pillar origins.
5. In the **Layout** panel:
   - Run **ForceAtlas2** or **Yifan Hu** to naturally cluster correlated multi-stage campaigns.
   - Use the **Timeline** or **Hierarchical** layout to display causal progression over time.
6. In **Preview**: Export high-resolution SVG, PNG, or PDF attack diagrams for incident reports.

#### Key Advantages:
- **Instant Large Graph Rendering**: Handles thousands of nodes and edges smoothly.
- **Dynamic Filtering**: Use range sliders to isolate critical nodes (`risk_score >= 0.8`).
- **Visual Clarity**: Clear representation of delayed swarms and branching attack paths.

---

### 🌐 3. Cytoscape / Cytoscape.js — Interactive Web Dashboards & SOC Platforms

**Best for**: Building interactive web user interfaces, custom browser-based SOC canvases, and embedding threat topology inside web applications.

#### How to Use with Blackwall JSON:
Cytoscape.js natively maps to Blackwall's structured JSON export:

```javascript
import cytoscape from 'cytoscape';

// Fetch Blackwall JSON export payload
const blackwallExport = JSON.parse(jsonPayload);

const elements = [
  // Map nodes
  ...blackwallExport.nodes.map(n => ({
    data: {
      id: n.node_id,
      label: `${n.event.action} (${n.event.agent_id})`,
      riskScore: n.event.risk_score,
      source: n.event.source,
      target: n.event.target
    }
  })),
  // Map edges
  ...blackwallExport.edges.map(e => ({
    data: {
      id: e.edge_id,
      source: e.from_node,
      target: e.to_node,
      relationship: e.relationship
    }
  }))
];

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: elements,
  style: [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'background-color': 'mapData(riskScore, 0, 1, #22c55e, #ef4444)',
        'width': 'mapData(riskScore, 0, 1, 20, 50)',
        'height': 'mapData(riskScore, 0, 1, 20, 50)'
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#94a3b8',
        'target-arrow-color': '#94a3b8',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier'
      }
    }
  ],
  layout: {
    name: 'breadthfirst',
    directed: true,
    padding: 10
  }
});

// Interactive node click handler
cy.on('tap', 'node', function(evt) {
  const node = evt.target;
  console.log('Selected Event:', node.data());
});
```

#### Key Advantages:
- **Web Native**: Embeds seamlessly in React, Vue, Next.js, or vanilla JS dashboards.
- **Full Interactivity**: Supports zooming, panning, node tooltips, selection events, and custom overlays.
- **Lightweight**: Zero desktop install required for end users.

---

## 3. Decision Matrix

| Requirement | Recommended Tool | Preferred Format |
| :--- | :--- | :--- |
| **Automated CI/CD security pipelines & algorithms** | **NetworkX** | GraphML XML (`.graphml`) |
| **Interactive desktop visual forensics & triage** | **Gephi** | GraphML XML (`.graphml`) |
| **Executive security reports & PDF/SVG diagrams** | **Gephi** | GraphML XML (`.graphml`) |
| **Custom web UI / browser SOC dashboard canvas** | **Cytoscape.js** | Structured JSON (`.json`) |
| **Ad-hoc Python REPL investigation** | **NetworkX** | GraphML XML (`.graphml`) |

---

## 4. Summary Recommendation

* **For Backend Engineers & Automated Workflows**: Use **NetworkX** to programmatically query and validate exported attack graphs.
* **For Security Analysts & Incident Responders**: Use **Gephi** to visually explore lateral movement chains, tune layout physics, and generate forensic visuals.
* **For Web Dashboard Developers**: Use **Cytoscape.js** with Blackwall JSON exports to embed responsive, interactive attack graphs directly in web applications.
