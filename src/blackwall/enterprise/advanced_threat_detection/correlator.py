"""Multi-Stage Attack Path Correlation component for Blackwall Advanced Threat Detection (Pillar 6 Task 5)."""

from datetime import datetime
import math
import re
from typing import Dict, List, Optional, Set, Tuple
import uuid

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore


from blackwall.validators import validate_temporal_sequence, validate_utc_datetime


# MITRE ATT&CK technique mapping patterns
MITRE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"command|exec|script|bash|sh|python|powershell|cmd", re.IGNORECASE), "T1059"),
    (re.compile(r"sudo|privilege|root|su|chmod|elevate", re.IGNORECASE), "T1068"),
    (re.compile(r"token|credential|secret|password|key|auth|var/run/secrets", re.IGNORECASE), "T1552"),
    (re.compile(r"http|socket|connect|c2|beacon|webhook|requestbin|pastebin", re.IGNORECASE), "T1071"),
    (re.compile(r"cron|timer|service|persistence|daemon|respawn", re.IGNORECASE), "T1053"),
    (re.compile(r"k8s|pod|kube|container|docker|artifactory|npm|pypi", re.IGNORECASE), "T1613"),
]

# Action progression hierarchy for semantic edge scoring
SEMANTIC_TIERS: Dict[EventSource, int] = {
    EventSource.KERNEL_SYSCALL: 1,
    EventSource.TOOL_CALL: 2,
    EventSource.IDENTITY_ACCESS: 3,
    EventSource.PIPELINE_EXECUTION: 4,
    EventSource.FORENSIC_ALERT: 5,
}


class PathCorrelator:
    """Correlates security events into multi-stage attack paths using DFS and temporal graph analysis."""

    def __init__(self, store: Optional[AttackGraphStore] = None) -> None:
        self.store = store or AttackGraphStore(in_memory=True)

    async def correlate_attack_paths(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
        min_path_length: int = 2,
        max_nodes: int = 500,
        max_paths: int = 1000,
        max_depth: int = 10,
    ) -> List[AttackPath]:
        """Correlate security events for an agent into multi-stage attack paths within a time window.

        Args:
            agent_id: Identifier of agent to correlate paths for.
            time_window: Tuple of (start_time, end_time) UTC datetime filters.
            min_path_length: Minimum number of nodes required in an attack path (default 2).
            max_nodes: Maximum candidate nodes to fetch and correlate (default 500).
            max_paths: Maximum number of attack paths to materialize and return (default 1000).
            max_depth: Maximum path depth during DFS traversal (default 10).

        Returns:
            List of AttackPath objects sorted by risk_score descending.
        """
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")

        start_raw, end_raw = time_window
        validate_temporal_sequence(start_raw, end_raw, start_name="start_time", end_name="end_time")
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)


        # 1. Fetch candidate nodes from store within time window, up to max_nodes
        candidate_nodes = await self.store.query_nodes(agent_id, (start_win, end_win), limit=max_nodes)

        # Requirement 3.6 & Property 19: Return empty list if events < min_path_length
        if len(candidate_nodes) < min_path_length:
            return []

        # 2. Build temporal adjacency graph with 5-minute (300s) window edges & weights
        adj_graph = self.build_temporal_adjacency_graph(candidate_nodes)

        # 3. Depth-first search (DFS) for path enumeration
        all_paths: List[List[AttackNode]] = []

        for start_node in candidate_nodes:
            if len(all_paths) >= max_paths:
                break
            self._dfs_path_search(
                current_node=start_node,
                current_path=[start_node],
                adj_graph=adj_graph,
                min_path_length=min_path_length,
                visited_in_path={start_node.node_id},
                results=all_paths,
                max_depth=max_depth,
                max_results=max_paths,
            )

        # 4. Filter and construct AttackPath models with MITRE techniques & risk scores
        attack_paths: List[AttackPath] = []
        seen_path_signatures: Set[Tuple[str, ...]] = set()

        for path_nodes in all_paths:
            if len(path_nodes) < min_path_length:
                continue

            # Deduplicate paths by node ID sequence
            sig = tuple(n.node_id for n in path_nodes)
            if sig in seen_path_signatures:
                continue
            seen_path_signatures.add(sig)

            start_time = path_nodes[0].event.timestamp
            end_time = path_nodes[-1].event.timestamp

            # Compute edge weights along path
            edge_weights: List[float] = []
            for i in range(len(path_nodes) - 1):
                w = self.compute_edge_weight(path_nodes[i], path_nodes[i + 1])
                edge_weights.append(w)

            risk_score, correlation_score = self.compute_path_scores(path_nodes, edge_weights)
            attack_stages = self.map_mitre_techniques(path_nodes)

            path_obj = AttackPath(
                path_id=uuid.uuid4(),
                agent_id=agent_id,
                nodes=path_nodes,
                start_time=start_time,
                end_time=end_time,
                risk_score=risk_score,
                attack_stages=attack_stages,
                correlation_score=correlation_score,
            )
            attack_paths.append(path_obj)

        # 5. Order paths by risk_score descending (Requirement 3.5 & Property 18)
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return attack_paths[:max_paths]

    def build_temporal_adjacency_graph(
        self, nodes: List[AttackNode]
    ) -> Dict[str, List[Tuple[AttackNode, float]]]:
        """Build temporal adjacency graph where edges exist iff nodes occur <= 5 minutes apart or have causal edge."""
        sorted_nodes = sorted(nodes, key=lambda n: n.event.timestamp)
        adj: Dict[str, List[Tuple[AttackNode, float]]] = {n.node_id: [] for n in sorted_nodes}

        for i, node_a in enumerate(sorted_nodes):
            for node_b in sorted_nodes[i + 1 :]:
                delta_sec = (node_b.event.timestamp - node_a.event.timestamp).total_seconds()

                # Causal edge check
                is_causal = any(e in node_a.outgoing_edges for e in node_b.incoming_edges)

                # Property 15 / Requirement 3.2: Edge exists iff within 5 minutes (300s) or causal
                if (0 <= delta_sec <= 300) or is_causal:
                    weight = self.compute_edge_weight(node_a, node_b)
                    adj[node_a.node_id].append((node_b, weight))
                elif not node_a.outgoing_edges:
                    # Non-causal node beyond 300s window cannot link to any subsequent node
                    break

        return adj

    def compute_edge_weight(self, node_a: AttackNode, node_b: AttackNode) -> float:
        """Compute edge weight in [0.0, 1.0] based on temporal proximity and semantic relationship."""
        delta_sec = max(0.0, (node_b.event.timestamp - node_a.event.timestamp).total_seconds())

        # Temporal proximity score (exponential decay over 300s window)
        temporal_prox = math.exp(-delta_sec / 300.0)

        # Semantic relationship score based on action & target similarity or tier transition
        tier_a = SEMANTIC_TIERS.get(node_a.event.source, 1)
        tier_b = SEMANTIC_TIERS.get(node_b.event.source, 1)

        # Progressive tier escalation adds semantic weight
        tier_diff = abs(tier_b - tier_a)
        semantic_base = 0.5 + (0.1 * tier_diff)

        # Action/target keyword overlap boost
        same_target = 0.2 if node_a.event.target == node_b.event.target else 0.0

        semantic_score = min(1.0, semantic_base + same_target)

        # Weighted combination bounded [0.0, 1.0]
        weight = 0.5 * temporal_prox + 0.5 * semantic_score
        return round(max(0.0, min(1.0, weight)), 4)

    def map_mitre_techniques(self, nodes: List[AttackNode]) -> List[str]:
        """Map event node sequences to MITRE ATT&CK technique IDs."""
        techniques: List[str] = []

        for node in nodes:
            action_text = f"{node.event.action} {node.event.target}"
            matched = False
            for pattern, tech_id in MITRE_PATTERNS:
                if pattern.search(action_text):
                    if tech_id not in techniques:
                        techniques.append(tech_id)
                    matched = True
                    break

            if not matched:
                # Default fallback technique ID for uncategorized local system actions
                fallback_id = "T1005"
                if fallback_id not in techniques:
                    techniques.append(fallback_id)

        return techniques

    def compute_path_scores(
        self, nodes: List[AttackNode], edge_weights: List[float]
    ) -> Tuple[float, float]:
        """Compute aggregate risk_score and correlation_score in [0.0, 1.0]."""
        if not nodes:
            return 0.0, 0.0

        max_node_risk = max(n.event.risk_score for n in nodes)
        avg_node_risk = sum(n.event.risk_score for n in nodes) / len(nodes)

        avg_edge_weight = sum(edge_weights) / len(edge_weights) if edge_weights else 0.5

        # Compound risk score blending max risk, average risk, and path length weight
        length_bonus = min(0.2, 0.05 * len(nodes))
        raw_risk = 0.6 * max_node_risk + 0.3 * avg_node_risk + 0.1 * avg_edge_weight + length_bonus
        risk_score = round(max(0.0, min(1.0, raw_risk)), 4)

        # Correlation score derived from average edge weight
        correlation_score = round(max(0.0, min(1.0, avg_edge_weight)), 4)

        return risk_score, correlation_score

    def _dfs_path_search(
        self,
        current_node: AttackNode,
        current_path: List[AttackNode],
        adj_graph: Dict[str, List[Tuple[AttackNode, float]]],
        min_path_length: int,
        visited_in_path: Set[str],
        results: List[List[AttackNode]],
        max_depth: int = 10,
        max_results: int = 1000,
    ) -> None:
        """Recursive DFS traversal to find paths meeting min_path_length up to max_depth and max_results."""
        if len(results) >= max_results:
            return

        if len(current_path) >= min_path_length:
            results.append(list(current_path))

        if len(current_path) >= max_depth:
            return

        neighbors = adj_graph.get(current_node.node_id, [])
        for neighbor_node, _ in neighbors:
            if len(results) >= max_results:
                break
            if neighbor_node.node_id not in visited_in_path:
                visited_in_path.add(neighbor_node.node_id)
                current_path.append(neighbor_node)

                self._dfs_path_search(
                    current_node=neighbor_node,
                    current_path=current_path,
                    adj_graph=adj_graph,
                    min_path_length=min_path_length,
                    visited_in_path=visited_in_path,
                    results=results,
                    max_depth=max_depth,
                    max_results=max_results,
                )

                current_path.pop()
                visited_in_path.remove(neighbor_node.node_id)
