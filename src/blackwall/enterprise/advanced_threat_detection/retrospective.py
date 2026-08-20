"""Retrospective Analysis and Historical Query component for Blackwall Advanced Threat Detection (Pillar 6 Task 17)."""

import logging
import math
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from blackwall.enterprise.advanced_threat_detection.correlator import (
    MITRE_PATTERNS,
    SEMANTIC_TIERS,
    PathCorrelator,
    map_mitre_attack_techniques,
)
from blackwall.enterprise.advanced_threat_detection.graph_export import (
    AttackGraphExporter,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.validators import (
    clamp_score,
    compute_exponential_decay,
    normalize_time_window,
    validate_utc_datetime,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.retrospective")


class RetrospectiveAnalyzer:
    """Performs retrospective analysis, multi-day historical queries, delayed swarm correlation, and graph exports."""

    def __init__(
        self,
        store: AttackGraphStore | None = None,
        correlator: PathCorrelator | None = None,
        swarm_detector: AgentSwarmDetector | None = None,
        exporter: AttackGraphExporter | None = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self.correlator = correlator or PathCorrelator(store=self.store)
        self.swarm_detector = swarm_detector or AgentSwarmDetector(store=self.store)
        self.exporter = exporter or AttackGraphExporter()

    async def analyze_historical_window(
        self,
        agent_id: str | None,
        time_window: tuple[datetime, datetime],
        min_path_length: int = 2,
        max_nodes: int = 1000,
        max_paths: int = 1000,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        """Query attack paths across historical time windows spanning days, weeks, or arbitrary spans.

        Args:
            agent_id: Identifier of target agent, or None to query across all agents.
            time_window: Tuple of (start_time, end_time) UTC timezone-aware datetimes.
            min_path_length: Minimum nodes per attack path (>= 2).
            max_nodes: Maximum nodes to evaluate per correlation run.
            max_paths: Maximum paths to return.
            max_depth: Maximum DFS depth.

        Returns:
            List of AttackPath instances sorted by risk_score descending.
        """
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")
        if max_nodes <= 0:
            raise ValueError("max_nodes must be positive")
        if max_paths <= 0:
            raise ValueError("max_paths must be positive")
        if max_depth <= 0:
            raise ValueError("max_depth must be positive")

        start_win, end_win = normalize_time_window(time_window)

        if agent_id is not None:
            return await self.correlator.correlate_attack_paths(
                agent_id=agent_id,
                time_window=(start_win, end_win),
                min_path_length=min_path_length,
                max_nodes=max_nodes,
                max_paths=max_paths,
                max_depth=max_depth,
            )

        # Query all agents in the historical window with bounded limit
        all_nodes = await self.store.query_nodes(None, (start_win, end_win), limit=max_nodes)
        distinct_agents = sorted(list({n.event.agent_id for n in all_nodes}))

        combined_paths: list[AttackPath] = []
        for aid in distinct_agents:
            paths = await self.correlator.correlate_attack_paths(
                agent_id=aid,
                time_window=(start_win, end_win),
                min_path_length=min_path_length,
                max_nodes=max_nodes,
                max_paths=max_paths,
                max_depth=max_depth,
            )
            combined_paths.extend(paths)

        # Re-sort across all agents and limit to max_paths
        combined_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return combined_paths[:max_paths]

    async def reconstruct_causal_graph(
        self,
        agent_id: str | None,
        time_window: tuple[datetime, datetime] | None = None,
        min_path_length: int = 2,
        min_risk_score: float = 0.0,
        max_time_gap_seconds: float = 86400.0 * 7,
    ) -> list[AttackPath]:
        """Reconstruct multi-day or multi-week attack paths with extended causal linking.

        Args:
            agent_id: Identifier of target agent, or None across all agents.
            time_window: Optional tuple of (start_time, end_time) UTC timezone-aware datetimes.
            min_path_length: Minimum nodes per path (>= 2).
            min_risk_score: Minimum aggregate risk score.
            max_time_gap_seconds: Maximum allowable time gap for semantic transitions (defaults to 7 days).

        Returns:
            List of reconstructed AttackPath objects with full causal fidelity.
        """
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")
        if max_time_gap_seconds <= 0:
            raise ValueError("max_time_gap_seconds must be positive")

        start_win, end_win = normalize_time_window(
            time_window, default_duration_seconds=30 * 86400.0
        )

        all_nodes = await self.store.query_nodes(agent_id, (start_win, end_win))
        if not all_nodes:
            return []

        identified_paths: list[AttackPath] = []
        seen_signatures: set[tuple[uuid.UUID, ...]] = set()

        # Group nodes by agent
        agent_nodes_map: dict[str, list[AttackNode]] = defaultdict(list)
        for n in all_nodes:
            agent_nodes_map[n.event.agent_id].append(n)

        for aid, agent_nodes in agent_nodes_map.items():
            if len(agent_nodes) < min_path_length:
                continue

            sorted_nodes = sorted(agent_nodes, key=lambda n: (n.event.timestamp, str(n.node_id)))

            # Build extended adjacency graph supporting causal links + semantic affinity
            adj: dict[uuid.UUID, list[tuple[AttackNode, float]]] = defaultdict(list)
            in_degree: dict[uuid.UUID, int] = defaultdict(int)
            edge_to_targets: dict[uuid.UUID, list[AttackNode]] = defaultdict(list)
            for n in sorted_nodes:
                for inc_edge in n.incoming_edges:
                    edge_to_targets[inc_edge].append(n)

            for i, n_a in enumerate(sorted_nodes):
                added_target_ids = set()

                # 1. Direct causal edges (highest confidence, any time gap across the whole window)
                for out_edge in n_a.outgoing_edges:
                    for target_node in edge_to_targets.get(out_edge, []):
                        if (
                            target_node.node_id != n_a.node_id
                            and target_node.node_id not in added_target_ids
                            and target_node.event.timestamp >= n_a.event.timestamp
                        ):
                            adj[n_a.node_id].append((target_node, 0.95))
                            in_degree[target_node.node_id] += 1
                            added_target_ids.add(target_node.node_id)

                # 2. Semantic and temporal sequence links across extended gap (up to max_time_gap_seconds)
                for j in range(i + 1, len(sorted_nodes)):
                    n_b = sorted_nodes[j]
                    if n_b.node_id in added_target_ids:
                        continue

                    delta = (n_b.event.timestamp - n_a.event.timestamp).total_seconds()
                    if delta > max_time_gap_seconds:
                        break

                    tier_a = SEMANTIC_TIERS.get(n_a.event.source, 1)
                    tier_b = SEMANTIC_TIERS.get(n_b.event.source, 1)

                    same_target = bool(n_a.event.target and n_a.event.target == n_b.event.target)
                    a_has_mitre = any(pat.search(n_a.event.action) or pat.search(n_a.event.target) for pat, _ in MITRE_PATTERNS)
                    b_has_mitre = any(pat.search(n_b.event.action) or pat.search(n_b.event.target) for pat, _ in MITRE_PATTERNS)
                    is_strict_tier_escalation = (tier_b > tier_a) and (tier_b - tier_a <= 3) and (a_has_mitre or b_has_mitre)

                    if same_target:
                        decay = compute_exponential_decay(delta, max(300.0, max_time_gap_seconds))
                        weight = clamp_score(0.4 + 0.4 * decay, 0.0, 1.0, decimals=4)
                        if weight >= 0.4:
                            adj[n_a.node_id].append((n_b, weight))
                            in_degree[n_b.node_id] += 1
                            added_target_ids.add(n_b.node_id)

                    elif is_strict_tier_escalation:
                        decay = compute_exponential_decay(delta, max(300.0, max_time_gap_seconds))
                        semantic_base = 0.4 + (0.1 * abs(tier_b - tier_a))
                        weight = clamp_score(semantic_base + 0.3 * decay, 0.0, 1.0, decimals=4)
                        if weight >= 0.4:
                            adj[n_a.node_id].append((n_b, weight))
                            in_degree[n_b.node_id] += 1
                            added_target_ids.add(n_b.node_id)

            # Traverse paths using DFS starting from root nodes (in_degree == 0 or earliest nodes)
            start_nodes = [n for n in sorted_nodes if in_degree[n.node_id] == 0] or sorted_nodes[:3]

            paths_for_agent: list[list[AttackNode]] = []
            for root in start_nodes:
                self._dfs_retrospective(
                    current_node=root,
                    current_path=[root],
                    adj=adj,
                    min_path_length=min_path_length,
                    visited_in_path={root.node_id},
                    results=paths_for_agent,
                    max_depth=15,
                    max_results=5000,
                )

            for path_nodes in paths_for_agent:
                sig = tuple(n.node_id for n in path_nodes)
                if sig in seen_signatures or len(path_nodes) < min_path_length:
                    continue
                seen_signatures.add(sig)

                max_risk = max(n.event.risk_score for n in path_nodes)
                if max_risk < min_risk_score:
                    continue

                # Compute dynamic correlation score from path edge weights
                weights = []
                for k in range(len(path_nodes) - 1):
                    curr_n = path_nodes[k]
                    next_n = path_nodes[k + 1]
                    matched_w = next(
                        (w for nb, w in adj[curr_n.node_id] if nb.node_id == next_n.node_id),
                        0.7,
                    )
                    weights.append(matched_w)

                correlation_score = clamp_score(sum(weights) / max(1, len(weights)), 0.0, 1.0)
                stages = map_mitre_attack_techniques(path_nodes, default_fallback=None)

                try:
                    path_obj = AttackPath(
                        path_id=uuid.uuid4(),
                        agent_id=aid,
                        nodes=path_nodes,
                        start_time=path_nodes[0].event.timestamp,
                        end_time=path_nodes[-1].event.timestamp,
                        risk_score=clamp_score(max_risk, 0.0, 1.0),
                        attack_stages=stages,
                        correlation_score=correlation_score,
                    )
                    identified_paths.append(path_obj)
                except ValueError:
                    continue

        identified_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return identified_paths

    async def detect_retrospective_paths(
        self,
        agent_id: str | None = None,
        time_window: tuple[datetime, datetime] | None = None,
        batch_size: int = 100,
        min_path_length: int = 2,
        max_time_gap_seconds: int = 86400 * 7,
        min_risk_score: float = 0.0,
    ) -> list[AttackPath]:
        """Perform retrospective analysis on historical events to identify attack paths missed by real-time detection."""
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        return await self.reconstruct_causal_graph(
            agent_id=agent_id,
            time_window=time_window,
            min_path_length=min_path_length,
            min_risk_score=min_risk_score,
            max_time_gap_seconds=float(max_time_gap_seconds),
        )

    def _dfs_retrospective(
        self,
        current_node: AttackNode,
        current_path: list[AttackNode],
        adj: dict[uuid.UUID, list[tuple[AttackNode, float]]],
        min_path_length: int,
        visited_in_path: set[uuid.UUID],
        results: list[list[AttackNode]],
        max_depth: int = 15,
        max_results: int = 5000,
    ) -> None:
        """Depth-first search traversing causal and semantic relationships across extended historical time horizons."""
        if len(current_path) >= min_path_length:
            results.append(list(current_path))

        if len(current_path) >= max_depth:
            return

        neighbors = adj.get(current_node.node_id, [])
        for neighbor, _ in neighbors:
            if len(results) >= max_results:
                break
            if neighbor.node_id not in visited_in_path:
                visited_in_path.add(neighbor.node_id)
                current_path.append(neighbor)
                self._dfs_retrospective(
                    neighbor,
                    current_path,
                    adj,
                    min_path_length,
                    visited_in_path,
                    results,
                    max_depth,
                    max_results,
                )
                current_path.pop()
                visited_in_path.remove(neighbor.node_id)

    async def correlate_multi_agent_history(
        self,
        time_window: tuple[datetime, datetime],
        similarity_threshold: float = 0.7,
        min_agents: int = 2,
    ) -> list[SwarmEvidence]:
        """Correlate events across multiple agents in historical data to identify delayed or slow-moving swarm patterns.

        Args:
            time_window: Tuple of (start_time, end_time) UTC timezone-aware datetimes.
            similarity_threshold: Minimum coordination / pattern overlap threshold in [0.0, 1.0].
            min_agents: Minimum number of coordinated agents required (>= 2).

        Returns:
            List of SwarmEvidence records.
        """
        if not (0.0 <= similarity_threshold <= 1.0):
            raise ValueError("similarity_threshold must be between 0.0 and 1.0")
        if min_agents < 2:
            raise ValueError("min_agents must be at least 2")

        start_win, end_win = normalize_time_window(time_window)

        all_nodes = await self.store.query_nodes(None, (start_win, end_win))
        if not all_nodes:
            return []

        # Group activities by target and action keywords across agents
        target_to_agents: dict[str, set[str]] = defaultdict(set)
        target_to_timestamps: dict[str, list[datetime]] = defaultdict(list)
        agent_actions: dict[str, set[str]] = defaultdict(set)

        for node in all_nodes:
            aid = node.event.agent_id
            target = node.event.target
            action = node.event.action
            target_to_agents[target].add(aid)
            target_to_timestamps[target].append(node.event.timestamp)
            agent_actions[aid].add(action)

        swarms: list[SwarmEvidence] = []
        for target, agents in target_to_agents.items():
            if len(agents) >= min_agents:
                # Compute temporal span
                ts_list = sorted(target_to_timestamps[target])
                first_seen = ts_list[0]
                last_seen = ts_list[-1]

                # Compute temporal and action correlation
                all_actions = [agent_actions[a] for a in agents]
                common_actions = set.intersection(*all_actions) if all_actions else set()
                shared_action_ratio = len(common_actions) / max(1, max(len(a_set) for a_set in all_actions))
                agent_weight = min(1.0, len(agents) / 4.0)

                coordination_score = clamp_score(
                    0.4 + (0.3 * shared_action_ratio) + (0.3 * agent_weight), 0.0, 1.0
                )

                if coordination_score >= similarity_threshold:
                    swarm_obj = SwarmEvidence(
                        swarm_id=uuid.uuid4(),
                        agent_ids=set(agents),
                        shared_patterns=[target] + list(common_actions),
                        temporal_correlation=0.8,
                        coordination_score=coordination_score,
                        first_seen=first_seen,
                        last_seen=max(last_seen, first_seen),
                    )
                    swarms.append(swarm_obj)

        return swarms

    async def purge_expired_events(self, retention_days: int = 30) -> int:
        """Purge historical events older than retention_days (default 30 days) to enforce retention policies."""
        if retention_days < 1:
            raise ValueError("retention_days must be at least 1")
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        return await self.store.purge_events_before(cutoff)

    async def export_attack_graph(
        self,
        format: str = "json",
        agent_id: str | None = None,
        time_window: tuple[datetime, datetime] | None = None,
    ) -> str:
        """Export current attack graph to JSON or GraphML format, scoping nodes and edges strictly to the subgraph."""
        if time_window:
            nodes = await self.store.query_nodes(agent_id, time_window)
        else:
            nodes = await self.store.get_all_nodes()

        if agent_id:
            nodes = [n for n in nodes if n.event.agent_id == agent_id]

        # Retrieve all edges to prevent omitting causal edges created outside node time window
        edges = await self.store.get_edges()

        return self.exporter.export(format, nodes, edges)
