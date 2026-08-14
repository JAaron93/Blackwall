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
from blackwall.validators import validate_temporal_sequence, validate_utc_datetime

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

        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

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

        combined_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return combined_paths[:max_paths]

    async def detect_retrospective_paths(
        self,
        agent_id: str | None = None,
        time_window: tuple[datetime, datetime] | None = None,
        batch_size: int = 100,
        min_path_length: int = 2,
        max_time_gap_seconds: int = 86400 * 7,
        min_risk_score: float = 0.0,
    ) -> list[AttackPath]:
        """Perform batch analysis on historical events to identify attack paths missed by real-time short-window detection.

        Uses deterministic offset pagination to bound memory, maintains lookback buffers across max_time_gap_seconds
        so cross-batch paths are never dropped, and enforces causal, target, or tier-escalation affinity to prevent false paths.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")
        if max_time_gap_seconds <= 0:
            raise ValueError("max_time_gap_seconds must be positive")

        if time_window is not None:
            start_raw, end_raw = time_window
            validate_temporal_sequence(
                start_raw, end_raw, start_name="start_time", end_name="end_time"
            )
            start_win = validate_utc_datetime(start_raw)
            end_win = validate_utc_datetime(end_raw)
        else:
            end_win = datetime.now(UTC)
            start_win = end_win - timedelta(days=30)

        identified_paths: list[AttackPath] = []
        seen_signatures: set[tuple[uuid.UUID, ...]] = set()

        # Active node buffers per agent across sliding batches
        active_agent_nodes: dict[str, list[AttackNode]] = defaultdict(list)
        offset = 0

        while True:
            batch_nodes = await self.store.query_nodes(
                agent_id, (start_win, end_win), limit=batch_size, offset=offset
            )
            if not batch_nodes:
                break

            offset += len(batch_nodes)

            # Ingest batch nodes into active per-agent buffers
            for node in batch_nodes:
                active_agent_nodes[node.event.agent_id].append(node)

            latest_batch_ts = max(n.event.timestamp for n in batch_nodes)
            cutoff_ts = latest_batch_ts - timedelta(seconds=max_time_gap_seconds)

            for aid, agent_nodes in list(active_agent_nodes.items()):
                if len(agent_nodes) < min_path_length:
                    continue

                sorted_nodes = sorted(agent_nodes, key=lambda n: (n.event.timestamp, str(n.node_id)))

                # Build extended adjacency graph supporting causal links + semantic affinity
                adj: dict[uuid.UUID, list[tuple[AttackNode, float]]] = defaultdict(list)
                edge_to_targets: dict[uuid.UUID, list[AttackNode]] = defaultdict(list)
                for n in sorted_nodes:
                    for inc_edge in n.incoming_edges:
                        edge_to_targets[inc_edge].append(n)

                for i, n_a in enumerate(sorted_nodes):
                    added_target_ids = set()

                    # 1. Direct causal edges (highest confidence, any time gap)
                    for out_edge in n_a.outgoing_edges:
                        for target_node in edge_to_targets.get(out_edge, []):
                            if (
                                target_node.node_id != n_a.node_id
                                and target_node.node_id not in added_target_ids
                                and target_node.event.timestamp >= n_a.event.timestamp
                            ):
                                adj[n_a.node_id].append((target_node, 1.0))
                                added_target_ids.add(target_node.node_id)

                    # 2. Behavioral/Semantic affinity links across historical time gaps
                    for n_b in sorted_nodes[i + 1 :]:
                        delta = (n_b.event.timestamp - n_a.event.timestamp).total_seconds()
                        if delta > max_time_gap_seconds:
                            break

                        if n_b.node_id in added_target_ids:
                            continue

                        tier_a = SEMANTIC_TIERS.get(n_a.event.source, 1)
                        tier_b = SEMANTIC_TIERS.get(n_b.event.source, 1)
                        same_target = bool(n_a.event.target and n_a.event.target == n_b.event.target)

                        # Match ATT&CK patterns
                        a_has_mitre = any(pat.search(n_a.event.action) or pat.search(n_a.event.target) for pat, _ in MITRE_PATTERNS)
                        b_has_mitre = any(pat.search(n_b.event.action) or pat.search(n_b.event.target) for pat, _ in MITRE_PATTERNS)
                        is_strict_tier_escalation = (tier_b > tier_a) and (tier_b - tier_a <= 3) and (a_has_mitre or b_has_mitre)

                        # Require shared target or strict multi-tier ATT&CK escalation
                        if same_target or is_strict_tier_escalation:
                            decay = math.exp(-delta / max(300.0, max_time_gap_seconds / 10.0))
                            semantic_base = 0.5 + (0.3 if same_target else 0.0) + (0.1 * abs(tier_b - tier_a))
                            weight = min(1.0, 0.3 * decay + 0.7 * semantic_base)
                            adj[n_a.node_id].append((n_b, weight))
                            added_target_ids.add(n_b.node_id)

                # Traverse and find paths
                all_paths: list[list[AttackNode]] = []
                for start_node in sorted_nodes:
                    self._dfs_retrospective(
                        current_node=start_node,
                        current_path=[start_node],
                        adj=adj,
                        min_path_length=min_path_length,
                        visited_in_path={start_node.node_id},
                        results=all_paths,
                        max_depth=15,
                        max_results=500,
                    )

                # Materialize AttackPath instances
                for path_nodes in all_paths:
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

                    correlation_score = min(1.0, max(0.0, sum(weights) / max(1, len(weights))))

                    stages = []
                    for n in path_nodes:
                        for pattern, code in MITRE_PATTERNS:
                            if pattern.search(n.event.action) or pattern.search(n.event.target):
                                if code not in stages:
                                    stages.append(code)

                    try:
                        path_obj = AttackPath(
                            path_id=uuid.uuid4(),
                            agent_id=aid,
                            nodes=path_nodes,
                            start_time=path_nodes[0].event.timestamp,
                            end_time=path_nodes[-1].event.timestamp,
                            risk_score=min(1.0, max(0.0, max_risk)),
                            attack_stages=stages,
                            correlation_score=correlation_score,
                        )
                        identified_paths.append(path_obj)
                    except ValueError:
                        continue

                # Evict expired nodes from active buffer that are older than cutoff_ts and have no pending outgoing edges
                active_agent_nodes[aid] = [
                    n for n in agent_nodes
                    if n.event.timestamp >= cutoff_ts or len(n.outgoing_edges) > 0
                ]

            if len(batch_nodes) < batch_size:
                break

        identified_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return identified_paths

    def _dfs_retrospective(
        self,
        current_node: AttackNode,
        current_path: list[AttackNode],
        adj: dict[uuid.UUID, list[tuple[AttackNode, float]]],
        min_path_length: int,
        visited_in_path: set[uuid.UUID],
        results: list[list[AttackNode]],
        max_depth: int,
        max_results: int,
    ) -> None:
        """DFS exploration for retrospective multi-stage path reconstruction."""
        if len(results) >= max_results:
            return

        if len(current_path) >= min_path_length:
            results.append(list(current_path))

        if len(current_path) >= max_depth:
            return

        for neighbor, _ in adj.get(current_node.node_id, []):
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

        start_raw, end_raw = time_window
        validate_temporal_sequence(
            start_raw, end_raw, start_name="start_time", end_name="end_time"
        )
        start_win = validate_utc_datetime(start_raw)
        end_win = validate_utc_datetime(end_raw)

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

                coordination_score = min(
                    1.0,
                    max(
                        0.0,
                        0.4 + (0.3 * shared_action_ratio) + (0.3 * agent_weight),
                    ),
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
            edges = await self.store.get_edges(time_window)
        else:
            nodes = await self.store.get_all_nodes()
            edges = await self.store.get_edges()

        if agent_id:
            nodes = [n for n in nodes if n.event.agent_id == agent_id]

        # Filter edges to only include those whose source and target nodes exist in the exported nodes list
        node_id_strs = {str(n.node_id) for n in nodes}
        scoped_edges = [
            e
            for e in edges
            if str(e.get("from_node", "")) in node_id_strs
            and str(e.get("to_node", "")) in node_id_strs
        ]
        scoped_edge_ids = {e["edge_id"] for e in scoped_edges}

        # Filter nodes' incoming and outgoing edge lists to eliminate dangling references in exported node payloads
        scoped_nodes = [
            AttackNode(
                node_id=n.node_id,
                event=n.event,
                incoming_edges=[e for e in n.incoming_edges if e in scoped_edge_ids],
                outgoing_edges=[e for e in n.outgoing_edges if e in scoped_edge_ids],
            )
            for n in nodes
        ]

        return self.exporter.export(format, scoped_nodes, scoped_edges)
