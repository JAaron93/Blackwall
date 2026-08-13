"""Retrospective Analysis and Historical Query component for Blackwall Advanced Threat Detection (Pillar 6 Task 17)."""

import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from blackwall.enterprise.advanced_threat_detection.correlator import (
    MITRE_PATTERNS,
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

        # Query all agents in the historical window
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

        Identifies multi-hop chains spanning wide temporal gaps (e.g. low-and-slow stealth campaigns)
        using causal edge tracking and relaxed temporal adjacency.
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

        nodes = await self.store.query_nodes(agent_id, (start_win, end_win))
        if len(nodes) < min_path_length:
            return []

        # Group nodes by agent_id for per-agent path reconstruction
        nodes_by_agent: dict[str, list[AttackNode]] = defaultdict(list)
        for node in nodes:
            nodes_by_agent[node.event.agent_id].append(node)

        identified_paths: list[AttackPath] = []

        # Process each agent's historical stream in batches
        for aid, agent_nodes in nodes_by_agent.items():
            sorted_nodes = sorted(agent_nodes, key=lambda n: n.event.timestamp)

            # Build extended adjacency graph supporting causal links + multi-day gaps
            adj: dict[uuid.UUID, list[tuple[AttackNode, float]]] = defaultdict(list)
            edge_to_targets: dict[uuid.UUID, list[AttackNode]] = defaultdict(list)
            for n in sorted_nodes:
                for inc_edge in n.incoming_edges:
                    edge_to_targets[inc_edge].append(n)

            for i, n_a in enumerate(sorted_nodes):
                added_target_ids = set()

                # 1. Causal edge links (any time gap)
                for out_edge in n_a.outgoing_edges:
                    for target_node in edge_to_targets.get(out_edge, []):
                        if (
                            target_node.node_id != n_a.node_id
                            and target_node.node_id not in added_target_ids
                            and target_node.event.timestamp >= n_a.event.timestamp
                        ):
                            adj[n_a.node_id].append((target_node, 1.0))
                            added_target_ids.add(target_node.node_id)

                # 2. Relaxed temporal links up to max_time_gap_seconds
                for n_b in sorted_nodes[i + 1 :]:
                    delta = (n_b.event.timestamp - n_a.event.timestamp).total_seconds()
                    if delta > max_time_gap_seconds:
                        break
                    if n_b.node_id not in added_target_ids:
                        weight = 0.5 + (0.5 * (1.0 - (delta / max_time_gap_seconds)))
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
            seen_signatures: set[tuple[uuid.UUID, ...]] = set()
            for path_nodes in all_paths:
                sig = tuple(n.node_id for n in path_nodes)
                if sig in seen_signatures or len(path_nodes) < min_path_length:
                    continue
                seen_signatures.add(sig)

                max_risk = max(n.event.risk_score for n in path_nodes)
                if max_risk < min_risk_score:
                    continue

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
                        correlation_score=0.9,
                    )
                    identified_paths.append(path_obj)
                except ValueError:
                    continue

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
                coordination_score = min(
                    1.0,
                    0.5 + (0.1 * len(common_actions)) + (0.1 * min(len(agents), 5)),
                )

                if coordination_score >= similarity_threshold * 0.5:
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
        """Export current attack graph to JSON or GraphML format."""
        if time_window:
            nodes = await self.store.query_nodes(agent_id, time_window)
            edges = await self.store.get_edges(time_window)
        else:
            nodes = await self.store.get_all_nodes()
            edges = await self.store.get_edges()

        if agent_id:
            nodes = [n for n in nodes if n.event.agent_id == agent_id]

        return self.exporter.export(format, nodes, edges)
