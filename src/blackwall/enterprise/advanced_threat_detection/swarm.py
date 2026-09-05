"""Agent Swarm Detector component for Blackwall Advanced Threat Detection (Pillar 6 Task 7)."""

import hashlib
import logging
import re
import uuid
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.covert_channel import (
    CovertChannelDetector,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    CovertChannelEvidence,
    NormalizedEvent,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.policy.models import PolicyConfig
from blackwall.validators import (
    clamp_score,
    compute_exponential_decay,
    compute_jaccard_similarity,
    normalize_time_window,
    utc_now,
    validate_utc_datetime,
)

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.swarm")

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _avg_min_time_diff(ts1: list[datetime], ts2: list[datetime]) -> float:
    """Compute average minimal time difference (in seconds) between two sorted timestamp lists in O(N+M) time."""
    if not ts1 or not ts2:
        return 0.0

    total_diff = 0.0
    idx2 = 0
    len2 = len(ts2)

    for t1 in ts1:
        while idx2 + 1 < len2 and abs((ts2[idx2 + 1] - t1).total_seconds()) < abs(
            (ts2[idx2] - t1).total_seconds()
        ):
            idx2 += 1
        total_diff += abs((ts2[idx2] - t1).total_seconds())

    return total_diff / len(ts1)


class AgentSwarmDetector:
    """Detects coordinated multi-agent swarms using behavioral fingerprinting and temporal correlation."""

    def __init__(
        self,
        store: AttackGraphStore | None = None,
        policy: PolicyConfig | None = None,
        default_window: int | None = None,
        default_min_agents: int | None = None,
        default_correlation_threshold: float | None = None,
        covert_channel_detector: CovertChannelDetector | None = None,
        alert_bus: AlertBus | None = None,
    ) -> None:
        self.store = store or AttackGraphStore(in_memory=True)
        self.policy = policy
        self.alert_bus = alert_bus

        p_cfg = policy.advancedThreatDetection.swarmDetector if policy else None

        self.default_window = (
            default_window
            if default_window is not None
            else (p_cfg.windowSeconds if p_cfg else 3600)
        )
        self.default_min_agents = (
            default_min_agents
            if default_min_agents is not None
            else (p_cfg.minAgents if p_cfg else 2)
        )
        self.default_correlation_threshold = (
            default_correlation_threshold
            if default_correlation_threshold is not None
            else (p_cfg.correlationThreshold if p_cfg else 0.75)
        )
        self.covert_channel_detector = covert_channel_detector or CovertChannelDetector(
            min_agents=self.default_min_agents,
            min_correlation_threshold=0.80,
            min_coordination_threshold=0.80,
        )
        self.last_detected_covert_channels: list[CovertChannelEvidence] = []
        self._fingerprint_state: dict[str, dict[str, Any]] = {}

    def update_fingerprint_incremental(
        self,
        agent_id: str,
        new_events: list[NormalizedEvent],
        window: int | None = None,
    ) -> str:
        """Incrementally update behavioral fingerprint state with new events without full window recomputation.

        Args:
            agent_id: Identifier of the agent.
            new_events: List of new NormalizedEvent instances to incorporate.
            window: Optional window size in seconds (default 3600).

        Returns:
            Updated SHA-256 behavioral fingerprint hex string.
        """
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must be non-empty")
        win = window if window is not None else self.default_window
        if win <= 0:
            raise ValueError("window must be positive")

        if agent_id not in self._fingerprint_state:
            self._fingerprint_state[agent_id] = {
                "events": deque(maxlen=5000),
                "action_tokens": deque(maxlen=5000),
                "last_hash": "",
            }

        state = self._fingerprint_state[agent_id]
        sorted_new = sorted(new_events, key=lambda e: e.timestamp)

        for e in sorted_new:
            token = f"{e.source.value}:{e.action}:{e.target}"
            state["events"].append(e)
            state["action_tokens"].append(token)

        if state["events"]:
            latest_ts = state["events"][-1].timestamp
            cutoff = latest_ts - timedelta(seconds=win)
            while state["events"] and state["events"][0].timestamp < cutoff:
                state["events"].popleft()
                state["action_tokens"].popleft()

        seq_str = "|".join(state["action_tokens"])
        fingerprint = hashlib.sha256(seq_str.encode("utf-8")).hexdigest()
        state["last_hash"] = fingerprint
        return fingerprint

    async def fingerprint_agent(
        self,
        agent_id: str,
        window: int | None = None,
        end_time: datetime | None = None,
    ) -> str:
        """Generate behavioral fingerprint for agent over time window (seconds) using action sequence hashing."""
        win = window if window is not None else self.default_window
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must be non-empty")
        if win <= 0:
            raise ValueError("window must be positive")

        if end_time is None:
            end_win = utc_now()
        else:
            end_win = validate_utc_datetime(end_time)

        start_win = end_win - timedelta(seconds=win)

        # Query events for agent in window
        nodes = await self.store.query_nodes(agent_id, (start_win, end_win), limit=5000)
        events = [node.event for node in nodes]
        events.sort(key=lambda e: e.timestamp)

        action_sequence = [f"{e.source.value}:{e.action}:{e.target}" for e in events]
        sequence_str = "|".join(action_sequence)
        return hashlib.sha256(sequence_str.encode("utf-8")).hexdigest()

    async def detect_swarms(
        self,
        time_window: tuple[datetime, datetime],
        min_agents: int | None = None,
        correlation_threshold: float | None = None,
    ) -> list[SwarmEvidence]:
        """Detect coordinated agent swarms meeting correlation and minimum agent count thresholds."""
        m_agents = min_agents if min_agents is not None else self.default_min_agents
        c_thresh = (
            correlation_threshold
            if correlation_threshold is not None
            else self.default_correlation_threshold
        )

        if m_agents < 2:
            raise ValueError("min_agents must be at least 2")
        if not (0.0 <= c_thresh <= 1.0):
            raise ValueError("correlation_threshold must be between 0.0 and 1.0")

        self.last_detected_covert_channels.clear()

        start_win, end_win = normalize_time_window(time_window)

        # Fetch nodes across all agents within time window
        all_nodes = await self.store.query_nodes(
            agent_id=None, time_window=(start_win, end_win), limit=5000
        )

        # Group nodes/events by agent_id
        events_by_agent: dict[str, list[NormalizedEvent]] = {}
        for node in all_nodes:
            aid = node.event.agent_id
            if aid not in events_by_agent:
                events_by_agent[aid] = []
            events_by_agent[aid].append(node.event)

        agent_ids = list(events_by_agent.keys())
        if len(agent_ids) < m_agents:
            self.last_detected_covert_channels.clear()
            return []

        # Find pairwise correlations and build agent adjacency graph
        all_pairwise_corrs: dict[tuple[str, str], float] = {}
        correlated_pairs: dict[tuple[str, str], float] = {}

        for i in range(len(agent_ids)):
            for j in range(i + 1, len(agent_ids)):
                a1, a2 = agent_ids[i], agent_ids[j]
                corr = self._compute_pairwise_correlation(
                    events_by_agent[a1], events_by_agent[a2], (start_win, end_win)
                )
                all_pairwise_corrs[(a1, a2)] = corr
                if corr >= c_thresh:
                    correlated_pairs[(a1, a2)] = corr

        # Build connected components (swarms) of agents
        adjacency: dict[str, set[str]] = {aid: set() for aid in agent_ids}
        for a1, a2 in correlated_pairs:
            adjacency[a1].add(a2)
            adjacency[a2].add(a1)

        visited: set[str] = set()
        swarms: list[SwarmEvidence] = []

        for aid in agent_ids:
            if aid in visited or not adjacency[aid]:
                continue

            # BFS component search using deque
            component: set[str] = set()
            queue = deque([aid])
            while queue:
                curr = queue.popleft()
                if curr in component:
                    continue
                component.add(curr)
                visited.add(curr)
                for nxt in adjacency[curr]:
                    if nxt not in component:
                        queue.append(nxt)

            if len(component) < m_agents:
                continue

            # Compute swarm evidence properties
            comp_list = list(component)
            shared_patterns = self._extract_shared_infrastructure(
                {a: events_by_agent[a] for a in comp_list}
            )

            # Average pairwise correlation across ALL pairs in component
            pair_corrs = []
            for i in range(len(comp_list)):
                for j in range(i + 1, len(comp_list)):
                    pair = (comp_list[i], comp_list[j])
                    rev_pair = (comp_list[j], comp_list[i])
                    if pair in all_pairwise_corrs:
                        pair_corrs.append(all_pairwise_corrs[pair])
                    elif rev_pair in all_pairwise_corrs:
                        pair_corrs.append(all_pairwise_corrs[rev_pair])

            avg_corr = sum(pair_corrs) / len(pair_corrs) if pair_corrs else c_thresh
            temporal_correlation = clamp_score(float(avg_corr), 0.0, 1.0)

            coord_score = await self.compute_coordination_score(
                comp_list, (start_win, end_win)
            )

            comp_events = [e for a in comp_list for e in events_by_agent[a]]
            first_seen = min(e.timestamp for e in comp_events)
            last_seen = max(e.timestamp for e in comp_events)

            swarm = SwarmEvidence(
                swarm_id=uuid.uuid4(),
                agent_ids=component,
                shared_patterns=shared_patterns,
                temporal_correlation=temporal_correlation,
                coordination_score=coord_score,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            swarms.append(swarm)

        # Evaluate covert channel evidence for detected swarms (TASK-2B.3, FR-3, FR-4)
        self.last_detected_covert_channels.clear()
        if self.covert_channel_detector is not None:
            for swarm in swarms:
                comp_events_by_agent = {a: events_by_agent.get(a, []) for a in swarm.agent_ids}
                evidences = self.covert_channel_detector.detect_for_swarm(
                    swarm, events_by_agent=comp_events_by_agent
                )
                self.last_detected_covert_channels.extend(evidences)

        return swarms

    async def compute_coordination_score(
        self,
        agents: list[str],
        time_window: tuple[datetime, datetime],
    ) -> float:
        """Compute coordination score for agent group in range [0.0, 1.0]."""
        if not agents or len(agents) < 2:
            return 0.0

        start_win, end_win = normalize_time_window(time_window)

        all_nodes = await self.store.query_nodes(
            agent_id=None, time_window=(start_win, end_win), limit=5000
        )
        events_by_agent: dict[str, list[NormalizedEvent]] = {a: [] for a in agents}
        for node in all_nodes:
            if node.event.agent_id in events_by_agent:
                events_by_agent[node.event.agent_id].append(node.event)

        active_agents = [a for a in agents if events_by_agent[a]]
        if len(active_agents) < 2:
            return 0.0

        # Sub-score 1: Temporal alignment (closeness of event timestamps across agents in O(N+M))
        timestamps_by_agent = {
            a: sorted([e.timestamp for e in events_by_agent[a]]) for a in active_agents
        }
        alignment_scores = []
        for i in range(len(active_agents)):
            for j in range(i + 1, len(active_agents)):
                ts1 = timestamps_by_agent[active_agents[i]]
                ts2 = timestamps_by_agent[active_agents[j]]
                if not ts1 or not ts2:
                    continue
                avg_diff = (
                    _avg_min_time_diff(ts1, ts2) + _avg_min_time_diff(ts2, ts1)
                ) / 2.0
                score_pair = compute_exponential_decay(avg_diff, 30.0)
                alignment_scores.append(score_pair)

        temporal_alignment = (
            sum(alignment_scores) / len(alignment_scores) if alignment_scores else 0.0
        )

        # Sub-score 2: Behavioral similarity (action and target overlap using Jaccard similarity)
        action_sets = {
            a: {f"{e.action}:{e.target}" for e in events_by_agent[a]}
            for a in active_agents
        }
        jaccards = []
        for i in range(len(active_agents)):
            for j in range(i + 1, len(active_agents)):
                s1 = action_sets[active_agents[i]]
                s2 = action_sets[active_agents[j]]
                if s1 or s2:
                    jaccard = compute_jaccard_similarity(s1, s2)
                    jaccards.append(jaccard)
        behavioral_sim = sum(jaccards) / len(jaccards) if jaccards else 0.0

        # Sub-score 3: Shared infrastructure score
        shared_patterns = self._extract_shared_infrastructure(
            {a: events_by_agent[a] for a in active_agents}
        )
        infra_score = min(1.0, len(shared_patterns) * 0.25)

        # Weighted aggregate: 40% temporal alignment, 40% behavioral similarity, 20% shared infra
        raw_score = (
            (0.4 * temporal_alignment) + (0.4 * behavioral_sim) + (0.2 * infra_score)
        )
        return clamp_score(raw_score, 0.0, 1.0)

    def _compute_pairwise_correlation(
        self,
        events1: list[NormalizedEvent],
        events2: list[NormalizedEvent],
        time_window: tuple[datetime, datetime],
    ) -> float:
        """Compute pairwise correlation between two agents' events in O(N+M) time."""
        if not events1 or not events2:
            return 0.0

        # 1. Temporal closeness score using two-pointer O(N+M) pass
        ts1 = sorted([e.timestamp for e in events1])
        ts2 = sorted([e.timestamp for e in events2])

        avg_diff1 = _avg_min_time_diff(ts1, ts2)
        avg_diff2 = _avg_min_time_diff(ts2, ts1)
        avg_diff = (avg_diff1 + avg_diff2) / 2.0
        temporal_score = compute_exponential_decay(avg_diff, 60.0)

        # 2. Action similarity score using Jaccard similarity
        actions1 = {e.action for e in events1}
        actions2 = {e.action for e in events2}
        action_sim = compute_jaccard_similarity(actions1, actions2)

        # 3. Target similarity score using Jaccard similarity
        targets1 = {e.target for e in events1}
        targets2 = {e.target for e in events2}
        target_sim = compute_jaccard_similarity(targets1, targets2)

        correlation = (0.5 * temporal_score) + (0.25 * action_sim) + (0.25 * target_sim)
        return clamp_score(correlation, 0.0, 1.0)


    def _extract_shared_infrastructure(
        self,
        events_by_agent: dict[str, list[NormalizedEvent]],
    ) -> list[str]:
        """Extract shared IP addresses, domains, and resource patterns across agents."""
        if len(events_by_agent) < 2:
            return []

        agent_ips: dict[str, set[str]] = {}
        agent_domains: dict[str, set[str]] = {}
        agent_resources: dict[str, set[str]] = {}

        for aid, events in events_by_agent.items():
            agent_ips[aid] = set()
            agent_domains[aid] = set()
            agent_resources[aid] = set()

            for e in events:
                for ip in IP_REGEX.findall(e.target):
                    agent_ips[aid].add(ip)
                for dom in DOMAIN_REGEX.findall(e.target):
                    agent_domains[aid].add(dom)

                if isinstance(e.metadata, dict):
                    for k, v in e.metadata.items():
                        v_str = str(v)
                        for ip in IP_REGEX.findall(v_str):
                            agent_ips[aid].add(ip)
                        for dom in DOMAIN_REGEX.findall(v_str):
                            agent_domains[aid].add(dom)
                        if k in ("resource", "url", "endpoint", "path"):
                            agent_resources[aid].add(v_str)

        shared_patterns: list[str] = []

        all_ips = set.union(*agent_ips.values()) if agent_ips else set()
        for ip in all_ips:
            sharing_agents = [aid for aid, ips in agent_ips.items() if ip in ips]
            if len(sharing_agents) >= 2:
                shared_patterns.append(f"ip:{ip}")

        all_domains = set.union(*agent_domains.values()) if agent_domains else set()
        for dom in all_domains:
            sharing_agents = [aid for aid, doms in agent_domains.items() if dom in doms]
            if len(sharing_agents) >= 2:
                shared_patterns.append(f"domain:{dom}")

        all_resources = (
            set.union(*agent_resources.values()) if agent_resources else set()
        )
        for res in all_resources:
            sharing_agents = [
                aid for aid, res_set in agent_resources.items() if res in res_set
            ]
            if len(sharing_agents) >= 2:
                shared_patterns.append(f"resource:{res}")

        return sorted(set(shared_patterns))
