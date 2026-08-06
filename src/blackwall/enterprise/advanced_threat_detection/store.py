"""Attack Graph Store component for Blackwall Advanced Threat Detection (Pillar 6)."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

import asyncpg

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import (
    AttackNode,
    AttackPath,
    NormalizedEvent,
)
from blackwall.validators import validate_uuid_v4_format

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.store")


class AttackGraphStore:
    """Persistent temporal graph database store for security events and multi-hop attack path queries."""

    def __init__(
        self,
        dsn: Optional[str] = None,
        pool: Optional[Any] = None,
        in_memory: bool = False,
        min_pool_size: int = 1,
        max_pool_size: int = 10,
    ) -> None:
        self.dsn = dsn
        self._external_pool = pool
        self._pool: Optional[asyncpg.Pool] = None
        self.in_memory = in_memory or (dsn is not None and (dsn.startswith("sqlite") or dsn == ":memory:"))
        self.min_pool_size = min_pool_size
        self.max_pool_size = max_pool_size

        # In-memory backing structures (used when in_memory=True or as local cache/fallback)
        self._nodes: Dict[uuid.UUID, AttackNode] = {}
        self._edges: List[Dict[str, Any]] = []  # edge_id, from_node, to_node, relationship, created_at
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize database connection pool, create tables and TimescaleDB hypertable if applicable."""
        if self._initialized:
            return

        if self._external_pool:
            self._pool = self._external_pool
            self.in_memory = False
        elif self.dsn and not self.in_memory:
            try:
                self._pool = await asyncpg.create_pool(
                    dsn=self.dsn,
                    min_size=self.min_pool_size,
                    max_size=self.max_pool_size,
                )
            except Exception as exc:
                # Do not log DSN raw string to prevent credentials leakage
                logger.warning("Failed to connect to PostgreSQL database pool: %s", exc)
                # If explicit DSN was provided and in_memory wasn't requested, do not silently fallback
                raise

        if self._pool:
            async with self._pool.acquire() as conn:
                # Create event_nodes table
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_nodes (
                        node_id TEXT PRIMARY KEY,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TIMESTAMPTZ NOT NULL,
                        source TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT NOT NULL,
                        metadata JSONB NOT NULL,
                        risk_score DOUBLE PRECISION NOT NULL,
                        incoming_edges JSONB NOT NULL DEFAULT '[]'::jsonb,
                        outgoing_edges JSONB NOT NULL DEFAULT '[]'::jsonb
                    );
                    """
                )

                # Create indexes
                await conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_event_nodes_agent_ts ON event_nodes (agent_id, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_event_nodes_timestamp ON event_nodes (timestamp);
                    """
                )

                # Create causal_edges table
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS causal_edges (
                        edge_id TEXT PRIMARY KEY,
                        from_node TEXT NOT NULL REFERENCES event_nodes(node_id) ON DELETE CASCADE,
                        to_node TEXT NOT NULL REFERENCES event_nodes(node_id) ON DELETE CASCADE,
                        relationship TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL
                    );
                    """
                )

                await conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_causal_edges_from ON causal_edges (from_node);
                    CREATE INDEX IF NOT EXISTS idx_causal_edges_to ON causal_edges (to_node);
                    """
                )

                # Attempt TimescaleDB hypertable creation for time-series optimization
                try:
                    await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb;")
                    await conn.execute("SELECT create_hypertable('event_nodes', 'timestamp', if_not_exists => TRUE);")
                except Exception as ts_exc:
                    logger.debug("TimescaleDB extension setup skipped/unavailable: %s", ts_exc)

        self._initialized = True

    async def close(self) -> None:
        """Close database connection pool."""
        if self._pool and not self._external_pool:
            await self._pool.close()
            self._pool = None
        self._initialized = False

    async def insert_event(self, event: NormalizedEvent) -> AttackNode:
        """Insert event as node in attack graph, preserving temporal ordering."""
        node_id = event.event_id

        # Preserve cached node and its edges if re-inserted
        if node_id in self._nodes:
            return self._nodes[node_id]

        node = AttackNode(
            node_id=node_id,
            event=event,
            incoming_edges=[],
            outgoing_edges=[],
        )

        if self._pool:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO event_nodes (
                        node_id, event_id, timestamp, source, agent_id, action, target, metadata, risk_score, incoming_edges, outgoing_edges
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb, $11::jsonb)
                    ON CONFLICT (node_id) DO NOTHING;
                    """,
                    str(node_id),
                    str(event.event_id),
                    event.timestamp,
                    event.source.value if hasattr(event.source, "value") else str(event.source),
                    event.agent_id,
                    event.action,
                    event.target,
                    json.dumps(event.metadata),
                    event.risk_score,
                    json.dumps([]),
                    json.dumps([]),
                )

        self._nodes[node_id] = node
        return node

    async def link_events(
        self,
        from_node: Union[uuid.UUID, str],
        to_node: Union[uuid.UUID, str],
        relationship: str,
    ) -> None:
        """Create directed causal edge between from_node and to_node."""
        from_uuid = validate_uuid_v4_format(from_node)
        to_uuid = validate_uuid_v4_format(to_node)

        if from_uuid not in self._nodes or to_uuid not in self._nodes:
            # If not in cache, try fetching from pool if available
            if self._pool:
                await self.get_node(from_uuid)
                await self.get_node(to_uuid)

        if from_uuid not in self._nodes or to_uuid not in self._nodes:
            raise ValueError(f"Cannot link non-existent nodes: {from_node} -> {to_node}")

        edge_id = uuid.uuid4()
        edge_id_str = str(edge_id)
        from_node_str = str(from_uuid)
        to_node_str = str(to_uuid)
        created_at = datetime.now(timezone.utc)

        # Database persistence inside atomic transaction first
        if self._pool:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO causal_edges (edge_id, from_node, to_node, relationship, created_at)
                        VALUES ($1, $2, $3, $4, $5);
                        """,
                        edge_id_str,
                        from_node_str,
                        to_node_str,
                        relationship,
                        created_at,
                    )
                    await conn.execute(
                        "UPDATE event_nodes SET outgoing_edges = outgoing_edges || $1::jsonb WHERE node_id = $2;",
                        json.dumps([edge_id_str]),
                        from_node_str,
                    )
                    await conn.execute(
                        "UPDATE event_nodes SET incoming_edges = incoming_edges || $1::jsonb WHERE node_id = $2;",
                        json.dumps([edge_id_str]),
                        to_node_str,
                    )

        # Update in-memory node structures only after DB write succeeds (or in in-memory mode)
        src_node = self._nodes[from_uuid]
        tgt_node = self._nodes[to_uuid]

        if edge_id not in src_node.outgoing_edges:
            src_node.outgoing_edges.append(edge_id)
        if edge_id not in tgt_node.incoming_edges:
            tgt_node.incoming_edges.append(edge_id)

        edge_record = {
            "edge_id": edge_id,
            "from_node": from_uuid,
            "to_node": to_uuid,
            "relationship": relationship,
            "created_at": created_at,
        }
        self._edges.append(edge_record)

    async def get_node(self, node_id: Union[uuid.UUID, str]) -> Optional[AttackNode]:
        """Retrieve AttackNode by node_id."""
        node_uuid = validate_uuid_v4_format(node_id)

        if node_uuid in self._nodes:
            return self._nodes[node_uuid]

        if self._pool:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow("SELECT * FROM event_nodes WHERE node_id = $1;", str(node_uuid))
                if row:
                    event = NormalizedEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=EventSource(row["source"]),
                        agent_id=row["agent_id"],
                        action=row["action"],
                        target=row["target"],
                        metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"],
                        risk_score=row["risk_score"],
                    )
                    raw_inc = json.loads(row["incoming_edges"]) if isinstance(row["incoming_edges"], str) else row["incoming_edges"]
                    raw_out = json.loads(row["outgoing_edges"]) if isinstance(row["outgoing_edges"], str) else row["outgoing_edges"]
                    inc = [validate_uuid_v4_format(e) for e in raw_inc]
                    out = [validate_uuid_v4_format(e) for e in raw_out]

                    node = AttackNode(
                        node_id=row["node_id"],
                        event=event,
                        incoming_edges=inc,
                        outgoing_edges=out,
                    )
                    self._nodes[node.node_id] = node
                    return node

        return None

    async def query_nodes(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
        limit: Optional[int] = None,
    ) -> List[AttackNode]:
        """Fetch all AttackNodes for an agent within the specified time window."""
        start_time_win, end_time_win = time_window

        nodes_map: Dict[uuid.UUID, AttackNode] = {}
        for node in self._nodes.values():
            if (
                node.event.agent_id == agent_id
                and start_time_win <= node.event.timestamp <= end_time_win
            ):
                nodes_map[node.node_id] = node

        if self._pool:
            async with self._pool.acquire() as conn:
                query = """
                    SELECT * FROM event_nodes
                    WHERE agent_id = $1 AND timestamp >= $2 AND timestamp <= $3
                    ORDER BY timestamp ASC
                """
                if limit is not None:
                    query += f" LIMIT {int(limit)}"
                query += ";"

                rows = await conn.fetch(
                    query,
                    agent_id,
                    start_time_win,
                    end_time_win,
                )
                for row in rows:
                    ev = NormalizedEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=EventSource(row["source"]),
                        agent_id=row["agent_id"],
                        action=row["action"],
                        target=row["target"],
                        metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"],
                        risk_score=row["risk_score"],
                    )
                    raw_inc = json.loads(row["incoming_edges"]) if isinstance(row["incoming_edges"], str) else row["incoming_edges"]
                    raw_out = json.loads(row["outgoing_edges"]) if isinstance(row["outgoing_edges"], str) else row["outgoing_edges"]
                    inc = [validate_uuid_v4_format(e) for e in raw_inc]
                    out = [validate_uuid_v4_format(e) for e in raw_out]

                    db_node = AttackNode(
                        node_id=row["node_id"],
                        event=ev,
                        incoming_edges=inc,
                        outgoing_edges=out,
                    )
                    self._nodes[db_node.node_id] = db_node
                    nodes_map[db_node.node_id] = db_node

        candidate_nodes = list(nodes_map.values())
        candidate_nodes.sort(key=lambda n: n.event.timestamp)
        if limit is not None:
            candidate_nodes = candidate_nodes[:limit]
        return candidate_nodes

    async def query_paths(
        self,
        agent_id: str,
        time_window: Tuple[datetime, datetime],
        min_path_length: int = 2,
    ) -> List[AttackPath]:
        """Query multi-hop attack paths for agent within specified time window."""
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")

        candidate_nodes = await self.query_nodes(agent_id, time_window)

        if len(candidate_nodes) < min_path_length:
            return []

        # Group nodes into contiguous temporal or causally connected paths
        paths: List[AttackPath] = []
        current_path_nodes: List[AttackNode] = [candidate_nodes[0]]

        for next_node in candidate_nodes[1:]:
            prev_node = current_path_nodes[-1]
            # Link if within 10 minutes or causally linked
            delta = (next_node.event.timestamp - prev_node.event.timestamp).total_seconds()
            is_causal = any(e in prev_node.outgoing_edges for e in next_node.incoming_edges)

            if delta <= 600 or is_causal:
                current_path_nodes.append(next_node)
            else:
                if len(current_path_nodes) >= min_path_length:
                    paths.append(self._build_attack_path(agent_id, current_path_nodes))
                current_path_nodes = [next_node]

        if len(current_path_nodes) >= min_path_length:
            paths.append(self._build_attack_path(agent_id, current_path_nodes))

        # Sort paths by risk_score descending
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def _build_attack_path(self, agent_id: str, nodes: List[AttackNode]) -> AttackPath:
        """Helper to create valid AttackPath object from list of nodes."""
        path_id = uuid.uuid4()
        start_time = nodes[0].event.timestamp
        end_time = nodes[-1].event.timestamp

        # Compute aggregate risk_score (max risk in path) and correlation_score
        max_risk = max(n.event.risk_score for n in nodes)
        risk_score = min(1.0, max(0.0, max_risk))
        correlation_score = 0.95  # Default high correlation for temporally grouped nodes

        # Simple ATT&CK stage mapping based on actions
        stages = []
        for n in nodes:
            action_lower = n.event.action.lower()
            if "exec" in action_lower:
                stages.append("T1059")  # Command and Scripting Interpreter
            elif "connect" in action_lower or "socket" in action_lower:
                stages.append("T1071")  # Application Layer Protocol
            elif "read" in action_lower or "token" in action_lower:
                stages.append("T1552")  # Unsecured Credentials

        return AttackPath(
            path_id=path_id,
            agent_id=agent_id,
            nodes=nodes,
            start_time=start_time,
            end_time=end_time,
            risk_score=risk_score,
            attack_stages=stages,
            correlation_score=correlation_score,
        )

    async def find_correlated_agents(
        self,
        pattern: str,
        time_window: Tuple[datetime, datetime],
    ) -> List[Tuple[str, str]]:
        """Find pairs of agents exhibiting similar patterns within time window."""
        start_win, end_win = time_window
        matched_agents: Dict[str, Set[str]] = {}

        for node in self._nodes.values():
            if start_win <= node.event.timestamp <= end_win:
                if pattern in node.event.action or pattern in node.event.target:
                    matched_agents.setdefault(pattern, set()).add(node.event.agent_id)

        agents_list = sorted(list(matched_agents.get(pattern, set())))
        pairs: List[Tuple[str, str]] = []
        for i in range(len(agents_list)):
            for j in range(i + 1, len(agents_list)):
                pairs.append((agents_list[i], agents_list[j]))

        return pairs
