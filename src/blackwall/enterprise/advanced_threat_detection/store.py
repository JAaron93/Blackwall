"""Attack Graph Store component for Blackwall Advanced Threat Detection (Pillar 6)."""

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

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
        dsn: str | None = None,
        pool: Any | None = None,
        in_memory: bool = False,
        min_pool_size: int = 1,
        max_pool_size: int = 10,
    ) -> None:
        self.dsn = dsn
        self._external_pool = pool
        self._pool: asyncpg.Pool | None = None
        self.in_memory = in_memory or (
            dsn is not None and (dsn.startswith("sqlite") or dsn == ":memory:")
        )
        self.min_pool_size = min_pool_size
        self.max_pool_size = max_pool_size

        # In-memory backing structures (used when in_memory=True or as local cache/fallback)
        self._nodes: dict[uuid.UUID, AttackNode] = {}
        self._agent_nodes_index: dict[str, list[uuid.UUID]] = {}
        self._path_cache: dict[tuple[str, datetime, datetime, int], list[AttackPath]] = {}
        self._edges: list[dict[str, Any]] = (
            []
        )  # edge_id, from_node, to_node, relationship, created_at
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
                    await conn.execute(
                        "SELECT create_hypertable('event_nodes', 'timestamp', if_not_exists => TRUE);"
                    )
                except Exception as ts_exc:
                    logger.debug(
                        "TimescaleDB extension setup skipped/unavailable: %s", ts_exc
                    )

        self._initialized = True

    async def close(self) -> None:
        """Close database connection pool."""
        if self._pool and not self._external_pool:
            await self._pool.close()
            self._pool = None
        self._initialized = False

    def _invalidate_path_cache(self, agent_id: str | None = None) -> None:
        """Invalidate query path cache entries."""
        if agent_id is None:
            self._path_cache.clear()
        else:
            keys_to_del = [k for k in self._path_cache if k[0] == agent_id]
            for k in keys_to_del:
                self._path_cache.pop(k, None)

    async def insert_event(self, event: NormalizedEvent) -> AttackNode:
        """Insert event as node in attack graph, preserving temporal ordering."""
        node_id = event.event_id

        # Preserve cached node and its edges if re-inserted
        if node_id in self._nodes:
            return self._nodes[node_id]

        if self._pool:
            committed_node: AttackNode | None = None
            async with self._pool.acquire() as conn:
                async with conn.transaction():
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
                        (
                            event.source.value
                            if hasattr(event.source, "value")
                            else str(event.source)
                        ),
                        event.agent_id,
                        event.action,
                        event.target,
                        json.dumps(event.metadata),
                        event.risk_score,
                        json.dumps([]),
                        json.dumps([]),
                    )
                    # Fetch authoritative row from DB to handle conflict-skipped rows
                    row = await conn.fetchrow(
                        "SELECT * FROM event_nodes WHERE node_id = $1;", str(node_id)
                    )
                    if row:
                        ev_parsed = NormalizedEvent(
                            event_id=row["event_id"],
                            timestamp=row["timestamp"],
                            source=EventSource(row["source"]),
                            agent_id=row["agent_id"],
                            action=row["action"],
                            target=row["target"],
                            metadata=(
                                json.loads(row["metadata"])
                                if isinstance(row["metadata"], str)
                                else row["metadata"]
                            ),
                            risk_score=row["risk_score"],
                        )
                        inc = self._parse_edge_uuids(row["incoming_edges"])
                        out = self._parse_edge_uuids(row["outgoing_edges"])
                        committed_node = AttackNode(
                            node_id=node_id,
                            event=ev_parsed,
                            incoming_edges=inc,
                            outgoing_edges=out,
                        )

            # Mutate cache only after successful commit
            if committed_node:
                self._nodes[node_id] = committed_node
                if node_id not in self._agent_nodes_index.get(committed_node.event.agent_id, []):
                    self._agent_nodes_index.setdefault(committed_node.event.agent_id, []).append(node_id)
                self._invalidate_path_cache(committed_node.event.agent_id)
                return committed_node

        node = AttackNode(
            node_id=node_id,
            event=event,
            incoming_edges=[],
            outgoing_edges=[],
        )
        self._nodes[node_id] = node
        self._agent_nodes_index.setdefault(event.agent_id, []).append(node_id)
        self._invalidate_path_cache(event.agent_id)
        return node

    async def insert_events_batch(
        self, events: list[NormalizedEvent]
    ) -> list[AttackNode]:
        """Insert a batch of events as nodes in the attack graph atomically and efficiently."""
        if not events:
            return []

        nodes_by_id: dict[uuid.UUID, AttackNode] = {}
        new_nodes: list[AttackNode] = []
        nodes_to_insert_db: list[NormalizedEvent] = []

        for event in events:
            node_id = event.event_id
            if node_id in self._nodes:
                if node_id not in nodes_by_id:
                    nodes_by_id[node_id] = self._nodes[node_id]
                continue
            if node_id in nodes_by_id:
                # Within-batch duplicate: reuse already prepared AttackNode
                continue

            node = AttackNode(
                node_id=node_id,
                event=event,
                incoming_edges=[],
                outgoing_edges=[],
            )
            nodes_by_id[node_id] = node
            new_nodes.append(node)
            nodes_to_insert_db.append(event)

        # 1. Database persistence inside atomic transaction FIRST
        if self._pool and nodes_to_insert_db:
            committed_nodes: list[AttackNode] = []
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    insert_tuples = [
                        (
                            str(ev.event_id),
                            str(ev.event_id),
                            ev.timestamp,
                            (
                                ev.source.value
                                if hasattr(ev.source, "value")
                                else str(ev.source)
                            ),
                            ev.agent_id,
                            ev.action,
                            ev.target,
                            json.dumps(ev.metadata),
                            ev.risk_score,
                            json.dumps([]),
                            json.dumps([]),
                        )
                        for ev in nodes_to_insert_db
                    ]
                    await conn.executemany(
                        """
                        INSERT INTO event_nodes (
                            node_id, event_id, timestamp, source, agent_id, action, target, metadata, risk_score, incoming_edges, outgoing_edges
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb, $11::jsonb)
                        ON CONFLICT (node_id) DO NOTHING;
                        """,
                        insert_tuples,
                    )
                    # Fetch authoritative DB rows for all inserted/conflicted IDs to maintain cache consistency
                    db_rows = await conn.fetch(
                        "SELECT * FROM event_nodes WHERE node_id = ANY($1::text[]);",
                        [str(ev.event_id) for ev in nodes_to_insert_db],
                    )
                    for row in db_rows:
                        n_uuid = validate_uuid_v4_format(row["node_id"])
                        ev_parsed = NormalizedEvent(
                            event_id=row["event_id"],
                            timestamp=row["timestamp"],
                            source=EventSource(row["source"]),
                            agent_id=row["agent_id"],
                            action=row["action"],
                            target=row["target"],
                            metadata=(
                                json.loads(row["metadata"])
                                if isinstance(row["metadata"], str)
                                else row["metadata"]
                            ),
                            risk_score=row["risk_score"],
                        )
                        inc = self._parse_edge_uuids(row["incoming_edges"])
                        out = self._parse_edge_uuids(row["outgoing_edges"])
                        db_node = AttackNode(
                            node_id=n_uuid,
                            event=ev_parsed,
                            incoming_edges=inc,
                            outgoing_edges=out,
                        )
                        committed_nodes.append(db_node)

            # Transaction has committed successfully: mutate in-memory cache now
            for node in committed_nodes:
                nodes_by_id[node.node_id] = node
                self._nodes[node.node_id] = node
                if node.node_id not in self._agent_nodes_index.get(node.event.agent_id, []):
                    self._agent_nodes_index.setdefault(node.event.agent_id, []).append(node.node_id)
        else:
            # 2. Mutate in-memory cache structures for in-memory mode
            for node in new_nodes:
                self._nodes[node.node_id] = node
                self._agent_nodes_index.setdefault(node.event.agent_id, []).append(node.node_id)

        affected_agents = {e.agent_id for e in events}
        for aid in affected_agents:
            self._invalidate_path_cache(aid)

        return [nodes_by_id[e.event_id] for e in events]

    async def link_events(
        self,
        from_node: uuid.UUID | str,
        to_node: uuid.UUID | str,
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
            raise ValueError(
                f"Cannot link non-existent nodes: {from_node} -> {to_node}"
            )

        edge_id = uuid.uuid4()
        edge_id_str = str(edge_id)
        from_node_str = str(from_uuid)
        to_node_str = str(to_uuid)
        created_at = datetime.now(UTC)

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
        self._invalidate_path_cache()

    def _parse_edge_uuids(self, raw_edges: Any) -> list[uuid.UUID]:
        """Safely parse edge UUIDs from DB JSON/list, logging warnings for malformed entries."""
        if not raw_edges:
            return []
        edge_list = json.loads(raw_edges) if isinstance(raw_edges, str) else raw_edges
        if not isinstance(edge_list, list):
            return []

        valid_edges: list[uuid.UUID] = []
        for item in edge_list:
            try:
                valid_edges.append(validate_uuid_v4_format(item))
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "Skipping malformed edge UUID '%s' from DB record: %s", item, exc
                )
        return valid_edges

    async def get_node(self, node_id: uuid.UUID | str) -> AttackNode | None:
        """Retrieve AttackNode by node_id."""
        node_uuid = validate_uuid_v4_format(node_id)

        if node_uuid in self._nodes:
            return self._nodes[node_uuid]

        if self._pool:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM event_nodes WHERE node_id = $1;", str(node_uuid)
                )
                if row:
                    event = NormalizedEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=EventSource(row["source"]),
                        agent_id=row["agent_id"],
                        action=row["action"],
                        target=row["target"],
                        metadata=(
                            json.loads(row["metadata"])
                            if isinstance(row["metadata"], str)
                            else row["metadata"]
                        ),
                        risk_score=row["risk_score"],
                    )
                    inc = self._parse_edge_uuids(row["incoming_edges"])
                    out = self._parse_edge_uuids(row["outgoing_edges"])

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
        agent_id: str | None,
        time_window: tuple[datetime, datetime],
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[AttackNode]:
        """Fetch all AttackNodes for an agent (or all agents if agent_id is None) within the specified time window."""
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive")
        if offset is not None and offset < 0:
            raise ValueError("offset must be non-negative")

        start_time_win, end_time_win = time_window

        if self._pool:
            async with self._pool.acquire() as conn:
                if agent_id is not None:
                    query = """
                        SELECT * FROM event_nodes
                        WHERE agent_id = $1 AND timestamp >= $2 AND timestamp <= $3
                        ORDER BY timestamp ASC, node_id ASC
                    """
                    params = [agent_id, start_time_win, end_time_win]
                else:
                    query = """
                        SELECT * FROM event_nodes
                        WHERE timestamp >= $1 AND timestamp <= $2
                        ORDER BY timestamp ASC, node_id ASC
                    """
                    params = [start_time_win, end_time_win]

                if limit is not None:
                    query += f" LIMIT {int(limit)}"
                if offset is not None:
                    query += f" OFFSET {int(offset)}"
                query += ";"

                rows = await conn.fetch(
                    query,
                    *params,
                )
                db_nodes: list[AttackNode] = []
                for row in rows:
                    ev = NormalizedEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=EventSource(row["source"]),
                        agent_id=row["agent_id"],
                        action=row["action"],
                        target=row["target"],
                        metadata=(
                            json.loads(row["metadata"])
                            if isinstance(row["metadata"], str)
                            else row["metadata"]
                        ),
                        risk_score=row["risk_score"],
                    )
                    inc = self._parse_edge_uuids(row["incoming_edges"])
                    out = self._parse_edge_uuids(row["outgoing_edges"])

                    db_node = AttackNode(
                        node_id=row["node_id"],
                        event=ev,
                        incoming_edges=inc,
                        outgoing_edges=out,
                    )
                    db_nodes.append(db_node)
                return db_nodes

        # In-memory mode (self._pool is None)
        if agent_id is not None:
            node_ids = self._agent_nodes_index.get(agent_id, [])
            candidate_nodes = []
            for nid in node_ids:
                node = self._nodes.get(nid)
                if node and start_time_win <= node.event.timestamp <= end_time_win:
                    candidate_nodes.append(node)
        else:
            candidate_nodes = [
                node
                for node in self._nodes.values()
                if start_time_win <= node.event.timestamp <= end_time_win
            ]

        candidate_nodes.sort(key=lambda n: (n.event.timestamp, str(n.node_id)))
        start_idx = offset if offset is not None else 0
        end_idx = (start_idx + limit) if limit is not None else len(candidate_nodes)
        return candidate_nodes[start_idx:end_idx]


    async def query_paths(
        self,
        agent_id: str,
        time_window: tuple[datetime, datetime],
        min_path_length: int = 2,
    ) -> list[AttackPath]:
        """Query multi-hop attack paths for agent within specified time window."""
        if min_path_length < 2:
            raise ValueError("min_path_length must be at least 2")

        cache_key = (agent_id, time_window[0], time_window[1], min_path_length)
        if cache_key in self._path_cache:
            return list(self._path_cache[cache_key])

        candidate_nodes = await self.query_nodes(agent_id, time_window)

        if len(candidate_nodes) < min_path_length:
            return []

        # Group nodes into contiguous temporal or causally connected paths
        paths: list[AttackPath] = []
        current_path_nodes: list[AttackNode] = [candidate_nodes[0]]

        for next_node in candidate_nodes[1:]:
            prev_node = current_path_nodes[-1]
            # Link if within 10 minutes or causally linked
            delta = (
                next_node.event.timestamp - prev_node.event.timestamp
            ).total_seconds()
            is_causal = any(
                e in prev_node.outgoing_edges for e in next_node.incoming_edges
            )

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
        self._path_cache[cache_key] = paths
        return paths

    def _build_attack_path(self, agent_id: str, nodes: list[AttackNode]) -> AttackPath:
        """Helper to create valid AttackPath object from list of nodes."""
        path_id = uuid.uuid4()
        start_time = nodes[0].event.timestamp
        end_time = nodes[-1].event.timestamp

        # Compute aggregate risk_score (max risk in path) and correlation_score
        max_risk = max(n.event.risk_score for n in nodes)
        risk_score = min(1.0, max(0.0, max_risk))
        correlation_score = (
            0.95  # Default high correlation for temporally grouped nodes
        )

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
        time_window: tuple[datetime, datetime],
    ) -> list[tuple[str, str]]:
        """Find pairs of agents exhibiting similar patterns within time window."""
        start_win, end_win = time_window
        matched_agents: dict[str, set[str]] = {}

        for node in self._nodes.values():
            if start_win <= node.event.timestamp <= end_win:
                if pattern in node.event.action or pattern in node.event.target:
                    matched_agents.setdefault(pattern, set()).add(node.event.agent_id)

        agents_list = sorted(list(matched_agents.get(pattern, set())))
        pairs: list[tuple[str, str]] = []
        for i in range(len(agents_list)):
            for j in range(i + 1, len(agents_list)):
                pairs.append((agents_list[i], agents_list[j]))

        return pairs

    async def get_edges(
        self, time_window: tuple[datetime, datetime] | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve causal edges from database or in-memory store."""
        if self._pool:
            async with self._pool.acquire() as conn:
                if time_window:
                    rows = await conn.fetch(
                        """
                        SELECT edge_id, from_node, to_node, relationship, created_at
                        FROM causal_edges
                        WHERE created_at >= $1 AND created_at <= $2
                        ORDER BY created_at ASC;
                        """,
                        time_window[0],
                        time_window[1],
                    )
                else:
                    rows = await conn.fetch(
                        """
                        SELECT edge_id, from_node, to_node, relationship, created_at
                        FROM causal_edges
                        ORDER BY created_at ASC;
                        """
                    )
                return [
                    {
                        "edge_id": row["edge_id"],
                        "from_node": row["from_node"],
                        "to_node": row["to_node"],
                        "relationship": row["relationship"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]

        if time_window:
            start_win, end_win = time_window
            return [
                e
                for e in self._edges
                if start_win <= e["created_at"] <= end_win
            ]
        return list(self._edges)

    async def get_all_nodes(self) -> list[AttackNode]:
        """Retrieve all nodes from the attack graph."""
        if self._pool:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM event_nodes ORDER BY timestamp ASC;"
                )
                db_nodes: list[AttackNode] = []
                for row in rows:
                    ev = NormalizedEvent(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=EventSource(row["source"]),
                        agent_id=row["agent_id"],
                        action=row["action"],
                        target=row["target"],
                        metadata=(
                            json.loads(row["metadata"])
                            if isinstance(row["metadata"], str)
                            else row["metadata"]
                        ),
                        risk_score=row["risk_score"],
                    )
                    inc = self._parse_edge_uuids(row["incoming_edges"])
                    out = self._parse_edge_uuids(row["outgoing_edges"])
                    db_node = AttackNode(
                        node_id=row["node_id"],
                        event=ev,
                        incoming_edges=inc,
                        outgoing_edges=out,
                    )
                    db_nodes.append(db_node)
                return db_nodes

        nodes = list(self._nodes.values())
        nodes.sort(key=lambda n: n.event.timestamp)
        return nodes

    async def purge_events_before(self, cutoff_time: datetime) -> int:
        """Purge events older than cutoff_time from attack graph (enforcing retention invariant)."""
        purged_count = 0
        if self._pool:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    purged_rows = await conn.fetch(
                        "SELECT node_id FROM event_nodes WHERE timestamp < $1;", cutoff_time
                    )
                    purged_ids = [r["node_id"] for r in purged_rows]
                    if purged_ids:
                        edge_rows = await conn.fetch(
                            "SELECT edge_id FROM causal_edges WHERE from_node = ANY($1) OR to_node = ANY($1);",
                            purged_ids,
                        )
                        edge_ids_to_remove = [str(r["edge_id"]) for r in edge_rows]

                        result = await conn.execute(
                            "DELETE FROM event_nodes WHERE timestamp < $1;", cutoff_time
                        )
                        try:
                            purged_count = int(result.split()[-1])
                        except (ValueError, IndexError):
                            purged_count = len(purged_ids)

                        if edge_ids_to_remove:
                            await conn.execute(
                                """
                                UPDATE event_nodes
                                SET incoming_edges = (
                                    SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                                    FROM jsonb_array_elements_text(incoming_edges) AS elem
                                    WHERE elem != ALL($1)
                                ),
                                outgoing_edges = (
                                    SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                                    FROM jsonb_array_elements_text(outgoing_edges) AS elem
                                    WHERE elem != ALL($1)
                                )
                                WHERE incoming_edges ?| $1::text[] OR outgoing_edges ?| $1::text[];
                                """,
                                edge_ids_to_remove,
                            )

        # Purge from in-memory structures
        to_delete = [
            nid
            for nid, node in self._nodes.items()
            if node.event.timestamp < cutoff_time
        ]
        removed_edge_ids = {
            e["edge_id"]
            for e in self._edges
            if e["from_node"] in to_delete or e["to_node"] in to_delete
        }
        for nid in to_delete:
            node = self._nodes.pop(nid, None)
            if node:
                purged_count = max(purged_count, len(to_delete))
                agent_nids = self._agent_nodes_index.get(node.event.agent_id, [])
                if nid in agent_nids:
                    agent_nids.remove(nid)

        for node in self._nodes.values():
            if removed_edge_ids:
                node.incoming_edges = [
                    e for e in node.incoming_edges if e not in removed_edge_ids
                ]
                node.outgoing_edges = [
                    e for e in node.outgoing_edges if e not in removed_edge_ids
                ]

        self._edges = [
            e
            for e in self._edges
            if e["edge_id"] not in removed_edge_ids
        ]
        self._invalidate_path_cache()
        return len(to_delete) if not self._pool else purged_count


