import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
import uuid
import time
from .pool import AsyncConnectionPool

import structlog

logger = structlog.get_logger("blackwall.db.repository")


class SQLiteThreatRepository:
    def __init__(self, db_path: str = "./blackwall.db"):
        self.db_path = db_path
        self.pool = AsyncConnectionPool(db_path, max_connections=10)
        self._schema_initialized = False
        self._init_lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initializes the database schema if it doesn't exist."""
        if self._schema_initialized:
            return

        async with self._init_lock:
            if self._schema_initialized:
                return

            await self.pool.initialize()

            async with self.pool.connection() as conn:
                # Nodes Table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    signature_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    last_matched_at INTEGER,
                    attacker_intent TEXT NOT NULL,
                    payload_pattern TEXT NOT NULL,
                    target_tool TEXT NOT NULL,
                    target_sink TEXT,
                    dependency_chain TEXT,
                    mitigation_action TEXT NOT NULL,
                    match_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    similarity_vector BLOB,
                    metadata TEXT
                );
                """)

                # Indexes for signatures table
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tool ON signatures(target_tool);"
                )
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_last_matched ON signatures(last_matched_at);"
                )

                # Edges Table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS signature_relationships (
                    edge_id TEXT PRIMARY KEY,
                    source_signature_id TEXT NOT NULL,
                    target_signature_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    weight REAL NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (source_signature_id) REFERENCES signatures(signature_id) ON DELETE CASCADE,
                    FOREIGN KEY (target_signature_id) REFERENCES signatures(signature_id) ON DELETE CASCADE
                );
                """)

                # Indexes for signature_relationships table
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_source ON signature_relationships(source_signature_id);"
                )
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_type ON signature_relationships(relationship_type);"
                )

                # FTS5 virtual table
                await conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS signature_fts USING fts5(
                    signature_id UNINDEXED,
                    payload_pattern,
                    attacker_intent,
                    content=signatures,
                    content_rowid=rowid
                );
                """)

                # Triggers to keep FTS in sync with the signatures table
                await conn.execute("""
                CREATE TRIGGER IF NOT EXISTS signatures_ai AFTER INSERT ON signatures BEGIN
                    INSERT INTO signature_fts(rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.payload_pattern, new.attacker_intent);
                END;
                """)

                await conn.execute("""
                CREATE TRIGGER IF NOT EXISTS signatures_ad AFTER DELETE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.payload_pattern, old.attacker_intent);
                END;
                """)

                await conn.execute("""
                CREATE TRIGGER IF NOT EXISTS signatures_au AFTER UPDATE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.payload_pattern, old.attacker_intent);
                    INSERT INTO signature_fts(rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.payload_pattern, new.attacker_intent);
                END;
                """)
                # Audit Incidents table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_type TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    stack_trace TEXT
                );
                """)

                # Blocked Executables table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_executables (
                    executable TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
                """)

                # Blocked IOCs table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_iocs (
                    ioc TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """)

                # GTI Cache table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS gti_cache (
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    response_data TEXT NOT NULL,
                    cached_at INTEGER NOT NULL,
                    PRIMARY KEY (indicator, indicator_type)
                );
                """)

                # Background Tasks table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS background_tasks (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """)

                # In-Flight Background Tasks table
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS in_flight_tasks (
                    task_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
                """)

            self._schema_initialized = True

    async def close(self) -> None:
        """Closes the connection pool."""
        await self.pool.close()

    async def writeSignature(self, signature_data: Dict[str, Any]) -> str:
        """Writes a threat signature using INSERT OR IGNORE to enforce uniqueness."""
        await self.initialize()

        raw_sig_id = signature_data.get("signatureId")
        sig_id = str(raw_sig_id) if raw_sig_id is not None else str(uuid.uuid4())

        raw_created_at = signature_data.get("createdAt")
        created_at = (
            int(raw_created_at) if raw_created_at is not None else int(time.time())
        )

        _raw_last_matched_at = signature_data.get("lastMatchedAt")
        last_matched_at = (
            int(_raw_last_matched_at) if _raw_last_matched_at is not None else None
        )

        raw_intent = signature_data.get("attackerIntent")
        attacker_intent = str(raw_intent) if raw_intent is not None else ""

        raw_pattern = signature_data.get("payloadPattern")
        payload_pattern = str(raw_pattern) if raw_pattern is not None else ""

        raw_tool = signature_data.get("targetTool")
        target_tool = str(raw_tool) if raw_tool is not None else ""

        raw_sink = signature_data.get("targetSink")
        target_sink = str(raw_sink) if raw_sink is not None else None

        raw_chain = signature_data.get("dependencyChain")
        dependency_chain = json.dumps(raw_chain) if raw_chain is not None else None

        raw_mitigation = signature_data.get("mitigationAction")
        mitigation_action = str(raw_mitigation) if raw_mitigation is not None else ""

        raw_match_count = signature_data.get("matchCount")
        match_count = int(raw_match_count) if raw_match_count is not None else 0

        raw_fp_count = signature_data.get("falsePositiveCount")
        false_positive_count = int(raw_fp_count) if raw_fp_count is not None else 0

        similarity_vector = signature_data.get("similarityVector")
        if similarity_vector is not None:
            if isinstance(similarity_vector, (bytes, bytearray)):
                pass
            elif hasattr(similarity_vector, "tobytes") and callable(
                similarity_vector.tobytes
            ):
                similarity_vector = similarity_vector.tobytes()
            elif isinstance(similarity_vector, (list, tuple)):
                import array

                similarity_vector = array.array("f", similarity_vector).tobytes()

        raw_metadata = signature_data.get("metadata")
        metadata = json.dumps(raw_metadata) if raw_metadata is not None else None

        async with self.pool.connection() as conn:
            await conn.execute(
                """
                INSERT OR IGNORE INTO signatures (
                    signature_id, created_at, last_matched_at, attacker_intent,
                    payload_pattern, target_tool, target_sink, dependency_chain,
                    mitigation_action, match_count, false_positive_count,
                    similarity_vector, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    sig_id,
                    created_at,
                    last_matched_at,
                    attacker_intent,
                    payload_pattern,
                    target_tool,
                    target_sink,
                    dependency_chain,
                    mitigation_action,
                    match_count,
                    false_positive_count,
                    similarity_vector,
                    metadata,
                ),
            )

        return sig_id

    async def getStatistics(self) -> Dict[str, Any]:
        """Returns statistics about the graph, including cumulative eviction count."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            total_signatures = row[0] if row else 0

            # Read cumulative eviction count written by EvictionManager
            eviction_count = 0
            try:
                cursor2 = await conn.execute(
                    "SELECT COALESCE(SUM(total_evicted), 0) FROM graph_eviction_stats"
                )
                ev_row = await cursor2.fetchone()
                eviction_count = int(ev_row[0]) if ev_row else 0
            except Exception:
                # Table may not yet exist if EvictionManager hasn't started
                pass

        return {
            "totalSignatures": total_signatures,
            "avgQueryTimeMs": 0.0,
            "cacheHitRate": 0.0,
            "evictionCount": eviction_count,
            "avgMatchesPerSignature": 0.0,
        }

    async def addBlockedExecutable(self, executable: str) -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO blocked_executables (executable, created_at) VALUES (?, ?)",
                (executable, int(time.time())),
            )

    async def addBlockedIOC(self, ioc: str, ioc_type: str = "ip") -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO blocked_iocs (ioc, type, created_at) VALUES (?, ?, ?)",
                (ioc, ioc_type, int(time.time())),
            )

    async def getAuditIncidents(self) -> List[Dict[str, Any]]:
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT incident_id, incident_type, timestamp, details, stack_trace FROM audit_incidents ORDER BY timestamp DESC"
            )
            rows = await cursor.fetchall()
            return [
                {
                    "incident_id": r[0],
                    "incident_type": r[1],
                    "timestamp": r[2],
                    "details": r[3],
                    "stack_trace": r[4],
                }
                for r in rows
            ]

    async def cache_gti_response(
        self, indicator: str, indicator_type: str, response: Dict[str, Any]
    ) -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                """
                INSERT OR REPLACE INTO gti_cache (indicator, indicator_type, response_data, cached_at)
                VALUES (?, ?, ?, ?)
                """,
                (indicator, indicator_type, json.dumps(response), int(time.time())),
            )

    async def get_cached_gti_response(
        self, indicator: str, indicator_type: str
    ) -> Optional[Dict[str, Any]]:
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT response_data, cached_at FROM gti_cache WHERE indicator = ? AND indicator_type = ?",
                (indicator, indicator_type),
            )
            row = await cursor.fetchone()
            if not row:
                return None

            response_data_str, cached_at = row
            # 24-hour TTL (86400 seconds)
            if time.time() - cached_at > 86400:
                # Expired. Delete from cache.
                await conn.execute(
                    "DELETE FROM gti_cache WHERE indicator = ? AND indicator_type = ?",
                    (indicator, indicator_type),
                )
                return None

            try:
                result: Dict[str, Any] = json.loads(response_data_str)
                return result
            except json.JSONDecodeError:
                return None

    async def increment_match_count(self, signature_id: str) -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "UPDATE signatures SET match_count = match_count + 1, last_matched_at = ? WHERE signature_id = ?",
                (int(time.time()), signature_id),
            )

    async def querySimilarSignatures(
        self,
        query_text: str,
        query_vector: Optional[List[float]] = None,
        threshold: float = 0.85
    ) -> List[Dict[str, Any]]:
        """
        Computes cosine similarity between query_vector and stored signatures.
        Falls back to FTS5 full-text search if the signature lacks a vector or if
        no query_vector is provided.
        """
        await self.initialize()
        matches = []

        # Helper to parse sqlite rows into dict matches
        def _parse_row(row, score):
            (
                sig_id, created_at, last_matched_at, attacker_intent, payload_pattern,
                target_tool, target_sink, dependency_chain, mitigation_action, match_count,
                false_positive_count, _, metadata
            ) = row
            return {
                "signature_id": sig_id,
                "created_at": created_at,
                "last_matched_at": last_matched_at,
                "attacker_intent": attacker_intent,
                "payload_pattern": payload_pattern,
                "target_tool": target_tool,
                "target_sink": target_sink,
                "dependency_chain": json.loads(dependency_chain) if dependency_chain else None,
                "mitigation_action": mitigation_action,
                "match_count": match_count,
                "false_positive_count": false_positive_count,
                "similarity_score": score,
                "metadata": json.loads(metadata) if metadata else None
            }

        import re
        words = re.findall(r"\w+", query_text)
        fts_query = " OR ".join(words) if words else ""

        async with self.pool.connection() as conn:
            if query_vector is not None:
                # 1. Load signatures with vectors for cosine similarity
                cursor = await conn.execute(
                    "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                    "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                    "false_positive_count, similarity_vector, metadata FROM signatures "
                    "WHERE similarity_vector IS NOT NULL"
                )
                vector_rows = await cursor.fetchall()

                # Validate query_vector dimension
                if len(query_vector) != 768:
                    raise ValueError(
                        f"Query vector has incorrect dimension {len(query_vector)}, expected 768"
                    )

                for row in vector_rows:
                    sig_id = row[0]
                    similarity_vector = row[11]

                    is_valid_vector = False
                    vector_floats = None
                    try:
                        import array
                        arr = array.array("f")
                        arr.frombytes(similarity_vector)
                        vector_floats = arr.tolist()

                        if len(vector_floats) == 768:
                            is_valid_vector = True
                        else:
                            logger.warning(
                                f"Excluding signature {sig_id} from vector similarity query due to incorrect vector dimension {len(vector_floats)}",
                                signature_id=sig_id,
                                dimension=len(vector_floats)
                            )
                    except Exception as e:
                        logger.warning(
                            f"Excluding signature {sig_id} from vector similarity query due to error decoding vector: {e}",
                            signature_id=sig_id,
                            error=str(e)
                        )

                    if not is_valid_vector:
                        continue

                    # Calculate cosine similarity
                    import math
                    dot_product = sum(x * y for x, y in zip(query_vector, vector_floats, strict=True))
                    norm_q = math.sqrt(sum(x * x for x in query_vector))
                    norm_s = math.sqrt(sum(x * x for x in vector_floats))
                    similarity_score = dot_product / (norm_q * norm_s) if norm_q > 0.0 and norm_s > 0.0 else 0.0

                    if similarity_score >= threshold:
                        matches.append(_parse_row(row, similarity_score))

                # 2. For signatures without vectors, query them via FTS5 if there's a query
                if fts_query:
                    cursor = await conn.execute(
                        "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                        "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                        "false_positive_count, similarity_vector, metadata FROM signatures "
                        "WHERE similarity_vector IS NULL "
                        "AND signature_id IN (SELECT signature_id FROM signature_fts WHERE signature_fts MATCH ?)",
                        (fts_query,)
                    )
                    fts_rows = await cursor.fetchall()
                    for row in fts_rows:
                        sig_id = row[0]
                        logger.warning(
                            "FTS5 fallback triggered for signature similarity match",
                            signature_id=sig_id,
                            reason="missing or invalid vector",
                            timestamp=int(time.time())
                        )
                        current_threshold = min(threshold, 0.7)
                        if 0.75 >= current_threshold:
                            matches.append(_parse_row(row, 0.75))
            else:
                # No query vector provided: all signatures fallback to FTS5
                if fts_query:
                    cursor = await conn.execute(
                        "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                        "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                        "false_positive_count, similarity_vector, metadata FROM signatures "
                        "WHERE signature_id IN (SELECT signature_id FROM signature_fts WHERE signature_fts MATCH ?)",
                        (fts_query,)
                    )
                    fts_rows = await cursor.fetchall()
                    for row in fts_rows:
                        sig_id = row[0]
                        logger.warning(
                            "FTS5 fallback triggered for signature similarity match",
                            signature_id=sig_id,
                            reason="missing query vector",
                            timestamp=int(time.time())
                        )
                        current_threshold = min(threshold, 0.7)
                        if 0.75 >= current_threshold:
                            matches.append(_parse_row(row, 0.75))

            matches.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)
            return matches

    async def find_matching_signature(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        query_vector: Optional[List[float]] = None,
        threshold: float = 0.85
    ) -> Optional[Dict[str, Any]]:
        await self.initialize()

        # Construct query text for similarity & FTS5 matching
        args_values = " ".join(str(v) for v in arguments.values())
        query_text = f"{tool_name} {args_values}"

        # 1. Query similar signatures (Vector similarity + FTS5 fallback)
        matches = await self.querySimilarSignatures(
            query_text=query_text,
            query_vector=query_vector,
            threshold=threshold
        )

        if matches:
            best_match = matches[0]
            sig_id = best_match["signature_id"]
            await self.increment_match_count(sig_id)
            return best_match

        # 2. Substring fallback to maintain backward compatibility
        args_str = json.dumps(arguments)
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT signature_id, target_tool, payload_pattern, mitigation_action, attacker_intent FROM signatures WHERE target_tool = ?",
                (tool_name,),
            )
            rows = await cursor.fetchall()
            for row in rows:
                sig_id, tool, pattern, mitigation, intent = row
                if pattern in args_str:
                    await self.increment_match_count(sig_id)
                    return {
                        "signature_id": sig_id,
                        "target_tool": tool,
                        "payload_pattern": pattern,
                        "mitigation_action": mitigation,
                        "attacker_intent": intent,
                    }
        return None

    async def add_background_task(self, task_id: str, status: str = "PENDING_WEBHOOK_CALLBACK") -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO background_tasks (task_id, status, created_at) VALUES (?, ?, ?)",
                (task_id, status, int(time.time())),
            )

    async def update_background_task_status(self, task_id: str, status: str) -> None:
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "UPDATE background_tasks SET status = ? WHERE task_id = ?",
                (status, task_id),
            )

    async def add_in_flight_task(self, task_id: str) -> None:
        """Adds a task ID to the in-flight list."""
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO in_flight_tasks (task_id, created_at) VALUES (?, ?)",
                (task_id, int(time.time()))
            )

    async def remove_in_flight_task(self, task_id: str) -> None:
        """Removes a task ID from the in-flight list."""
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute("DELETE FROM in_flight_tasks WHERE task_id = ?", (task_id,))

    async def is_task_valid(self, task_id: str) -> bool:
        """Checks if a task ID is valid and not stale (> 12 hours old)."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT created_at FROM in_flight_tasks WHERE task_id = ?",
                (task_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False
            created_at = row[0]
            # 12 hours = 43200 seconds
            if time.time() - created_at > 43200:
                await conn.execute("DELETE FROM in_flight_tasks WHERE task_id = ?", (task_id,))
                return False
            return True

    async def write_signatures_batch(self, signatures: List[Dict[str, Any]]) -> None:
        """Writes multiple threat signatures in a single atomic transaction."""
        await self.initialize()

        async with self.pool.connection() as conn:
            # aiosqlite connection executes in auto-commit mode by default unless transaction is started
            await conn.execute("BEGIN TRANSACTION")
            try:
                for signature_data in signatures:
                    raw_intent = signature_data.get("attackerIntent")
                    attacker_intent = str(raw_intent) if raw_intent is not None else ""

                    raw_pattern = signature_data.get("payloadPattern")
                    payload_pattern = str(raw_pattern) if raw_pattern is not None else ""

                    raw_tool = signature_data.get("targetTool")
                    target_tool = str(raw_tool) if raw_tool is not None else ""

                    raw_sig_id = signature_data.get("signatureId")
                    if raw_sig_id is not None:
                        sig_id = str(raw_sig_id)
                    else:
                        # Derive stable deduplication key for recurring signature content
                        sig_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{target_tool}:{payload_pattern}:{attacker_intent}"))

                    raw_created_at = signature_data.get("createdAt")
                    created_at = int(raw_created_at) if raw_created_at is not None else int(time.time())

                    _raw_last_matched_at = signature_data.get("lastMatchedAt")
                    last_matched_at = int(_raw_last_matched_at) if _raw_last_matched_at is not None else None

                    target_sink = str(signature_data.get("targetSink")) if signature_data.get("targetSink") is not None else None

                    raw_chain = signature_data.get("dependencyChain")
                    dependency_chain = json.dumps(raw_chain) if raw_chain is not None else None

                    raw_mitigation = signature_data.get("mitigationAction")
                    mitigation_action = str(raw_mitigation) if raw_mitigation is not None else ""

                    raw_match_count = signature_data.get("matchCount")
                    match_count = int(raw_match_count) if raw_match_count is not None else 0

                    raw_fp_count = signature_data.get("falsePositiveCount")
                    false_positive_count = int(raw_fp_count) if raw_fp_count is not None else 0

                    similarity_vector = signature_data.get("similarityVector")
                    if similarity_vector is not None:
                        if isinstance(similarity_vector, (bytes, bytearray)):
                            vector_blob = similarity_vector
                        elif hasattr(similarity_vector, "tobytes") and callable(similarity_vector.tobytes):
                            vector_blob = similarity_vector.tobytes()
                        elif isinstance(similarity_vector, (list, tuple)):
                            import array
                            vector_blob = array.array("f", similarity_vector).tobytes()
                        else:
                            vector_blob = None
                    else:
                        vector_blob = None

                    raw_metadata = signature_data.get("metadata")
                    metadata_str = json.dumps(raw_metadata) if raw_metadata is not None else None

                    await conn.execute(
                        """
                        INSERT OR REPLACE INTO signatures (
                            signature_id, created_at, last_matched_at, attacker_intent, payload_pattern,
                            target_tool, target_sink, dependency_chain, mitigation_action,
                            match_count, false_positive_count, similarity_vector, metadata
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sig_id, created_at, last_matched_at, attacker_intent, payload_pattern,
                            target_tool, target_sink, dependency_chain, mitigation_action,
                            match_count, false_positive_count, vector_blob, metadata_str,
                        ),
                    )
                await conn.commit()
            except Exception as e:
                await conn.rollback()
                logger.error(f"Failed to batch write signatures: {e}")
                raise
