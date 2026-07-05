import asyncio
import json
import logging
from typing import Dict, Any, List
import uuid
import time
from .pool import AsyncConnectionPool

logger = logging.getLogger(__name__)


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
        """Returns statistics about the graph."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            total_signatures = row[0] if row else 0

        return {
            "totalSignatures": total_signatures,
            "avgQueryTimeMs": 0.0,
            "cacheHitRate": 0.0,
            "evictionCount": 0,
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
