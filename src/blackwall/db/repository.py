import asyncio
import json
import logging
from typing import Dict, Any
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
                await conn.execute(
                    """
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
                """
                )

                # Indexes for signatures table
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tool ON signatures(target_tool);"
                )
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_last_matched ON signatures(last_matched_at);"
                )

                # Edges Table
                await conn.execute(
                    """
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
                """
                )

                # Indexes for signature_relationships table
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_source ON signature_relationships(source_signature_id);"
                )
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_type ON signature_relationships(relationship_type);"
                )

                # FTS5 virtual table
                await conn.execute(
                    """
                CREATE VIRTUAL TABLE IF NOT EXISTS signature_fts USING fts5(
                    signature_id UNINDEXED,
                    payload_pattern,
                    attacker_intent,
                    content=signatures,
                    content_rowid=rowid
                );
                """
                )

                # Triggers to keep FTS in sync with the signatures table
                await conn.execute(
                    """
                CREATE TRIGGER IF NOT EXISTS signatures_ai AFTER INSERT ON signatures BEGIN
                    INSERT INTO signature_fts(rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.payload_pattern, new.attacker_intent);
                END;
                """
                )

                await conn.execute(
                    """
                CREATE TRIGGER IF NOT EXISTS signatures_ad AFTER DELETE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.payload_pattern, old.attacker_intent);
                END;
                """
                )

                await conn.execute(
                    """
                CREATE TRIGGER IF NOT EXISTS signatures_au AFTER UPDATE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.payload_pattern, old.attacker_intent);
                    INSERT INTO signature_fts(rowid, signature_id, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.payload_pattern, new.attacker_intent);
                END;
                """
                )

            self._schema_initialized = True

    async def close(self) -> None:
        """Closes the connection pool."""
        await self.pool.close()

    async def writeSignature(self, signature_data: Dict[str, Any]) -> str:
        """Writes a threat signature using INSERT OR IGNORE to enforce uniqueness."""
        await self.initialize()

        sig_id = str(signature_data.get("signatureId", uuid.uuid4()))
        created_at = int(signature_data.get("createdAt", time.time()))
        last_matched_at = signature_data.get("lastMatchedAt")
        attacker_intent = str(signature_data.get("attackerIntent", ""))
        payload_pattern = str(signature_data.get("payloadPattern", ""))
        target_tool = str(signature_data.get("targetTool", ""))
        target_sink = signature_data.get("targetSink")
        dependency_chain = json.dumps(signature_data.get("dependencyChain", []))
        mitigation_action = str(signature_data.get("mitigationAction", ""))
        match_count = int(signature_data.get("matchCount", 0))
        false_positive_count = int(signature_data.get("falsePositiveCount", 0))
        similarity_vector = signature_data.get("similarityVector")
        metadata = json.dumps(signature_data.get("metadata", {}))

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
