import asyncio
import json
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog

from blackwall.models import AttackerProfile, SwarmContextSummary
from blackwall.validators import (
    compute_word_intersection_match_quality,
    format_iso_datetime,
    parse_iso_datetime,
    parse_json_safely,
    utc_now,
)
from .pool import AsyncConnectionPool

try:
    try:
        from blackwall import _core_rs
    except ImportError:
        import _core_rs
except (ImportError, AttributeError):
    _core_rs = None

logger = structlog.get_logger("blackwall.db.repository")


# Track 3 (Pillar 3) explicit SQL construction: swarm lineage statements are
# defined once at module level so reviewers can audit every query in one
# place. All value binding uses `?` placeholders; no identifiers or values
# are ever interpolated into these statements.
_SWARM_PROFILE_COLUMN_MIGRATIONS = (
    ("swarm_memberships", "TEXT DEFAULT '[]'"),
    ("suspected_covert_channels", "TEXT DEFAULT '[]'"),
    ("collective_confidence", "REAL DEFAULT 0.0"),
    ("collective_name", "TEXT"),
)

_CREATE_LOCAL_SWARM_CONTEXTS_TABLE = """
CREATE TABLE IF NOT EXISTS local_swarm_contexts (
    swarm_id TEXT PRIMARY KEY,
    collective_name TEXT,
    collective_confidence REAL NOT NULL DEFAULT 0.0,
    coordinating_agents TEXT NOT NULL DEFAULT '[]',
    suspected_covert_channels TEXT NOT NULL DEFAULT '[]',
    covert_channel_type TEXT,
    deduction_rationale TEXT,
    first_detected TEXT NOT NULL,
    last_detected TEXT NOT NULL
);
"""

_CREATE_IDX_SWARM_AGENTS = "CREATE INDEX IF NOT EXISTS idx_swarm_agents ON local_swarm_contexts(coordinating_agents);"

_UPSERT_ATTACKER_PROFILE = """
INSERT INTO attacker_profiles (
    fingerprint, first_seen, last_seen, total_attacks,
    threat_score, associated_signatures, targeted_tools, risk_category,
    swarm_memberships, suspected_covert_channels,
    collective_confidence, collective_name
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
) ON CONFLICT(fingerprint) DO UPDATE SET
    last_seen = excluded.last_seen,
    total_attacks = attacker_profiles.total_attacks + excluded.total_attacks,
    threat_score = excluded.threat_score,
    risk_category = excluded.risk_category,
    targeted_tools = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(attacker_profiles.targeted_tools)
            UNION
            SELECT value FROM json_each(excluded.targeted_tools)
        )
    ),
    associated_signatures = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(attacker_profiles.associated_signatures)
            UNION
            SELECT value FROM json_each(excluded.associated_signatures)
        )
    ),
    swarm_memberships = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(attacker_profiles.swarm_memberships)
            UNION
            SELECT value FROM json_each(excluded.swarm_memberships)
        )
    ),
    suspected_covert_channels = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(attacker_profiles.suspected_covert_channels)
            UNION
            SELECT value FROM json_each(excluded.suspected_covert_channels)
        )
    ),
    collective_confidence = MAX(
        attacker_profiles.collective_confidence,
        excluded.collective_confidence
    ),
    collective_name = COALESCE(
        excluded.collective_name, attacker_profiles.collective_name
    )
RETURNING fingerprint, first_seen, last_seen, total_attacks, threat_score, targeted_tools, associated_signatures, risk_category, swarm_memberships, suspected_covert_channels, collective_confidence, collective_name;
"""

_SELECT_ATTACKER_PROFILE = """
SELECT fingerprint, first_seen, last_seen, total_attacks,
        threat_score, associated_signatures, targeted_tools, risk_category,
        swarm_memberships, suspected_covert_channels,
        collective_confidence, collective_name
FROM attacker_profiles
WHERE fingerprint = ?
"""

_UPSERT_SWARM_CONTEXT = """
INSERT INTO local_swarm_contexts (
    swarm_id, collective_name, collective_confidence,
    coordinating_agents, suspected_covert_channels,
    covert_channel_type, deduction_rationale,
    first_detected, last_detected
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?
) ON CONFLICT(swarm_id) DO UPDATE SET
    collective_name = COALESCE(
        excluded.collective_name, local_swarm_contexts.collective_name
    ),
    collective_confidence = MAX(
        local_swarm_contexts.collective_confidence,
        excluded.collective_confidence
    ),
    coordinating_agents = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(local_swarm_contexts.coordinating_agents)
            UNION
            SELECT value FROM json_each(excluded.coordinating_agents)
        )
    ),
    suspected_covert_channels = (
        SELECT json_group_array(value) FROM (
            SELECT value FROM json_each(local_swarm_contexts.suspected_covert_channels)
            UNION
            SELECT value FROM json_each(excluded.suspected_covert_channels)
        )
    ),
    covert_channel_type = COALESCE(
        excluded.covert_channel_type, local_swarm_contexts.covert_channel_type
    ),
    deduction_rationale = COALESCE(
        excluded.deduction_rationale, local_swarm_contexts.deduction_rationale
    ),
    first_detected = MIN(
        local_swarm_contexts.first_detected, excluded.first_detected
    ),
    last_detected = MAX(
        local_swarm_contexts.last_detected, excluded.last_detected
    )
RETURNING swarm_id, collective_name, collective_confidence,
    coordinating_agents, suspected_covert_channels,
    covert_channel_type, deduction_rationale,
    first_detected, last_detected;
"""

_SELECT_SWARM_CONTEXT_BY_ID = """
SELECT swarm_id, collective_name, collective_confidence,
       coordinating_agents, suspected_covert_channels,
       covert_channel_type, deduction_rationale,
       first_detected, last_detected
FROM local_swarm_contexts
WHERE swarm_id = ?
"""

_SELECT_SWARM_CONTEXT_BY_AGENT = """
SELECT swarm_id, collective_name, collective_confidence,
       coordinating_agents, suspected_covert_channels,
       covert_channel_type, deduction_rationale,
       first_detected, last_detected
FROM local_swarm_contexts
WHERE EXISTS (
    SELECT 1 FROM json_each(local_swarm_contexts.coordinating_agents)
    WHERE value = ?
)
ORDER BY last_detected DESC
LIMIT 1;
"""

_SELECT_SWARM_MEMBERSHIPS = (
    "SELECT swarm_memberships FROM attacker_profiles WHERE fingerprint = ?;"
)


class SQLiteThreatRepository:
    def __init__(self, db_path: str = "./blackwall.db"):
        self.db_path = db_path
        self.pool = AsyncConnectionPool(db_path, max_connections=10)
        self._schema_initialized = False
        self._init_lock = asyncio.Lock()
        self._query_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._query_cache_ttl: float = 300.0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._total_query_time_ms: float = 0.0
        self._total_queries: int = 0

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

                # Self-healing migration for FTS virtual table to include target_tool if missing
                fts_migration_occurred = False
                cursor = await conn.execute("PRAGMA table_info(signature_fts);")
                columns = [row[1] for row in await cursor.fetchall()]
                if columns and "target_tool" not in columns:
                    await conn.execute("DROP TRIGGER IF EXISTS signatures_ai;")
                    await conn.execute("DROP TRIGGER IF EXISTS signatures_ad;")
                    await conn.execute("DROP TRIGGER IF EXISTS signatures_au;")
                    await conn.execute("DROP TABLE IF EXISTS signature_fts;")
                    fts_migration_occurred = True

                # FTS5 virtual table
                await conn.execute(
                    """
                CREATE VIRTUAL TABLE IF NOT EXISTS signature_fts USING fts5(
                    signature_id UNINDEXED,
                    target_tool,
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
                    INSERT INTO signature_fts(rowid, signature_id, target_tool, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.target_tool, new.payload_pattern, new.attacker_intent);
                END;
                """
                )

                await conn.execute(
                    """
                CREATE TRIGGER IF NOT EXISTS signatures_ad AFTER DELETE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, target_tool, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.target_tool, old.payload_pattern, old.attacker_intent);
                END;
                """
                )

                await conn.execute(
                    """
                CREATE TRIGGER IF NOT EXISTS signatures_au AFTER UPDATE ON signatures BEGIN
                    INSERT INTO signature_fts(signature_fts, rowid, signature_id, target_tool, payload_pattern, attacker_intent)
                    VALUES('delete', old.rowid, old.signature_id, old.target_tool, old.payload_pattern, old.attacker_intent);
                    INSERT INTO signature_fts(rowid, signature_id, target_tool, payload_pattern, attacker_intent)
                    VALUES (new.rowid, new.signature_id, new.target_tool, new.payload_pattern, new.attacker_intent);
                END;
                """
                )

                # Rebuild FTS index only if the migration flag is set
                if fts_migration_occurred:
                    await conn.execute(
                        "INSERT INTO signature_fts(signature_fts) VALUES('rebuild');"
                    )
                # Audit Incidents table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS audit_incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_type TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    stack_trace TEXT
                );
                """
                )

                # Blocked Executables table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS blocked_executables (
                    executable TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
                """
                )

                # Blocked IOCs table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS blocked_iocs (
                    ioc TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
                )

                # GTI Cache table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS gti_cache (
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    response_data TEXT NOT NULL,
                    cached_at INTEGER NOT NULL,
                    PRIMARY KEY (indicator, indicator_type)
                );
                """
                )

                # Threat Intelligence Cache table (3.0.0)
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (indicator, indicator_type, provider)
                );
                """
                )
                await conn.execute(
                    """
                CREATE INDEX IF NOT EXISTS idx_threat_cache_lookup 
                ON threat_intel_cache(indicator, indicator_type, expires_at);
                """
                )

                # Automatic purge of expired threat intelligence cache records (FR-05)
                await conn.execute(
                    "DELETE FROM threat_intel_cache WHERE expires_at <= ?;",
                    (time.time(),),
                )

                # Threat Intelligence Cache Metrics table for persistent hit/miss tracking
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS threat_intel_cache_metrics (
                    metric_name TEXT PRIMARY KEY,
                    metric_value INTEGER NOT NULL DEFAULT 0
                );
                """
                )
                await conn.execute(
                    "INSERT OR IGNORE INTO threat_intel_cache_metrics (metric_name, metric_value) VALUES ('hits', 0);"
                )
                await conn.execute(
                    "INSERT OR IGNORE INTO threat_intel_cache_metrics (metric_name, metric_value) VALUES ('misses', 0);"
                )

                # Background Tasks table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS background_tasks (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
                )

                # In-Flight Background Tasks table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS in_flight_tasks (
                    task_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
                """
                )

                # Attacker Profiles table
                await conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_attacks INTEGER NOT NULL DEFAULT 1,
                    threat_score REAL NOT NULL DEFAULT 0.5,
                    associated_signatures TEXT,
                    targeted_tools TEXT,
                    risk_category TEXT NOT NULL DEFAULT 'HIGH'
                );
                """
                )

                # Self-healing swarm lineage columns for pre-existing DBs.
                cursor = await conn.execute("PRAGMA table_info(attacker_profiles);")
                profile_columns = {row[1] for row in await cursor.fetchall()}
                for column_name, column_ddl in _SWARM_PROFILE_COLUMN_MIGRATIONS:
                    if column_name not in profile_columns:
                        await conn.execute(
                            f"ALTER TABLE attacker_profiles ADD COLUMN {column_name} {column_ddl};"
                        )

                # Local Swarm Contexts table (Track 3, Pillar 3 bridge persistence)
                await conn.execute(_CREATE_LOCAL_SWARM_CONTEXTS_TABLE)
                await conn.execute(_CREATE_IDX_SWARM_AGENTS)

            self._schema_initialized = True

    async def close(self) -> None:
        """Closes the connection pool."""
        await self.pool.close()

    async def upsert_attacker_profile(
        self, profile: AttackerProfile
    ) -> AttackerProfile:
        """
        Upserts an attacker profile record in SQLite.
        If profile exists by fingerprint:
          - Increments total_attacks += 1
          - Updates last_seen to current UTC time
          - Updates threat_score
          - Merges targeted_tools and associated_signatures
        If profile does not exist:
          - Inserts new profile record.
        Must complete in < 5ms (NFR-1).
        """
        await self.initialize()
        now_dt = utc_now()
        now_str = format_iso_datetime(now_dt)
        first_seen_str = (
            format_iso_datetime(profile.first_seen) if profile.first_seen else now_str
        )

        tools_json = json.dumps(profile.targeted_tools)
        sigs_json = json.dumps(profile.associated_signatures)
        swarm_json = json.dumps([str(s) for s in profile.swarm_memberships])
        channels_json = json.dumps(profile.suspected_covert_channels)

        async with self.pool.connection() as conn:
            try:
                cursor = await conn.execute(
                    _UPSERT_ATTACKER_PROFILE,
                    (
                        profile.fingerprint,
                        first_seen_str,
                        now_str,
                        max(1, profile.total_attacks),
                        profile.threat_score,
                        sigs_json,
                        tools_json,
                        profile.risk_category,
                        swarm_json,
                        channels_json,
                        profile.collective_confidence,
                        profile.collective_name,
                    ),
                )
                row = await cursor.fetchone()
                await conn.commit()

                if row:
                    (
                        fp,
                        fs_str,
                        ls_str,
                        attacks,
                        score,
                        tools_raw,
                        sigs_raw,
                        risk,
                        swarm_raw,
                        channels_raw,
                        collective_confidence,
                        collective_name,
                    ) = row
                    fs_dt = parse_iso_datetime(fs_str, default=now_dt)
                    ls_dt = parse_iso_datetime(ls_str, default=now_dt)
                    tools = parse_json_safely(tools_raw, default=[])
                    sigs = parse_json_safely(sigs_raw, default=[])
                    swarm_ids = self._parse_uuid_list(
                        parse_json_safely(swarm_raw, default=[])
                    )
                    channels = parse_json_safely(channels_raw, default=[])
                    return AttackerProfile(
                        fingerprint=fp,
                        first_seen=fs_dt,
                        last_seen=ls_dt,
                        total_attacks=attacks,
                        threat_score=score,
                        targeted_tools=tools,
                        associated_signatures=sigs,
                        risk_category=risk,
                        swarm_memberships=swarm_ids,
                        suspected_covert_channels=channels,
                        collective_confidence=collective_confidence or 0.0,
                        collective_name=collective_name,
                    )
                return profile
            except Exception:
                await conn.rollback()
                raise

    async def get_attacker_profile(self, fingerprint: str) -> Optional[AttackerProfile]:
        """Fetches an AttackerProfile by fingerprint from SQLite."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                _SELECT_ATTACKER_PROFILE,
                (fingerprint,),
            )
            row = await cursor.fetchone()
            if not row:
                return None

            (
                fp,
                fs,
                ls,
                total_attacks,
                score,
                sigs_json,
                tools_json,
                risk,
                swarm_raw,
                channels_raw,
                collective_confidence,
                collective_name,
            ) = row
            first_dt = parse_iso_datetime(fs)
            last_dt = parse_iso_datetime(ls)
            sigs = parse_json_safely(sigs_json, default=[])
            tools = parse_json_safely(tools_json, default=[])
            swarm_ids = self._parse_uuid_list(parse_json_safely(swarm_raw, default=[]))
            channels = parse_json_safely(channels_raw, default=[])

            return AttackerProfile(
                fingerprint=fp,
                first_seen=first_dt,
                last_seen=last_dt,
                total_attacks=total_attacks,
                threat_score=score,
                associated_signatures=sigs,
                targeted_tools=tools,
                risk_category=risk,
                swarm_memberships=swarm_ids,
                suspected_covert_channels=channels,
                collective_confidence=collective_confidence or 0.0,
                collective_name=collective_name,
            )

    @staticmethod
    def _parse_uuid_list(values: Any) -> List[UUID]:
        """Parse a JSON-decoded list into UUIDs, skipping malformed entries."""
        parsed: List[UUID] = []
        if not isinstance(values, list):
            return parsed
        for value in values:
            try:
                parsed.append(UUID(str(value)))
            except (ValueError, TypeError, AttributeError):
                continue
        return parsed

    def _row_to_swarm_context(self, row: Any) -> SwarmContextSummary:
        """Maps a local_swarm_contexts row to a SwarmContextSummary."""
        (
            swarm_id_raw,
            collective_name,
            collective_confidence,
            agents_raw,
            channels_raw,
            covert_channel_type,
            deduction_rationale,
            first_raw,
            last_raw,
        ) = row
        return SwarmContextSummary(
            swarm_id=UUID(str(swarm_id_raw)),
            is_collective=True,
            collective_name=collective_name,
            collective_confidence=collective_confidence or 0.0,
            coordinating_agents=parse_json_safely(agents_raw, default=[]),
            suspected_covert_channels=parse_json_safely(channels_raw, default=[]),
            covert_channel_type=covert_channel_type,
            deduction_rationale=deduction_rationale,
            first_detected=parse_iso_datetime(first_raw),
            last_detected=parse_iso_datetime(last_raw),
        )

    async def upsert_swarm_context(
        self, context: SwarmContextSummary
    ) -> SwarmContextSummary:
        """Inserts or updates a local swarm context record (< 5ms SLA)."""
        await self.initialize()
        now_dt = utc_now()
        swarm_id = context.swarm_id or uuid.uuid4()
        first_str = format_iso_datetime(context.first_detected or now_dt)
        last_str = format_iso_datetime(context.last_detected or now_dt)

        async with self.pool.connection() as conn:
            try:
                cursor = await conn.execute(
                    _UPSERT_SWARM_CONTEXT,
                    (
                        str(swarm_id),
                        context.collective_name,
                        context.collective_confidence,
                        json.dumps(context.coordinating_agents),
                        json.dumps(context.suspected_covert_channels),
                        context.covert_channel_type,
                        context.deduction_rationale,
                        first_str,
                        last_str,
                    ),
                )
                row = await cursor.fetchone()
                await conn.commit()
                if row:
                    return self._row_to_swarm_context(row)
                return context
            except Exception:
                await conn.rollback()
                raise

    async def _fetch_swarm_context(
        self, conn: Any, swarm_id: UUID
    ) -> Optional[SwarmContextSummary]:
        """Fetches a swarm context by UUID using an existing connection."""
        cursor = await conn.execute(
            _SELECT_SWARM_CONTEXT_BY_ID,
            (str(swarm_id),),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_swarm_context(row)

    async def get_swarm_context(self, swarm_id: UUID) -> Optional[SwarmContextSummary]:
        """Fetches a swarm context by UUID (< 5ms SLA)."""
        await self.initialize()
        async with self.pool.connection() as conn:
            return await self._fetch_swarm_context(conn, swarm_id)

    async def find_swarm_by_agent_or_fingerprint(
        self, agent_id: Optional[str], fingerprint: str
    ) -> Optional[SwarmContextSummary]:
        """Resolves active swarm lineage via agent membership or profile lineage (< 5ms SLA)."""
        await self.initialize()
        async with self.pool.connection() as conn:
            if agent_id:
                cursor = await conn.execute(
                    _SELECT_SWARM_CONTEXT_BY_AGENT,
                    (agent_id,),
                )
                row = await cursor.fetchone()
                if row:
                    return self._row_to_swarm_context(row)

            if fingerprint:
                cursor = await conn.execute(
                    _SELECT_SWARM_MEMBERSHIPS,
                    (fingerprint,),
                )
                profile_row = await cursor.fetchone()
                if profile_row:
                    memberships = self._parse_uuid_list(
                        parse_json_safely(profile_row[0], default=[])
                    )
                    linked_contexts = []
                    for membership_id in memberships:
                        linked = await self._fetch_swarm_context(conn, membership_id)
                        if linked is not None:
                            linked_contexts.append(linked)
                    if linked_contexts:
                        # Profiles may link stale and current swarms; resolve to
                        # the most recently detected context, mirroring the
                        # agent-membership branch ordering above.
                        linked_contexts.sort(
                            key=lambda ctx: ctx.last_detected
                            or datetime.min.replace(tzinfo=timezone.utc),
                            reverse=True,
                        )
                        return linked_contexts[0]
            return None

    async def writeSignature(self, signature_data: dict[str, Any]) -> str:
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
            try:
                if isinstance(similarity_vector, (bytes, bytearray)):
                    pass
                elif hasattr(similarity_vector, "tobytes") and callable(
                    similarity_vector.tobytes
                ):
                    converted = similarity_vector.tobytes()
                    if isinstance(converted, (bytes, bytearray)):
                        similarity_vector = converted
                    else:
                        logger.warning(
                            "Ignoring similarity_vector whose tobytes() did not return bytes; storing NULL"
                        )
                        similarity_vector = None
                elif isinstance(similarity_vector, (list, tuple)):
                    import array

                    similarity_vector = array.array("f", similarity_vector).tobytes()
                else:
                    logger.warning(
                        "Ignoring unsupported similarity_vector type; storing NULL"
                    )
                    similarity_vector = None
            except Exception as exc:
                # The vector is optional enrichment: never fail the row for it.
                logger.warning(
                    "Ignoring similarity_vector that failed coercion; storing NULL: %s",
                    exc,
                )
                similarity_vector = None

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

        self._query_cache.clear()
        return sig_id

    async def getStatistics(self) -> dict[str, Any]:
        """Returns statistics about the graph, including cumulative eviction count."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM signatures")
            row = await cursor.fetchone()
            total_signatures = row[0] if row else 0

            cursor_avg = await conn.execute(
                "SELECT COALESCE(AVG(match_count), 0.0) FROM signatures"
            )
            avg_row = await cursor_avg.fetchone()
            avg_matches = float(avg_row[0]) if avg_row else 0.0

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

        total_q = self._cache_hits + self._cache_misses
        cache_hit_rate = (self._cache_hits / total_q) if total_q > 0 else 0.0
        avg_query_time = (
            (self._total_query_time_ms / self._total_queries)
            if self._total_queries > 0
            else 0.0
        )

        return {
            "totalSignatures": total_signatures,
            "avgQueryTimeMs": avg_query_time,
            "cacheHitRate": cache_hit_rate,
            "evictionCount": eviction_count,
            "avgMatchesPerSignature": avg_matches,
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

    async def getAuditIncidents(self) -> list[dict[str, Any]]:
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
        self, indicator: str, indicator_type: str, response: dict[str, Any]
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
    ) -> dict[str, Any] | None:
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
                result: dict[str, Any] = json.loads(response_data_str)
                return result
            except json.JSONDecodeError:
                return None

    async def cache_threat_intel(
        self,
        response: Any,
        ttl_seconds: Optional[float] = None,
        provider: Optional[str] = None,
    ) -> None:
        """Caches a ThreatIntelResponse with TTL (24h benign, 6h malicious by default)."""
        await self.initialize()
        if ttl_seconds is None:
            ttl_seconds = 21600.0 if getattr(response, "is_malicious", False) else 86400.0
        now = time.time()
        expires_at = now + ttl_seconds
        payload_json = (
            response.model_dump_json()
            if hasattr(response, "model_dump_json")
            else json.dumps(response)
        )
        ind_type = (
            response.indicator_type.value
            if hasattr(response.indicator_type, "value")
            else str(response.indicator_type)
        )
        provider_key = (
            provider
            if provider is not None
            else getattr(response, "provider_name", "unknown")
        )

        async with self.pool.connection() as conn:
            await conn.execute(
                """
                INSERT OR REPLACE INTO threat_intel_cache (
                    indicator, indicator_type, provider, is_malicious, risk_score, payload, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response.indicator,
                    ind_type,
                    provider_key,
                    1 if response.is_malicious else 0,
                    response.risk_score,
                    payload_json,
                    now,
                    expires_at,
                ),
            )

    async def get_cached_threat_intel(
        self,
        indicator: str,
        indicator_type: str,
        provider: Optional[str] = None,
    ) -> Optional[Any]:
        """Look up cached ThreatIntelResponse with TTL check (< 1ms SLA)."""
        from blackwall.threat_intel.models import ThreatIntelResponse

        await self.initialize()
        now = time.time()
        async with self.pool.connection() as conn:
            if provider:
                cursor = await conn.execute(
                    """
                    SELECT payload, expires_at FROM threat_intel_cache
                    WHERE indicator = ? AND indicator_type = ? AND provider = ? AND expires_at > ?
                    """,
                    (indicator, indicator_type, provider, now),
                )
            else:
                cursor = await conn.execute(
                    """
                    SELECT payload, expires_at FROM threat_intel_cache
                    WHERE indicator = ? AND indicator_type = ? AND expires_at > ?
                    ORDER BY is_malicious DESC, risk_score DESC, created_at DESC
                    LIMIT 1
                    """,
                    (indicator, indicator_type, now),
                )
            row = await cursor.fetchone()
            if not row:
                return None
            payload_str, _ = row
            try:
                data = json.loads(payload_str)
                resp = ThreatIntelResponse.model_validate(data)
                resp.cached = True
                return resp
            except Exception:
                return None

    async def prune_expired_threat_intel(self) -> int:
        """Evicts expired records from threat_intel_cache."""
        await self.initialize()
        now = time.time()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "DELETE FROM threat_intel_cache WHERE expires_at <= ?",
                (now,),
            )
            return cursor.rowcount

    async def record_threat_intel_cache_hit(self) -> None:
        """Increment persistent threat intelligence cache hit count."""
        await self.record_threat_intel_cache_metrics_batch(hits=1, misses=0)

    async def record_threat_intel_cache_miss(self) -> None:
        """Increment persistent threat intelligence cache miss count."""
        await self.record_threat_intel_cache_metrics_batch(hits=0, misses=1)

    async def record_threat_intel_cache_metrics_batch(
        self, hits: int = 0, misses: int = 0
    ) -> None:
        """Batch increment persistent cache metrics in a single atomic transaction."""
        if hits <= 0 and misses <= 0:
            return
        await self.initialize()
        async with self.pool.connection() as conn:
            if hits > 0:
                await conn.execute(
                    "UPDATE threat_intel_cache_metrics SET metric_value = metric_value + ? WHERE metric_name = 'hits';",
                    (hits,),
                )
            if misses > 0:
                await conn.execute(
                    "UPDATE threat_intel_cache_metrics SET metric_value = metric_value + ? WHERE metric_name = 'misses';",
                    (misses,),
                )

    async def get_threat_intel_cache_metrics(self) -> Dict[str, int]:
        """Return persistent threat intelligence cache hits and misses."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT metric_name, metric_value FROM threat_intel_cache_metrics;"
            )
            rows = await cursor.fetchall()
            metrics = {row[0]: int(row[1]) for row in rows}
            return {
                "hits": metrics.get("hits", 0),
                "misses": metrics.get("misses", 0),
            }

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
        query_vector: list[float] | None = None,
        threshold: float = 0.85,
        fts_fallback_score: float = 0.75,
        fts_threshold_cap: float = 0.70,
        target_tool: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Computes cosine similarity between query_vector and stored signatures.
        Falls back to FTS5 full-text search if the signature lacks a vector or if
        no query_vector is provided.
        """
        t0 = time.perf_counter()
        import array
        import hashlib

        # Check in-memory query cache
        cache_key_elements = [
            str(target_tool or ""),
            str(threshold),
            str(fts_fallback_score),
            str(fts_threshold_cap),
            str(limit),
            query_text,
        ]
        if query_vector is not None:
            vec_hash = hashlib.sha256(
                array.array("f", query_vector).tobytes()
            ).hexdigest()[:16]
            cache_key_elements.append(vec_hash)
        cache_key = ":".join(cache_key_elements)

        if cache_key in self._query_cache:
            ts, cached_matches = self._query_cache[cache_key]
            if time.time() - ts < self._query_cache_ttl:
                self._cache_hits += 1
                self._total_queries += 1
                elapsed = (time.perf_counter() - t0) * 1000.0
                self._total_query_time_ms += elapsed
                return [dict(m) for m in cached_matches]

        await self.initialize()
        matches = []

        # Helper to parse sqlite rows into dict matches
        def _parse_row(row, score):
            (
                sig_id,
                created_at,
                last_matched_at,
                attacker_intent,
                payload_pattern,
                target_tool_name,
                target_sink,
                dependency_chain,
                mitigation_action,
                match_count,
                false_positive_count,
                _,
                metadata,
            ) = row
            return {
                "signature_id": sig_id,
                "created_at": created_at,
                "last_matched_at": last_matched_at,
                "attacker_intent": attacker_intent,
                "payload_pattern": payload_pattern,
                "target_tool": target_tool_name,
                "target_sink": target_sink,
                "dependency_chain": (
                    json.loads(dependency_chain) if dependency_chain else None
                ),
                "mitigation_action": mitigation_action,
                "match_count": match_count,
                "false_positive_count": false_positive_count,
                "similarity_score": score,
                "metadata": json.loads(metadata) if metadata else None,
            }

        import re

        # Extract payload/intent search terms only (exclude tool_name to prevent tokenization into MATCH)
        # Build MATCH query from payload/intent terms without requiring all argument tokens
        words = re.findall(r"\w+", query_text)
        # Use OR semantics to allow partial matches (evasion variants that omit tokens)
        # Quote each token in double quotes to prevent FTS5 parsing errors on bare operators (AND/OR/NOT)
        fts_query = (
            " OR ".join('"' + w.replace('"', '""') + '"' for w in words)
            if words
            else ""
        )

        async with self.pool.connection() as conn:
            if query_vector is not None:
                # 1. Load signatures with vectors for cosine similarity
                if target_tool:
                    cursor = await conn.execute(
                        "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                        "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                        "false_positive_count, similarity_vector, metadata FROM signatures "
                        "WHERE similarity_vector IS NOT NULL AND target_tool = ?",
                        (target_tool,),
                    )
                else:
                    cursor = await conn.execute(
                        "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                        "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                        "false_positive_count, similarity_vector, metadata FROM signatures "
                        "WHERE similarity_vector IS NOT NULL"
                    )
                vector_rows = await cursor.fetchall()

                # Validate query_vector dimension and finite values
                if len(query_vector) != 768:
                    raise ValueError(
                        f"Query vector has incorrect dimension {len(query_vector)}, expected 768"
                    )
                if any(not math.isfinite(x) for x in query_vector):
                    raise ValueError(
                        "Query vector contains non-finite values (NaN or Inf)"
                    )

                if _core_rs is not None and hasattr(
                    _core_rs, "batch_cosine_similarity"
                ):
                    row_map = {row[0]: row for row in vector_rows}
                    candidates = [
                        (row[0], bytes(row[11]))
                        for row in vector_rows
                        if row[11] is not None
                    ]
                    batch_matches, exclusions = _core_rs.batch_cosine_similarity(
                        query_vector, candidates, 768, threshold
                    )
                    for sig_id, err_str in exclusions:
                        logger.warning(
                            f"Excluding signature {sig_id} from vector similarity query due to {err_str}",
                            signature_id=sig_id,
                            error=err_str,
                        )
                    for sig_id, score in batch_matches[:limit]:
                        if sig_id in row_map:
                            matches.append(_parse_row(row_map[sig_id], score))
                else:
                    for row in vector_rows:
                        sig_id = row[0]
                        similarity_vector = row[11]

                        is_valid_vector = False
                        vector_floats = None
                        try:
                            arr = array.array("f")
                            arr.frombytes(similarity_vector)
                            vector_floats = arr.tolist()

                            if len(vector_floats) != 768:
                                logger.warning(
                                    f"Excluding signature {sig_id} from vector similarity query due to incorrect vector dimension {len(vector_floats)}",
                                    signature_id=sig_id,
                                    dimension=len(vector_floats),
                                )
                            elif any(not math.isfinite(x) for x in vector_floats):
                                logger.warning(
                                    f"Excluding signature {sig_id} from vector similarity query due to non-finite float values",
                                    signature_id=sig_id,
                                )
                            else:
                                is_valid_vector = True
                        except Exception as e:
                            logger.warning(
                                f"Excluding signature {sig_id} from vector similarity query due to error decoding vector: {e}",
                                signature_id=sig_id,
                                error=str(e),
                            )

                        if not is_valid_vector:
                            continue

                        # Calculate cosine similarity
                        dot_product = sum(
                            x * y
                            for x, y in zip(query_vector, vector_floats, strict=True)
                        )
                        norm_q = math.sqrt(sum(x * x for x in query_vector))
                        norm_s = math.sqrt(sum(x * x for x in vector_floats))
                        similarity_score = (
                            dot_product / (norm_q * norm_s)
                            if norm_q > 0.0 and norm_s > 0.0
                            else 0.0
                        )

                        if similarity_score >= threshold:
                            matches.append(_parse_row(row, similarity_score))
                            if len(matches) >= limit:
                                break

                # 2. For signatures without vectors, query them via FTS5 if there's a query
                # Use target_tool as a separate WHERE predicate, not in MATCH
                # Use BM25 ranking for dynamic score instead of fixed fallback score
                if fts_query:
                    if target_tool:
                        cursor = await conn.execute(
                            "SELECT s.signature_id, s.created_at, s.last_matched_at, s.attacker_intent, s.payload_pattern, "
                            "s.target_tool, s.target_sink, s.dependency_chain, s.mitigation_action, s.match_count, "
                            "s.false_positive_count, s.similarity_vector, s.metadata, fts.rank "
                            "FROM signatures s "
                            "JOIN signature_fts fts ON s.signature_id = fts.signature_id "
                            "WHERE s.similarity_vector IS NULL "
                            "AND s.target_tool = ? "
                            "AND fts.signature_fts MATCH ? "
                            "ORDER BY fts.rank LIMIT ?",
                            (target_tool, fts_query, limit),
                        )
                    else:
                        cursor = await conn.execute(
                            "SELECT s.signature_id, s.created_at, s.last_matched_at, s.attacker_intent, s.payload_pattern, "
                            "s.target_tool, s.target_sink, s.dependency_chain, s.mitigation_action, s.match_count, "
                            "s.false_positive_count, s.similarity_vector, s.metadata, fts.rank "
                            "FROM signatures s "
                            "JOIN signature_fts fts ON s.signature_id = fts.signature_id "
                            "WHERE s.similarity_vector IS NULL "
                            "AND fts.signature_fts MATCH ? "
                            "ORDER BY fts.rank LIMIT ?",
                            (fts_query, limit),
                        )
                    fts_rows = await cursor.fetchall()
                    for row in fts_rows:
                        sig_id = row[0]
                        bm25_rank = row[13]
                        attacker_intent = row[3] or ""
                        payload_pattern = row[4] or ""
                        target_tool_val = row[5] or ""
                        candidate_text = (
                            f"{attacker_intent} {payload_pattern} {target_tool_val}"
                        )
                        match_quality = compute_word_intersection_match_quality(
                            query_text, candidate_text
                        )

                        fts_rank_scale = min(max(1.0 + abs(bm25_rank) / 10.0, 1.0), 1.5)
                        normalized_score = min(
                            match_quality * fts_fallback_score * fts_rank_scale,
                            fts_threshold_cap,
                        )

                        logger.debug(
                            "FTS5 fallback triggered for signature similarity match",
                            signature_id=sig_id,
                            reason="missing or invalid vector",
                            bm25_rank=bm25_rank,
                            match_quality=match_quality,
                            normalized_score=normalized_score,
                            timestamp=int(time.time()),
                        )
                        current_threshold = max(
                            min(threshold, fts_threshold_cap) * match_quality, 0.15
                        )
                        if normalized_score >= current_threshold and match_quality > 0:
                            matches.append(_parse_row(row[:13], normalized_score))
            else:
                # No query vector provided: all signatures fallback to FTS5
                # Use target_tool as a separate WHERE predicate, not in MATCH
                # Use BM25 ranking for dynamic score instead of fixed fallback score
                if fts_query:
                    if target_tool:
                        cursor = await conn.execute(
                            "SELECT s.signature_id, s.created_at, s.last_matched_at, s.attacker_intent, s.payload_pattern, "
                            "s.target_tool, s.target_sink, s.dependency_chain, s.mitigation_action, s.match_count, "
                            "s.false_positive_count, s.similarity_vector, s.metadata, fts.rank "
                            "FROM signatures s "
                            "JOIN signature_fts fts ON s.signature_id = fts.signature_id "
                            "WHERE s.target_tool = ? "
                            "AND fts.signature_fts MATCH ? "
                            "ORDER BY fts.rank LIMIT ?",
                            (target_tool, fts_query, limit),
                        )
                    else:
                        cursor = await conn.execute(
                            "SELECT s.signature_id, s.created_at, s.last_matched_at, s.attacker_intent, s.payload_pattern, "
                            "s.target_tool, s.target_sink, s.dependency_chain, s.mitigation_action, s.match_count, "
                            "s.false_positive_count, s.similarity_vector, s.metadata, fts.rank "
                            "FROM signatures s "
                            "JOIN signature_fts fts ON s.signature_id = fts.signature_id "
                            "WHERE fts.signature_fts MATCH ? "
                            "ORDER BY fts.rank LIMIT ?",
                            (fts_query, limit),
                        )
                    fts_rows = await cursor.fetchall()
                    for row in fts_rows:
                        sig_id = row[0]
                        bm25_rank = row[13]
                        attacker_intent = row[3] or ""
                        payload_pattern = row[4] or ""
                        target_tool_val = row[5] or ""
                        candidate_text = (
                            f"{attacker_intent} {payload_pattern} {target_tool_val}"
                        )
                        match_quality = compute_word_intersection_match_quality(
                            query_text, candidate_text
                        )

                        fts_rank_scale = min(max(1.0 + abs(bm25_rank) / 10.0, 1.0), 1.5)
                        normalized_score = min(
                            match_quality * fts_fallback_score * fts_rank_scale,
                            fts_threshold_cap,
                        )

                        logger.debug(
                            "FTS5 fallback triggered for signature similarity match",
                            signature_id=sig_id,
                            reason="missing query vector",
                            bm25_rank=bm25_rank,
                            match_quality=match_quality,
                            normalized_score=normalized_score,
                            timestamp=int(time.time()),
                        )
                        current_threshold = max(
                            min(threshold, fts_threshold_cap) * match_quality, 0.15
                        )
                        if normalized_score >= current_threshold and match_quality > 0:
                            matches.append(_parse_row(row[:13], normalized_score))

            matches.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)
            if limit > 0:
                matches = matches[:limit]

            self._cache_misses += 1
            self._total_queries += 1
            elapsed = (time.perf_counter() - t0) * 1000.0
            self._total_query_time_ms += elapsed

            if len(self._query_cache) >= 1000:
                oldest_key = next(iter(self._query_cache))
                del self._query_cache[oldest_key]
            self._query_cache[cache_key] = (time.time(), [dict(m) for m in matches])

            return matches

    async def find_matching_signature(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        query_vector: list[float] | None = None,
        threshold: float = 0.85,
        fts_fallback_score: float = 0.75,
        fts_threshold_cap: float = 0.70,
    ) -> Optional[Dict[str, Any]]:
        await self.initialize()

        # Construct query text for similarity & FTS5 matching from payload/intent terms only
        import urllib.parse

        # Exclude tool_name from tokenization to prevent cross-tool matches
        args_values = " ".join(str(v) for v in arguments.values())
        decoded_values = urllib.parse.unquote(args_values)
        query_text = (
            f"{args_values} {decoded_values}"
            if decoded_values != args_values
            else args_values
        )  # Include unquoted values to detect encoded evasion attempts

        # 1. Query similar signatures (Vector similarity + FTS5 fallback)
        matches = await self.querySimilarSignatures(
            query_text=query_text,
            query_vector=query_vector,
            threshold=threshold,
            fts_fallback_score=fts_fallback_score,
            fts_threshold_cap=fts_threshold_cap,
            target_tool=tool_name,  # Pass tool_name as separate predicate
        )

        if matches:
            best_match = matches[0]
            sig_id = best_match["signature_id"]
            await self.increment_match_count(sig_id)
            return best_match

        # 2. Substring fallback to maintain backward compatibility
        args_str = json.dumps(arguments)
        decoded_args_str = urllib.parse.unquote(args_str)
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT signature_id, target_tool, payload_pattern, mitigation_action, attacker_intent FROM signatures WHERE target_tool = ?",
                (tool_name,),
            )
            rows = await cursor.fetchall()
            for row in rows:
                sig_id, tool, pattern, mitigation, intent = row
                if pattern in args_str or (
                    decoded_args_str != args_str and pattern in decoded_args_str
                ):
                    await self.increment_match_count(sig_id)
                    return {
                        "signature_id": sig_id,
                        "target_tool": tool,
                        "payload_pattern": pattern,
                        "mitigation_action": mitigation,
                        "attacker_intent": intent,
                    }
        return None

    async def get_signature(self, signature_id: str) -> Optional[dict[str, Any]]:
        """Retrieves a single threat signature by signature_id."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                "false_positive_count, similarity_vector, metadata FROM signatures WHERE signature_id = ?",
                (str(signature_id),),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                "signature_id": row[0],
                "created_at": row[1],
                "last_matched_at": row[2],
                "attacker_intent": row[3],
                "payload_pattern": row[4],
                "target_tool": row[5],
                "target_sink": row[6],
                "dependency_chain": json.loads(row[7]) if row[7] else None,
                "mitigation_action": row[8],
                "match_count": row[9],
                "false_positive_count": row[10],
                "similarity_vector": row[11],
                "metadata": json.loads(row[12]) if row[12] else None,
            }

    async def get_all_signatures(self) -> list[dict[str, Any]]:
        """Retrieves all threat signatures from the repository."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, "
                "target_tool, target_sink, dependency_chain, mitigation_action, match_count, "
                "false_positive_count, similarity_vector, metadata FROM signatures"
            )
            rows = await cursor.fetchall()
            return [
                {
                    "signature_id": row[0],
                    "created_at": row[1],
                    "last_matched_at": row[2],
                    "attacker_intent": row[3],
                    "payload_pattern": row[4],
                    "target_tool": row[5],
                    "target_sink": row[6],
                    "dependency_chain": json.loads(row[7]) if row[7] else None,
                    "mitigation_action": row[8],
                    "match_count": row[9],
                    "false_positive_count": row[10],
                    "similarity_vector": row[11],
                    "metadata": json.loads(row[12]) if row[12] else None,
                }
                for row in rows
            ]

    # Alias for camelCase
    getAllSignatures = get_all_signatures

    async def add_background_task(
        self, task_id: str, status: str = "PENDING_WEBHOOK_CALLBACK"
    ) -> None:
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
                (task_id, int(time.time())),
            )

    async def remove_in_flight_task(self, task_id: str) -> None:
        """Removes a task ID from the in-flight list."""
        await self.initialize()
        async with self.pool.connection() as conn:
            await conn.execute(
                "DELETE FROM in_flight_tasks WHERE task_id = ?", (task_id,)
            )

    async def is_task_valid(self, task_id: str) -> bool:
        """Checks if a task ID is valid and not stale (> 12 hours old)."""
        await self.initialize()
        async with self.pool.connection() as conn:
            cursor = await conn.execute(
                "SELECT created_at FROM in_flight_tasks WHERE task_id = ?", (task_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False
            created_at = row[0]
            # 12 hours = 43200 seconds
            if time.time() - created_at > 43200:
                await conn.execute(
                    "DELETE FROM in_flight_tasks WHERE task_id = ?", (task_id,)
                )
                return False
            return True

    async def write_signatures_batch(self, signatures: list[dict[str, Any]]) -> None:
        """Writes multiple threat signatures in a single atomic transaction."""
        await self.initialize()

        async with self.pool.connection() as conn:
            # aiosqlite connection executes in auto-commit mode by default unless transaction is started
            await conn.execute("BEGIN TRANSACTION")
            try:
                values_to_insert = []
                for signature_data in signatures:
                    raw_intent = (
                        signature_data.get("attackerIntent")
                        or signature_data.get("attacker_intent")
                        or signature_data.get("description")
                    )
                    attacker_intent = str(raw_intent) if raw_intent is not None else ""

                    raw_pattern = (
                        signature_data.get("payloadPattern")
                        or signature_data.get("payload_pattern")
                        or signature_data.get("pattern")
                    )
                    payload_pattern = (
                        str(raw_pattern) if raw_pattern is not None else ""
                    )

                    raw_tool = signature_data.get("targetTool") or signature_data.get(
                        "target_tool"
                    )
                    target_tool = str(raw_tool) if raw_tool is not None else ""

                    raw_sig_id = signature_data.get(
                        "signatureId"
                    ) or signature_data.get("signature_id")
                    if raw_sig_id is not None:
                        sig_id = str(raw_sig_id)
                    else:
                        # Derive stable deduplication key for recurring signature content
                        sig_id = str(
                            uuid.uuid5(
                                uuid.NAMESPACE_DNS,
                                f"{target_tool}:{payload_pattern}:{attacker_intent}",
                            )
                        )

                    raw_created_at = signature_data.get(
                        "createdAt"
                    ) or signature_data.get("created_at")
                    if raw_created_at is not None:
                        if hasattr(raw_created_at, "timestamp"):
                            created_at = int(raw_created_at.timestamp())
                        else:
                            try:
                                created_at = int(raw_created_at)
                            except Exception:
                                created_at = int(time.time())
                    else:
                        created_at = int(time.time())

                    _raw_last_matched_at = signature_data.get(
                        "lastMatchedAt"
                    ) or signature_data.get("last_matched_at")
                    if _raw_last_matched_at is not None:
                        if hasattr(_raw_last_matched_at, "timestamp"):
                            last_matched_at = int(_raw_last_matched_at.timestamp())
                        else:
                            try:
                                last_matched_at = int(_raw_last_matched_at)
                            except Exception:
                                last_matched_at = None
                    else:
                        last_matched_at = None

                    target_sink_val = (
                        signature_data.get("targetSink")
                        or signature_data.get("target_sink")
                        or signature_data.get("sink_type")
                    )
                    target_sink = (
                        str(target_sink_val) if target_sink_val is not None else None
                    )

                    raw_chain = signature_data.get(
                        "dependencyChain"
                    ) or signature_data.get("dependency_chain")
                    dependency_chain = (
                        json.dumps(raw_chain) if raw_chain is not None else None
                    )

                    raw_mitigation = signature_data.get(
                        "mitigationAction"
                    ) or signature_data.get("mitigation_action")
                    mitigation_action = (
                        str(raw_mitigation) if raw_mitigation is not None else ""
                    )

                    raw_match_count = signature_data.get(
                        "matchCount"
                    ) or signature_data.get("match_count")
                    match_count = (
                        int(raw_match_count) if raw_match_count is not None else 0
                    )

                    raw_fp_count = signature_data.get(
                        "falsePositiveCount"
                    ) or signature_data.get("false_positive_count")
                    false_positive_count = (
                        int(raw_fp_count) if raw_fp_count is not None else 0
                    )

                    similarity_vector = signature_data.get(
                        "similarityVector"
                    ) or signature_data.get("similarity_vector")
                    if similarity_vector is not None:
                        if isinstance(similarity_vector, (bytes, bytearray)):
                            vector_blob = similarity_vector
                        elif hasattr(similarity_vector, "tobytes") and callable(
                            similarity_vector.tobytes
                        ):
                            vector_blob = similarity_vector.tobytes()
                        elif isinstance(similarity_vector, (list, tuple)):
                            import array

                            vector_blob = array.array("f", similarity_vector).tobytes()
                        else:
                            vector_blob = None
                    else:
                        vector_blob = None

                    raw_metadata = signature_data.get("metadata")
                    metadata_str = (
                        json.dumps(raw_metadata) if raw_metadata is not None else None
                    )

                    values_to_insert.append(
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
                            vector_blob,
                            metadata_str,
                        )
                    )

                await conn.executemany(
                    """
                    INSERT OR REPLACE INTO signatures (
                        signature_id, created_at, last_matched_at, attacker_intent, payload_pattern,
                        target_tool, target_sink, dependency_chain, mitigation_action,
                        match_count, false_positive_count, similarity_vector, metadata
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values_to_insert,
                )
                await conn.commit()
                self._query_cache.clear()
            except Exception as e:
                await conn.rollback()
                logger.error(f"Failed to batch write signatures: {e}")
                raise
