# Architectural, Database, & Security Rules

## 1. DSN & Credential Log Sanitization Hygiene
* **Rule:** Log messages MUST NEVER include raw DSN connection strings (`self.dsn`), URLs containing embedded credentials, or raw authentication keys. Omit DSN parameters or log sanitized host/port strings to prevent credential exposure in failure logs.
* **Rationale:** In failure scenarios, logs are widely captured and shared across SOC systems. Including DSNs or URLs with embedded credentials leaks database passwords into log streams.

## 2. Atomic Database Transactions & Cache Synchronization
* **Rule:** Store modules persisting data across both a database backend (e.g. PostgreSQL via `asyncpg`) and an in-memory cache MUST wrap database persistence statements in an explicit transaction (`async with conn.transaction():`), and mutate in-memory cache structures ONLY after successful DB commit. Re-ingesting duplicate items (e.g. `ON CONFLICT DO NOTHING`) MUST preserve existing cached edge/relationship lists.
* **Rationale:** Non-atomic operations leave in-memory caches and database tables out of sync during transient network failures, corrupting graph edge relationships.

## 3. Explicit Connection Error Escalation
* **Rule:** Persistent store initialization methods MUST NOT silently degrade to in-memory mode when an explicit connection DSN is provided and `in_memory=False`. Database connection exceptions MUST be raised to signal non-durable state to callers.
* **Rationale:** Silently falling back to in-memory storage hides infrastructure misconfigurations and leads to data loss upon process restarts.

## 4. Production Import Error Enforcement
* **Rule:** Module entrypoints (`agent/__init__.py`, `blackwall/__init__.py`) MUST NOT swallow missing configuration `ValueError` exceptions in production. Exception suppression is permitted ONLY when `PYTEST_CURRENT_TEST` or `BLACKWALL_TEST_MODE` is present in `os.environ`.
* **Rationale:** Suppressing configuration errors in production allows daemons to launch in invalid or unmonitored security states.

## 5. Unconditional Credential Purging
* **Rule:** Provider configuration helpers (`configure_provider_env()`) MUST purge legacy API keys (`GEMINI_API_KEY`, `LLM_API_KEY`) and re-assert required mode variables (`GOOGLE_GENAI_USE_VERTEXAI="true"`, `GEMINI_TIER="paid"`) on *every* call, regardless of module-level caching flags.
* **Rationale:** Prevents credential leakage and ensures GCP Vertex AI enterprise mode compliance across all sub-processes.

## 6. Context Hygiene & Sanitization
* **Rule:** `ContextResolver` middleware must replace sensitive environment variable patterns with generic placeholders (`[[VARIABLE_NAME]]`). Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g. `wd-bouygues.com`) to prevent accidental sanitization matching.

## 7. Pydantic Model Import Preservation
* **Rule:** When modifying imports in Pydantic schema files (`models.py`, `policy/models.py`), core Pydantic symbols (`BaseModel`, `Field`, `field_validator`, `model_validator`) MUST NOT be deleted or replaced. Always preserve Pydantic imports alongside newly added utility imports to avoid import-time `NameError` failures.

## 8. Telemetry Ingestion & Stream Reconnection Invariants
* **Rule:** Telemetry normalization MUST use explicit `val is None` checks instead of truthiness fallbacks (`or`) to prevent dropping valid falsy identifiers (e.g. `agent_id = 0`).
* **Rule:** Naive `datetime` objects or timezone-less ISO strings MUST log a warning containing the source, preserve `metadata["raw_timestamp"]`, and fall back to `datetime.now(timezone.utc)`.
* **Rule:** Stream reconnection loops MUST validate `hasattr(stream, "__aiter__")`, support `inspect.iscoroutine` awaiting, and immediately re-raise `TypeError` / `ValueError` to fail fast on programming errors without executing backoff delays.
* **Rule:** Stream warning logs MUST include the `EventSource` parameter using %-formatting (e.g. `logger.warning("... for source %s", source)`) for structured observability.

## 9. Advanced Threat Graph Store Persistence & Edge Resilience
* **Rule (Cache Isolation):** In DB-backed store mode (when database pool/connection is set), query methods (e.g. `query_nodes()`) MUST construct and return node records directly without mutating or populating the long-lived `self._nodes` in-memory dictionary. Primary storage in `self._nodes` is reserved strictly for `in_memory=True` mode to prevent unbounded memory growth over long-running daemon operations.
* **Rule (Edge UUID Resilience):** Database edge array columns (`incoming_edges`, `outgoing_edges`) parsed from JSON MUST wrap UUID conversion for each entry in a `try...except (ValueError, TypeError)` block, log a warning, and skip malformed or non-v4 UUID strings rather than letting exceptions propagate and abort store queries.

## 10. Attack Path Correlation & Temporal Adjacency Invariants
* **Rule (Limit Validation & Integrity):** Public correlator and store parameters (`max_nodes`, `max_paths`, `max_depth`, `limit`) MUST validate that input integers are strictly positive (`> 0`) and that `max_depth >= min_path_length`, raising a clear `ValueError` on invalid values. Internal traversal helper functions MUST respect explicit parameters directly without silent internal parameter overrides.
* **Rule (Chronological Causal Edges):** Causal edges in temporal adjacency graph construction MUST enforce `target_node.event.timestamp >= node_a.event.timestamp`. Path materialization loops MUST skip reverse-ordered sequences (`end_time < start_time`) and catch `ValueError` during `AttackPath` model instantiation to prevent invalid edge data from failing correlation calls.
* **Rule (O(1) Causal Edge Resolution):** Temporal window iteration MUST break unconditionally when temporal distance exceeds the 300-second window (`delta_sec > 300`). Explicit causal edges MUST be resolved via a precomputed incoming edge index (`Dict[uuid.UUID, List[AttackNode]]`) for $O(1)$ directed edge lookup regardless of time separation.


