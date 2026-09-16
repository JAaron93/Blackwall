# Architectural, Database, & Security Rules

## 1. DSN & Credential Log Sanitization Hygiene
* **Rule:** Log messages MUST NEVER include raw DSN connection strings (`self.dsn`), URLs containing embedded credentials, or raw authentication keys. Omit DSN parameters or log sanitized host/port strings to prevent credential exposure in failure logs.
* **Rationale:** In failure scenarios, logs are widely captured and shared across SOC systems. Including DSNs or URLs with embedded credentials leaks database passwords into log streams.

## 2. Atomic Database Transactions & Post-Commit Cache Synchronization
* **Rule:** Store modules persisting data across both a database backend (e.g. PostgreSQL via `asyncpg`) and an in-memory cache MUST wrap database persistence statements in an explicit transaction (`async with conn.transaction():`). In-memory cache structures (`self._nodes`, `self._agent_nodes_index`, and cache invalidation) MUST be mutated strictly **after** the transaction block exits and commits. Cache structures MUST NOT be mutated inside the transaction context manager.
* **Rationale:** If PostgreSQL fails during the commit phase upon exiting `conn.transaction()`, any in-memory cache mutations performed inside the transaction block leave phantom records in memory that were rolled back in the database, causing state corruption and foreign-key failures in subsequent edge links.

## 3. Explicit Connection Error Escalation
* **Rule:** Persistent store initialization methods MUST NOT silently degrade to in-memory mode when an explicit connection DSN is provided and `in_memory=False`. Database connection exceptions MUST be raised to signal non-durable state to callers.
* **Rationale:** Silently falling back to in-memory storage hides infrastructure misconfigurations and leads to data loss upon process restarts.

## 4. Production Import Error Enforcement
* **Rule:** Module entrypoints (`agent/__init__.py`) MUST NOT swallow missing configuration `ValueError` exceptions in production. Exception suppression is permitted ONLY when `PYTEST_CURRENT_TEST` or `BLACKWALL_TEST_MODE` is present in `os.environ`.
* **Rationale:** Suppressing configuration errors in production allows daemons to launch in invalid or unmonitored security states.

## 5. Unconditional Credential Purging
* **Rule:** Provider configuration helpers (`configure_provider_env()`) MUST purge legacy API keys (`GEMINI_API_KEY`, `LLM_API_KEY`) and re-assert required mode variables (`GOOGLE_GENAI_USE_VERTEXAI="true"`, `GEMINI_TIER="paid"`) on *every* call, regardless of module-level caching flags. Vertex AI has NO free tier; it operates exclusively on paid billing quota (300+ RPM). Free-tier or 15 RPM fallback logic must never be introduced for Vertex AI. Third-party rate limiters (e.g. VirusTotal GTI 4 queries/60s) remain separate and preserved.
* **Rationale:** Prevents credential leakage and ensures GCP Vertex AI enterprise mode compliance across all sub-processes without artificial rate throttling.

## 6. Context Hygiene & Sanitization
* **Rule:** `ContextHygiene` middleware (production interception path uses the implementation in `src/blackwall/resolver.py`; the async variant in `src/blackwall/middleware/context_hygiene.py` is exercised by `tests/middleware/` only) must replace sensitive environment variable patterns with generic placeholders (`[[VARIABLE_NAME]]`). Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g. `wd-bouygues.com`) to prevent accidental sanitization matching.
* **Rule (IoC Preservation for Semantic Triage):** When context is sanitized for model-based semantic triage (`SyncResolver`), callers MUST set `preserve_iocs=True`. This preserves critical target file paths (e.g., `/etc/shadow`, `/etc/passwd`) and remote network indicators (e.g., `http://evil-c2.com/payload.sh`) while strictly redacting secrets, Bearer tokens, private keys, and query parameter credentials (`?token=...`, `?key=...`), enabling Gemini 3.5 Flash-Lite to accurately evaluate intent without evaluating dummy placeholders.

## 7. Pydantic Model Import Preservation
* **Rule:** When modifying imports in Pydantic schema files (`models.py`, `src/blackwall/policy/models.py`), core Pydantic symbols (`BaseModel`, `Field`, `field_validator`, `model_validator`) MUST NOT be deleted or replaced. Always preserve Pydantic imports alongside newly added utility imports to avoid import-time `NameError` failures.

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
## 11. Security Model Fingerprinting & UTC Temporal Invariants
* **Rule (Fingerprint Integrity & Tampering Prevention):** Identity fingerprinting methods (e.g. `compute_fingerprint()`) MUST recompute expected SHA-256 hashes unconditionally from canonical identity fields. If a caller supplies an explicit fingerprint parameter, it MUST be validated against the recomputed hash and raise a `ValueError` on mismatch. Numerical identity attributes (e.g. `process_uid`, `agent_id`) MUST use explicit `val is None` checks rather than `or` truthiness fallbacks to prevent collapsing valid falsy identifiers (e.g., `process_uid=0` for root).
* **Rule (Freshness & Temporal Sequence Invariants):** Model timestamp validators MUST NOT drop freshness window bounds (e.g. ±5.0 second delta limit on `SecurityEvent`) when applying UTC timezone validation (`validate_utc_datetime`). Models containing multi-timestamp lifecycles (e.g. `AttackerProfile` with `first_seen` and `last_seen`) MUST enforce `last_seen >= first_seen` via `@model_validator` and `validate_temporal_sequence()`.

## 12. Chronological Causal Edges & O(1) Directed Edge Resolution
* **Rule (Chronological Causal Edges):** Causal edges in temporal adjacency graph construction MUST enforce `target_node.event.timestamp >= node_a.event.timestamp`. Path materialization loops MUST skip reverse-ordered sequences (`end_time < start_time`) and catch `ValueError` during `AttackPath` model instantiation to prevent invalid edge data from failing correlation calls.
* **Rule (O(1) Causal Edge Resolution):** Temporal window iteration MUST break unconditionally when temporal distance exceeds the 300-second window (`delta_sec > 300`). Explicit causal edges MUST be resolved via a precomputed incoming edge index (`Dict[uuid.UUID, List[AttackNode]]`) for $O(1)$ directed edge lookup regardless of time separation.

## 13. Pydantic Configuration Model Declarations & Field Optionality Invariants
* **Rule:** In Pydantic configuration models (`src/blackwall/policy/models.py`, `src/blackwall/models.py`), nested configuration sections MUST NOT combine `Optional[T]` type annotations with `default_factory=T`.
  - If a nested configuration section should always exist with default values when omitted from YAML/JSON inputs, declare it as `section: SectionConfig = Field(default_factory=SectionConfig)` (non-optional).
  - If a nested configuration section's omission represents an unconfigured/disabled state, declare it as `section: Optional[SectionConfig] = None` (without `default_factory`).
  - Accessing callers MUST align with the chosen contract: use direct attribute access (`policy.section.sub_field`) for always-present sections, or explicit `is not None` checks (`if policy.section is not None:`) for truly optional sections.
* **Rationale:** Combining `Optional[T]` with `default_factory=T` creates ambiguous model definitions where the field is never `None` on parsed instances, invalidating `if policy.section:` checks and obscuring whether a section was explicitly configured or omitted.

## 14. CodeQL Test Assertion Invariants
* **Rule:** Unit test assertions checking pattern containment or string matches MUST NOT use arbitrary substring `in` checks on un-sanitized URL/string targets (e.g. `any("192.168.1.50" in p for p in patterns)`). Assertions MUST use explicit string equality (`pattern == "ip:192.168.1.50"`) or exact set containment (`"ip:192.168.1.50" in patterns`) to prevent CodeQL security alerts regarding un-sanitized substring matching.
* **Rationale:** Direct set or list membership assertions eliminate false positives and ensure strict, deterministic verification of security evidence outputs.

## 15. Advanced Threat Detection Identifier Semantics & Contextual Field Error Messaging
* **Rule (UUID v4 Enforcement):** All identifier fields in Advanced Threat Detection Pydantic models (e.g. `event_id`, `node_id`, `path_id`, `swarm_id`, `chain_id`, `grant_id`, `granted_by`, `granted_to`) MUST be typed as `UUID4` (or validate UUID v4 format via `validate_uuid_v4_format`). Field validators delegating to `validate_uuid_v4_format` MUST pass `field_name=info.field_name` to provide field-specific error messages in `ValidationError` exceptions instead of hard-coding `event_id`.
* **Rule (Bounded State & Strict Capacity Validation):** In-memory state trackers storing per-entity sequences MUST use bounded collections (e.g. `collections.deque(maxlen=max_capacity)`). Constructor capacity parameters MUST validate that values are strictly non-boolean integers (`not isinstance(v, bool) and isinstance(v, int) and v > 0`), raising `ValueError` on invalid types or non-positive values.
* **Rule (Trust Boundary Classification):** Security context transition classifiers (e.g. `identify_boundary_crossing()`) MUST evaluate context changes against predefined `TRUST_BOUNDARIES` sets, rather than returning `True` for any arbitrary string inequality.

## 16. GitHub Mergeability Re-Evaluation After Merge Commits
* **Rule:** After resolving merge conflicts locally (`git merge origin/main`) and pushing the merge commit, GitHub may still report `CONFLICTING / DIRTY` on the PR. This is not always lag — GitHub runs its own three-way merge check independently. If `git diff origin/main HEAD` shows no conflict markers but the PR still reports `CONFLICTING`, force re-evaluation with an empty commit:
  ```bash
  git commit --allow-empty -m "chore: trigger GitHub mergeability re-evaluation"
  git push
  ```
  Then verify resolution with: `gh pr view <N> --json mergeable,mergeStateStatus`
* **Rationale:** GitHub's mergeability computation is asynchronous and keyed to push events. A merge commit alone may not trigger a fresh evaluation; an empty commit guarantees a new push event that re-queues the check.

## 17. `add/add` Conflict Resolution Strategy
* **Rule:** When `git merge` reports `CONFLICT (add/add)`, never use `git checkout --ours` or `--theirs` — both unconditionally discard one branch's contribution. Instead:
  1. Read both versions: `git show HEAD:<file>` (ours) and `git show MERGE_HEAD:<file>` (theirs).
  2. Produce a manually merged file that preserves intent from both sides.
  3. Write the merged result, `git add <file>`, and commit with a clear rationale explaining what was kept from each side.
* **Rationale:** `add/add` conflicts arise when two branches independently create the same file (e.g. configuration, spec files). The content from both branches is meaningful — discarding either side silently drops intentional work.

## 18. Two-Pass Secret Redaction Strategy for Tool Arguments & Telemetry
* **Rule:** Sanitization components handling dictionary arguments or event contexts (e.g. `_sanitize_arguments()`, `ContextHygiene`) MUST use a two-pass sanitization strategy:
  1. **Pass 1 — Key-name pre-serialization inspection**: Inspect dict key names directly against compiled sensitive patterns (`password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `auth`, `credential`, `bearer`) and redact values *before* stringifying to JSON.
  2. **Pass 2 — Regex scan over serialized string**: Apply regex pattern matching over the stringified JSON payload to redact embedded credential patterns (e.g. multi-segment project keys `sk-(?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]{8,}`, Google `AIza`, URLs, emails, IP addresses).
  3. **Live execution path carve-out**: The canonical implementation lives in `src/blackwall/validators.py` (`sanitize_dict_payload()` / `sanitize_value()`). Incident-report and telemetry contexts use the full `REDACTION_PATTERNS` table (URLs, emails, IPs, file paths redacted). Live `tools/call` execution payloads (`InboundProtocolFilter.sanitize_incoming_rpc`) MUST use the credential-only subset (`CREDENTIAL_REDACTION_PATTERNS`) so executable targets survive sanitization while secrets are still redacted. Do NOT demand full-table redaction on live execution paths (established in PR #142 Greptile review: 2/5 to success across two P1 cycles).
* **Rationale:** Performing regex substitution exclusively on JSON-serialized strings fails to match quoted property names (e.g., `(?i)password[\s:=]+` misses `"password": "value"` due to double quotes around key names), allowing plaintext credentials to survive in sanitized payloads and leak into serialized incident reports or telemetry streams.


## 19. Strict UTC Zero-Offset Pydantic Validator Invariant
* **Rule:** Pydantic `@field_validator` classmethods enforcing UTC timezone compliance on timestamps MUST verify `v.tzinfo is None or v.utcoffset() != timedelta(0)` and raise `ValueError` on failure. Checking only `v.tzinfo is None` or `v.tzinfo.utcoffset(v) is None` is strictly prohibited.
* **Rationale:** Aware datetimes with non-UTC offsets (e.g. `EST`, `-05:00`, `+02:00`) have non-null `tzinfo` objects. Checking only for timezone awareness accepts non-UTC offsets, violating the required zero-offset UTC timestamp contract across security event graphs.

## 20. Mandatory Evidence-Derived Evaluation Containment Gate
* **Rule:** Security engines executing active mitigation actions (e.g. eBPF socket drops, ZeroMQ Threat Mesh broadcasts, Vault token revocations) MUST require an explicit `ActiveReactionPayload` instance containing `trigger_evidence_id` and mandatorily query `await self.is_evaluation_mode(payload.trigger_evidence_id, env_id=payload.evaluation_env_id)`. Action methods MUST evaluate both the evidence graph / environment manager provenance and envelope metadata (`evaluation_env_id`, `is_evaluation=True`, `eval_mode=True`), quashing actions when evaluation origin is confirmed while permitting standard production execution when evaluation stores confirm no matching evaluation session.
* **Rationale:** Callers converting evaluation evidence into payloads might omit optional fields, or downstream detection pipelines might serialize alerts asynchronously. Evaluating both deterministic envelope markers and evidence graph provenance guarantees evaluation containment without misclassifying un-indexed production alerts.

## 21. Explicit Pydantic v2 Field Constraints in Architectural Specifications
* **Rule:** Interface code blocks and data models in technical design specifications (`design.md`) MUST be declared using explicit Pydantic `BaseModel` schemas with field-level constraints (`UUID4`, `AwareDatetime`, `Field(min_length=1)`, `Field(gt=0)`, `Field(ge=0)`, `Field(ge=0.0, le=1.0)`) and Pydantic String Enums, rather than standard Python `@dataclass` or bare primitive type annotations (`str`, `int`, `datetime`).
* **Rationale:** Declaring bare primitive types in spec interfaces allows implementers to create models that accept empty strings, negative numbers, or invalid enum values, bypassing validation at instantiation.

## 22. Mandatory Field-Level Constraints on Security Data Models
* **Rule:** Pydantic schemas and specification model declarations for security payloads, network targets, RPC streams, and sanitized text MUST use explicit Pydantic v2 `Field` constraints (`IPvAnyAddress`, `min_length=1`, `pattern=r"..."`, `Dict[str, Any] = Field(..., min_length=1)`) rather than bare unconstrained types (`Optional[str] = None`, `dict`, `str`).
* **Rationale:** Bare primitive types accept malformed IP strings (`"not_an_ip"`), empty environment identifiers (`""`), unconstrained empty dicts (`{}`), or empty sanitized strings, allowing malformed data to bypass validation and reach persistence or mitigation engines.

## 23. Atomic SQLite Upsert & Read-Modify-Write Contention Prevention
* **Rule:** SQLite database persistence methods tracking entity metrics or updating aggregated state (e.g. `upsert_attacker_profile`, `upsert_threat_signature`) MUST use a single atomic SQL statement (`INSERT INTO ... ON CONFLICT(key) DO UPDATE SET ... RETURNING ...`) utilizing SQLite 3.35+ `RETURNING` clauses and SQLite JSON functions (`json_each`, `json_group_array`). Executing sequential `SELECT` followed by `UPDATE`/`INSERT` or acquiring explicit database-wide write locks (`BEGIN IMMEDIATE TRANSACTION`) is strictly prohibited.
* **Rationale:** Sequential read-modify-write loops introduce race conditions and lost updates under concurrent async calls. Explicit transaction lock blocks (`BEGIN IMMEDIATE TRANSACTION`) cause database lock contention and busy timeouts under SQLite connection pools. Single-statement atomic SQL upserts execute in <1ms, guarantee zero lost updates, and prevent connection pool starvation.

## 24. Non-Blocking Synchronous User Callbacks in Interception Resolvers
* **Rule:** Async security resolvers and interception engines (`SyncResolver`, callback handlers) executing user-registered synchronous hooks (e.g. `on_attacker_identified`, security event handlers) MUST run synchronous functions off the main event loop thread via `loop.run_in_executor(None, fn, arg)` wrapped in `await asyncio.wait_for(..., timeout=0.05)`. Resolver execution paths MUST NOT invoke synchronous user functions directly on the main event loop thread or leave timed-out threadpool tasks un-isolated.
* **Rationale:** Direct synchronous execution on the event loop thread halts all concurrent security evaluations for the duration of the callback. Calling `asyncio.to_thread` inside `wait_for` without executor management can leak threadpool workers when callbacks time out. Using `loop.run_in_executor` with explicit `asyncio.wait_for` isolation guarantees the resolver SLA (<5ms budget) while safely timing out slow callbacks after 50ms without stalling the event loop thread or accumulating executor workers.

## 25. VirusTotal GTI Free-Tier Rate Limit Architectural Invariant
* **Rule:** VirusTotal Google Threat Intelligence (GTI) MCP queries MUST remain strictly capped at 4 queries per 60-second sliding window via `GTIQueryBudgetTracker` token bucket rate limiting (1 token replenished every 15 seconds). Provider configuration refactors migrating Gemini LLM providers to GCP Vertex AI Mode MUST NEVER strip, loosen, or remove VirusTotal free-tier rate limits.
* **Rationale:** VirusTotal commercial enterprise API subscriptions cost >$1,000/month and are an explicit non-goal. Conflating third-party Threat Intelligence rate limits with Gemini LLM model quotas creates catastrophic financial exposure.

## 26. Network Security Detector Endpoint Parsing & IPv4/IPv6 Loopback Range Filtering
* **Rule:** Security detection modules parsing network targets or hostnames (e.g. `C2InfrastructureDetector`, network event correlators, `InboundProtocolFilter`) MUST:
  1. Enclose unbracketed IPv6 target strings (e.g. `::1`, `::1:8080`) in brackets (`[::1]`, `[::1]:8080`) before passing to URL parsers (`urlparse`) to prevent colons from being split into empty host components.
  2. Treat the entire `127.0.0.0/8` IPv4 loopback block (e.g. `127.0.0.2`), IPv6 loopback (`::1`, `[::1]`), and IPv4-mapped IPv6 loopback addresses (`::ffff:127.0.0.0/8`, e.g. `[::ffff:127.0.0.1]:8080`) as local loopback endpoints (`_is_local_host` / `_is_local_endpoint` / `_is_loopback`) alongside `localhost`.
  3. Extract IP literals from bracketed IPv6 host headers with ports (e.g. `[::1]:8000` -> `::1` or `[::1]`) by parsing bracket delimiters (`clean[1:clean.index("]")]`) before port stripping or IP address parsing. Naive colon splitting (`split(":")[0]`) leaves trailing colons or corrupted IPv6 addresses.
* **Rationale:** Single IP exact-string comparisons and naive colon splitting allow valid bracketed IPv6 requests with ports (`[::1]:8000`) or alternative loopback subnets (`127.0.0.2`) to be rejected or misclassified as remote traffic.

## 27. Destination Metadata Extraction Isolation in Security Event Correlation
* **Rule:** Cross-pillar security correlation components and endpoint classifiers extracting target endpoints from event metadata MUST restrict metadata extraction strictly to explicit, known network destination keys (`DESTINATION_KEYS = {"url", "uri", "endpoint", "domain", "host", "target", "c2_url", "remote_url", "destination", "dest_url", "server"}`) or validated HTTP/HTTPS URLs. Security engines MUST NOT perform loose substring searches (e.g. searching for `"http"`, `"bin"`, or `"paste"`) over arbitrary string metadata values.
* **Rationale:** Loose substring scanning over generic metadata keys converts incidental string values (e.g., `metadata["command"] = "/bin/bash"` or `metadata["referrer"] = "https://docs.python.org"`) into target network endpoint identities, causing false cross-pillar correlation overlaps and false threat evidence between unrelated events.

## 28. Case & Scheme Preservation in URL Endpoint Normalization
* **Rule:** URL endpoint normalization functions (`_normalize_endpoint`) MUST preserve the lowercased scheme (`http://` vs `https://`) and lowercased netloc (with port), while preserving the original letter-casing of path and query string parameters (`f"{scheme}://{netloc}{path}{query}"`).
* **Rationale:** Stripping schemes or collapsing HTTP and HTTPS URLs into identical endpoint identities merges distinct protocol traffic, corrupting periodic beaconing frequency metrics ($\sigma / \mu \le 0.25$) and generating false C2 correlation.

## 29. Kubernetes Control-Plane & Domain Endpoint Action Coupling Invariants
* **Rule:** Security detection modules evaluating infrastructure-specific API abuse (e.g. `KubernetesDefenseLayer.detect_secrets_exfiltration`, cloud IAM monitors) MUST strictly couple target control-plane endpoint validation (`K8S_SECRET_API_REGEX`, `k8s://`, `/api/v1/namespaces/`, explicit `k8s_api` metadata) directly with specific domain action classifiers (`get_secret`, `list_secrets`, etc.). Detectors MUST NOT match generic action names or unqualified substring patterns in isolation without verifying that the destination target resides within the Kubernetes control plane.
* **Rationale:** Matching generic action names (`get_secret`) or unqualified substring tokens (`"secret"`) without control-plane target scoping causes non-Kubernetes third-party tool calls (e.g. Vault lookups, SaaS API requests, internal service queries) to be counted as Kubernetes API abuse, producing false `secrets_exfiltration` security evidence.

## 30. Workload Token Authorization & Pod Lifecycle Event Scoping Invariants
* **Rule (Token Theft Authorization):** Detectors scanning well-known service account token paths (e.g. `/var/run/secrets/kubernetes.io/serviceaccount/token`) MUST distinguish legitimate workload in-cluster authentication from unauthorized agent token theft by honoring explicit workload authorization flags (`is_authorized`, `authorized`, `access_type == "legitimate"`, `legitimate`) and never suppressing evidence on unverified risk-score fallbacks.
* **Rule (Pod Lifecycle State Scoping):** Detectors monitoring pod lifecycle state transitions (e.g. `detect_self_respawn`) MUST restrict event filtering strictly to explicit lifecycle actions (`POD_TERM_ACTIONS`, `POD_CREATE_ACTIONS`) or `event_type == "pod_lifecycle"`, and verify chronological ordering (termination precedes creation). Generic status metadata strings (`status="running"`, `status="terminated"`) from health checks or telemetry events MUST NOT be evaluated as pod lifecycle transitions in isolation.
* **Rationale:** Evaluating generic status strings or unverified risk score fallbacks causes routine health checks, telemetry streams, and authorized workload authentications to produce false `pod_token_theft` and `self_respawning_pod` alerts.

## 31. Package Registry Scanning Distinctness, Multi-Pillar Shared Store Discriminators, & Persistence Decoupling
* **Rule (Package Registry Scanning Distinctness):** Package registry monitoring detectors (`PackageRegistryMonitor.detect_exploit_probing`) analyzing unusual 404 response bursts MUST calculate distinct package targets across each sliding burst window and require at least 5 distinct packages (`len(distinct_pkgs) >= 5`) before emitting scanning threat evidence. Standard client retry behavior for a single missing package (`len(distinct_pkgs) < 5`) MUST NOT be classified as multi-package namespace enumeration or scanning.
* **Rule (Multi-Pillar Shared Store Discriminator):** Specialized threat detection engines (e.g. `PackageRegistryMonitor`, `KubernetesDefenseLayer`) querying mixed-pillar events from a shared `AttackGraphStore` MUST filter candidate events using strict domain discriminators (e.g. `_infer_registry_type` returning `None` for non-registry endpoints) before analyzing targets or deriving domain entities (such as package names). Generic HTTP 404s or non-registry tool calls MUST NOT be evaluated as package registry interactions.
* **Rule (Stream Parsing Decoupled from DB Persistence):** In asynchronous streaming normalizers (`monitor_registry_access`), raw record validation and normalization MUST be decoupled from database insertion (`store.insert_event`). Database connection or infrastructure exceptions MUST propagate directly to the caller and MUST NOT be swallowed or masked as malformed stream records, ensuring in-memory caches and persistent stores remain synchronized.
* **Rationale:** Blurring single-package client retries with multi-package reconnaissance generates false-positive alerts on routine network retries. Querying shared attack graphs without domain discriminators allows unrelated non-registry 404 errors to contaminate security evidence. Conflating database connection errors with malformed stream data leaves unsynchronized in-memory state and drops valid security telemetry without alerting operators.

## 32. Event-Driven Non-Polling Invariant & Retry Delay Declarations
* **Rule:** Blackwall enforces an event-driven execution architecture strictly validated by `scripts/verify_no_polling.py` and `tests/integration/test_pipeline_checkpoint.py`. New modules implementing asynchronous delivery retry or connection backoff routines using `await asyncio.sleep(...)` MUST be explicitly declared in `approved_locations` in `scripts/verify_no_polling.py`. They MUST ensure backoff delays are triggered strictly on exception retry branches and never executed on the happy path.
* **Rationale:** Automated CI gates run AST scans across `src/` to prevent polling loops from entering the fast analysis path. Omitting retry-capable modules from the approved locations list breaks CI verification.

## 33. Authoritative Persisted Row Ingestion on Database Conflict
* **Rule:** Dual-tier or database-backed stores utilizing `ON CONFLICT DO NOTHING` on single or batch insertions MUST fetch authoritative persisted rows from the database (e.g. `SELECT * FROM ... WHERE node_id = ANY(...)`) for all inserted or conflicted entities. In-memory node caches MUST be populated with the authoritative persisted rows (including existing incoming/outgoing causal edges) rather than caching incoming unlinked payloads.
* **Rationale:** When an event already exists in PostgreSQL but is absent from the local cache, `ON CONFLICT DO NOTHING` ignores the insert in the database. Caching the incoming payload with empty edge lists causes database-backed and cache-backed graph consumers to observe contradictory relationship graphs for the same entity.

## 34. Within-Batch Identifier Deduplication in Bulk Operations
* **Rule:** Bulk ingestion and batch normalization methods (`insert_events_batch`, `process_event_batch`) MUST track and deduplicate identifiers (e.g. `event_id`) within the batch payload itself before instantiating node records or updating index collections.
* **Rationale:** Batches containing multiple events with the same `event_id` pass single-item cache checks and can append the same identifier multiple times to entity indices (e.g. `_agent_nodes_index`), causing in-memory graph traversals to observe duplicate nodes absent from persistence.

## 35. Graph Export Edge Scoping Invariant
* **Rule:** Attack graph exporters (e.g. `AttackGraphExporter`, `RetrospectiveAnalyzer.export_attack_graph`) MUST defensively scope exported graphs before serialization. Regardless of whether filtering occurs at the query layer or direct exporter invocation:
  1. Exported edges MUST be filtered strictly to edges whose source and target nodes both exist in the exported node set (`from_node` and `to_node` in exported node IDs).
  2. Exported node records MUST have their `incoming_edges` and `outgoing_edges` arrays filtered strictly to the scoped edge IDs.
* **Rationale:** Direct callers often pass filtered node subsets alongside full edge tables. Serializing un-scoped edges or retaining dangling edge IDs in node payloads creates malformed JSON/GraphML outputs that fail downstream schema validators and graph visualizers.

## 36. Purge Edge Array Cascading & Dual Storage Synchronization
* **Rule:** Database and in-memory event purging routines (`purge_events_before`) in hybrid/dual-tier stores MUST maintain exact state parity across PostgreSQL and process-local cache:
  1. Candidate purged node IDs MUST combine both persisted database rows and in-memory cache records (`purged_ids | to_delete_candidates`).
  2. In PostgreSQL, all causal edges adjacent to any purged node ID (`causal_edges WHERE from_node = ANY(...) OR to_node = ANY(...)`) MUST be queried and removed, and retained database nodes updated to strip those edge IDs.
  3. In process-local memory, all adjacent edge IDs (combining database-purged edge IDs and `self._edges` connections) MUST be stripped from `incoming_edges` and `outgoing_edges` across all retained cached node instances using stringified ID matching.
  4. Cache invalidations MUST reference valid attributes (e.g. `self._path_cache.clear()`), and process-local indices (`self._agent_nodes_index`) MUST be purged of deleted node IDs.
* **Rationale:** If a cached node's adjacent edge was persisted in PostgreSQL but absent from process-local `self._edges`, purging only database rows leaves dangling edge references on cached node instances, leading to corrupted cache-backed graph queries.

## 37. Cross-Window Causal Path Preservation in Retrospective Traversal
* **Rule:** Retrospective analysis engines (`RetrospectiveAnalyzer.detect_retrospective_paths`) querying historical attack paths across multi-day/week windows MUST preserve direct causal links regardless of elapsed time:
  1. Direct causal edges (`outgoing_edges` / `causal_edges`) represent explicit execution dependencies and MUST NOT be subjected to short-window or arbitrary time-gap eviction filters.
  2. Batching or sliding-window historical queries MUST evaluate complete agent node histories or retain unresolved causal source nodes until all chronological successors have been processed.
* **Rationale:** Adversaries executing slow-moving or low-and-slow campaigns may trigger secondary payloads days after initial access. Evicting causal sources at batch or sliding-window boundaries severs multi-hop attack paths and allows persistent stealth campaigns to evade detection.

## 38. Evaluation Environment Support & Mandatory Production Containment Gate (Architecture Rule 20)
* **Rule (When and How to Use Evaluation Environments):**
  1. **When to Use:** Security testing agents, eval suites, and red-team benchmarks (e.g. CyberGym, synthetic prompt injections, GCP Vertex AI evals) MUST route telemetry through `EvaluationEnvironmentManager` / `EvaluationEnvironment` (`blackwall.enterprise.advanced_threat_detection.evaluation`) to isolate synthetic attacks from production databases and active incident response.
  2. **Mandatory Containment Gate:** Live mitigation handlers (e.g., eBPF socket drops, Threat Mesh broadcasts, Vault honeytoken revocations) MUST evaluate `await manager.is_evaluation_mode(evidence_id)` or `manager.should_suppress_production_reaction(alert_or_event)` before executing active production mitigations. If containment evaluates to `True`, active production disruption MUST be suppressed.
  3. **Multi-Tenant Deterministic ID Derivation:** Evaluation environments ingesting events MUST deterministically derive scoped UUIDv4 identifiers per environment (`blackwall://eval/{env_id}/{event_id}`) using SHA-256 derivation while preserving `original_event_id` in metadata. This guarantees zero identifier collisions and prevents cross-tenant state leakage when multiple evaluation environments share a single PostgreSQL database.
  4. **Scoped PostgreSQL Reset & Edge Cleanup:** Environment state resets (`env.reset()`) MUST scope deletions strictly to `metadata->>'evaluation_env_id' = $1` inside atomic transactions and clean up deleted edge IDs from surviving nodes' `incoming_edges` and `outgoing_edges` JSONB arrays.
  5. **Lifecycle Closure Guards:** Calling `env.close()` or `manager.delete_environment()` MUST transition the underlying store to a closed state. Retained store references MUST reject subsequent writes (`insert_event`, `insert_events_batch`, `link_events`) with `RuntimeError` rather than silently writing to detached in-memory graphs.
* **Rationale:** Blurring evaluation telemetry with production threat graphs triggers false-positive incident response actions (such as dropping legitimate connections or revoking live infrastructure tokens). In shared database configurations, un-scoped event identifiers cause cross-tenant collision ignores and corrupt evidence provenance.

## 39. Active Threat Reaction, Kernel Tracepoint Semantics, & Identity Revocation Invariants
* **Rule (Kernel Tracepoint Enforcement Scope):** `LinuxeBPFDriver` uses eBPF tracepoints (`sys_enter_connect`, `sys_enter_execve`) backed by BPF map lookup tables (`dropped_pids`, `dropped_ips`, `dropped_ip6s`). Kernel enforcement operates via portable `bpf_send_signal(9)` (`SIGKILL`) delivered upon intercepted syscall entry. Tracepoint probes MUST NOT be designed or reviewed as inline network packet rewrite filters (`SO_REJECT`/TC-eBPF) or error-injection kprobes (`bpf_override_return`, which requires non-standard kernel error injection builds). `UserSpaceAuditDriver` provides in-process audit hook enforcement via `sys.addaudithook` for development and non-Linux hosts.
* **Rule (Atomic Kernel Rule Rollback):** When installing PID or IP drop rules, drivers MUST atomically update BPF maps and roll back userspace state bookkeeping if BPF map updates fail.
* **Rule (JIT Identity Binding & Revocation Scoping):** STS credentials issued by `VaultMCPAdapter` and `SecretVaultSidecar` MUST bind explicit `agent_id` and `principal_id` ownership fields. `ActiveReactionEngine` token revocation MUST scope strictly to tokens owned by the target agent/principal. When an alert supplies a compromised `token_id` without an explicit `agent_id`, the engine MUST resolve the owning principal from the active token registry prior to dispatching revocation.
* **Rationale:** Prevents contradictory review expectations between tracepoint signal delivery vs. inline firewalling, protects multi-tenant credentials from cross-principal revocation, and ensures atomic consistency across kernel enforcement maps.

## 40. GCP-Native Evaluation Service & Dual-Tiered Sandbox Architecture
* **Rule (Dual-Tiered Evaluation Strategy):**
  1. **Tier 1 (Fast CI/CD & Functional Firewalls)**: Security evaluation for Blackwall Core MUST use the Google Cloud Agent Platform / ADK Adversarial Harness in 100% GCP Vertex AI Mode (`before_tool_callback`, Gemini models in Vertex AI mode via Application Default Credentials).
  2. **Tier 2 (Enterprise Kernel & Multi-Stage Attack Simulations)**: Deep penetration testing and multi-stage exploit simulations (swarms, C2 beaconing, kernel escalation, pipeline poisoning) MUST execute inside containerized environments (such as Cybench / CyberGym) hosted on Google Cloud Run or GKE Sandbox backed by gVisor microVM kernel isolation.
* **Rule (Deterministic Evaluation Provenance Gate):** Evaluation containment membranes MUST never rely on loose substring checks (e.g. `"/eval/" in path`) to classify events. They MUST require verified URI schemes (`blackwall://eval/`, `blackwall://evaluation/`) or registered evaluation store lookups to prevent synthetic evaluation spoofing from suppressing production mitigations.
* **Rule (Zero-SaaS Evaluation Invariant & Weave Deprecation):**
  - Legacy Weights & Biases (Weave) workflows are fully deprecated.
  - All threat detection evaluations MUST use the cloud-native **GCP Vertex AI Gen AI Evaluation Service (`vertexai.preview.evaluation` / `EvalTask`)** with `PointwiseMetric`, `PairwiseMetric`, and trajectory evaluation metrics.
  - Evaluation telemetry MUST be exported directly to Google Cloud Trace (`opentelemetry-exporter-gcp-trace`) and Google Cloud Logging.
  - Evaluation harnesses MUST authenticate strictly via Application Default Credentials (ADC) without requiring third-party SaaS API keys (`WANDB_API_KEY`, AI Studio keys).
* **Rationale:** Eliminates external third-party credential dependencies, prevents data exfiltration to non-compliant SaaS platforms, optimizes GCP enterprise credit utilization, and guarantees that kernel containment tests run within secure microVM sandbox boundaries.

## 41. Principal-Scoped JIT Credential Binding & Token Revocation
* **Rule (Strict Principal Scoping):** When issuing JIT credentials (`issue_jit_token`, `get_jit_credential`), the token must bind strictly to the requesting agent's explicit `agent_id` or `principal_id`.
* **Rule (No Role Substitution):** The system MUST NOT substitute a shared role name (e.g. `"devops"`, `"analytics"`) as the principal or agent identifier. Unspecified callers must receive a unique, isolated instance identifier (`token_id` or unique instance UUID) to guarantee that agent-scoped revocation (`revoke_agent_tokens`) never causes cross-agent collateral invalidation or containment evasion.
* **Rationale:** Prevents multi-tenant credentials from escaping scoped revocations and stops rogue agents sharing a role from invalidating benign sibling workloads.

## 42. Production LLM Model Standards (Gemini 3.X Generation)
* **Rule (Main Interception & Rapid Triage Model):** MUST default to `gemini-3.5-flash-lite` for sub-100ms synchronous anomaly classification, structural policy escalation, and tool interception.
* **Rule (Deep Reasoning & Forensic Attribution Model):** MUST default to `gemini-3.8-flash` for frontier semantic reasoning, attack path decompilation, and threat signature synthesis.
* **Rule (Flash-Only Architecture & Prohibition of Pro Models):** Blackwall operates exclusively on Gemini Flash models. All Gemini Pro models (`gemini-*-pro*`) and unverified/hallucinated model identifiers are strictly prohibited in production, test suites, evaluation judges, benchmarks, mocks, and property tests.
* **Rule (Embeddings Model):** MUST default to `gemini-embedding-001` (768 dimensions).
* **Rule (Deprecated Models Deny List):** All legacy model identifiers (`gemini-1.5-*`, `gemini-2.0-*`, `gemini-2.5-*`, and `gemini-3.1-*` including `gemini-3.1-flash-lite` and `gemini-3.1-pro-preview`) are strictly deprecated and prohibited in production and test configurations.
* **Rationale:** `gemini-3.5-flash-lite` provides sub-100ms SLA compliance for the hot synchronous path, while `gemini-3.8-flash` delivers frontier reasoning speed and depth without the latency penalties of legacy preview models.

## 43. GCP Vertex AI EvalTask Failure Escalation & Cloud Trace Telemetry Invariants
* **Rule (Explicit EvalTask Failure Escalation):**
  - `GCPVertexAIEvaluationHarness` MUST NOT silently swallow Vertex AI initialization errors, ADC authentication failures, or runtime `EvalTask` execution exceptions as successful `LOCAL_FALLBACK` results unless `allow_fallback=True` is explicitly enabled in `GCPVertexEvalConfig`.
  - Default configuration (`allow_fallback=False`) MUST return `status="FAILED"` with the root cause error or raise `RuntimeError` on failure to prevent masking cloud evaluation defects in CI/CD pipelines.
* **Rule (Fallback Span Lifecycle & Telemetry Preservation):**
  - When `allow_fallback=True` and `EvalTask.evaluate()` raises an exception, the failure MUST be recorded as an error on the primary evaluation span with `record_evaluation_error(span, error=e, status="ERROR")` and flushed to Cloud Trace.
  - The subsequent local fallback aggregation MUST be emitted on a dedicated, separate `vertex_eval.local_fallback` span. The harness MUST NEVER overwrite the error status on an already-ended span or invoke `.finish()` / `.end()` on an OpenTelemetry span multiple times.
* **Rule (Cloud Trace Default Instrumentation & Disable Precedence):**
  - `GCPCloudTraceExporter` MUST attach `CloudTraceSpanExporter` and `BatchSpanProcessor` by default whenever OpenTelemetry Cloud Trace SDK packages are installed.
  - `BLACKWALL_DISABLE_CLOUD_TRACE=true` MUST take strict precedence over `BLACKWALL_EXPORT_CLOUD_TRACE=true` or initialization arguments to guarantee absolute opt-out in local/offline environments.
* **Rule (Span Latency & Lifecycle Tracking):**
  - Evaluation spans MUST be created at the beginning of the operation via `start_span()` and passed into execution handlers, ensuring that duration metrics in Google Cloud Trace accurately measure the full evaluation runtime.
* **Rule (Hermetic Evaluation Threat Graph Isolation):**
  - All red-team evaluations, swarm simulations, exploit chain tests, and BDD scenarios MUST instantiate an isolated `AttackGraphStore(in_memory=True)` and inject it into detectors to prevent synthetic test events from polluting persistent databases.
* **Rule (Curated Dataset Dependency Hygiene):**
  - Dataset utilities providing tabular outputs (`as_dataframe=True`) MUST gracefully handle missing optional dependencies (`pandas`) with safe `ImportError` fallback to standard dictionaries, without referencing uninitialized loggers.
* **Rationale:** Enforces deterministic evaluation reporting in Vertex AI mode, guarantees end-to-end telemetry capture in Google Cloud Trace, prevents silent false positives during security harness runs, and preserves pristine isolation between evaluation artifacts and persistent threat graphs.

## 44. Ingress Payload Scanning, Literal Substitution, & Positive Threshold Validation Invariants
* **Rule (Strictly Positive Confidence Thresholds & Benign Alert Guarding):**
  - Parameter validators for security confidence thresholds (e.g. `confidence_threshold`, `critical_confidence_threshold`) MUST enforce strictly positive values (`0.0 < threshold <= 1.0`), raising `ValueError` when `0.0` or negative values are provided.
  - Alert publishing routines MUST explicitly verify that threat indicators were matched (`if matched_patterns and confidence >= self.confidence_threshold:`) before publishing alerts to the `AlertBus`, ensuring benign inputs receiving baseline `0.0` confidence never trigger false-positive security alerts with `NO_INJECTION_DETECTED` evidence.
* **Rule (Literal Replacement in Regex Sanitization & Redaction):**
  - When replacing detected malicious payloads or injection vectors via `Pattern.sub` or `re.sub` with configurable user-provided or default placeholders (e.g., `redaction_placeholder`), replacement MUST be performed using a callable (`pattern.sub(lambda _match: self.redaction_placeholder, text)`) or `re.escape`-protected string.
  - Passing unescaped replacement strings directly to `re.sub` is strictly prohibited to prevent regex template/group backreference injection (e.g., `\g<0>`, `\1`) from re-inserting malicious payloads or raising syntax errors that leave exploit vectors unredacted in host execution contexts.
* **Rationale:** Permitting `0.0` threshold values allows benign inputs to satisfy `>= 0.0` comparisons and emit spurious `HIGH`/`CRITICAL` alerts that flood SOC pipelines. Passing unescaped replacement strings to regex engines allows crafted placeholders with backreferences to reconstitute stripped exploit spans, defeating prompt injection and data poisoning containment.

## 45. Non-Finite Numeric Limit Validation & Resource Quota Invariants
* **Rule (Finite Float Validation on Numeric Thresholds, Rates, and Durations):**
  - All numeric constructor and method parameters representing security limits, rate caps, sliding windows, timeouts, multipliers, and durations (e.g. `token_burn_rate_limit`, `request_velocity_limit`, `sliding_window_sec`, `quarantine_duration_sec`, `critical_burn_rate_multiplier`, `duration_sec`, `confidence_threshold`) MUST be explicitly validated with `math.isfinite(x)` in addition to type and positivity checks:
    ```python
    if (
        isinstance(x, bool)
        or not isinstance(x, (int, float))
        or not math.isfinite(x)
        or x <= 0.0
    ):
        raise ValueError("x must be a finite float greater than 0.0")
    ```
  - **Configuration and Environment Variable Resolvers**: Resolvers reading numeric settings from environment variables (e.g. `get_gemini_http_timeout`, `get_gemini_max_output_tokens`) MUST validate parsed floats/ints with `math.isfinite(val) and val > 0`. Because Python's `float("nan")` and `float("inf")` parse without raising `ValueError`, resolvers MUST catch non-finite or non-positive values and fall back to safe architectural defaults rather than passing invalid values to downstream SDKs.
  - Relying solely on `x <= 0.0` or `x < 1.0` is strictly prohibited because comparisons with `NaN` (e.g. `float('nan') <= 0.0`) evaluate to `False` in Python, accepting invalid inputs. Similarly, positive infinity (`float('inf')`) passes `> 0.0` checks and breaks enforcement: infinite rate/velocity limits prevent threshold comparisons from triggering, while infinite timeouts and quarantine durations produce holds that never expire automatically.
* **Rationale:** Accepting `NaN` breaks mathematical comparisons in sliding-window calculations and alert severity evaluation, causing silent security failures. Accepting `+inf` disables throttling and creates unexpiring quarantines, causing denial of service for benign workloads or unmitigated Denial of Wallet (DoW) exposure for adversarial workloads.

## 46. Low-Level Syscall vs. Container Orchestrator Lifecycle Separation
* **Rule:** Container and Kubernetes security detectors (`KubernetesDefenseLayer`, container sandbox monitors) MUST strictly separate low-level kernel/process syscall actions (`sys_clone`, `sys_fork`, `clone`) from high-level orchestrator lifecycle actions (`POD_CREATE_ACTIONS`, `POD_TERM_ACTIONS`, `FLEET_SPAWN_ACTIONS`).
* **Rule:** Low-level process creation syscalls captured via eBPF tracepoints or audit hooks MUST NOT be included in pod creation or pod self-respawn action sets.
* **Rationale:** Generic process/thread cloning inside sandbox containers (e.g. worker process forks during CyBench executions) shares the same process namespace or container ID. Treating `sys_clone` as pod creation produces false `fleet_spawning` and `self_respawning_pod` threat evidence.

## 47. Multi-Day Retrospective Semantic Edge Decay & MITRE Technique Gating
* **Rule:** Retrospective attack path correlators (`RetrospectiveAnalyzer.reconstruct_causal_graph`) constructing semantic and temporal edges across multi-day analysis windows MUST:
  1. Scale non-causal same-target edge weights strictly by continuous exponential decay ($w = \text{base} \cdot e^{-\Delta t / \tau}$), requiring $w \ge 0.4$ for edge creation without applying artificial constant baselines that keep weights $\ge 0.4$ as $\Delta t \to \infty$.
  2. Gate base edge multipliers on MITRE ATT&CK technique matches (e.g. $\text{base} = 0.8$ for MITRE-matched actions, $\text{base} = 0.5$ for non-MITRE routine actions).
  3. Traverse all identified root nodes without artificial finite result collection caps that terminate DFS early and starve sibling branches.
* **Rationale:** Constant baseline additions connect unrelated routine actions occurring days apart, while un-gated decay severs multi-stage stealth campaigns. Gating decay on MITRE technique relevance preserves genuine multi-day attack paths while rejecting disconnected benign activity.

## 48. Active Enforcement Method Fail-Closed Contract & Inbound RPC Origin Validation
* **Rule (Fail-Closed Success Initialization):** Every action method in `ActiveReactionEngine` (`execute_ebpf_socket_drop`, `broadcast_fleet_signature`, `revoke_identity_session`) MUST initialize `success = False` unconditionally before any conditional dispatch. `success` MUST be set to `True` only inside a branch that *completes an enforcement action without exception*. The following initializations are strictly prohibited:
  - `success = True` — leaves `success` unchanged when a branch is silently skipped (e.g. unsupported interface, absent dependency)
  - `success = self.dep is not None` — leaves `success = True` when the dependency is present but its interface matches no dispatch branch
* **Rule (Dispatcher Return Value Capture):** Dispatch branches that optionally await a coroutine MUST assign the awaited result back to the same variable before inspecting it:
  ```python
  res = self.mesh_broadcaster(payload)
  if asyncio.iscoroutine(res):
      res = await res          # ← captured, not discarded
  success = bool(res) if res is not None else True
  ```
  The return value of `await` MUST NOT be discarded with a bare `await res` statement. Success semantics: `None` → completed without explicit failure signal (success); any other falsy value (e.g. `False`, `0`) → caller-signalled failure.
* **Rule (Empty-Result Oracle Guard for Token Revocation):** When a vault-style adapter returns an empty collection from `revoke_agent_tokens`, the failure condition MUST apply unless the local token registry confirms zero tokens were ever issued:
  ```python
  if len(revoked_tokens) == 0 and not (
      isinstance(adapter_tokens, dict) and len(adapter_tokens) == 0
  ):
      success = False   # absent registry, non-dict, or non-empty dict → failure
  # else: empty dict registry → no tokens existed, empty return is correct
  ```
  An absent registry (`None`), a non-dict registry, or a non-empty registry all require treating zero revocations as a failure; only a confirmed empty dict (`{}`) is a legitimate "nothing to revoke" result.
* **Rule (Inbound RPC Origin Validation — Always Enforced):** `InboundProtocolFilter.validate_headers_and_origin()` MUST be called unconditionally on every inbound RPC request, regardless of whether `headers` or `remote_addr` are provided by the caller. Callers that omit these optional parameters MUST receive safe defaults (`headers={}`, `remote_addr=""`) before the validation gate so that loopback enforcement and Origin/Host restrictions are never bypassed by simply omitting arguments.
* **Rationale:** Fail-open enforcement methods produce false `COMPLETED` audit records for actions that never occurred. Gating RPC header validation on presence allowed unauthenticated non-loopback callers to bypass authorization by omitting arguments.

## 49. Active Reaction Dispatch Fault Isolation & Structured Logging Hygiene
* **Rule (Reaction Dispatch Fault Isolation):** Every `await active_reaction.*()` call within `correlate_agent_threats()` (eBPF socket drop, ZeroMQ mesh broadcast, Vault token revocation) MUST be wrapped individually in a `try/except Exception` block. Exceptions from the reaction adapter layer MUST be logged via `logger.error()` and MUST NOT propagate to abort the detection correlation loop or suppress alerts that were already generated.
* **Rule (Structured Logging via `extra` Dictionary):** When emitting structured metadata or event objects via standard Python `logging.Logger` instances, custom payload dictionaries MUST be passed through the `extra={...}` parameter (e.g. `logger.info("EVENT", extra={"event": payload.model_dump()})`) or formatted into the log message string. Passing arbitrary keyword arguments directly to standard logger methods (`logger.info("...", event=...)`) is strictly prohibited to prevent runtime `TypeError` exceptions.
* **Rationale:** Fault isolation ensures that partial adapter failures degrade gracefully without silently discarding security intelligence. Standard Python `logging.Logger._log()` does not accept arbitrary keyword arguments and raises `TypeError` if custom keywords are passed directly.


## 50. Independent Security Gate Bypass-Proofing
* **Rule:** Multi-layer security validation sequences (e.g. loopback check → allow-list check → header presence check) MUST be designed so that disabling one gate (e.g. `enforce_loopback=False`) does not implicitly open a free path through the remaining gates. Each gate MUST independently provide a baseline rejection for the "no identifying information" case:
  1. When loopback enforcement is disabled AND the caller is unauthenticated, require at least one other identifying signal (Origin or Host header) to be present — regardless of whether allow-lists are configured.
  2. When allow-lists are configured (strict mode), absent headers MUST fail the check; header absence must never be treated as implicit allowance in strict mode.
  3. Gates that combine boolean `enforce_*` flags with optional allow-list sets MUST be audited for all 2^N flag combinations to verify each combination has a correct accept/reject outcome for both authenticated and unauthenticated callers.
* **Rationale:** The three-iteration fix on `InboundProtocolFilter.validate_headers_and_origin` demonstrated that optional-parameter disablement (`enforce_loopback=False`) combined with unconfigured allow-lists (`allowed_origins=None`, `allowed_hosts=None`) created a silent "all gates off" path that passed unauthenticated callers with zero headers. Each gate must provide independent rejection rather than relying on the others to catch what it does not.

## 51. Evaluation Judge Agents & Antigravity SDK Invariants
* **Rule (Mandatory Paid-Tier Contract Validation at Startup):**
  `GEMINI_TIER=paid`, `BLACKWALL_TIER=paid`, and `GCP_PROJECT` (or `GOOGLE_CLOUD_PROJECT`) must be verified at judge agent creation time. Tier contract violations MUST raise `ValueError` immediately; they must NOT be caught inside candidate evaluation retry loops or converted into heuristic fallbacks.
* **Rule (Asynchronous Agent Lifecycle Management):**
  Autonomous Antigravity SDK agents must be invoked within an async context manager (`async with agent as active_agent:`) to guarantee proper session initialization and runtime resource cleanup across evaluation retries.
* **Rule (Resilient Heuristic Fallback Ground-Truth Mapping):**
  Fallback scorers must check both canonical scenario schema fields (e.g. `stages`, `c2_endpoints`, `ground_truth_coordination` with `agents`/`score`) and legacy aliases to prevent inverted scoring during degraded-mode execution.
* **Rationale:** Discovered during Track B implementation and PR #100 review cycles:
  1. Catching tier contract errors inside the evaluation loop allowed misconfigured environments to silently fall back to heuristic scoring instead of failing at startup.
  2. Skipping agent `__aenter__`/`__aexit__` leaked runtime resources and caused Vertex AI agents to fail repeatedly.
  3. Fallback ground truth key mismatches caused fallback scorers to evaluate empty expected sets, penalizing correct detections and rewarding candidates that detected nothing.

## 52. AILM Security Trust Boundary Domain Scoping vs. Resource Labels
* **Rule:**
  - `AILMTracker.identify_boundary_crossing()` and evaluation datasets targeting AI-Induced Lateral Movement must strictly scope trust boundaries to recognized architectural, system-isolation, and network-perimeter domains (`user_space`, `kernel_space`, `sandbox`, `host`, `untrusted`, `trusted`, `public`, `private`, `internal_api`, `external_net`, `external_network`, `tenant_a`, `tenant_b`).
  - Fine-grained workload, queue, or resource-level identifiers (e.g., specific database names, support queues, or table names) must NOT be classified as security trust boundaries.
* **Rationale:** Treating arbitrary resource scopes or workload labels as security trust boundaries causes legitimate multi-service or multi-tenant agents to accumulate false-positive crossing counts, escalating risk to `HIGH` or `CRITICAL` and inadvertently triggering automated identity session revocation (`revoke_identity_session()`).

## 53. Blackwall MCP Gateway Architecture & Transport Security Invariants
* **Rule (Agent Agnosticism & Specification Boundaries):** Gateway specification components (`src/blackwall/gateway/`, `src/blackwall/cli.py`, and `gateway.yaml` representing the Blackwall MCP Gateway Architectural Specification governed by `.kiro/specs/blackwall-mcp-gateway/`) MUST NOT include hardcoded rules, special casing, or coupling for any specific agent runtime (Hermes Agent, Antigravity, Warp Terminal, Claude Desktop, Cursor). All communication must adhere strictly to the generic Model Context Protocol (MCP) JSON-RPC specification.
* **Rule (Transport Security & Loopback Default):** The MCP Streamable HTTP transport MUST default to `127.0.0.1:9229` with `Origin` and `Host` header validation to prevent DNS rebinding attacks.
* **Rule (Remote Authentication Boundary & Startup Guard):** When `--host` binds to a non-loopback address, a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`) is mandatory. Inbound requests missing a valid `Authorization: Bearer <token>` header MUST be rejected with HTTP 401 before JSON-RPC processing. The gateway daemon MUST refuse to start if configured with a non-loopback host without an auth token.
* **Rule (JSON-RPC Request ID Concurrency Isolation):** The gateway stream layer MUST track all in-flight requests by JSON-RPC `id` to ensure responses, cancellations, and errors are mapped deterministically during concurrent evaluation.
* **Rule (Downstream Tool Proxying & Verdict Synthesis):** ALLOW'd tool calls MUST be forwarded intact to downstream tool servers (spawned via `--wrap` or configured in specification `gateway.yaml`). BLOCK verdicts MUST synthesize a JSON-RPC error `-32603` with a generic message, reusing the incoming `id` and never exposing internal threat telemetry to the agent.
* **Rationale:** Discovered during MCP Gateway spec rebaseline and Greptile PR #108 review cycles: clear transport security boundaries, loopback defaults, startup guards, and protocol-level synthesis prevent unauthorized network exposure of downstream tools and prevent leaking sensitive threat intelligence to calling agents.

## 54. Cross-Platform Background Service Management (`launchd` & `systemd`) & Supervision Invariants
* **Rule (Non-Interactive Environment Variable Injection):** Because macOS `launchd` and Linux `systemd` execute service units in clean non-interactive shells that do not source terminal startup scripts (`.zshrc`, `.bash_profile`), service installation commands (`blackwall service install`) MUST capture active cloud credentials (`GCP_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_TIER="paid"`, `PATH`) and embed them in the service configuration (plist `<key>EnvironmentVariables</key>` block or systemd `Environment=` directives).
* **Rule (Install-Time Validation & Fail-Fast Guard):** `blackwall service install` MUST validate that required cloud credentials (e.g. `GCP_PROJECT`) are configured at install time (or supplied via `--project`). If missing, installation MUST fail immediately with an exit code != 0 and a clear error message, preventing the creation of a broken service.
* **Rule (Crash-Loop Throttling & systemd Syntax):** Services MUST configure crash throttling to prevent tight restart storms. On macOS `launchd`, configure `<key>ThrottleInterval</key><integer>30</integer>` and `<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>`. On Linux `systemd`, configure `StartLimitBurst=5` and `StartLimitIntervalSec=60s` strictly under the `[Unit]` section (where systemd rate limits belong), and `Restart=on-failure` / `RestartSec=5s` under `[Service]`. Placing rate limits under `[Service]` is invalid systemd syntax.
* **Rule (Absolute Path Resolution & Non-Tilde Invariant):** Because systemd `ExecStart` and daemon runners do not execute in a shell and do not expand tildes (`~`), `blackwall service install` MUST resolve all configuration paths, executable paths, log file locations, and credential paths to absolute filesystem paths (`Path.resolve()`) at install time. Raw `~` characters MUST NOT appear in generated service definitions.
* **Rule (Foreground Supervision & PID File Invariant):** Supervised services on both macOS (`launchd`) and Linux (`systemd`) MUST execute `blackwall serve --foreground` (with `Type=exec` and `PIDFile=` in systemd), ensuring the supervisor directly monitors the primary process rather than tracking an exiting parent process. In `--foreground` mode, whenever `--pidfile <path>` is supplied, `blackwall serve` MUST write its active PID to the designated file upon startup and delete it upon termination.
* **Rule (Authoritative Upstream Specification):** Service definitions MUST explicitly include an upstream configuration flag (e.g. `--config <resolved-path>` or `--wrap <cmd>`), ensuring allowed tool requests are deterministically forwarded to downstream tool servers.
* **Rationale:** Discovered during PR #110 and PR #111 review cycles. Running a gateway under `launchd` without an `EnvironmentVariables` dictionary caused instant authentication failures, omitting `ThrottleInterval` caused `launchd` to restart the crashed daemon in a tight loop, and omitting `--foreground` caused systemd/launchd to track an exiting parent process.

## 55. Linux Systemd System Services vs. User Units & FHS Directory Separation
* **Rule (User vs. System Service Separation):** User services (`~/.config/systemd/user/blackwall.service`) run as `$USER` and store configuration/state in `~/.blackwall/`. System services (`/etc/systemd/system/blackwall.service`) run under a system service account and MUST NEVER reference `~/.blackwall/` user home directory paths.
* **Rule (FHS Directory Provisioning):** When `--system` is specified, the systemd unit MUST configure standard FHS directories: `/etc/blackwall/gateway.yaml` (config), `/run/blackwall/blackwall.pid` via `RuntimeDirectory=blackwall`, `/var/log/blackwall/blackwall.log` via `LogsDirectory=blackwall`, and `/var/lib/blackwall/threat_signatures.db` via `StateDirectory=blackwall`.
* **Rule (Non-Root Identity Derivation & Account Creation):** System services MUST NOT run as root (`User=root`). The installer derives non-root execution identity in order: (1) explicit `--user <name>`, (2) `SUDO_USER` under `sudo`, or (3) dedicated system user `blackwall` (group `blackwall`). If the `blackwall` system account is created, it MUST be provisioned with a home directory: `useradd --system --home-dir /var/lib/blackwall --create-home blackwall`.
* **Rule (Explicit FHS Path Wiring in ExecStart):** System units MUST explicitly pass FHS paths in `ExecStart` (`--pidfile /run/blackwall/blackwall.pid --logfile /var/log/blackwall/blackwall.log --db /var/lib/blackwall/threat_signatures.db`) and inject `Environment="BLACKWALL_DB_PATH=/var/lib/blackwall/threat_signatures.db"`, ensuring runtime daemon components never fall back to user-space defaults.
* **Rule (Fallback ADC Resolution for Service Users):** Fallback ADC resolution (Application Default Credentials JSON schema) under `sudo` or `--system` MUST resolve against the derived service user's home directory. In direct-root mode with the dedicated `blackwall` user, the installer accepts `--credentials <path>` and copies credentials to `/etc/blackwall/credentials.json` owned by `blackwall:blackwall` (`0600`).
* **Rationale:** Discovered during PR #111 Greptile review iterations: running system units with user home paths causes crashes when the service user lacks access to `~/.blackwall`, and running as root violates the principle of least privilege.

## 56. NVIDIA DGX Spark Co-Existence, Unified Memory Bounding & Zero-GPU VRAM Conformance
* **Rule (Unified Memory Guarantee & RSS Ceiling):** On unified memory architectures (NVIDIA DGX Spark / Grace Blackwell GB10, 128GB LPDDR5x), Blackwall Core MUST run 100% in CPU user-space threads with 0MB allocated in CUDA contexts/VRAM. Its host process RSS memory MUST NOT exceed 350MB (<0.28% of the unified pool), strictly preserving >127.6GB (>99.7%) of the unified memory for local LLM inference engines (vLLM, Ollama, TensorRT-LLM) or model fine-tuning.
* **Rule (Port Non-Collision Invariant):** The default gateway port `9229` MUST NOT collide with standard DGX OS AI serving ports: `11434` (Ollama), `8000`/`8001`/`8002` (vLLM, Triton), or `8888`/`8080` (JupyterLab).
* **Rule (Multi-Layer Zero-CUDA Verification):** Conformance testing MUST assert non-encroachment across multiple layers:
  1. Character device file descriptors: verify 0 open file descriptors to `/dev/nvidia*`, `/dev/nvidiactl`, `/dev/nvidia-uvm` in the daemon's `/proc/<daemon_pid>/fd/` (resolving daemon PID via `blackwall.pid` across user and FHS paths, or subprocess handle — NOT `/proc/self/fd/` which inspects the test runner).
  2. NVML compute process registration: verify daemon PID is absent from `nvmlDeviceGetComputeRunningProcesses`.
  3. Framework context: `torch.cuda.is_initialized() is False` if torch is present.
  4. cgroup & host RSS bounds: `MemoryHigh=320M` and `MemoryMax=350M` in systemd unit, and host process RSS ≤ 350MB under active evaluation load.
* **Rule (Windows Strictly Excluded):** Windows packaging (`.exe`, `.msi`, PowerShell) is explicitly barred from all release and maintenance workflows.
* **Rationale:** Discovered during DGX Spark spec review on PR #111. Unified memory pools require strict co-existence guarantees and multi-layer verification to ensure agent security firewalls never starve colocated AI models.

## 57. GCP Vertex AI Thinking Budget Mapping & Telemetry Truthfulness
* **Rule (Vertex AI Thinking Budget Mapping):** In Google Cloud Vertex AI evaluations and models (`vertexai.generative_models`, `vertexai.preview.evaluation.EvalTask`), configuring reasoning levels MUST NOT merely set `include_thoughts=True`. The `thinking_level` string MUST be translated to `ThinkingConfig.thinking_budget`:
  - `"high"` → `thinking_budget = -1` (dynamic unthrottled reasoning)
  - `"medium"` → `thinking_budget = 16384`
  - `"low"` → `thinking_budget = 2048`
  - `"off"` → `thinking_budget = 0`
* **Rule (Fail-Safe Capability Attachment & Telemetry Truthfulness):** When attaching `ThinkingConfig` or private configuration overrides to Vertex AI models, code MUST NOT silently suppress attachment errors while reporting requested capabilities as active:
  - If `raise_on_error=True`: raise a descriptive `RuntimeError` immediately.
  - If `raise_on_error=False`: log a warning and record `applied_thinking_level = "sdk_default"` in evaluation results and Cloud Trace / OpenTelemetry span attributes (`gen_ai.request.thinking_level`), ensuring telemetry accurately reflects executed capabilities.
* **Rationale:** Discovered during PR #113 Greptile reviews. Toggling only `include_thoughts` omits the reasoning budget, while masking attachment failures produces false-positive evaluation claims and misleading telemetry in production benchmarks.

## 58. Core vs. Enterprise Tier Boundary Isolation in Swarm Attribution & Data Models
* **Rule (Strict Downward Tier Dependency & Zero-Enterprise Core Imports):**
  - Data models and services in Blackwall Core (`src/blackwall/models.py`, `src/blackwall/attribution/`, `src/blackwall/db/`) MUST NOT import from or depend upon Enterprise modules (`src/blackwall/enterprise/`).
  - Cross-tier exchange models and protocol contracts (such as `LinguisticSwarmMarkers`, `SwarmContextSummary`, and provider protocols) MUST reside in Core (`src/blackwall/models.py`) so Enterprise modules can import and implement them without circular or inverted dependencies.
  - Core attribution enrichment and resolution logic MUST query process-local storage (`SQLiteThreatRepository` in `src/blackwall/db/repository.py`), whereas distributed or cluster-mesh graph queries remain isolated within Enterprise (`AttackGraphStore` via `asyncpg`).
* **Rationale:** Violating downward tier dependency undermines Blackwall Core as an independent, single-host developer firewall and forces non-enterprise workstations to depend on enterprise database and networking infrastructure.

## 59. Multi-Agent Swarm Cardinality, Bounded Confidence, & Temporal Invariants
* **Rule (Minimal Coordination Cardinality $N \ge 2$):**
  - Pydantic models representing multi-agent coordination or covert communication channels (`CovertChannelEvidence`, `SwarmEvidence`, etc.) MUST enforce that coordinating agent collections contain at least two agents (`validate_min_items(coordinating_agents, min_items=2)`). Single-agent coordination is semantically invalid.
* **Rule (Strict Confidence Clamping $[0.0, 1.0]$):**
  - All collective confidence scores and linguistic marker scores MUST be declared as bounded floats within `[0.0, 1.0]` using Pydantic `Field(ge=0.0, le=1.0)`.
* **Rule (Temporal Detection Window Ordering & Zero-Offset UTC):**
  - Models defining detection windows with start and end timestamps (`first_detected`, `last_detected` or `first_seen`, `last_seen`) MUST enforce zero-offset UTC validation (`validate_utc_datetime`) and temporal sequence ordering (`validate_temporal_sequence`, requiring `end_time >= start_time`).
* **Rule (Non-Breaking Single-Agent Backward Compatibility):**
  - Extending base attribution models (`AttackerIdentity`, `AttackerProfile`, `IncidentReport`) with collective attributes MUST maintain backward compatibility for single-agent workflows by defaulting `is_collective=False`, `swarm_id=None`, `collective_confidence=0.0`, and empty list factories (`default_factory=list`).
* **Rationale:** Discovered during PR #114 review and Track 1 implementation. Unconstrained confidence scores permit invalid probabilities, naive timestamps break event graph correlation, and missing coordination cardinality checks allow single-agent operations to produce false swarm alerts.

## 60. Endpoint Host Isolation vs. Path Literal Parsing & RFC 4291 IPv6 Normalization
* **Rule (Host Component Isolation Before Path/Query/Fragment):**
  - Security detection components extracting network target endpoints, IOCs, and shared infrastructure (`_extract_all_ips`, `_extract_ip`, `C2InfrastructureDetector`, `CovertChannelDetector`, `AgentSwarmDetector`) MUST strictly isolate the network host component before any path (`/`), query (`?`), or fragment (`#`) delimiters.
  - Path literals (e.g. `https://artifactory.internal/api/198.51.100.5/storage` or non-scheme `resource:artifactory.internal/api/198.51.100.5/storage`) represent application data or REST resources, not network routing infrastructure. Parsers MUST NOT scan entire target strings with broad IP regex patterns that promote path literals to external C2 endpoints.
* **Rule (First-Class IPv6 Endpoint Extraction):**
  - Endpoint parsers MUST support RFC 4291 IPv6 addresses across all formats:
    1. Bracketed IPv6 with and without ports (e.g. `[2607:f8b0:4005:805::200e]:8080` -> `2607:f8b0:4005:805::200e`).
    2. Unbracketed IPv6 with and without ports (e.g. `connect 2607:f8b0:4005:805::200e:8080` or `tcp://2607:...:8080`).
    3. URLs with scheme (`http://`, `https://`, `tcp://`) and protocol-relative URLs (`//`).
  - Extracted IPv6 endpoints MUST populate `shared_patterns` with canonical `ip:<normalized_ipv6>` prefixes. Valid public IPv6 targets MUST be recognized as external infrastructure to avoid false-positive `UNLOCATED_MESSAGE_BOARD` covert channel alerts.
* **Rationale:** Discovered on PR #116. Broad regex scans mistakenly elevated internal REST URL path literals to external C2, while omitting unbracketed IPv6 targets from swarm extraction caused normal public IPv6 traffic to be falsely flagged as covert communication boards.

## 61. Core Tier Dependency Scoping & Enterprise Extra Isolation (`pyproject.toml`)
* **Rule:** Enterprise-specific dependencies—including ZeroMQ (`pyzmq`), NATS, or eBPF libraries—MUST NEVER be listed in base `[project.dependencies]` in `pyproject.toml`. Enterprise dependencies MUST be declared strictly within `[project.optional-dependencies].enterprise` (and mirrored in `dev` for testing). Blackwall Core (`src/blackwall/` outside `src/blackwall/enterprise/`) MUST remain a lightweight, single-host daemon with zero imports or installation dependencies on distributed clustering or kernel interception libraries.
* **Rationale:** Adding distributed networking or kernel libraries to base dependencies forces all single-host developer installations to compile and install heavy C/extension dependencies, breaking Core tier isolation and tripping Greptile architectural review invariants.

## 62. Threat Signature Non-Empty Pattern Validation & Wildcard Defense
* **Rule:** Threat signature normalizers, ingestion workers, and repository persistence interfaces MUST strictly reject messages or inputs where `payload_pattern` (or `pattern`) is missing, empty, or whitespace-only (`not pattern or not pattern.strip()`), returning `None` or raising `ValueError`. They MUST NOT substitute empty default patterns (`""`) into blocking threat signatures.
* **Rationale:** In signature repository lookups, substring matching evaluates an empty pattern as matching any string (`"" in args_str` is `True`). Ingesting an empty pattern with action `BLOCK` creates a critical false-positive security vulnerability that indiscriminately blocks all subsequent tool calls for the affected tool or sink.

## 63. ZeroMQ Socket Concurrency & Single Ownership Pattern
* **Rule:** A ZeroMQ socket (e.g., `zmq.SUB`, `zmq.PULL`) MUST be exclusively owned and polled by a single background worker task (e.g., `_ingestion_loop()`). Multiple coroutines or external query methods MUST NOT call `recv_multipart()` or `recv()` directly on the shared socket. Ingestion components exposing synchronous or ad-hoc retrieval methods (e.g., `receive_one()`) MUST buffer incoming messages into an internal bounded queue (`asyncio.Queue(maxsize=...)`) populated solely by the background worker, and consume from that queue.
* **Rationale:** Direct concurrent polling on a shared ZeroMQ socket creates race conditions where the background worker consumes messages meant for the ad-hoc caller, leading to false timeouts, dropped signatures, and non-deterministic behavior.

## 64. ZeroMQ Pub/Sub Slow-Joiner Mitigation, Bidirectional Readiness Lifecycle, & Quickstart Documentation Contract
* **Rule (Warmup Delay & Readiness Tracking):**
  - Both publisher (`MeshBroadcaster`) and subscriber (`MeshReceiver`) components managing ZeroMQ sockets MUST implement a configurable warmup grace period (`warmup_delay_s: float = 0.05` default) and explicit readiness state tracking (`is_ready: bool`).
  - Sockets MUST allow the warmup period to elapse after `bind()` or `connect()` before transmitting payloads. Any `broadcast()` or `broadcast_sync()` call invoked on an uninitialized or unready broadcaster MUST ensure the warmup grace period is satisfied prior to message transmission.
* **Rule (Bounded Lifecycle Helper & Immediate Ready Return):**
  - Distributed messaging components MUST expose an explicit async lifecycle helper `wait_until_ready(timeout: float = 0.08) -> None`.
  - If the socket is already ready (`self._is_ready is True`), `wait_until_ready()` MUST return immediately (0 ms) to avoid injecting unnecessary latency.
  - The wait duration MUST be strictly bounded by `timeout` using `min(warmup_delay, timeout)` if `timeout > 0`, preventing callers from exceeding lifecycle deadlines or waiting indefinitely.
* **Rule (Quickstart Documentation & Orchestration Contract):**
  - Public-facing documentation snippets (e.g. `README.md`) and orchestration scripts demonstrating pub/sub broadcast MUST NOT emit messages immediately after calling `receiver.start()` without demonstrating the required readiness sequence (`await receiver.wait_until_ready()`).
  - Snippets MUST illustrate end-to-end lifecycle closure by demonstrating both publication and ingestion retrieval (`received = await receiver.receive_one(timeout=1.0)`).
* **Rationale:** ZeroMQ PUB/SUB sockets exhibit the classic "slow joiner" race condition: messages sent immediately after socket creation or connection are dropped by the underlying transport before subscriber peers complete TCP connection handshakes and subscription frame exchanges. Enforcing bidirectional readiness tracking, bounded lifecycle helpers, and end-to-end documentation patterns guarantees that distributed cluster nodes receive broadcasted threat signatures without message drops or misleading quickstart experiences.

## 65. GitHub CLI (`gh`) & Git Operational Guardrails
* **Rule (Feature Branches Only):** All code modifications must occur within an isolated git worktree and be pushed to a dedicated feature branch. Direct commits or pushes to `main` and `master` are strictly prohibited.
* **Rule (No Autonomous Merging):** Automated agents may create Pull Requests via `gh pr create` and inspect reviews via `gh pr view`, but are strictly barred from merging Pull Requests via the terminal (`gh pr merge` is prohibited) or any API. A human developer must review and merge all code.
* **Rule (Pre-Commit Hygiene):** Before staging files via `git add`, verify that no `.env` files, API keys, credentials, or `.sqlite` WAL files are included in the commit payload.
* **Rule (No Destructive API / CLI Actions):** Repository deletion, branch protection tampering, and visibility modifications are blocked at the token level and strictly prohibited.
* **Rationale:** Prevents repository corruption, credential leakage, and bypassing of human-in-the-loop review guardrails.

## 66. CLI Output Hygiene & Token Conservation Protocol
* **Rule (Mandatory Projection Flags):** Terminal commands supporting structured outputs (`gh`, `gcloud`, `aws`, `docker`) MUST specify projection flags:
  - `gh`: Use `--json <field1,field2>` and `--limit <N>` (or `--template`).
  - `gcloud`: Use `--format="value(field)"` or `--format="table(field1,field2)"`.
  - `docker`: Use `--format "{{.ID}}: {{.Names}} ({{.Status}})"`.
* **Rule (Unix Pipeline Filtering):** Filter raw text streams before they reach model context. Pipe through `jq`, `head -n <N>`, `grep`, `awk`, or `cut` (e.g. `gh run view <id> --log-failed | head -n 50`).
* **Rule (Scratch Buffering for Large Outputs):** If a diagnostic command or test run generates more than 100 lines of logs, redirect or tee it to the conversation scratch directory and inspect targeted segments rather than dumping the full trace into context.
* **Rule (Atomic Pipelines):** Prefer chaining commands in a single shell invocation using `&&` or pipelines (`|`) rather than executing separate single-command tool calls across multiple turns.
* **Rationale:** Prevents context window saturation, lowers latency, and avoids quota drain during long agentic pair-programming workflows.

## 67. MCP Scope, Stateful Boundaries, & Downstream Perpetuation Invariant
* **Rule (Developer Tooling vs. Blackwall Product Runtime Scope):** This invariant strictly governs **agentic development tool selection** (how AI coding assistants, subagents, and review bots interact with development environments). It does **NOT** restrict Blackwall's own product runtime architecture. The Blackwall agent and daemon are explicitly designed as an **MCP Gateway security proxy** on `localhost:9229` (background daemon with macOS LaunchAgent integration), actively utilizing `codebase-memory-mcp` AST knowledge graphs and Google Threat Intelligence (GTI) MCP during interception resolution, alongside enterprise MCP adapters (Falco, Vault, Container Sandbox, OpenTelemetry).
* **Rule (MCP Scope & Stateful Boundaries for Development):** For AI coding assistants developing this codebase, MCP servers are strictly reserved for persistent stateful daemons and deep integrations:
  - `codebase-memory-mcp`: Persistent SQLite Abstract Syntax Tree (AST) graph for codebase navigation.
  - `context7`: External library documentation resolution.
  - `chrome-devtools` / `axe-core`: Stateful Chrome DevTools Protocol (CDP) browser sessions.
  - `greptile`: Automated PR code review gateway.
  All stateless development tasks (version control, PR management, issues, cloud management, containers, builds) MUST route through native CLI tools (`gh`, `git`, `gcloud`, `docker`) paired with companion skills. Adding stateless developer MCP servers (e.g. GitHub MCP, Git MCP, Jira/Slack MCP) to agent environments is strictly prohibited.
* **Rule (Downstream Perpetuation):** When designing developer tools or authoring agent instructions, all agents and subagents must perpetuate this CLI-first pattern and codify it in downstream project rules.
* **Rationale:** Eliminates developer MCP server sprawl, avoids token bloat from stateless tool schemas, and preserves MCP resources for complex stateful graph analysis, while keeping Blackwall's core security firewall gateway architecture intact.

## 68. Shell Background Daemon Orchestration & Process-Group PID Preservation
* **Rule (Direct Leader PID Capture):** Shell orchestration scripts managing background ambient services (e.g. `scripts/run_demo.sh` launching mock servers or agent daemons with `set -m`) MUST ensure that recorded process IDs (`$!`) capture the actual service process-group leader. Scripts MUST NOT pipe background commands directly into `tee` (e.g. `cmd 2>&1 | tee log.txt &`), which causes `$!` to evaluate to the PID of `tee` rather than the service process. Background services MUST use direct file redirection (`cmd > log.txt 2>&1 &` or process substitution) so that `$!` records the service process group ID.
* **Rule (Robust Process-Group Termination):** Cleanup traps MUST send `SIGTERM` followed by `SIGKILL` to the entire process group (negative PID, e.g. `kill -TERM "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null`) to guarantee that all child processes (e.g. Uvicorn worker threads, ADK daemon subprocesses) are cleanly terminated upon script exit or interruption.
* **Rationale:** Pipelining a background service into `tee` makes `$!` reference `tee`. When the script exits, cleanup targets a non-existent process group and terminates only `tee`, leaving background applications and listening socket daemons orphaned in the OS.

## 69. Live Demo Scoreboard Derivation & Adversarial Metric Accounting
* **Rule (Dynamic Metric Derivation):** Interactive demonstration TUIs, terminal showdown scoreboards, and live evaluators (`demo_live.py`) MUST NOT hardcode security metrics (such as 0% FRR or 0% evasion rate) or treat non-`BLOCK` results unconditionally as `ALLOW`. Scoreboards MUST derive metrics directly from resolver verdict objects (`verdict.decision`):
  - **Threats Blocked**: Count of `VerdictDecision.BLOCK` verdicts.
  - **Quarantined**: Count of `VerdictDecision.QUARANTINE` verdicts (isolated sandboxed execution).
  - **Evasions (Allowed)**: Count of malicious attack scenarios receiving `VerdictDecision.ALLOW`.
  - **Evasion Rate**: Strictly computed as `(allowed_count / total_scenarios) * 100.0`.
  - **False Refusal Rate (FRR)**: In purely adversarial attack test suites containing zero benign requests, FRR cannot be measured and MUST be explicitly reported as `N/A (Adversarial Suite)` rather than advertising false `0.00% FRR`.
* **Rule (Multi-Verdict Visual Representation):** UI panels, status indicators, and completion banners MUST visually distinguish `QUARANTINE` (warning yellow, mock sandboxing) from both `BLOCK` (red, signature persistence) and `ALLOW` (green, target execution). Completion banners MUST report actual neutralization counts (`blocked + quarantined`) and warn if evasions occurred, rather than unconditionally claiming 100% protection.
* **Rationale:** Discovered during PR #124 Greptile review. Hardcoding metrics or ignoring `QUARANTINE` states causes live demonstration scoreboards to report false security assurances when attacks bypass thresholds or are diverted to mock sandboxes.

## 70. Cypher & Graph Query AST Parameterization Hygiene & Input Sanitization
* **Rule (No F-String Query Interpolation):** Codebase memory MCP adapters, graph query clients, and internal database drivers MUST NEVER interpolate user- or caller-provided variable strings (e.g. `moduleName`, `symbolName`, `targetNode`) directly into Cypher or graph query strings using f-strings (e.g. `f"MATCH (m:Module {{name: '{moduleName}'}})..."`).
* **Rule (Bound Parameter Syntax):** All graph queries requiring dynamic filters must pass values via bound parameters (e.g. `query="MATCH (m:Module {name: $module_name}) RETURN m"`, with `"params": {"module_name": moduleName}`).
* **Rule (Input Sanitization Pre-Check):** Query methods accepting dynamic module or symbol names MUST strictly validate caller-provided arguments against injection and query control characters (e.g. `re.search(r"['\"`\x00-\x1f;{}\\]", val)`), rejecting or returning safe empty defaults if suspicious characters are present before invoking any MCP or network transport.
* **Rationale:** Discovered during PR #125 review. Greptile and automated security review bots enforce AST-level parameterization hygiene across all query dialects (including Cypher). Interpolating dynamic strings into graph query f-strings triggers immediate P1 security findings for query injection.

## 71. Security Boundary Documentation Integrity & Verified API Contracts
* **Rule (Production API Alignment):** High-level project documentation (e.g. `README.md`, `ARCHITECTURE.md`, `ENTERPRISE_ARCHITECTURE.md`) explaining OS-level interception, runtime audit hooks (`sys.addaudithook`), or kernel boundaries MUST strictly reflect verified production code APIs rather than speculative pseudo-code.
* **Rule (No Fictional Helper Functions):** Documented code snippets MUST import and reference actual codebase classes and entrypoints (e.g., `AuditHookManager(db_path=...).start()`) rather than fictional helper functions (e.g., `is_inside_approved_tool_execution()`).
* **Rule (Accurate Exception Semantics):** Documentation MUST accurately state error-handling semantics (e.g., `PermissionError` is raised before OS syscall dispatch; never claim standard Python runtime exceptions are "uncatchable").
* **Rationale:** Discovered during PR #125 review. Automated AI review bots (Greptile, CodeRabbit) cross-reference documentation code snippets against repository AST definitions. Introducing imaginary functions or claiming standard Python exceptions cannot be caught triggers P1 accuracy and security boundary review failures.

## 72. Pydantic v2 `model_dump()` Serialization & Database Key Casing Invariants
* **Rule (Explicit Key Casing & Aliasing):** When serializing Pydantic v2 data models (which use idiomatic Python `snake_case` attributes like `signature_id`, `created_at`, `target_tool`, `mitigation_action`) for ingestion into SQLite repositories, key-value stores, or legacy subsystems expecting `camelCase` (e.g. `signatureId`, `createdAt`, `targetTool`), code MUST NEVER perform bare `model.model_dump()` without key transformation or aliasing (`by_alias=True`).
* **Rule (Defensive Repository Ingestion):** Database batch insertion methods (e.g. `write_signatures_batch`) MUST defensively accept both `snake_case` and `camelCase` field names using fallback key extraction (`row.get("signatureId") or row.get("signature_id")`) and resilient timestamp parsing (`datetime.fromisoformat` and `str` fallback).
* **Rule (No Silent Data Loss / Phantom Success):** Serialization layers must never drop metadata or payload fields (e.g. dropping `targetTool`, `mitigationAction`, or similarity vectors) while still marking the task as `COMPLETED`.
* **Rationale:** Discovered during PR #126 Greptile review (Finding `PRRT_kwDOTIJot86h0QHO`). `ThreatSignature.model_dump()` produced snake_case keys that were silently omitted by the existing SQLite repository, persisting hollow records while falsely reporting `COMPLETED`.

## 73. Gemini Client HTTP Timeout Floor vs. Caller Synchronous Deadline Scoping
* **Rule (Client Timeout vs. Caller Contract Separation):** The mandatory 120.0s HTTP client request timeout floor for Gemini API models (configured to allow sufficient runway for deep reasoning, tool chaining, and batch analysis) applies strictly to the underlying Gemini network transport (`types.HttpOptions(timeout=...)` or `google.genai.Client` configurations).
* **Rule (No Caller Timeout Inflation):** Helper methods, background submitters, or task orchestrators that accept a caller-specified execution timeout (e.g. `triggerRefactoring(timeout=5.0)`) MUST NEVER overwrite or inflate the caller's timeout with the 120s HTTP floor. The caller's synchronous deadline contract must be honored independently of the underlying network timeout ceiling.
* **Rationale:** Discovered during PR #126 Greptile review (Finding `PRRT_kwDOTIJot86hzGD2`). Applying `max(configured, 120.0)` to the caller's parameter caused synchronous helper methods with a 5.0s contract to block for up to 120s, failing SLA assertions.

## 74. In-Process Agentic Execution Lifecycle & Candidate Result Consumption
* **Rule (Explicit Candidate Extraction & Dispatch):** When an agentic task submitter executes in synchronous or in-process mode (`in_process=True`, `background=False`), the submitter MUST actively extract candidate responses from the interaction object and dispatch them to the downstream analysis or signature generation pipeline.
* **Rule (No Abandoned In-Process Tasks):** The submitter MUST NOT mark an in-process task as `PENDING_IN_PROCESS` or `COMPLETED` without actually consuming the result and persisting downstream side effects. If an unhandled error occurs during candidate consumption, the task status must transition to `FAILED` with an explicit error record rather than silently reporting `COMPLETED`.
* **Rule (Method Name Contract Verification):** Inter-component calls between task dispatchers and analytics engines must strictly adhere to exported class interfaces (e.g. supporting both camelCase `generateSignature` and snake_case `generate_signature` aliases where dual-convention consumers exist).
* **Rationale:** Discovered during PR #126 Greptile review (Findings `PRRT_kwDOTIJot86hzGD4` and `PRRT_kwDOTIJot86hzLMq`). The new in-process path omitted candidate output processing, leaving tasks in a pending state without generating threat signatures, and subsequently encountered a naming mismatch (`generate_signature` vs `generateSignature`).

## 75. Threat Signature Graph URL-Encoded Evasion Normalization
* **Rule (Bounded Iterative URL-Decoding):** SQLite Threat Signature Graph queries (FTS5 and pattern matching) and in-memory signature lookup resolvers MUST perform **bounded iterative URL-decoding** on candidate queries and tool arguments prior to pattern matching. A single `urllib.parse.unquote(query)` call is insufficient — double- and triple-encoded evasion payloads (e.g. `%2520UNION%2520SELECT` → `%20UNION%20SELECT` → `UNION SELECT`) remain encoded after one pass. Implementations MUST loop until the decoded value stabilizes or a maximum of **3 iterations** is reached, whichever comes first:
  ```python
  def normalize_url_encoded(query: str, max_passes: int = 3) -> str:
      from urllib.parse import unquote
      for _ in range(max_passes):
          decoded = unquote(query)
          if decoded == query:
              break
          query = decoded
      return query
  ```
* **Rule (Evasion Resilience):** Security resolvers must ensure that URL-encoded attack variants at any nesting depth up to 3 levels (e.g. `%2527%2520OR%25201%253D1`) match persisted plaintext threat signatures (`' OR 1=1`) without requiring duplicate encoded signature entries in the database.
* **Rationale:** Discovered during PR #126 review and Greptile security audit (PRRT_kwDOTIJot86h0UA8). Single-pass decoding is insufficient when the evasion corpus includes double- and triple-encoded payloads; codifying a single `unquote()` as compliant leaves multi-pass encoded attacks able to bypass plaintext TSG signatures.

## 76. Native Structured Outputs & Prompt Scaffolding Prohibition
* **Rule (Structured Outputs Mandatory):** All Gemini Interactions API and generative model invocations for triage, verdict resolution, or entity synthesis (e.g. `BatchResolver`, `SyncResolver`, `BackgroundTaskSubmitter`) MUST enforce native structured output schemas using `response_schema=<PydanticModel>` and `response_mime_type="application/json"`.
* **Rule (No Manual Regex JSON Extraction):** Codebases and evaluation pipelines MUST NOT use manual regex JSON extractors, markdown code fence strippers (e.g. `r'```json\\s*(\\{.*?\\})\\s*```'`), or bracket-counting heuristic parsers to parse model responses. Responses must be accessed via native `response.parsed` or strict JSON parsing.
* **Rule (No Negative Prompt Scaffolding):** System and developer prompts for Gemini 3.5+ models MUST NOT contain defensive negative constraints or conversational scaffolding instructing the model not to emit markdown delimiters, conversational commentary, or duplicate scratchpads. Schema constraints belong strictly in `response_schema`.
* **Rationale:** Gemini 3.5 Flash-Lite natively adheres to Pydantic schemas. Legacy regex extractors and defensive prompt clutter from Gemini 3.1 Flash-Lite waste context tokens, inflate latency, and introduce brittle parsing edge cases.

## 77. Filesystem Watcher Concurrency, Trailing Retries, & Rollback Invariants
* **Rule (Serialized Reload Lock):** Filesystem watcher event handlers (such as `PolicyFileHandler` in `src/blackwall/policy/watcher.py`) that trigger asynchronous or background reloading MUST serialize execution using a dedicated `_reload_lock = threading.Lock()`. Never drop locks before invoking reload callbacks, as OS observer threads and timer threads can otherwise execute callbacks concurrently and cause out-of-order race conditions.
* **Rule (Non-Dropping Failure Retries):** Debounced file handlers MUST only advance `_last_reload_time` AFTER a reload callback succeeds. If an initial event reads an incomplete, truncated, or invalid file during an atomic write sequence, the handler MUST schedule a trailing retry and MUST NOT drop subsequent write-completion events within the debounce window.
* **Rule (Rollback Timestamp Preservation):** Handlers MUST NOT discard reload events based on lower file modification timestamps (`mtime < last_loaded_mtime`). Valid administrative rollbacks (e.g. restoring backups, `git checkout`, `rsync -a`) preserve older file timestamps; discarding them leaves systems stuck on stale policies.
* **Rule (Bounded Shutdown Teardown):** Watcher `stop()` and `cancel_pending()` methods MUST cancel pending timers, wait for active timer threads (`timer.join(timeout=2.0)`), and acquire `with self._reload_lock: pass` to ensure in-flight reloads finish before returning, preventing background thread leaks.
* **Rationale:** Discovered during Greptile review on PR #130. Atomic saves in text editors emit multi-event bursts (truncate, write, flush, rename) over 10–30ms. Naive debouncers drop completed writes after early failures, unjoined timers leak daemon threads, and timestamp gating prevents legitimate rollbacks.

## 78. Native SDK Async Client Dispatch & Mock Duck-Typing Invariants
* **Rule (Coroutine Function Pre-Check):** When branching to invoke native async surfaces on SDK clients (e.g. `client.aio.models.generate_content` or `client.aio.interactions.create` in Google GenAI SDK v2), code MUST NOT rely solely on `hasattr(client, "aio")`. In Python, standard `unittest.mock.MagicMock` objects evaluate `hasattr(...)` to `True` for any attribute and return a new `MagicMock` (which is not awaitable), causing `TypeError: object MagicMock can't be used in 'await' expression`.
* **Rule (Safe Coroutine Detection):** Code MUST verify `asyncio.iscoroutinefunction(method)` (or duck-typed `hasattr(method, "assert_awaited")` in tests) before awaiting the coroutine directly. If `iscoroutinefunction` is `False`, fall back to synchronous execution or `asyncio.to_thread`.
* **Rationale:** Discovered during google-genai 2.23.0 client.aio refactoring. Python's `asyncio.iscoroutinefunction` returns `True` for both native `async def` functions and `unittest.mock.AsyncMock`, but `False` for plain `MagicMock`, guaranteeing 100% test mock compatibility without thread-pool overhead in production.

## 79. Local Secret Storage at Rest: HKDF Derivation & Atomic 0o600 Permission Hardening
* **Rule (Standard Key Derivation):** Encrypted local credential stores (`EncryptedLocalStore` / `LocalVault`) MUST use standard key derivation functions (e.g. `cryptography.hazmat.primitives.kdf.hkdf.HKDF` with `hashes.SHA256()`) to derive symmetric cipher keys from master secrets, rather than raw unsalted hashes (`hashlib.sha256(key).digest()`).
* **Rule (Backward-Compatible Decryption Fallback):** When upgrading cryptographic key derivation algorithms, the store's `load()` method MUST implement dual-cipher fallback: attempt modern HKDF decryption first, and if `InvalidToken` is raised, fall back to the legacy cipher to preserve seamless backward compatibility for existing stores.
* **Rule (Atomic 0o600 File Creation):** Sensitive credential stores written to disk MUST NOT use default `open()` (which inherits the ambient process umask, often leaving files world-readable at `0o644`). Saves MUST write to a temporary file created via `os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` and atomically replace the destination using `os.replace`.
* **Rationale:** Raw unsalted SHA-256 key derivation is vulnerable to dictionary attacks, while standard file writers expose plaintext or ciphertext credentials to other users on shared host filesystems.

## 80. Post-Verdict Self-Learning Side Effects Outside Synchronous Critical Path
* **Rule (Non-Blocking Post-Verdict Dispatch):** Interception resolvers governed by strict latency budgets (<5ms SLA, such as `SyncResolver`) MUST NOT await long-running operations (e.g. `AgentBehavioralAnalytics.generateSignature()` embedding generation, LLM refactoring triage, or external threat queries) inside the synchronous `evaluate()` return path. Verdict decisions (ALLOW, BLOCK, QUARANTINE) must be returned to the client immediately.
* **Rule (Lifecycle Tracking & Background Task Registry):** Background side effects MUST NOT use bare, unmonitored `asyncio.create_task()` calls. Resolvers MUST maintain an active `self._background_tasks: set[asyncio.Task[Any]]` registry with a `_done(task)` callback that:
  1. Discards completed tasks from the registry.
  2. Inspects and logs unhandled exceptions (`if not t.cancelled() and t.exception(): logger.warning(...)`).
* **Rule (Shutdown & Flush Control):** Resolvers MUST provide `flush_background_tasks()` and `close()` methods that `asyncio.gather` all pending tasks, ensuring that in-flight signatures and refactoring hints are not cancelled or lost during process shutdown or test teardown.
* **Rationale:** Discovered during Greptile review on PR #132 (Tasks 25 & 26). Awaiting multi-second Gemini API calls in `evaluate()` violates the <5ms verdict delivery SLA, while untracked fire-and-forget tasks leak errors and cause silent signature loss during shutdown.

## 81. `aiosqlite` Connection Pool Lifecycle & Asynchronous Teardown
* **Rule (Asynchronous Connection Teardown):** Connection pools managing `aiosqlite` connections (`AsyncConnectionPool`) MUST always invoke the asynchronous `await conn.close()` method during pool shutdown and connection draining. Calling synchronous `conn._connection.close()` directly from the event loop thread bypasses `aiosqlite`'s internal worker thread queue, causing `_connection_worker_thread` to hang or raise unhandled thread exceptions (`RuntimeError: Event loop is closed`).
* **Rule (Multi-Loop Re-initialization):** In environments where asynchronous tasks execute across different event loops (such as sequential `pytest-bdd` steps using `run_async`), the pool MUST track the active loop (`asyncio.get_running_loop()`). If the running loop changes, the pool MUST drain and close old connections asynchronously and reinitialize the pool queue on the active loop.
* **Rationale:** Discovered during PR #132 test execution. Synchronous sqlite3 connection closures leave background worker threads attempting to post callbacks to closed event loops, producing unhandled `PytestUnhandledThreadExceptionWarning` failures.

## 82. Bounded Provider Lookup Deadlines in Interception Resolvers
* **Rule (Explicit `asyncio.wait_for` Deadline):** Interception resolvers (`SyncResolver`, callback handlers) awaiting asynchronous provider lookups (e.g. swarm lineage resolution, threat intelligence queries) MUST bound every await with an explicit `asyncio.wait_for(..., timeout=...)` deadline declared as a module-level constant scaled to a small multiple of the provider's SLA (e.g. 50ms against a 15ms lookup SLA). Awaiting a provider coroutine without a deadline is strictly prohibited, even on background tasks.
* **Rule (Deadline Degradation to Fail-Safe):** `asyncio.TimeoutError` (and any provider exception) MUST degrade to the fail-safe default (individual attribution, cached verdict, empty lineage) with a `%`-formatted warning log, and MUST NOT propagate to abort profile persistence, incident report generation, or notification sinks scheduled after the lookup.
* **Rule (Cancellation-Safe Resource Cleanup):** Provider implementations performing I/O (e.g. connection-pool checkouts) MUST tolerate `wait_for` cancellation via context-managed acquisition (`async with pool.connection()`) so timed-out lookups roll back and release resources instead of leaking pooled connections.
* **Rationale:** Discovered via Greptile P1 review on PR #140 (Track 4). An unbounded provider await stalled the background attribution task indefinitely: the attack record and incident report were never produced, and both `flush_background_tasks()` and resolver shutdown waited forever instead of degrading to individual attribution.

## 83. Git Stash Prohibition in Multi-Worktree Workflows
* **Rule (Shared-Stash Prohibition):** In repositories with multiple active git worktrees, agents MUST NOT use `git stash` / `git stash pop` for baseline comparisons: the stash is shared per repository, and popping on a clean tree applies a foreign pre-existing stash from another branch.
* **Rule (Stash-Free Baselines):** For pre/post-change comparisons, use `git show <ref>:<path>` materialized to temp files, or a pristine detached `git worktree add <path> <ref>` — never the shared stash.
* **Rationale:** Discovered during the v2.0 release audit: a stash/pop cycle on a clean tree applied another branch's WIP as unmerged (`UU`) paths into the release worktree. Recovery required `git reset --hard HEAD` and was only safe because all work was committed.

## 84. Container Build Invariants for Maturin/PyO3 Projects
* **Rule (Crate Manifest Availability):** Dockerfiles MUST `COPY crates/` before dependency-install layers: the maturin backend needs the Cargo manifest (`crates/<crate>/Cargo.toml`) at metadata-generation time, so a dependency layer built from `pyproject.toml` alone fails.
* **Rule (Explicit Toolchain & Linker):** Release images MUST install a C linker (`build-essential`) and an explicit pinned Rust toolchain (no reliance on maturin-implicit rustup downloads, which are network-fragile and unpinned).
* **Rule (Honest Entrypoint):** Images MUST NOT set a service-mimicking CMD when no long-lived entrypoint exists; use an import smoke-check until the service CLI lands.
* **Rationale:** Discovered during Task 27 release verification: the Dockerfile was unbuildable (missing manifest layer, missing linker) and its CMD pointed at a nonexistent `blackwall.main` module.

## 85. Circuit Breaker Exception Filtering & Client-Side Error Immunity
* **Rule (Client Input Error Exclusion):** Circuit breakers wrapping outbound network adapters or external service providers (e.g. `CircuitBreaker`, `CircuitBreakerProvider`) MUST distinguish client input errors (`ValueError`, `TypeError`) from upstream backend outages (connection drops, HTTP 5xx, timeouts).
* **Rule (Non-Swallowing Propagation):** Client input errors MUST NOT increment the circuit breaker's consecutive failure counter, and MUST be re-raised immediately to the caller rather than swallowed into degraded fallback responses.
* **Rule (Concurrency & Probe Guard):** Circuit breaker state transitions (`CLOSED`, `OPEN`, `HALF-OPEN`) and probe limits during `HALF-OPEN` MUST be protected by an `asyncio.Lock()` to prevent race conditions during concurrent coroutine execution.
* **Rationale:** Discovered during Phase 2 implementation on PR #150. If a circuit breaker catches generic `Exception` without filtering `ValueError`/`TypeError`, an invalid client argument (such as passing a domain indicator to an IP-only provider like AbuseIPDB) increments the failure counter. Five consecutive client errors trip the breaker to `OPEN` for 60 seconds, causing an accidental Denial of Service against legitimate traffic.

## 86. External API Payload Null-Coalescing & Safe Default Normalization
* **Rule (Explicit Null-Coalescing):** When parsing JSON payloads from external threat intelligence or third-party APIs (e.g. AbuseIPDB, abuse.ch, OTX), field access MUST NOT rely exclusively on `dict.get(key, default)`. In Python, `payload.get("data", [])` evaluates to `None` if the JSON key is explicitly null (`{"data": null}` or `{"abuseConfidenceScore": null}`).
* **Rule (Coalesced Type Casting & Safe Iteration):** Parsing code MUST use explicit null-coalescing (`payload.get("data") or []`, `payload.get("score") or 0`) before performing type casts (`int(...)`) or iterating (`for item in ...`).
* **Rule (Benign Verdict on Empty Payloads):** Normalizers MUST verify that payload item lists contain valid dictionary records before indexing into item fields. When an upstream API returns `query_status="ok"` with an empty or null data list (e.g. MalwareBazaar), normalizers MUST return a safe benign verdict (`is_malicious=False, risk_score=0.0`) or fall back cleanly to secondary services, rather than erroneously assuming presence or raising unhandled `TypeError` / `AttributeError`.
* **Rationale:** Discovered during Phase 2 implementation and Greptile P1 review on PR #150. External APIs frequently return explicit null fields or empty data arrays on 200 OK responses, crashing un-coalesced parsers or erroneously flagging empty MalwareBazaar responses as malicious.

## 87. Multi-Provider Cache Scoping Isolation & Entity Immutability
* **Rule (Decoupled Cache Scoping):** Multi-provider orchestrators persisting aggregated results into a shared database cache (e.g. `threat_intel_cache`) MUST NOT mutate the entity's attributing `provider_name` in the serialized payload JSON.
* **Rule (Explicit Provider Column Scoping):** Database repository methods (e.g. `SQLiteThreatRepository.cache_threat_intel`) MUST accept an explicit, decoupled `provider` column scoping parameter (`provider="aggregate"` vs. `provider="otx"`), keeping the storage index key separate from the entity's intrinsic attributes.
* **Rule (Cross-Scope Cache Isolation):** Single-provider lookups and multi-provider cascade lookups MUST use isolated cache scopes so that cross-provider aggregates never short-circuit single-provider queries, and single-provider records never satisfy multi-provider evaluations.
* **Rationale:** Discovered during Phase 2 implementation on PR #150. Mutating `response.provider_name = "aggregate"` before serializing to SQLite causes cache misses to return the true attributing provider (`provider_name="otx"`), while cache hits return `"aggregate"`, breaking entity immutability and contract consistency between fresh and cached resolutions.
