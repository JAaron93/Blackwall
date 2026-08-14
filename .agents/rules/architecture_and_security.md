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
## 11. Security Model Fingerprinting & UTC Temporal Invariants
* **Rule (Fingerprint Integrity & Tampering Prevention):** Identity fingerprinting methods (e.g. `compute_fingerprint()`) MUST recompute expected SHA-256 hashes unconditionally from canonical identity fields. If a caller supplies an explicit fingerprint parameter, it MUST be validated against the recomputed hash and raise a `ValueError` on mismatch. Numerical identity attributes (e.g. `process_uid`, `agent_id`) MUST use explicit `val is None` checks rather than `or` truthiness fallbacks to prevent collapsing valid falsy identifiers (e.g., `process_uid=0` for root).
* **Rule (Freshness & Temporal Sequence Invariants):** Model timestamp validators MUST NOT drop freshness window bounds (e.g. ±5.0 second delta limit on `SecurityEvent`) when applying UTC timezone validation (`validate_utc_datetime`). Models containing multi-timestamp lifecycles (e.g. `AttackerProfile` with `first_seen` and `last_seen`) MUST enforce `last_seen >= first_seen` via `@model_validator` and `validate_temporal_sequence()`.


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
* **Rationale:** Performing regex substitution exclusively on JSON-serialized strings fails to match quoted property names (e.g., `(?i)password[\s:=]+` misses `"password": "value"` due to double quotes around key names), allowing plaintext credentials to survive in sanitized payloads and leak into serialized incident reports or telemetry streams.


## 19. Strict UTC Zero-Offset Pydantic Validator Invariant
* **Rule:** Pydantic `@field_validator` classmethods enforcing UTC timezone compliance on timestamps MUST verify `v.tzinfo is None or v.utcoffset() != timedelta(0)` and raise `ValueError` on failure. Checking only `v.tzinfo is None` or `v.tzinfo.utcoffset(v) is None` is strictly prohibited.
* **Rationale:** Aware datetimes with non-UTC offsets (e.g. `EST`, `-05:00`, `+02:00`) have non-null `tzinfo` objects. Checking only for timezone awareness accepts non-UTC offsets, violating the required zero-offset UTC timestamp contract across security event graphs.

## 20. Mandatory Evidence-Derived Evaluation Containment Gate
* **Rule:** Security engines executing active mitigation actions (e.g. eBPF socket drops, ZeroMQ Threat Mesh broadcasts, Vault token revocations) MUST require an explicit `ActiveReactionPayload` instance containing `trigger_evidence_id` and mandatorily query `await self.is_evaluation_mode(payload.trigger_evidence_id)` against the evidence graph. Action methods MUST NOT rely on optional caller parameters (e.g. `evaluation_env_id: Optional[str] = None`) or check payload fields in isolation.
* **Rationale:** Callers converting evaluation evidence into payloads might omit optional fields or default them to `None`. Querying the underlying threat evidence graph directly ensures evaluation containment cannot be bypassed.

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
* **Rule:** Security detection modules parsing network targets or hostnames (e.g. `C2InfrastructureDetector`, network event correlators) MUST:
  1. Enclose unbracketed IPv6 target strings (e.g. `::1`, `::1:8080`) in brackets (`[::1]`, `[::1]:8080`) before passing to URL parsers (`urlparse`) to prevent colons from being split into empty host components.
  2. Treat the entire `127.0.0.0/8` IPv4 loopback block (e.g. `127.0.0.2`), IPv6 loopback (`::1`, `[::1]`), and IPv4-mapped IPv6 loopback addresses (`::ffff:127.0.0.0/8`, e.g. `[::ffff:127.0.0.1]:8080`) as local loopback endpoints (`_is_local_host` / `_is_local_endpoint`) alongside `localhost`.
* **Rationale:** Single IP exact-string comparisons (e.g., checking only `"127.0.0.1"` or `"::1"`) allow unbracketed IPv6 ports, alternative IPv4 loopback subnets (`127.0.0.2`), or IPv4-mapped IPv6 loopbacks (`::ffff:127.0.0.1`) to bypass local endpoint filtering, resulting in false cross-pillar persistence indicators and false `C2Evidence`.

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





