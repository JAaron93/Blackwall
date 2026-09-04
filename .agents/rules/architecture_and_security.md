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
* **Rule:** Provider configuration helpers (`configure_provider_env()`) MUST purge legacy API keys (`GEMINI_API_KEY`, `LLM_API_KEY`) and re-assert required mode variables (`GOOGLE_GENAI_USE_VERTEXAI="true"`, `GEMINI_TIER="paid"`) on *every* call, regardless of module-level caching flags. Vertex AI has NO free tier; it operates exclusively on paid billing quota (300+ RPM). Free-tier or 15 RPM fallback logic must never be introduced for Vertex AI. Third-party rate limiters (e.g. VirusTotal GTI 4 queries/60s) remain separate and preserved.
* **Rationale:** Prevents credential leakage and ensures GCP Vertex AI enterprise mode compliance across all sub-processes without artificial rate throttling.

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
  1. **When to Use:** Security testing agents, eval suites, and red-team benchmarks (e.g. CyberGym, synthetic prompt injections, Weave evals) MUST route telemetry through `EvaluationEnvironmentManager` / `EvaluationEnvironment` (`blackwall.enterprise.advanced_threat_detection.evaluation`) to isolate synthetic attacks from production databases and active incident response.
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
* **Rule (Deprecated Models Deny List):** All legacy model identifiers (`gemini-1.5-*`, `gemini-2.0-*`, `gemini-2.5-*`, and `gemini-3.1-pro-preview`) are strictly deprecated and prohibited in production and test configurations.
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

## 48. Active Enforcement Method Fail-Closed Contract

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

* **Rationale:** Fail-open enforcement methods produce false `COMPLETED` audit records for actions that never occurred (socket drops, Threat Mesh broadcasts, credential revocations). Discovered across PR #93 review cycles: (a) initializing `success = dep is not None` still reports COMPLETED when a non-None dep exposes an unsupported interface; (b) discarding `await res` ignores a broadcaster's explicit `False` failure signal; (c) guarding empty-revocation failure only on a non-empty `_issued_tokens` dict silently passes when the adapter has no local registry. Each flaw allows adversaries whose mitigations were not actually enforced to continue operating while the SOC log shows `COMPLETED`.

## 47. Multi-Day Retrospective Semantic Edge Decay & MITRE Technique Gating
* **Rule:** Retrospective attack path correlators (`RetrospectiveAnalyzer.reconstruct_causal_graph`) constructing semantic and temporal edges across multi-day analysis windows MUST:
  1. Scale non-causal same-target edge weights strictly by continuous exponential decay ($w = \text{base} \cdot e^{-\Delta t / \tau}$), requiring $w \ge 0.4$ for edge creation without applying artificial constant baselines that keep weights $\ge 0.4$ as $\Delta t \to \infty$.
  2. Gate base edge multipliers on MITRE ATT&CK technique matches (e.g. $\text{base} = 0.8$ for MITRE-matched actions, $\text{base} = 0.5$ for non-MITRE routine actions).
  3. Traverse all identified root nodes without artificial finite result collection caps that terminate DFS early and starve sibling branches.
* **Rationale:** Constant baseline additions connect unrelated routine actions occurring days apart, while un-gated decay severs multi-stage stealth campaigns. Gating decay on MITRE technique relevance preserves genuine multi-day attack paths while rejecting disconnected benign activity.

## 49. Structured Logging via `extra` Dictionary & Logger Keyword Hygiene
* **Rule:** When emitting structured metadata or event objects via standard Python `logging.Logger` instances, custom payload dictionaries MUST be passed through the `extra={...}` parameter (e.g. `logger.info("EVENT", extra={"event": payload.model_dump()})`) or formatted into the log message string. Passing arbitrary keyword arguments directly to standard logger methods (`logger.info("...", event=...)`) is strictly prohibited to prevent runtime `TypeError` exceptions.
* **Rationale:** Standard Python `logging.Logger._log()` does not accept arbitrary keyword arguments. Passing custom keywords directly raises `TypeError: Logger._log() got an unexpected keyword argument '...'` at runtime when log statements are triggered in production or test paths.



## 48. Inbound RPC Origin Validation — Always Enforced
* **Rule:** `InboundProtocolFilter.validate_headers_and_origin()` MUST be called unconditionally on every inbound RPC request, regardless of whether `headers` or `remote_addr` are provided by the caller. Callers that omit these optional parameters MUST receive safe defaults (`headers={}`, `remote_addr=""`) before the validation gate so that loopback enforcement and Origin/Host restrictions are never bypassed by simply omitting arguments.
* **Rationale:** When `validate_headers_and_origin` was gated on `headers is not None and remote_addr is not None`, an unauthenticated non-loopback caller could skip the entire authorization layer by omitting either parameter, proceed to the rate limiter and RPC parser, and receive a sanitized but authorized response.

## 49. Active Reaction Dispatch Fault Isolation
* **Rule:** Every `await active_reaction.*()` call within `correlate_agent_threats()` (eBPF socket drop, ZeroMQ mesh broadcast, Vault token revocation) MUST be wrapped individually in a `try/except Exception` block. Exceptions from the reaction adapter layer MUST be logged via `logger.error()` and MUST NOT propagate to abort the detection correlation loop or suppress alerts that were already generated.
* **Rationale:** A transient kernel driver failure, mesh broadcaster outage, or Vault connectivity error must not prevent the remaining detectors and correlation engines from completing and returning their alerts. Fault isolation ensures that partial adapter failures degrade gracefully without silently discarding security intelligence.

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
* **Rule (Agent Agnosticism):** Gateway components (`src/blackwall/gateway/`, `src/blackwall/cli.py`) MUST NOT include hardcoded rules, special casing, or coupling for any specific agent runtime (Hermes Agent, Antigravity, Warp Terminal, Claude Desktop, Cursor). All communication must adhere strictly to the generic Model Context Protocol (MCP) JSON-RPC specification.
* **Rule (Transport Security & Loopback Default):** The MCP Streamable HTTP transport MUST default to `127.0.0.1:9229` with `Origin` and `Host` header validation to prevent DNS rebinding attacks.
* **Rule (Remote Authentication Boundary & Startup Guard):** When `--host` binds to a non-loopback address, a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`) is mandatory. Inbound requests missing a valid `Authorization: Bearer <token>` header MUST be rejected with HTTP 401 before JSON-RPC processing. The gateway daemon MUST refuse to start if configured with a non-loopback host without an auth token.
* **Rule (JSON-RPC Request ID Concurrency Isolation):** The gateway stream layer MUST track all in-flight requests by JSON-RPC `id` to ensure responses, cancellations, and errors are mapped deterministically during concurrent evaluation.
* **Rule (Downstream Tool Proxying & Verdict Synthesis):** ALLOW'd tool calls MUST be forwarded intact to downstream tool servers (spawned via `--wrap` or configured in `gateway.yaml`). BLOCK verdicts MUST synthesize a JSON-RPC error `-32603` with a generic message, reusing the incoming `id` and never exposing internal threat telemetry to the agent.
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
* **Rule (Fallback ADC Resolution for Service Users):** Fallback ADC resolution (`application_default_credentials.json`) under `sudo` or `--system` MUST resolve against the derived service user's home directory. In direct-root mode with the dedicated `blackwall` user, the installer accepts `--credentials <path>` and copies credentials to `/etc/blackwall/credentials.json` owned by `blackwall:blackwall` (`0600`).
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



