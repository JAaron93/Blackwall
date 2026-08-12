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


