# Tasks: Blackwall Test Coverage Remediation

## Phase 1: Core MCP & Resolver (P1) — Target: ≥80% symbol coverage ✅ COMPLETE

> **Completed:** 2026-08-22 | PR #91 | 227 tests added | 873/873 unit tests passing
> Greptile review: 5/5 confidence, 0 unresolved comments, MERGEABLE

### Task 1.1: CodebaseMemory MCP Client Unit Tests
- [x] Read `src/blackwall/mcp/codebase_memory.py` to catalog all public/private methods
- [x] Create `tests/unit/test_codebase_memory_client.py`
- [x] Test `CodebaseMemoryClient.__init__()` with valid and missing config
- [x] Test `query()` with mock MCP tool responses (success, empty, error)
- [x] Test `identifyCriticalSinks()` with various CriticalSinkType returns
- [x] Test `traceDataFlow()` with DataFlowPath results and empty graph
- [x] Test `getBlastRadius()` with BlastRadiusReport generation
- [x] Test `queryDependencyChain()` with DependencyChain results and circular deps
- [x] Test `_safe_execute()` timeout path, exception path, success path
- [x] Test `_execute_mcp_tool()` with mock subprocess/network calls
- [x] Test `is_graph_stale()` with stale/fresh timestamp comparison
- [x] Test `set_mock_data()` for development mode override
- [x] Test `get_threat_score_penalty()` based on blast radius severity
- [x] Test `get_mitigation_hint()` for known and unknown sink types
- [x] Test data class construction: `BlastRadiusReport`, `CriticalSink`, `DataFlowPath`, `DependencyChain`, `BlastRadiusIsolation`
- [x] Run: `pytest tests/unit/test_codebase_memory_client.py -q` passes

### Task 1.2: GTI Client Private Method Tests
- [x] Read `src/blackwall/mcp/gti_client.py` focusing on untested private methods
- [x] Create `tests/unit/test_gti_client_internals.py`
- [x] Test `_calculate_entropy()` with "aaaa" (low), random UUID (high), empty string
- [x] Test `_parse_vt_response()` with valid VT API JSON structure
- [x] Test `_parse_vt_response()` with malformed JSON and missing `data.attributes`
- [x] Test `_is_private_ip()` with 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.0.0.1
- [x] Test `_is_private_ip()` with public IPs (8.8.8.8, 1.1.1.1)
- [x] Test `_handle_failure()` for degraded state transition and error metric
- [x] Test `_ensure_task_started()` for idempotent task creation
- [x] Test `GTIMCPClient.record_cache_hit()` metric increment
- [x] Test `is_degraded()` based on failure count threshold
- [x] Test `_replenish_loop()` for token replenishment timing (mock asyncio.sleep)
- [x] Run: `pytest tests/unit/test_gti_client_internals.py -q` passes

### Task 1.3: SyncResolver Internal Method Tests
- [x] Read `src/blackwall/sync_resolver.py` focusing on untested private methods
- [x] Create `tests/unit/test_sync_resolver_internals.py`
- [x] Test `_build_reasoning()` with high-score, medium-score, and low-score inputs
- [x] Test `_emit_sinks()` with each SinkType producing correct telemetry
- [x] Test `_extract_indicator()` with IP patterns (IPv4, IPv6)
- [x] Test `_extract_indicator()` with domain patterns (TLD, subdomain)
- [x] Test `_extract_indicator()` with URL patterns (http, https, custom schemes)
- [x] Test `_extract_indicator()` with file hash patterns (MD5, SHA256)
- [x] Test `_inline_generate_signature()` for signature structure compliance
- [x] Test `_process_attribution()` propagates data to attribution module
- [x] Test `_schedule_attribution()` creates background task
- [x] Test `_score_argument_novelty()` with seen vs. unseen arguments
- [x] Test `_score_tool_name()` with categorized dangerous/safe names
- [x] Test `_score_context()` with/without metadata effects
- [x] Test `close()` for clean shutdown (no pending tasks, resources released)
- [x] Test `get_metrics()` returns accurate counters
- [x] Run: `pytest tests/unit/test_sync_resolver_internals.py -q` passes

### Task 1.4: BatchResolver Private Method Tests
- [x] Read `src/blackwall/resolver.py` focusing on untested methods
- [x] Create `tests/unit/test_resolver_batch_internals.py`
- [x] Test `_parse_verdicts()` with valid Gemini JSON response (N verdicts matching N contexts)
- [x] Test `_parse_verdicts()` with partial response (fewer verdicts than contexts)
- [x] Test `_parse_verdicts()` with malformed JSON (graceful failure)
- [x] Test `_acquire_rate_limit_token()` when tokens available (returns immediately)
- [x] Test `_acquire_rate_limit_token()` when tokens exhausted (blocks/fails)
- [x] Test `submit_to_gemini_sync()` with mocked successful Gemini response
- [x] Test `submit_to_gemini_sync()` with mocked timeout
- [x] Test `submit_to_gemini_sync()` with mocked API error
- [x] Test `submit_to_gemini_background()` schedules task correctly
- [x] Test `track_background_submission()` tracks in-flight task
- [x] Test `track_webhook_callback()` registers callback for task_id
- [x] Test `TokenBucketRateLimiter.consume()` / refill behavior independently
- [x] Test `ContextHygiene.sanitize_value()` with nested dicts, lists, primitives
- [x] Run: `pytest tests/unit/test_resolver_batch_internals.py -q` passes

## Phase 2: Evaluation Environment (P1/P2) — Target: ≥80% coverage ✅ COMPLETE

> **Completed:** 2026-08-23 | Branch: test/phase2-evaluation-environment | 75 tests added | 947/948 unit tests passing (1 pre-existing GCP Vertex eval failure, unrelated to Phase 2)

### Task 2.1: EvaluationEnvironmentManager Unit Tests
- [x] Read `src/blackwall/enterprise/advanced_threat_detection/evaluation.py` fully
- [x] Create `tests/unit/test_evaluation_environment.py`
- [x] Test `get_or_create_environment()` creates new env on first call
- [x] Test `get_or_create_environment()` returns same instance on second call (idempotent)
- [x] Test `list_environments()` with 0, 1, 5 environments
- [x] Test `delete_environment()` removes env from list
- [x] Test `delete_environment()` with non-existent ID (expected behavior: no-op or KeyError)
- [x] Test `reset_environment()` clears events but preserves registration
- [x] Test `close_all()` makes all environments unusable
- [x] Test `reset_all()` resets state without closing
- [x] Test `get_environment()` with valid and invalid IDs
- [x] Test thread-safety: concurrent `get_or_create_environment` calls
- [x] Run: `pytest tests/unit/test_evaluation_environment.py -q` passes

### Task 2.2: EvaluationAttackGraphStore Unit Tests
- [x] Create `tests/unit/test_evaluation_attack_graph_store.py`
- [x] Test `initialize()` / `close()` lifecycle
- [x] Test `insert_event()` with valid NormalizedEvent
- [x] Test `insert_events_batch()` with 1, 5, and 0 events
- [x] Test `get_node()` with existing node ID returns correct node
- [x] Test `get_node()` with non-existing ID returns None or raises
- [x] Test `get_all_nodes()` after various insertions
- [x] Test `query_nodes()` with filter criteria
- [x] Test `purge_events_before()` removes old events, keeps new
- [x] Test `_check_not_closed()` raises RuntimeError after close()
- [x] Test `_check_store_open()` raises RuntimeError before initialize()
- [x] Test `derive_evaluation_event_id()` is deterministic (same input → same output)
- [x] Test `is_evaluation_alert()` correctly identifies eval-labeled alerts
- [x] Test `is_evaluation_event()` correctly identifies eval-labeled events
- [x] Run: `pytest tests/unit/test_evaluation_attack_graph_store.py -q` passes

### Task 2.3: EvaluationEnvironment Operations Unit Tests
- [x] Create `tests/unit/test_evaluation_environment_ops.py`
- [x] Test `is_evaluation_mode()` always True
- [x] Test `is_production_action_suppressed()` always True
- [x] Test `should_suppress_production_reaction()` always True in eval
- [x] Test `label_event()` attaches evaluation_env_id metadata
- [x] Test `label_alert()` attaches evaluation_env_id metadata
- [x] Test `label_raw_event()` with dict-based events
- [x] Test `reset()` clears state
- [x] Test `close()` makes subsequent operations raise RuntimeError
- [x] Run: `pytest tests/unit/test_evaluation_environment_ops.py -q` passes

## Phase 3: Enterprise Pillars (P2) — Target: ≥70% coverage ✅ COMPLETE

> **Completed:** 2026-08-23 | Branch: test/phase3-enterprise-pillars | PR #93 | 28 tests added across 4 new files (67 total new tests including review-cycle additions) | 1020/1020 unit tests passing
> Production fixes: `reaction.py` fail-closed enforcement contract (Rules 39/48), broadcaster return-value capture, empty-revocation oracle guard
> Greptile review iterations: 4 rounds → all comments resolved

### Task 3.1: Forensics OllamaEngine Unit Tests
- [x] Read `src/blackwall/enterprise/forensics/ollama_engine.py`
- [x] Create `tests/unit/test_ollama_engine.py`
- [x] Test `__init__()` with valid config (host, port, model)
- [x] Test `is_ollama_online()` with mock HTTP 200 (returns True)
- [x] Test `is_ollama_online()` with mock connection error (returns False)
- [x] Test `analyze_log_stream()` with sample logs → structured JSON output
- [x] Test `analyze_log_stream()` when Ollama offline → fallback behavior
- [x] Test `_parse_llm_json_response()` with valid JSON wrapped in text
- [x] Test `_parse_llm_json_response()` with completely malformed response
- [x] Test `_parse_llm_json_response()` with partial/truncated JSON
- [x] Run: `pytest tests/unit/test_ollama_engine.py -q` passes

### Task 3.2: OpenTelemetry MCP Adapter Unit Tests
- [x] Read `src/blackwall/enterprise/mcp/opentelemetry_mcp.py`
- [x] Create `tests/unit/test_opentelemetry_mcp_adapter.py`
- [x] Test `connect()` / `disconnect()` lifecycle transitions
- [x] Test `is_connected()` state tracking
- [x] Test `export_trace_span()` with valid span data structure
- [x] Test `ingest_log_event()` with valid log event
- [x] Test `get_active_spans()` returns previously exported spans
- [x] Test `get_ingested_logs()` returns previously ingested logs
- [x] Test `clear_buffers()` empties both span and log buffers
- [x] Test operations on disconnected adapter raise appropriate errors
- [x] Run: `pytest tests/unit/test_opentelemetry_mcp_adapter.py -q` passes

### Task 3.3: Pipeline Wrapper (inspect_code) Unit Tests
- [x] Read `src/blackwall/enterprise/pipeline/wrapper.py`
- [x] Create `tests/unit/test_pipeline_inspect_code.py`
- [x] Test `inspect_code()` with safe Python code (returns no violations)
- [x] Test `inspect_code()` with `pickle.loads()` pattern (detects deserialization risk)
- [x] Test `inspect_code()` with `eval()` / `exec()` patterns
- [x] Test `inspect_code()` with `os.system()` / `subprocess.Popen()` patterns
- [x] Test `inspect_code()` with obfuscated dangerous patterns (base64 encoded, string concat)
- [x] Test `inspect_code()` with empty string input
- [x] Test `inspect_code()` with syntax errors in input (graceful handling)
- [x] Test `@blackwall.guard_pipeline` decorator wraps function execution
- [x] Run: `pytest tests/unit/test_pipeline_inspect_code.py -q` passes

### Task 3.4: Active Reaction Engine Unit Tests
- [x] Read `src/blackwall/enterprise/advanced_threat_detection/reaction.py`
- [x] Create `tests/unit/test_reaction_engine.py`
- [x] Test `is_evaluation_mode()` detection logic
- [x] Test `broadcast_fleet_signature()` with mock mesh broadcaster
- [x] Test `execute_ebpf_socket_drop()` with mock kernel probe
- [x] Test `revoke_identity_session()` with mock identity sidecar
- [x] Test `get_reaction_history()` returns stored reactions
- [x] Test `_publish_reaction_alert()` publishes to alert bus
- [x] Test `_record_reaction()` persists reaction to store
- [x] Test all methods return no-op when `is_evaluation_mode()` is True
- [x] Run: `pytest tests/unit/test_reaction_engine.py -q` passes

## Phase 4: Data Models & Validators (P2/P3) — Target: ≥70% coverage ✅ COMPLETE

> **Completed:** 2026-08-23 | Branch: test/phase4-data-models-validators | 137 tests added across 2 new files | 1157/1157 unit tests passing

### Task 4.1: Core Models Comprehensive Tests
- [x] Read `src/blackwall/models.py` (all 330 lines)
- [x] Create `tests/unit/test_models_comprehensive.py`
- [x] Test all enum memberships and `.value` access
- [x] Test `Verdict` with boundary confidence_score (0.0, 0.5, 1.0)
- [x] Test `Verdict` with out-of-bounds confidence_score (raises ValidationError)
- [x] Test `ToolCallContext` with minimal and full fields
- [x] Test `CallbackToken` auto-generates unique token_id and timestamp
- [x] Test `BatchPayload` with empty and populated sanitized_contexts
- [x] Test all remaining models (ThreatSignature, InterceptionEvent, etc.) for valid construction
- [x] Test `model_dump()` → reconstruction round-trip for each model
- [x] Test all `field_validator` functions with invalid inputs
- [x] Run: `pytest tests/unit/test_models_comprehensive.py -q` passes

### Task 4.2: Enterprise ATD Models Validator Tests
- [x] Read `src/blackwall/enterprise/advanced_threat_detection/models.py`
- [x] Create `tests/unit/test_atd_model_validators.py`
- [x] Test `validate_utc_timestamp` with UTC, non-UTC, and naive datetimes
- [x] Test `validate_uuid_v4_fields` with valid UUID4, invalid UUID, and empty string
- [x] Test `validate_non_empty_fields` with empty and whitespace-only strings
- [x] Test `validate_min_nodes` with 0, 1, and threshold-meeting counts
- [x] Test `validate_min_agents` with 0, 1, 2 agents
- [x] Test `validate_temporal_ordering` with ordered and reversed timestamps
- [x] Test `validate_evaluation_env_id` with valid and invalid patterns
- [x] Test `validate_target_agent_id`, `validate_target_ip`, `validate_target_pid`
- [x] Test cross-field validators that reference multiple fields
- [x] Run: `pytest tests/unit/test_atd_model_validators.py -q` passes

## Phase 5: Property Tests (P2/P3) — Target: all invariants covered ✅ COMPLETE

> **Completed:** 2026-08-23 | Branch: test/phase5-property-tests | 33 property test suites added across 3 files | Hypothesis settings(max_examples=200) | 1406/1406 unit & property tests passing

### Task 5.1: GTI Budget Tracker Properties
- [x] Create `tests/property/test_gti_budget_tracker_properties.py`
- [x] Property: token count ∈ [0, max_tokens] after arbitrary acquire/replenish sequences
- [x] Property: try_acquire returns False exactly when tokens == 0
- [x] Property: replenish never exceeds max_tokens
- [x] Property: N acquires from full tracker → exactly min(N, max_tokens) succeed
- [x] Use `settings(max_examples=200)`
- [x] Run: `pytest tests/property/test_gti_budget_tracker_properties.py -q` passes

### Task 5.2: Context Hygiene Properties
- [x] Create `tests/property/test_context_hygiene_properties.py`
- [x] Property: sanitization is idempotent: `sanitize(sanitize(x)) == sanitize(x)`
- [x] Property: output never contains raw env var values from input
- [x] Property: non-sensitive plain text passes through unchanged
- [x] Property: all placeholder patterns match `[[VARIABLE_NAME]]` regex
- [x] Use strategies generating strings with embedded `KEY=value` and `$SECRET` patterns
- [x] Use `settings(max_examples=200)`
- [x] Run: `pytest tests/property/test_context_hygiene_properties.py -q` passes

### Task 5.3: Core Model Validation Properties
- [x] Create `tests/property/test_core_model_properties.py`
- [x] Property: all models accept valid input (custom strategies per model)
- [x] Property: invalid inputs consistently produce `ValidationError`
- [x] Property: `model_dump()` → reconstruction preserves all field values
- [x] Property: UUID fields are unique across 1000 generations
- [x] Property: Verdict.confidence_score is always stored as float ∈ [0,1]
- [x] Use `settings(max_examples=200)`
- [x] Run: `pytest tests/property/test_core_model_properties.py -q` passes

## Phase 6: BDD Feature Expansion (P2) — Target: all security contracts covered ✅ COMPLETE

> **Completed:** 2026-08-23 | Branch: test/phase6-bdd-features | 15 BDD scenarios added across 3 new feature/step files | 212/212 BDD tests passing (1638 total passing across unit, property, and BDD)

### Task 6.1: Codebase Memory Blast Radius BDD
- [x] Create `tests/features/codebase_memory_blast_radius.feature` with 5 scenarios
- [x] Create `tests/step_defs/test_codebase_memory_bdd.py`
- [x] Scenario: "Critical sink identified increases threat score"
- [x] Scenario: "No critical sinks produces baseline score"
- [x] Scenario: "MCP connection failure degrades gracefully"
- [x] Scenario: "Stale graph triggers re-query"
- [x] Scenario: "Blast radius isolation report contains affected modules"
- [x] Run: `pytest tests/step_defs/test_codebase_memory_bdd.py -q` passes

### Task 6.2: JIT Credential Privilege BDD
- [x] Create `tests/features/jit_credential_privilege.feature` with 5 scenarios
- [x] Create `tests/step_defs/test_jit_credential_bdd.py`
- [x] Scenario: "JIT credential valid within TTL"
- [x] Scenario: "JIT credential revoked after TTL"
- [x] Scenario: "JIT credential revoked on context exit"
- [x] Scenario: "Privilege drop removes elevated permissions"
- [x] Scenario: "Nested credential contexts maintain isolation"
- [x] Run: `pytest tests/step_defs/test_jit_credential_bdd.py -q` passes

### Task 6.3: GTI Rate Limiting BDD
- [x] Create `tests/features/gti_rate_limiting.feature` with 5 scenarios
- [x] Create `tests/step_defs/test_gti_rate_limiting_bdd.py`
- [x] Scenario: "High-risk event consumes GTI token"
- [x] Scenario: "Budget exhaustion triggers graceful degradation"
- [x] Scenario: "Low-risk event skips GTI validation"
- [x] Scenario: "Token replenishment restores capacity"
- [x] Scenario: "Concurrent events respect 4-query/60s cap"
- [x] Run: `pytest tests/step_defs/test_gti_rate_limiting_bdd.py -q` passes

## Phase 7: Utilities & Final Validation (P3) — Target: ≥60% coverage

### Task 7.1: Analytics Module Tests
- [ ] Read `src/blackwall/analytics/__init__.py`
- [ ] Create `tests/unit/test_analytics_coverage.py`
- [ ] Test `triggerRefactoring()` with various trigger conditions (complexity 19)
- [ ] Test `generateSignature()` for format and content (complexity 16)
- [ ] Test remaining untested symbols for basic operation
- [ ] Run: `pytest tests/unit/test_analytics_coverage.py -q` passes

### Task 7.2: Config, Exceptions, Metrics Tests
- [ ] Create `tests/unit/test_config_exceptions.py`
- [ ] Test `APIRateLimitException` construction with message, retry_after
- [ ] Test `APIRateLimitException` string representation
- [ ] Test `calculateMetrics()` with known evaluation results (precision, recall, F1)
- [ ] Test `config.py` remaining 4 untested symbols for loading and defaults
- [ ] Run: `pytest tests/unit/test_config_exceptions.py -q` passes

### Task 7.3: Weave Config & Datasets Tests
- [ ] Create `tests/unit/test_weave_config_coverage.py`
- [ ] Test `should_enable_weave()` with WEAVE_DISABLED=true → False
- [ ] Test `should_enable_weave()` with WEAVE_OFFLINE=true → True (when importable)
- [ ] Test `should_enable_weave()` with WANDB_API_KEY set → True (when importable)
- [ ] Test `has_wandb_credentials()` with mock netrc present/absent
- [ ] Test `init_weave()` idempotent behavior
- [ ] Test `load_weave_config()` with valid and missing files
- [ ] Test `_sanitize_scenario_event()` removes sensitive fields
- [ ] Test `_load_scenario_file()` with valid JSON, malformed, and missing
- [ ] Test `create_evaluation_dataset()` constructs dataset from files
- [ ] Run: `pytest tests/unit/test_weave_config_coverage.py -q` passes

### Task 7.4: Final Coverage Validation
- [ ] Run full suite: `pytest tests/unit/ tests/property/ tests/step_defs/ --tb=short -q`
- [ ] Verify 0 new failures introduced
- [ ] Re-index with `codebase-memory-mcp` (fast mode)
- [ ] Run coverage query: count tested vs. total symbols
- [ ] Verify overall structural coverage ≥ 75%
- [ ] Document final coverage numbers in this task file

## Summary

| Phase | Tasks | Est. New Tests | Target |
|-------|:-----:|:--------------:|--------|
| Phase 1: Core MCP & Resolver | 4 | ~120 | ≥80% P1 modules |
| Phase 2: Evaluation Environment | 3 | ~80 | ≥80% evaluation.py |
| Phase 3: Enterprise Pillars | 4 | ~60 | ≥70% pillar modules |
| Phase 4: Data Models & Validators | 2 | ~80 | ≥70% model coverage |
| Phase 5: Property Tests | 3 | ~40 | All invariants |
| Phase 6: BDD Features | 3 | ~15 scenarios | Security contracts |
| Phase 7: Utilities & Final | 4 | ~40 | ≥60% + validation |
| **Total** | **23** | **~435** | **≥75% global** |
