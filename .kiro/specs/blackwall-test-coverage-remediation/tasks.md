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

## Phase 2: Evaluation Environment (P1/P2) — Target: ≥80% coverage

### Task 2.1: EvaluationEnvironmentManager Unit Tests
- [ ] Read `src/blackwall/enterprise/advanced_threat_detection/evaluation.py` fully
- [ ] Create `tests/unit/test_evaluation_environment.py`
- [ ] Test `get_or_create_environment()` creates new env on first call
- [ ] Test `get_or_create_environment()` returns same instance on second call (idempotent)
- [ ] Test `list_environments()` with 0, 1, 5 environments
- [ ] Test `delete_environment()` removes env from list
- [ ] Test `delete_environment()` with non-existent ID (expected behavior: no-op or KeyError)
- [ ] Test `reset_environment()` clears events but preserves registration
- [ ] Test `close_all()` makes all environments unusable
- [ ] Test `reset_all()` resets state without closing
- [ ] Test `get_environment()` with valid and invalid IDs
- [ ] Test thread-safety: concurrent `get_or_create_environment` calls
- [ ] Run: `pytest tests/unit/test_evaluation_environment.py -q` passes

### Task 2.2: EvaluationAttackGraphStore Unit Tests
- [ ] Create `tests/unit/test_evaluation_attack_graph_store.py`
- [ ] Test `initialize()` / `close()` lifecycle
- [ ] Test `insert_event()` with valid NormalizedEvent
- [ ] Test `insert_events_batch()` with 1, 5, and 0 events
- [ ] Test `get_node()` with existing node ID returns correct node
- [ ] Test `get_node()` with non-existing ID returns None or raises
- [ ] Test `get_all_nodes()` after various insertions
- [ ] Test `query_nodes()` with filter criteria
- [ ] Test `purge_events_before()` removes old events, keeps new
- [ ] Test `_check_not_closed()` raises RuntimeError after close()
- [ ] Test `_check_store_open()` raises RuntimeError before initialize()
- [ ] Test `derive_evaluation_event_id()` is deterministic (same input → same output)
- [ ] Test `is_evaluation_alert()` correctly identifies eval-labeled alerts
- [ ] Test `is_evaluation_event()` correctly identifies eval-labeled events
- [ ] Run: `pytest tests/unit/test_evaluation_attack_graph_store.py -q` passes

### Task 2.3: EvaluationEnvironment Operations Unit Tests
- [ ] Create `tests/unit/test_evaluation_environment_ops.py`
- [ ] Test `is_evaluation_mode()` always True
- [ ] Test `is_production_action_suppressed()` always True
- [ ] Test `should_suppress_production_reaction()` always True in eval
- [ ] Test `label_event()` attaches evaluation_env_id metadata
- [ ] Test `label_alert()` attaches evaluation_env_id metadata
- [ ] Test `label_raw_event()` with dict-based events
- [ ] Test `reset()` clears state
- [ ] Test `close()` makes subsequent operations raise RuntimeError
- [ ] Run: `pytest tests/unit/test_evaluation_environment_ops.py -q` passes

## Phase 3: Enterprise Pillars (P2) — Target: ≥70% coverage

### Task 3.1: Forensics OllamaEngine Unit Tests
- [ ] Read `src/blackwall/enterprise/forensics/ollama_engine.py`
- [ ] Create `tests/unit/test_ollama_engine.py`
- [ ] Test `__init__()` with valid config (host, port, model)
- [ ] Test `is_ollama_online()` with mock HTTP 200 (returns True)
- [ ] Test `is_ollama_online()` with mock connection error (returns False)
- [ ] Test `analyze_log_stream()` with sample logs → structured JSON output
- [ ] Test `analyze_log_stream()` when Ollama offline → fallback behavior
- [ ] Test `_parse_llm_json_response()` with valid JSON wrapped in text
- [ ] Test `_parse_llm_json_response()` with completely malformed response
- [ ] Test `_parse_llm_json_response()` with partial/truncated JSON
- [ ] Run: `pytest tests/unit/test_ollama_engine.py -q` passes

### Task 3.2: OpenTelemetry MCP Adapter Unit Tests
- [ ] Read `src/blackwall/enterprise/mcp/opentelemetry_mcp.py`
- [ ] Create `tests/unit/test_opentelemetry_mcp_adapter.py`
- [ ] Test `connect()` / `disconnect()` lifecycle transitions
- [ ] Test `is_connected()` state tracking
- [ ] Test `export_trace_span()` with valid span data structure
- [ ] Test `ingest_log_event()` with valid log event
- [ ] Test `get_active_spans()` returns previously exported spans
- [ ] Test `get_ingested_logs()` returns previously ingested logs
- [ ] Test `clear_buffers()` empties both span and log buffers
- [ ] Test operations on disconnected adapter raise appropriate errors
- [ ] Run: `pytest tests/unit/test_opentelemetry_mcp_adapter.py -q` passes

### Task 3.3: Pipeline Wrapper (inspect_code) Unit Tests
- [ ] Read `src/blackwall/enterprise/pipeline/wrapper.py`
- [ ] Create `tests/unit/test_pipeline_inspect_code.py`
- [ ] Test `inspect_code()` with safe Python code (returns no violations)
- [ ] Test `inspect_code()` with `pickle.loads()` pattern (detects deserialization risk)
- [ ] Test `inspect_code()` with `eval()` / `exec()` patterns
- [ ] Test `inspect_code()` with `os.system()` / `subprocess.Popen()` patterns
- [ ] Test `inspect_code()` with obfuscated dangerous patterns (base64 encoded, string concat)
- [ ] Test `inspect_code()` with empty string input
- [ ] Test `inspect_code()` with syntax errors in input (graceful handling)
- [ ] Test `@blackwall.guard_pipeline` decorator wraps function execution
- [ ] Run: `pytest tests/unit/test_pipeline_inspect_code.py -q` passes

### Task 3.4: Active Reaction Engine Unit Tests
- [ ] Read `src/blackwall/enterprise/advanced_threat_detection/reaction.py`
- [ ] Create `tests/unit/test_reaction_engine.py`
- [ ] Test `is_evaluation_mode()` detection logic
- [ ] Test `broadcast_fleet_signature()` with mock mesh broadcaster
- [ ] Test `execute_ebpf_socket_drop()` with mock kernel probe
- [ ] Test `revoke_identity_session()` with mock identity sidecar
- [ ] Test `get_reaction_history()` returns stored reactions
- [ ] Test `_publish_reaction_alert()` publishes to alert bus
- [ ] Test `_record_reaction()` persists reaction to store
- [ ] Test all methods return no-op when `is_evaluation_mode()` is True
- [ ] Run: `pytest tests/unit/test_reaction_engine.py -q` passes

## Phase 4: Data Models & Validators (P2/P3) — Target: ≥70% coverage

### Task 4.1: Core Models Comprehensive Tests
- [ ] Read `src/blackwall/models.py` (all 330 lines)
- [ ] Create `tests/unit/test_models_comprehensive.py`
- [ ] Test all enum memberships and `.value` access
- [ ] Test `Verdict` with boundary confidence_score (0.0, 0.5, 1.0)
- [ ] Test `Verdict` with out-of-bounds confidence_score (raises ValidationError)
- [ ] Test `ToolCallContext` with minimal and full fields
- [ ] Test `CallbackToken` auto-generates unique token_id and timestamp
- [ ] Test `BatchPayload` with empty and populated sanitized_contexts
- [ ] Test all remaining models (ThreatSignature, InterceptionEvent, etc.) for valid construction
- [ ] Test `model_dump()` → reconstruction round-trip for each model
- [ ] Test all `field_validator` functions with invalid inputs
- [ ] Run: `pytest tests/unit/test_models_comprehensive.py -q` passes

### Task 4.2: Enterprise ATD Models Validator Tests
- [ ] Read `src/blackwall/enterprise/advanced_threat_detection/models.py`
- [ ] Create `tests/unit/test_atd_model_validators.py`
- [ ] Test `validate_utc_timestamp` with UTC, non-UTC, and naive datetimes
- [ ] Test `validate_uuid_v4_fields` with valid UUID4, invalid UUID, and empty string
- [ ] Test `validate_non_empty_fields` with empty and whitespace-only strings
- [ ] Test `validate_min_nodes` with 0, 1, and threshold-meeting counts
- [ ] Test `validate_min_agents` with 0, 1, 2 agents
- [ ] Test `validate_temporal_ordering` with ordered and reversed timestamps
- [ ] Test `validate_evaluation_env_id` with valid and invalid patterns
- [ ] Test `validate_target_agent_id`, `validate_target_ip`, `validate_target_pid`
- [ ] Test cross-field validators that reference multiple fields
- [ ] Run: `pytest tests/unit/test_atd_model_validators.py -q` passes

## Phase 5: Property Tests (P2/P3) — Target: all invariants covered

### Task 5.1: GTI Budget Tracker Properties
- [ ] Create `tests/property/test_gti_budget_tracker_properties.py`
- [ ] Property: token count ∈ [0, max_tokens] after arbitrary acquire/replenish sequences
- [ ] Property: try_acquire returns False exactly when tokens == 0
- [ ] Property: replenish never exceeds max_tokens
- [ ] Property: N acquires from full tracker → exactly min(N, max_tokens) succeed
- [ ] Use `settings(max_examples=200)`
- [ ] Run: `pytest tests/property/test_gti_budget_tracker_properties.py -q` passes

### Task 5.2: Context Hygiene Properties
- [ ] Create `tests/property/test_context_hygiene_properties.py`
- [ ] Property: sanitization is idempotent: `sanitize(sanitize(x)) == sanitize(x)`
- [ ] Property: output never contains raw env var values from input
- [ ] Property: non-sensitive plain text passes through unchanged
- [ ] Property: all placeholder patterns match `[[VARIABLE_NAME]]` regex
- [ ] Use strategies generating strings with embedded `KEY=value` and `$SECRET` patterns
- [ ] Use `settings(max_examples=200)`
- [ ] Run: `pytest tests/property/test_context_hygiene_properties.py -q` passes

### Task 5.3: Core Model Validation Properties
- [ ] Create `tests/property/test_core_model_properties.py`
- [ ] Property: all models accept valid input (custom strategies per model)
- [ ] Property: invalid inputs consistently produce `ValidationError`
- [ ] Property: `model_dump()` → reconstruction preserves all field values
- [ ] Property: UUID fields are unique across 1000 generations
- [ ] Property: Verdict.confidence_score is always stored as float ∈ [0,1]
- [ ] Use `settings(max_examples=200)`
- [ ] Run: `pytest tests/property/test_core_model_properties.py -q` passes

## Phase 6: BDD Feature Expansion (P2) — Target: all security contracts covered

### Task 6.1: Codebase Memory Blast Radius BDD
- [ ] Create `tests/features/codebase_memory_blast_radius.feature` with 5 scenarios
- [ ] Create `tests/step_defs/test_codebase_memory_bdd.py`
- [ ] Scenario: "Critical sink identified increases threat score"
- [ ] Scenario: "No critical sinks produces baseline score"
- [ ] Scenario: "MCP connection failure degrades gracefully"
- [ ] Scenario: "Stale graph triggers re-query"
- [ ] Scenario: "Blast radius isolation report contains affected modules"
- [ ] Run: `pytest tests/step_defs/test_codebase_memory_bdd.py -q` passes

### Task 6.2: JIT Credential Privilege BDD
- [ ] Create `tests/features/jit_credential_privilege.feature` with 5 scenarios
- [ ] Create `tests/step_defs/test_jit_credential_bdd.py`
- [ ] Scenario: "JIT credential valid within TTL"
- [ ] Scenario: "JIT credential revoked after TTL"
- [ ] Scenario: "JIT credential revoked on context exit"
- [ ] Scenario: "Privilege drop removes elevated permissions"
- [ ] Scenario: "Nested credential contexts maintain isolation"
- [ ] Run: `pytest tests/step_defs/test_jit_credential_bdd.py -q` passes

### Task 6.3: GTI Rate Limiting BDD
- [ ] Create `tests/features/gti_rate_limiting.feature` with 5 scenarios
- [ ] Create `tests/step_defs/test_gti_rate_limiting_bdd.py`
- [ ] Scenario: "High-risk event consumes GTI token"
- [ ] Scenario: "Budget exhaustion triggers graceful degradation"
- [ ] Scenario: "Low-risk event skips GTI validation"
- [ ] Scenario: "Token replenishment restores capacity"
- [ ] Scenario: "Concurrent events respect 4-query/60s cap"
- [ ] Run: `pytest tests/step_defs/test_gti_rate_limiting_bdd.py -q` passes

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
