# Requirements: Blackwall Test Coverage Remediation

## Requirement 1: Core MCP Client Coverage

### REQ-1.1: CodebaseMemory MCP Client Unit Tests
**Module:** `src/blackwall/mcp/codebase_memory.py`  
**Priority:** P1  
**Acceptance Criteria:**
- [ ] `CodebaseMemoryClient.query()` tested with valid query, empty result, and MCP connection failure
- [ ] `CodebaseMemoryClient.identifyCriticalSinks()` tested with various sink types returned
- [ ] `CodebaseMemoryClient.traceDataFlow()` tested with data flow path results and empty graph
- [ ] `CodebaseMemoryClient.getBlastRadius()` tested with isolation report generation
- [ ] `CodebaseMemoryClient.queryDependencyChain()` tested with chain results and circular dependencies
- [ ] `CodebaseMemoryClient._safe_execute()` tested with timeout, exception, and success paths
- [ ] `CodebaseMemoryClient._execute_mcp_tool()` tested with mock MCP responses
- [ ] `CodebaseMemoryClient.is_graph_stale()` tested with stale and fresh timestamps
- [ ] `CodebaseMemoryClient.set_mock_data()` tested for development mode override
- [ ] `CodebaseMemoryClient.get_threat_score_penalty()` tested with various blast radius results
- [ ] `CodebaseMemoryClient.get_mitigation_hint()` tested with known and unknown sink types
- [ ] All 5 data classes (`BlastRadiusReport`, `CriticalSink`, `DataFlowPath`, `DependencyChain`, `BlastRadiusIsolation`) tested for construction and serialization

### REQ-1.2: GTI Client Private Method Coverage
**Module:** `src/blackwall/mcp/gti_client.py`  
**Priority:** P1  
**Acceptance Criteria:**
- [ ] `GTIClient._calculate_entropy()` tested with low-entropy, high-entropy, and empty strings
- [ ] `GTIClient._parse_vt_response()` tested with valid VT JSON, malformed JSON, and missing fields
- [ ] `GTIClient._is_private_ip()` tested with RFC1918 ranges, public IPs, and edge cases (localhost, IPv6)
- [ ] `GTIClient._handle_failure()` tested for degraded mode transition and metric recording
- [ ] `GTIClient._ensure_task_started()` tested for idempotent replenish loop startup
- [ ] `GTIMCPClient.record_cache_hit()` tested for metrics increment
- [ ] `GTIClient.is_degraded()` tested after various failure counts
- [ ] `GTIQueryBudgetTracker._replenish_loop()` tested for token replenishment timing

## Requirement 2: Core Resolver & Pipeline Coverage

### REQ-2.1: SyncResolver Internal Methods
**Module:** `src/blackwall/sync_resolver.py`  
**Priority:** P1  
**Acceptance Criteria:**
- [ ] `SyncResolver._build_reasoning()` tested with various score combinations producing human-readable explanations
- [ ] `SyncResolver._emit_sinks()` tested with different sink types (FILE_SYSTEM, NETWORK, DATABASE, PROCESS)
- [ ] `SyncResolver._extract_indicator()` tested with IP, domain, URL, and file hash extraction patterns
- [ ] `SyncResolver._inline_generate_signature()` tested for signature format compliance
- [ ] `SyncResolver._process_attribution()` tested with attribution data propagation
- [ ] `SyncResolver._schedule_attribution()` tested for background task scheduling
- [ ] `SyncResolver._score_argument_novelty()` tested with seen/unseen argument patterns
- [ ] `SyncResolver._score_tool_name()` tested with dangerous vs. safe tool name categorization
- [ ] `SyncResolver._score_context()` tested with metadata presence/absence effects on score
- [ ] `SyncResolver.close()` tested for graceful shutdown and resource cleanup
- [ ] `SyncResolver.get_metrics()` tested for accurate metric reporting

### REQ-2.2: BatchResolver Private Methods
**Module:** `src/blackwall/resolver.py`  
**Priority:** P1  
**Acceptance Criteria:**
- [ ] `BatchResolver._parse_verdicts()` tested with valid Gemini responses, partial responses, and malformed JSON
- [ ] `BatchResolver._acquire_rate_limit_token()` tested with available and exhausted token scenarios
- [ ] `BatchResolver.submit_to_gemini_sync()` tested with mocked Gemini API responses (success, timeout, error)
- [ ] `BatchResolver.submit_to_gemini_background()` tested for task scheduling correctness
- [ ] `BatchResolver.track_background_submission()` tested for in-flight task tracking
- [ ] `BatchResolver.track_webhook_callback()` tested for callback registration
- [ ] `TokenBucketRateLimiter` tested independently for consume/refill semantics
- [ ] `ContextHygiene.sanitize_value()` tested with nested dicts, lists, and primitive types

### REQ-2.3: InterceptionQueue Private Methods
**Module:** `src/blackwall/interception.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `InterceptionQueue._flush_internal()` tested for correct batch extraction
- [ ] `InterceptionQueue._resolve_single_under_lock()` tested for callback invocation
- [ ] `BatchResolutionError` tested for proper exception formatting
- [ ] `QueueOverloadError` tested for emergency threshold behavior
- [ ] `QueueEmptyException` tested for message propagation

## Requirement 3: Data Model & Validator Coverage

### REQ-3.1: Core Models
**Module:** `src/blackwall/models.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] All Pydantic models tested for valid construction with minimal required fields
- [ ] All `field_validator` decorators tested with valid and invalid inputs
- [ ] `model_validator` (pre/post) tested for cross-field validation logic
- [ ] Serialization round-trip (`model_dump()` → construction) verified for all models
- [ ] `Verdict.confidence_score` boundary tested at 0.0, 1.0, and out-of-bounds values
- [ ] `CallbackToken.token_id` auto-generation and uniqueness verified
- [ ] `BatchPayload` tested with empty and populated `sanitized_contexts` lists
- [ ] All enum types (`EventType`, `VerdictDecision`, `SinkType`, `RelationshipType`, `GroundTruthLabel`) tested for membership and string coercion

### REQ-3.2: Enterprise Advanced Threat Detection Models
**Module:** `src/blackwall/enterprise/advanced_threat_detection/models.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `NormalizedEvent` tested with all validators: `validate_utc_timestamp`, `validate_uuid_v4_fields`, `validate_non_empty_fields`
- [ ] `AttackNode` tested with `validate_utc_timestamps`, `validate_non_empty_fields`
- [ ] `AttackPath` tested with `validate_min_nodes`, `validate_temporal_ordering`
- [ ] `Alert` tested with `validate_utc_timestamp`, `validate_non_empty_agent_id`
- [ ] `ActiveReactionPayload` tested with `validate_target_agent_id`, `validate_target_ip`, `validate_target_pid`
- [ ] `SwarmEvidence` tested with `validate_min_agents`
- [ ] `C2Evidence`, `ExploitChainEvidence`, `K8sThreatEvidence`, `RegistryThreatEvidence`, `AILMEvidence` tested for field validation
- [ ] `PermissionGrant` tested with `validate_evaluation_env_id`
- [ ] Invalid UUID, empty strings, and out-of-order timestamps all produce `ValidationError`

## Requirement 4: Evaluation Environment Coverage

### REQ-4.1: EvaluationEnvironmentManager Full Lifecycle
**Module:** `src/blackwall/enterprise/advanced_threat_detection/evaluation.py`  
**Priority:** P1  
**Acceptance Criteria:**
- [ ] `get_or_create_environment()` tested for creation and idempotent retrieval
- [ ] `list_environments()` tested with 0, 1, and N environments
- [ ] `delete_environment()` tested with existing and non-existing env IDs
- [ ] `reset_environment()` tested for event/node purge while preserving env registration
- [ ] `close_all()` tested for cleanup of all managed environments
- [ ] `reset_all()` tested for state reset without closing
- [ ] Thread-safety of `_initialize_locked`, `_close_locked` tested under concurrent access
- [ ] `get_environment()` tested for non-existent ID (expected: KeyError or None)

### REQ-4.2: EvaluationAttackGraphStore
**Module:** `src/blackwall/enterprise/advanced_threat_detection/evaluation.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `initialize()` / `close()` lifecycle tested
- [ ] `insert_event()` tested with valid NormalizedEvent
- [ ] `insert_events_batch()` tested with multiple events and empty batch
- [ ] `get_node()` tested with existing and non-existing node IDs
- [ ] `get_all_nodes()` tested after insertions
- [ ] `query_nodes()` tested with filter criteria
- [ ] `purge_events_before()` tested for time-based cleanup
- [ ] `_check_not_closed()` / `_check_store_open()` guards tested (RuntimeError on closed store)
- [ ] `derive_evaluation_event_id()` tested for deterministic ID generation
- [ ] `is_evaluation_alert()` / `is_evaluation_event()` tested for correct labeling detection

### REQ-4.3: EvaluationEnvironment Operations
**Module:** `src/blackwall/enterprise/advanced_threat_detection/evaluation.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `is_evaluation_mode()` always returns True
- [ ] `is_production_action_suppressed()` always returns True
- [ ] `should_suppress_production_reaction()` returns True in eval context
- [ ] `label_event()` attaches `evaluation_env_id` metadata
- [ ] `label_alert()` attaches `evaluation_env_id` metadata
- [ ] `label_raw_event()` works with dict-based events
- [ ] `reset()` clears internal state
- [ ] `close()` makes subsequent operations raise

## Requirement 5: Enterprise Pillar Coverage

### REQ-5.1: Forensics OllamaEngine
**Module:** `src/blackwall/enterprise/forensics/ollama_engine.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `OllamaForensicEngine.__init__()` tested with valid config
- [ ] `OllamaForensicEngine.is_ollama_online()` tested with mock HTTP success and failure
- [ ] `OllamaForensicEngine.analyze_log_stream()` tested with sample log input and expected JSON output
- [ ] `OllamaForensicEngine._parse_llm_json_response()` tested with valid JSON, malformed JSON, and partial responses
- [ ] Graceful fallback behavior tested when Ollama is offline

### REQ-5.2: OpenTelemetry MCP Adapter
**Module:** `src/blackwall/enterprise/mcp/opentelemetry_mcp.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `connect()` / `disconnect()` lifecycle tested
- [ ] `is_connected()` returns correct state before/after connect
- [ ] `export_trace_span()` tested with valid span data
- [ ] `ingest_log_event()` tested with valid log event
- [ ] `get_active_spans()` tested after span export
- [ ] `get_ingested_logs()` tested after log ingestion
- [ ] `clear_buffers()` tested for state reset
- [ ] Operations on disconnected adapter raise appropriate errors

### REQ-5.3: Container Sandbox MCP Adapter
**Module:** `src/blackwall/enterprise/mcp/sandbox_mcp.py`  
**Priority:** P3  
**Acceptance Criteria:**
- [ ] `connect()` / `disconnect()` lifecycle tested
- [ ] `is_connected()` returns correct state
- [ ] `run_in_sandbox()` tested with mock container execution (success and failure)
- [ ] `destroy_sandbox()` tested for cleanup
- [ ] Operations on disconnected adapter raise appropriate errors

### REQ-5.4: Pipeline Wrapper (inspect_code)
**Module:** `src/blackwall/enterprise/pipeline/wrapper.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `inspect_code()` (complexity 20) tested with safe Python code (no violations)
- [ ] `inspect_code()` tested with dangerous patterns (pickle.loads, eval, exec, os.system)
- [ ] `inspect_code()` tested with obfuscated dangerous patterns
- [ ] `@blackwall.guard_pipeline` decorator tested for interception behavior
- [ ] Edge cases: empty string input, binary content, syntax errors in input

### REQ-5.5: GCP Vertex AI Evaluation Components & Datasets
**Modules:** `src/blackwall/enterprise/advanced_threat_detection/gcp_vertex_eval.py`, `gcp_eval_datasets.py`, `gcp_trace_exporter.py`  
**Priority:** P3  
**Acceptance Criteria:**
- [ ] `GCPVertexEvalConfig` tested for default project, region, models, sampling limits, and empty field validation
- [ ] `GCPVertexEvalMetrics` tested for precision, recall, F1, FPR, trajectory precision/recall, and summary output calculations
- [ ] `GCPVertexAIEvaluationHarness` tested for initialization with custom config and explicit ADC/SDK error handling
- [ ] `create_pointwise_rubric` & `create_pairwise_autorater` tested for fallback dictionary structure when SDK is absent
- [ ] `evaluate_trajectory()` tested with exact matches, sub-sequences, empty reference, and empty candidate inputs
- [ ] `run_eval_task()` tested with `allow_fallback=True` vs `allow_fallback=False` (raises RuntimeError on unrecoverable init error)
- [ ] `load_gcp_eval_datasets()` tested for prompt injection, trajectory, and complex attack sample schema compliance (and DataFrame conversion)
- [ ] `GCPTraceSpan` tested for lifecycle (`finish()`), status tracking, and `duration_ms` calculation
- [ ] `GCPCloudTraceExporter` tested for `BLACKWALL_DISABLE_CLOUD_TRACE` precedence, `start_span()`, `record_evaluation_result()`, and `record_evaluation_error()`

### REQ-5.6: Active Reaction Engine
**Module:** `src/blackwall/enterprise/advanced_threat_detection/reaction.py`  
**Priority:** P2  
**Acceptance Criteria:**
- [ ] `is_evaluation_mode()` tested for production vs. evaluation context detection
- [ ] `broadcast_fleet_signature()` tested with mock mesh broadcaster
- [ ] `execute_ebpf_socket_drop()` tested with mock kernel probe driver
- [ ] `revoke_identity_session()` tested with mock identity sidecar
- [ ] `get_reaction_history()` tested for history retrieval
- [ ] `_publish_reaction_alert()` tested for alert bus publication
- [ ] `_record_reaction()` tested for persistence
- [ ] Evaluation mode suppression: all actions return no-op in eval context

## Requirement 6: Core Utility Coverage

### REQ-6.1: Analytics Module
**Module:** `src/blackwall/analytics/__init__.py`  
**Priority:** P3  
**Acceptance Criteria:**
- [ ] `triggerRefactoring()` (complexity 19) tested with various trigger conditions
- [ ] `generateSignature()` (complexity 16) tested for signature format and content
- [ ] Remaining 8 untested symbols tested for basic operation

### REQ-6.2: Configuration & Exceptions
**Modules:** `src/blackwall/config.py`, `src/blackwall/exceptions.py`, `src/blackwall/eval/metrics.py`  
**Priority:** P3  
**Acceptance Criteria:**
- [ ] `APIRateLimitException` tested for construction with message, retry_after, and string repr
- [ ] `calculateMetrics()` tested with evaluation result sets (precision, recall, F1 calculation)
- [ ] `config.py` remaining 4 untested symbols tested for loading and defaults

## Requirement 7: Property Test Expansion

### REQ-7.1: GTI Budget Tracker Properties
**Priority:** P2  
**Acceptance Criteria:**
- [ ] Token count ∈ [0, max_tokens] invariant holds after arbitrary acquire/replenish sequences
- [ ] Replenish rate produces correct token count over time intervals
- [ ] `try_acquire()` returns False when tokens exhausted (never goes negative)
- [ ] Concurrent acquire attempts maintain consistency

### REQ-7.2: Context Hygiene Properties
**Priority:** P2  
**Acceptance Criteria:**
- [ ] Sanitization is idempotent: `sanitize(sanitize(x)) == sanitize(x)`
- [ ] Sanitized output never contains original secret values
- [ ] Round-trip: sanitization preserves non-sensitive data unchanged
- [ ] All env var patterns in `[[VARIABLE_NAME]]` format after sanitization

### REQ-7.3: Core Model Validation Properties
**Priority:** P3  
**Acceptance Criteria:**
- [ ] All Pydantic models accept any valid input without raising (construction soundness)
- [ ] Invalid inputs consistently produce `ValidationError` (never silent corruption)
- [ ] Serialization round-trip preserves all field values
- [ ] UUID fields are unique across arbitrary generation sequences

## Requirement 8: BDD Feature Expansion

### REQ-8.1: Codebase Memory Blast Radius Feature
**Priority:** P2  
**Acceptance Criteria:**
- [ ] Scenario: "Critical sink identified in dependency chain increases threat score"
- [ ] Scenario: "No critical sinks found produces baseline score"
- [ ] Scenario: "MCP connection failure degrades gracefully without blocking verdict"
- [ ] Scenario: "Stale graph detected triggers re-query"
- [ ] Scenario: "Blast radius isolation report contains affected modules"

### REQ-8.2: JIT Credential Privilege Feature
**Priority:** P2  
**Acceptance Criteria:**
- [ ] Scenario: "JIT credential is valid within TTL window"
- [ ] Scenario: "JIT credential is revoked after TTL expires"
- [ ] Scenario: "JIT credential is revoked on context exit"
- [ ] Scenario: "Privilege drop removes elevated OS permissions"
- [ ] Scenario: "Nested credential contexts maintain isolation"

### REQ-8.3: GTI Rate Limiting Feature
**Priority:** P2  
**Acceptance Criteria:**
- [ ] Scenario: "High-risk event consumes GTI token and returns enriched verdict"
- [ ] Scenario: "Budget exhaustion triggers graceful degradation"
- [ ] Scenario: "Low-risk event skips GTI validation entirely"
- [ ] Scenario: "Token replenishment restores query capacity after cooldown"
- [ ] Scenario: "Concurrent high-risk events respect 4-query/60s cap"
