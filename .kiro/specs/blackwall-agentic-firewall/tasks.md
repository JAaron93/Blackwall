# Implementation Plan: Blackwall Agentic Firewall

## Overview

This implementation plan breaks down the Blackwall Agentic Firewall **local MVP** into discrete, testable tasks following a test-driven development approach. The system will be implemented in **Python** using ADK 2.0, with asynchronous processing via asyncio, embedded **SQLite for threat signature storage** (with WAL mode and connection pooling), and integration with GTI and codebase-memory MCPs. The architecture addresses the critical API rate constraint (300 RPM Gemini vs 600 RPM attacker) through asynchronous batched evaluation with callback queue management, maintaining sub-10% false positive/negative rates while demonstrating Zero Ambient Authority, Agent Behavioral Analytics, and runtime AgBOM tracing.

**KEY SCOPE CONSTRAINTS FOR LOCAL MVP:**
- **Single-instance local daemon** running in one Kali Linux VM (no Kubernetes, no load balancing, no failover clustering)
- **Embedded SQLite database only** (no Redis, no Memcached, no external distributed stores)
- **Unprivileged user execution** with Python runtime audit hooks forcing all tool calls through ADK layer
- **Local file-based configuration** and policy files (YAML, no external config servers)
- **No horizontal scaling or multi-tenant patterns**
- **Dual-agent demo scope**: Blackwall (Gemini 3.1 Flash-Lite, 300 RPM) vs. Rogue Agent (Qwen3, 600 RPM max) in single-VM sandbox
- **Limited test payloads** for demonstration (not 24/7 production operation)

**Key Architectural Constraints:**
- All rate limit fallbacks use fail-closed QUARANTINE verdicts (never ALLOW)
- SecurityEvent.verdict is nullable (None only for SIGNATURE_CREATED events)
- Thread-safe timeout handling via asyncio.wait_for() raising TimeoutError (not CancelledError)
- Atomic signature_id uniqueness enforced by SQLite PRIMARY KEY + INSERT OR IGNORE
- Standardized metric naming: False Refusal Rate (FRR), Evasion Rate (False Negative Rate)
- QUARANTINE on benign inputs counts as false positive (impacts FRR)
- Empty test suite returns zero metrics without division errors
- 12 correctness properties from design with explicit requirements traceability
- 28 requirements all with EARS-compliant acceptance criteria

Tasks are ordered by dependency (foundational → integration → evaluation → demo) and include both implementation and testing sub-tasks.

## Tasks

## Phase 1: Foundation Layer

These tasks form the architectural foundation of Blackwall and must be completed first.

### TASK-DB-01: Implement SQLite WAL Mode and Concrete Repository

**Priority:** HIGH
**Dependencies:** None
**Estimated Effort:** 3-4 days
**Status**: ✅ Completed

**Description:**
Create `SQLiteThreatRepository` using `aiosqlite`. Configure initialization scripts to execute `PRAGMA journal_mode=WAL;` and establish a thread-safe connection pool. Remove all redundant interface wrapper classes.

**Acceptance Criteria:**
1. SQLiteThreatRepository is a concrete class (no ICacheProvider, AbstractStorageEngine interfaces)
2. `aiosqlite` connection pool initialized with max 10 connections
3. WAL mode enabled: `PRAGMA journal_mode=WAL` executed on each connection
4. PRAGMA synchronous=NORMAL and wal_autocheckpoint=1000 configured
5. Atomic uniqueness: INSERT OR IGNORE enforces signature_id PRIMARY KEY uniqueness
6. Direct instantiation: `repo = SQLiteThreatRepository("./blackwall.db")` used throughout codebase
7. Unit tests verify WAL mode activation (PRAGMA journal_mode returns 'wal')
8. Unit tests verify connection pool maintains exactly 10 connections
9. Integration tests verify concurrent writes don't produce database lock errors
10. All database operations use connection pool, not direct connections

**Deliverables:**
- SQLiteThreatRepository.py (concrete class, 400-500 LOC)
- Initialization script with PRAGMA configuration
- Unit tests (SQLiteThreatRepository_test.py)
- Connection pool management and cleanup logic
- No abstract base classes or interfaces

---

## Phase 2: Core Infrastructure & Data Models

### Phase 2: Core Infrastructure & Data Models

- [x] 1. Set up project structure and core infrastructure
  - Create Python project with pyproject.toml and Poetry/pip requirements
  - Define project directory structure (src/blackwall/, tests/, config/, docs/, scripts/)
  - Set up pytest testing framework with asyncio support and hypothesis plugin
  - Configure pre-commit hooks for linting (ruff/black), type checking (mypy)
  - Create base YAML policy configuration file template
  - Set up structlog logging framework with JSON output format
  - Initialize git repository with .gitignore for Python
  - Create Dockerfile for containerized deployment with non-root user
  - _Requirements: 14.1, 14.2, 27.1, 27.2, 27.3, 28.1_

- [x] 2. Implement core data models and type definitions
  - [x] 2.1 Create Pydantic data model classes with validation
    - Define CallbackToken, ToolCallContext, Verdict data classes
    - Define ThreatSignature, SecurityEvent, PolicyServerState data classes
    - Define GTIResponse, CBMResponse, BehaviorScore, RefactoringHint data classes
    - Define SecurityMetrics, GraphStatistics, ResolverMetrics data classes
    - Implement Pydantic validators for UUID formats, timestamp ranges, threat scores [0.0, 1.0]
    - Implement semantic versioning format validation for policy version
    - Define Enum types: EventType, VerdictDecision, SinkType, RelationshipType
    - **NULLABLE VERDICT:** Define SecurityEvent.verdict as Optional[Verdict] (None only for SIGNATURE_CREATED events; required for INTERCEPTION, BLOCK, ALLOW, QUARANTINE)
    - **NULLABLE BEHAVIOR SCORE:** Define SecurityEvent.behaviorScore as Optional[BehaviorScore]
    - **METADATA FIELD:** Define ToolCallContext.metadata as Optional[Dict[str, Any]] for audit data
    - _Requirements: 1.2, 3.10, 3.11, 5.1, 5.6, 6.4, 9.1, 14.12_

  - [x] 2.2 Write unit tests for data model validation
    - Test valid model instantiation with correct fields
    - Test invalid inputs trigger Pydantic ValidationError
    - Test threat score bounds [0.0, 1.0] enforcement
    - Test semantic versioning format validation (MAJOR.MINOR.PATCH)
    - Test Enum value restrictions
    - Test timestamp validation (within 5 seconds of current time for SecurityEvent)
    - **NULLABLE VERDICT:** Test SecurityEvent with verdict=None is valid for eventType=SIGNATURE_CREATED
    - **NULLABLE VERDICT:** Test SecurityEvent with verdict=None raises error for eventType in {INTERCEPTION, BLOCK, ALLOW, QUARANTINE}
    - _Requirements: 1.2, 3.10, 3.11, 14.12, 25.2_

- [x] 3. Implement Context Hygiene middleware with regex sanitization
  - [x] 3.1 Create ContextHygiene class with regex-based redaction
    - Implement sanitize() method with regex pattern matching on JSON-serialized arguments
    - Define default redaction patterns: API keys, IPs, file paths, passwords, emails, URLs
    - Implement registerPattern() for custom pattern registration at runtime
    - Implement applyRedaction() with 100ms timeout protection per pattern
    - Create RedactionEntry logging with SHA256 one-way hashes (no reverse mapping)
    - Handle catastrophic backtracking with regex timeout protection
    - Preserve JSON structure after sanitization (validate parseable)
    - Implement idempotence: sanitize(sanitize(x)) = sanitize(x)
    - **METADATA FIELD:** Store redaction audit data in ToolCallContext.metadata (not a separate wrapper type)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.11, 4.12, 12.7, 12.8_

  - [x] 3.2 Test sanitization idempotence property
    - **Property 4: Sanitization Idempotence**
    - **Validates: Requirements 4.10**
    - Generate random ToolCallContext with sensitive data using hypothesis
    - Apply sanitization twice: result1 = sanitize(context), result2 = sanitize(result1)
    - Assert result1 == result2 (idempotent property)
    - Verify no raw secrets remain in sanitized output

  - [x] 3.3 Test sanitization structure preservation property
    - **Property 5: Sanitization Structure Preservation**
    - **Validates: Requirements 4.11**
    - Generate ToolCallContext instances with valid JSON arguments using hypothesis
    - Apply Context_Hygiene sanitization
    - Assert sanitizedArguments is parseable JSON (json.loads does not throw)
    - Assert top-level key set in sanitizedArguments matches key set in rawArguments

  - [x] 3.4 Write unit tests for Context Hygiene
    - Test API key redaction matches pattern and replaces with [[API_KEY]]
    - Test IP address placeholder replacement [[IP_ADDRESS]]
    - Test file path sanitization [[FILE_PATH]]
    - Test password, email, URL redaction
    - Test JSON structure preservation after redaction
    - Test redaction log contains only SHA256 hashes (no raw values)
    - Test regex timeout handling (100ms limit)
    - Test pattern auto-disable after 10 consecutive timeouts
    - Test redaction metadata stored in ToolCallContext.metadata field
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.10, 4.11, 12.7, 12.8, 25.9_

### TASK-SEC-01: Implement OS-Level Runtime Audit Hooks

**Priority:** HIGH
**Dependencies:** TASK-DB-01
**Estimated Effort:** 2-3 days
**Status**: ✅ Completed

**Description:**
Write custom Python interception daemon utilizing `sys.addaudithook`. Map subprocess, socket, and file-access events to the local synchronous evaluation engine. Ensure unauthorized execution attempts raise immediate runtime exceptions before kernel processing.

**Acceptance Criteria:**
1. AuditHookManager class registers custom audit hook via `sys.addaudithook()`
2. Intercepts `subprocess.Popen` events: validates executable against SQLiteThreatRepository blocklist
3. Intercepts `os.exec` events: blocks unauthorized privilege escalation attempts
4. Intercepts `socket.connect` events: verifies IP/port against IOC blacklist (local SQLite only)
5. Intercepts `open()` events: blocks write access to critical files (/etc/*, /root/*, .bashrc, .ssh/*)
6. All violations raise PermissionError immediately (before kernel execution)
7. All violations write telemetry to SQLite WAL (incident_type, timestamp, details, stack_trace)
8. Audit hook callback executes in <1ms (local lookups only, no API calls)
9. Unit tests verify each event type triggers correct validation
10. Unit tests verify violations logged at WARN level with full details
11. Integration tests verify rogue agent cannot bypass audit hook
12. Telemetry correctly written to SQLiteThreatRepository audit incidents table

**Deliverables:**
- AuditHookManager.py (audit hook registration & callback logic, 300-400 LOC)
- Incident telemetry schema and storage
- Unit tests (AuditHookManager_test.py)
- Blockist and critical file definitions
- <1ms execution time verified

---

### Phase 3: Interception & Batch Processing

- [x] 4. Implement Interception Queue with callback management and batching
  - [x] 4.1 Create InterceptionQueue class with asyncio.Queue and batch accumulation
    - Implement enqueue() storing CallbackToken with thread ID, timestamp, tool context, resume function
    - Implement dequeue() with configurable timeout parameter (milliseconds)
    - Implement getBatch() accumulating up to maxSize=5 or maxWaitMs=100 timeout
    - Use asyncio.create_task for timeout-based batch flushing (partial batches)
    - Implement flush() for emergency batch handling when queue size > 50
    - Implement resolveCallbacks() mapping verdict array to callback tokens by index
    - Validate verdict array size matches callback token batch size before resolution
    - Invoke resume function exactly once per token with proper error handling
    - Implement thread-safe operations using asyncio locks
    - Maintain correlation ID linking each callback token to batch position for debugging
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 19.1, 19.2, 19.3, 19.6, 19.7, 19.8, 19.9_

  - [x] 4.2 Test callback resolution completeness property
    - **Property 1: Callback Resolution Completeness**
    - **Validates: Requirements 1.6, 19.7**
    - Generate random sequences of 1-100 callback tokens using hypothesis
    - Enqueue all tokens to InterceptionQueue
    - Process batches and generate verdicts
    - Assert each callback is resumed exactly once (no duplicates, no missed tokens)
    - Verify no callbacks remain in queue after resolution

  - [x] 4.3 Write unit tests for Interception Queue
    - Test enqueue and dequeue operations with asyncio
    - Test batch accumulation reaches maxSize=5 and flushes
    - Test timeout flushing with maxWaitMs=100 for partial batches
    - Test verdict array mapping correctness (index i → callback i)
    - Test emergency flushing when queue size > 50
    - Test array size mismatch triggers critical error and batch rejection
    - **FAIL-CLOSED:** Test emergency fallback returns BLOCK verdicts on batch rejection (not ALLOW)
    - Test correlation ID tracking for debugging
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 19.2, 19.3, 19.4, 19.5, 19.9_

- [x] 5. Implement Batch Resolver with Gemini Interactions API (Rapid Triage + Background Submission)
  - [x] 5.1 Create BatchResolver class with token bucket rate limiter and context caching
    - Implement token bucket algorithm tracking 300 RPM sliding 60-second window (covers both sync and async tasks)
    - Implement processBatch() accepting array of CallbackTokens for Tier 2 (Rapid Triage) evaluation
    - Apply Context Hygiene sanitization to all contexts before API submission
    - Create BatchPayload with batch ID, timestamp, sanitized contexts, policy snapshot, `previous_interaction_id`
    - **TIER 2 - RAPID TRIAGE:** Implement submitToGeminiSync() using `client.interactions.create()` with `gemini-3.1-flash-lite` model
    - Use `previous_interaction_id` for server-side context caching to reduce token costs (target: >=50% token reduction on cache hits)
    - Leverage server-side context caching to track cache hit rate
    - Return BatchResponse with verdicts array, processing time, tokens consumed, cache hit count
    - Track batch metrics: total processed, average size, average latency (<100ms @ 99th percentile), rate limit hits, cache hit rate
    - **TIER 3 - DEEP REASONING:** Implement submitToGeminiBackground() using `client.interactions.create(background=True)` with `gemini-3.1-pro-preview` model
    - Background task submission includes webhook callback configuration (POST /webhook/analysis_complete)
    - Background submission returns task_id immediately (non-blocking)
    - _Requirements: 2.1, 2A.1, 2A.2, 2A.3, 2A.4, 2A.11, 2B.1, 2B.2, 2B.3, 2B.4_

  - [x] 5.2 Implement exponential backoff for APIRateLimitException handling
    - Detect APIRateLimitException from Gemini API response
    - Apply exponential backoff delays: 100ms, 200ms, 400ms for retries 1, 2, 3
    - Retry batch submission maximum 3 times
    - **FAIL-CLOSED:** If all retries fail, apply fail-closed policy: return QUARANTINE verdicts (not ALLOW) with warning logs and elevated monitoring flags
    - Log all rate limit hits with timestamp and batch details
    - _Requirements: 2.2, 2.3, 2.4, 12.3_

  - [x] 5.3 Implement batch processing metrics tracking and reporting
    - Track ResolverMetrics: total batches, average batch size, average latency, rate limit hits, cache hit rate
    - Track cache hit rate from `previous_interaction_id` reuse
    - Track background tasks submitted and webhook callbacks received
    - Track webhook processing latency
    - Expose getMetrics() method returning ResolverMetrics structure
    - Target average batch size >= 3 (batch efficiency requirement)
    - Target 99th percentile latency < 100ms for Rapid Triage
    - Target >=50% token reduction on cache hits
    - Log metrics periodically for monitoring dashboards
    - _Requirements: 2A.13, 2.6, 2.7, 2.8, 13.6, 13.8_

  - [x] 5.4 Write unit tests for Batch Resolver (Three-Tier Model)
    - Test token bucket rate limiter enforces 300 RPM cap (sliding window)
    - Test exponential backoff on APIRateLimitException (100ms, 200ms, 400ms)
    - **FAIL-CLOSED:** Test fallback to QUARANTINE verdicts (not ALLOW) after 3 failed retries
    - Test batch metrics tracking correctness
    - **TIER 2:** Test synchronous Gemini API calls with `gemini-3.1-flash-lite` model
    - **TIER 2:** Test `previous_interaction_id` included in request for context caching
    - **TIER 2:** Test cache hit rate calculation (>=50% token reduction on hits)
    - **TIER 2:** Test <100ms latency @ 99th percentile
    - **TIER 3:** Test background task submission with `gemini-3.1-pro-preview` model
    - **TIER 3:** Test webhook callback URL configuration
    - **TIER 3:** Test immediate return of task_id (non-blocking)
    - Mock Gemini Interactions API responses for deterministic testing
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2A.1, 2A.2, 2A.3, 2A.4, 2A.11, 2B.1, 2B.2, 2B.3_

  - [x] 5.5 Test rate limit compliance property
    - **Property 9: Rate Limit Compliance**
    - **Validates: Requirements 2.1, 13.7**
    - Using hypothesis, generate sequences of up to 600 batch submissions within any 60-second window
    - Assert total API calls submitted by Batch_Resolver within any 60-second sliding window is at most 300
    - Verify token bucket algorithm enforces the 300 RPM ceiling across randomized burst patterns

### Phase 4: Policy Evaluation

- [x] 6. Implement Structural Gating Engine with YAML policy evaluation
  - [x] 6.1 Create StructuralGatingEngine with YAML policy loader and rule evaluation
    - Implement loadPolicy() parsing YAML file into PolicyRules data structure
    - Validate YAML schema on load: version, rules, roles, thresholds, MCP configs
    - Validate all structural rule IDs are unique (reject duplicates with descriptive errors)
    - Create rule evaluation engine matching conditions against tool call context
    - Support condition expressions: equality checks (==), AND/OR operators, environment role references
    - Evaluate rules in ascending priority order (priority 1 before priority 2)
    - Apply first matching rule action: ALLOW, BLOCK, ESCALATE_TO_SEMANTIC
    - Skip disabled rules (enabled: false) during evaluation
    - Default to ESCALATE_TO_SEMANTIC if no rules match
    - Log matched rule ID and action for audit trail
    - Target <5ms evaluation latency for 99th percentile
    - _Requirements: 3.1, 3.2, 14.1, 14.2, 14.5, 14.10, 13.1, 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 22.7, 22.8, 22.9, 22.10_

  - [x] 6.2 Implement hot-reload for YAML policy updates without restart
    - Watch policy file for modifications using file system events (watchdog library)
    - Reload policy automatically on file change detection
    - Validate new policy before applying (schema check, rule ID uniqueness)
    - Atomically swap policy state to prevent race conditions during reload
    - Log policy reload events with version change
    - Reject invalid configurations and retain previous valid policy
    - _Requirements: 3.14, 14.9_

  - [x] 6.3 Write unit tests for Structural Gating Engine
    - Test YAML policy loading and schema validation
    - Test rule matching for toolName, environmentRole conditions
    - Test ALLOW fast-path without semantic review (requireSemanticReview: false)
    - Test BLOCK immediate rejection
    - Test ESCALATE_TO_SEMANTIC forwarding to semantic layer
    - Test rule priority ordering (priority 1 before priority 2)
    - Test disabled rule skipping
    - Test default ESCALATE_TO_SEMANTIC when no rules match
    - Test <5ms latency requirement
    - Test hot-reload without process restart
    - Test duplicate rule ID rejection
    - Test deterministic evaluation (same input → same output)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 14.9, 14.10, 13.1, 22.1, 22.2, 22.7, 22.8, 22.9, 22.10_

- [x] 7. Implement GTI MCP integration with circuit breaker pattern and rate-limit budgeting
  - [x] 7.1 Create GTIMCPClient for VirusTotal API queries with budget-aware caching and resilience
    - Implement queryIOC() for IP/domain/URL/hash reputation checks
    - Support indicator types: IP_ADDRESS, DOMAIN, URL, FILE_HASH
    - Parse GTIResponse with: isMalicious, threatCategories, detectionRate, confidence score
    - Include related malware campaign identifiers and last analysis date
    - Implement 24-hour TTL caching for responses (86400 seconds) stored in local SQLite (no Redis)
    - Handle 5-second query timeout using asyncio.wait_for() (cooperative cancellation)
    - Implement circuit breaker: switch to degraded mode after 5 consecutive failures
    - Apply default threat score penalty of 0.2 in degraded mode (missing GTI signal)
    - Auto-retry after 60-second cooldown period
    - Restore full GTI integration after 3 consecutive successful retries
    - Handle API rate limit responses with exponential backoff
    - **NEW:** Integrate with GTI_Query_Budget_Tracker to check budget before querying
    - **NEW:** Implement high-risk event classification (new IPs, suspicious hashes, unknown domains)
    - **NEW:** Calculate suspicion score for event prioritization (IOC novelty, domain reputation, geolocation, entropy)
    - **NEW:** Only query GTI when budget available AND event is high-risk
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 7.10, 7.11, 9.1, 9.2, 9.3, 9.6, 9.7, 12.1, 12.2, 21.1, 21.2, 21.3_

  - [x] 7.2 Write unit tests for GTI MCP integration with budget awareness
    - Test IOC query for malicious IP returns isMalicious=true
    - Test threat categories extraction (malware, botnet, C2, phishing)
    - Test detection rate calculation
    - Test 24-hour cache TTL reduces redundant API calls
    - Test 5-second timeout via asyncio.wait_for() triggers circuit breaker
    - Test circuit breaker switches to degraded mode after 5 failures
    - Test 60-second cooldown period before retry
    - Test threat score penalty of 0.2 applied in degraded mode
    - Test 3 successful retries restore full integration
    - **NEW:** Test GTI_Query_Budget_Tracker integration (budget check before query)
    - **NEW:** Test high-risk event classification logic
    - **NEW:** Test suspicion score calculation
    - **NEW:** Test query deferral when budget exhausted
    - **NEW:** Test weight redistribution (GTI 40% → CBM +20%, Context +20%) when budget exhausted
    - Mock VirusTotal API responses for deterministic testing
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.11, 9.8, 9.11, 9.19, 12.1, 12.2, 21.2, 21.3_

- [ ] 7.3 Implement GTI Query Budget Tracker with token bucket rate limiter
  - [ ] 7.3.1 Create GTIQueryBudgetTracker class with token bucket algorithm
    - Initialize token bucket with 4 tokens (matching VirusTotal free tier: 4 queries/minute)
    - Implement tryAcquire() method: returns true if token available, consumes 1 token, returns false if budget exhausted
    - Implement token replenishment: add 1 token every 15 seconds (4 tokens per 60-second sliding window)
    - Enforce hard cap: maximum 4 tokens (no accumulation beyond capacity)
    - Implement getAvailableTokens() method returning current token count (0-4)
    - Implement getMetrics() returning: total queries attempted, queries executed, queries deferred (budget exhausted), cache hit rate
    - Use asyncio.create_task for background token replenishment coroutine
    - Ensure thread-safe token operations using asyncio.Lock
    - _Requirements: 9.3, 9.4, 9.5, 9.19_

  - [ ] 7.3.2 Write unit tests for GTI Query Budget Tracker
    - Test token bucket initializes with 4 tokens
    - Test tryAcquire() consumes token when available
    - Test tryAcquire() returns false when budget exhausted (0 tokens)
    - Test token replenishment: 1 token added every 15 seconds
    - Test hard cap enforcement: tokens never exceed 4
    - Test sliding window behavior: 4 queries in 60 seconds enforced
    - Test concurrent access thread safety via asyncio.Lock
    - Test metrics tracking: attempted vs executed queries
    - Test query deferral counter increments when budget exhausted
    - _Requirements: 9.3, 9.4, 9.5, 9.19_

- [x] 8. Implement codebase-memory MCP integration with AST analysis
  - [x] 8.1 Create CodebaseMemoryClient for AST-based structural analysis
    - Implement queryDependencyChain() returning call chain, depth, critical sinks
    - Implement identifyCriticalSinks() detecting: SQL_QUERY, COMMAND_EXEC, FILE_WRITE, NETWORK_CALL
    - Identify unsafe sinks accepting unsanitized input
    - Implement traceDataFlow() returning: source node, sink node, taint status, sanitization points
    - Implement getBlastRadius() calculating: affected modules, risk score [0.0, 1.0], isolation level
    - Handle 2-second query timeout using asyncio.wait_for() (cooperative cancellation)
    - Apply threat score penalty of 0.4 when graph is stale (last updated > 1 hour ago)
    - Continue evaluation without CBM if unavailable (graceful degradation)
    - Provide mitigation hints based on AST analysis for vulnerability types
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 8.10, 12.9, 21.4, 21.5, 21.6, 21.7_

  - [x] 8.2 Write unit tests for codebase-memory integration
    - Test dependency chain query returns complete call path
    - Test critical sink detection for SQL, command exec, file write, network
    - Test unsafe sink identification (unsanitized input flag)
    - Test data flow tracing from source to sink with taint propagation
    - Test blast radius calculation with risk score
    - Test 2-second timeout handling via asyncio.wait_for() with graceful fallback
    - Test threat score penalty of 0.4 when graph is stale
    - Test mitigation hint generation for common vulnerabilities
    - Mock AST graph responses for deterministic testing
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 12.9, 21.5, 21.6_

### 

**Priority:** MEDIUM
**Dependencies:** Tasks 7, 8 (MCP clients)
**Estimated Effort:** 2 days
**Status**: ✅ Completed


**Description:**
Configure tool-caller definitions to sandbox `codebase-memory-mcp` exclusively to AST/structural code queries and restrict `GTI MCP` to asynchronous background IOC verification.

**Acceptance Criteria:**
1. CodebaseMemoryRouter class enforces hardcoded boundary for permitted operations:
   - query_dependency_chain (AST parsing)
   - identify_critical_sinks (sink detection)
   - trace_data_flow (taint analysis)
   - get_blast_radius (impact calculation)
2. CodebaseMemoryRouter prohibits:
   - General file dumping or arbitrary directory searches
   - Dynamic codeTASK-MCP-01: Hardcode MCP Routing Boundaries execution or runtime introspection
   - Modification of application state
3. GTIRouter class restricts GTI queries to asynchronous analysis loop only
4. GTIRouter enforces: GTI queries FORBIDDEN in synchronous (<10ms) path
5. Violations raise RuntimeError with descriptive message
6. Hardcoded routing logic (no dynamic tool discovery)
7. Routing logic prevents agent escape attempts
8. Unit tests verify each permitted operation allowed
9. Unit tests verify each prohibited operation blocked
10. Integration tests verify no MCP calls in synchronous path
11. Integration tests verify MCP routing enforced under attack scenarios

**Deliverables:**
- CodebaseMemoryRouter.py (AST operation routing, 150-200 LOC)
- GTIRouter.py (IOC verification routing, 150-200 LOC)
- Unit tests (MCPRouter_test.py)
- Integration tests with attack simulation
- Routing violation logs and alerting

---

- [x] 9. Implement Semantic Gating Engine with multi-source threat scoring and GTI budget awareness
  - [x] 9.1 Create SemanticGatingEngine with LLM-based intent analysis, signal aggregation, and rate-limited GTI queries
    - Implement evaluate() querying Threat Signature Graph first (cheapest check)
    - Extract IOCs from context: IP addresses, URLs, domains, file hashes
    - **NEW:** Classify event as high-risk based on: new external IPs not in cache, suspicious file hashes, unknown domains, structural gating signals
    - **NEW:** Calculate suspicion score for event prioritization (IOC novelty + domain reputation + geolocation + entropy)
    - **NEW:** Check GTI_Query_Budget_Tracker.tryAcquire() before querying GTI
    - Query GTI MCP for each IOC ONLY if: (1) event is high-risk AND (2) budget allows (tryAcquire() returns true)
    - IF budget exhausted, skip GTI query and apply 0.2 threat score penalty
    - Query codebase-memory MCP if context.targetFunction is present
    - Implement computeThreatScore() with weighted signal aggregation:
      * GTI signal: 40% weight (isMalicious, detectionRate, threat category severity)
      * CBM signal: 30% weight (critical sinks, unsafe flag, blast radius risk score)
      * Context signal: 30% weight (tool name risk, argument novelty, environment role)
    - **NEW:** When GTI unavailable (budget exhausted or circuit breaker), redistribute GTI weight (40%) → CBM (+20%) and Context (+20%)
    - Normalize final threat score to [0.0, 1.0] range
    - Apply verdict thresholds: >=0.75 BLOCK, >=0.5 QUARANTINE, <0.5 ALLOW
    - Return GateResult with verdict, reason, threat score, signature ID
    - Ensure deterministic scoring: same inputs → same score
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.16, 3.17, 9.6, 9.7, 9.8, 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8, 23.9, 23.10_

  - [x] 9.2 Test threat score bounded property
    - **Property 3: Threat Score Bounded**
    - **Validates: Requirements 3.10, 23.6, 23.7**
    - Generate diverse ToolCallContext samples with hypothesis
    - Generate random GTIResponse and CBMResponse combinations
    - Compute threat score for each combination
    - Assert all scores are in range [0.0, 1.0]
    - Verify BLOCK verdict only when score >= 0.75
    - Verify QUARANTINE verdict when 0.5 <= score < 0.75
    - Verify ALLOW verdict when score < 0.5

  - [x] 9.3 Write unit tests for Semantic Gating Engine with GTI budget constraints
    - Test signature matching returns BLOCK with signatureId
    - Test signature match count increment on successful match
    - **NEW:** Test high-risk event classification logic (new IPs, suspicious hashes, unknown domains)
    - **NEW:** Test suspicion score calculation
    - **NEW:** Test GTI_Query_Budget_Tracker.tryAcquire() called before GTI queries
    - **NEW:** Test GTI query skipped when budget exhausted (tryAcquire() returns false)
    - **NEW:** Test 0.2 threat score penalty applied when GTI budget exhausted
    - Test GTI malicious IOC increases threat score appropriately
    - Test CBM critical sink detection increases threat score
    - Test weighted threat score aggregation formula (GTI 40%, CBM 30%, Context 30%)
    - **NEW:** Test signal weight redistribution when GTI budget exhausted (GTI 40% → CBM +20%, Context +20%)
    - Test verdict thresholds: 0.75 BLOCK, 0.5 QUARANTINE, <0.5 ALLOW
    - Test signal weight redistribution when CBM unavailable
    - Test deterministic scoring for identical inputs
    - Test threat score included in verdict structure
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.16, 3.17, 9.6, 9.7, 9.8, 23.1, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8, 23.9, 23.10_

- [x] 10. Implement Hybrid Policy Server orchestrating structural and semantic gating
  - [x] 10.1 Create HybridPolicyServer coordinating dual-layer evaluation
    - Implement evaluate() invoking Structural Gating first (fast path)
    - Fast-path return BLOCK if structural gate blocks (skip semantic)
    - Fast-path return ALLOW if structural gate allows without review (skip semantic)
    - Invoke Semantic Gating if structural gate escalates
    - Implement evaluateBatch() processing multiple contexts in parallel using asyncio.gather
    - Return verdict array maintaining exact input order (verdict[i] → context[i])
    - **FAIL-CLOSED:** On APIRateLimitException or batch timeout, return QUARANTINE verdicts (not ALLOW) with monitoring flags
    - Expose getCurrentState() returning PolicyServerState snapshot
    - Expose updatePolicy() for hot-reload of YAML rules
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 19.1, 19.2_

  - [x] 10.2 Test verdict array order correspondence property
    - **Property 2: Verdict Array Correspondence**
    - **Validates: Requirements 3.1, 1.5, 19.1, 19.2**
    - Generate batch of 10-50 diverse ToolCallContext objects using hypothesis
    - Process batch through HybridPolicyServer.evaluateBatch()
    - Assert verdict array length equals input context array length
    - Verify verdict[i] corresponds to context[i] for all i in range
    - Test with random mix of BLOCK, ALLOW, ESCALATE conditions

  - [x] 10.3 Write integration tests for Hybrid Policy Server
    - Test structural BLOCK skips semantic evaluation (fast path)
    - Test structural ALLOW without review skips semantic (fast path)
    - Test structural ESCALATE triggers semantic gating
    - Test batch processing returns correctly ordered verdicts
    - Test end-to-end flow with mocked GTI and CBM queries
    - Test policy hot-reload updates rules without restart
    - Test parallel batch processing maintains order consistency
    - **FAIL-CLOSED:** Test rate limit or timeout returns QUARANTINE verdicts (not ALLOW)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.14, 19.1, 19.2_

### Phase 5: Analytics, Metrics & Verification

- [x] 11. Implement Agent Behavioral Analytics for signature generation and drift detection
  - [x] 11.1 Create AgentBehavioralAnalytics with signature generation pipeline
    - Implement scoreEvent() calculating behavioral drift using LLM-as-judge (0-5 scale)
    - Implement detectDrift() analyzing agent behavior across time windows
    - Detect anomalies when drift exceeds tolerance band ±0.5 from baseline
    - Implement generateSignature() extracting attacker intent from BLOCK verdict events
    - Use semantic gating reason field to extract LLM-derived intent summary
    - Generalize payload patterns: replace specific values (IPs, paths) with typed placeholders
    - **NO REDUNDANT CBM QUERY:** Read dependency chain from SecurityEvent.cbmResponse if present (populated upstream by Hybrid_Policy_Server during evaluation); do NOT issue a new Codebase_Memory_MCP query
    - Generate 768-dimensional embedding vector using Gemini Embedding API (`gemini-embedding-001`)
    - Combine attacker intent + generalized payload + tool name for embedding input text
    - Determine mitigation action based on critical sinks and GTI threat categories
    - Create ThreatSignature with all required fields and metadata
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 17.1, 17.2, 17.10, 27.1, 27.2_

  - [x] 11.2 Implement Green Team auto-refactoring for QUARANTINE verdicts
    - Implement triggerRefactoring() analyzing quarantined code paths
    - Identify specific vulnerability type from CBM critical sink type
    - Generate RefactoringHint with: target code, vulnerability description, suggested fix, confidence
    - Provide concrete remediation: "Use parameterized queries" for SQL injection
    - Complete analysis within 5 seconds to avoid blocking agent execution
    - Write threat signature with refactoring hint in metadata
    - _Requirements: 5.10, 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.9_

  - [x] 11.3 Implement Runtime AgBOM tracking and capability drift detection
    - Implement updateAgBOM() recording tool usage, frequencies, argument patterns
    - Maintain real-time inventory of agent capabilities
    - Track external APIs called by agent tools
    - Detect capability drift: new tools used without policy approval
    - Log anomaly events when unexpected tools appear
    - Export AgBOM as structured JSON for audit and compliance
    - _Requirements: 5.11, 10.9_

  - [x] 11.4 Write unit tests for Agent Behavioral Analytics
    - Test signature generation from BLOCK verdict event
    - Test payload generalization (IPs → [[IP_ADDRESS]], paths → [[FILE_PATH]])
    - Test attacker intent extraction from semantic gating reason
    - Test embedding vector generation (768 dimensions, via Gemini Embedding API)
    - Test mitigationAction determination based on signals
    - Test behavioral drift detection with tolerance band ±0.5
    - Test Green Team refactoring hint generation for SQL injection
    - Test refactoring analysis completes within 5 seconds
    - Test AgBOM update on new tool usage
    - Test capability drift anomaly logging
    - Test no redundant CBM query when cbmResponse is present
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 16.3, 16.4, 16.9, 17.1, 17.2_

### TASK-AI-01: Implement Webhook Listener and Gemini Background Task Integration

**Priority:** HIGH
**Dependencies:** TASK-DB-01, Task 11 (Agent Behavioral Analytics)
**Estimated Effort:** 3-4 days
**Status**: ✅ Completed

**Description:**
Build an async HTTP webhook listener bound to localhost:8090. Integrate Gemini Interactions API `background=True` task submission with JWT/JWKS asymmetric signature verification (RS256). Enforce zero polling by making all state transitions event-driven via webhook callbacks. Gemini delivers thin-payload Standard Webhooks envelopes containing only the `interaction_id`; full results are fetched via `client.interactions.get()` after acknowledgement.

**Acceptance Criteria:**
1. WebhookListener class implements async HTTP server using `aiohttp` (async-first)
2. Webhook listener binds to `localhost:8090` (configurable via `BLACKWALL_WEBHOOK_PORT` env var)
3. `POST /webhook/analysis_complete` endpoint accepts incoming Gemini callbacks
4. All incoming requests validated using **JWT/JWKS asymmetric signature verification (RS256)**: extract the JWT from the `Webhook-Signature` header, fetch the public key from `https://generativelanguage.googleapis.com/.well-known/jwks.json` using the `kid` field from the JWT header, verify the RS256 signature and `audience` claim
5. If signature verification fails, return `400 Bad Request` and log the rejection with details
6. If signature verification succeeds, endpoint returns `200 OK` within <50ms
7. After returning 200, payload queued for non-blocking async processing in background
8. **CRITICAL - ZERO POLLING:** No background threads checking task status, no sleep loops, no polling timers
9. When processing webhook payload, extract the `interaction_id` from `data.id` in the Standard Webhooks envelope (`{type, version, timestamp, data: {id}}`) — the webhook does NOT carry inline analysis results
10. After extraction, call `client.interactions.get(interaction_id)` to fetch the full analysis output from the Gemini API (fetch latency target: <100ms)
11. Cross-reference `interaction_id` with in-flight background tasks in SQLiteThreatRepository
12. If `interaction_id` is unknown or stale (>12 hours old), log warning and discard
13. Validate `webhook-timestamp` header and reject payloads older than 5 minutes to mitigate replay attacks
14. Deduplicate webhook deliveries using the `webhook-id` header, discarding events already processed
15. For each threat signature derived from the fetched interaction output, invoke Agent_Behavioral_Analytics.generateSignature()
16. Atomically write all generated signatures to SQLiteThreatRepository in single transaction
17. Emit OpenTelemetry span for each webhook event with: event_id, interaction_id, webhook_latency_ms, fetch_latency_ms, signatures_created_count
18. Implement graceful shutdown: on SIGTERM/SIGINT, drain in-flight requests with max 30-second grace period
19. Unit tests verify JWT/JWKS RS256 signature validation (valid JWT, invalid JWT, expired JWT, wrong audience)
20. Unit tests verify 200 response time <50ms
21. Unit tests verify `client.interactions.get()` is called after webhook receipt (not before)
22. Unit tests verify atomic signature writes with no race conditions
23. Unit tests verify replay attack rejection (timestamp > 5 minutes old)
24. Unit tests verify duplicate webhook-id is discarded
25. Integration tests verify webhook callbacks are processed before application shutdown

**Deliverables:**
- WebhookListener.py (aiohttp-based async listener, 300-400 LOC)
- JWT/JWKS RS256 signature verification module (with JWKS key caching)
- Webhook payload processor with async task queuing and `interactions.get()` fetch
- Graceful shutdown handler
- Unit tests (WebhookListener_test.py)
- Integration tests with webhook simulation
- OpenTelemetry span instrumentation

---

### TASK-AI-02: Integrate Gemini Interactions API for Background Task Submission

**Priority:** HIGH
**Dependencies:** TASK-AI-01, Task 11 (Agent Behavioral Analytics)
**Estimated Effort:** 2-3 days
**Status**: ✅ Completed

**Description:**
Implement Agent_Behavioral_Analytics submission of background tasks to Gemini Interactions API when BLOCK/QUARANTINE verdicts are issued. Use `background=True` with webhook callback configuration.

**Acceptance Criteria:**
1. AgentBehavioralAnalytics.submitBackgroundAnalysis() method submits task via `client.interactions.create(background=True)`
2. Background task includes: quarantined tool context, related signatures, CBM dependency chain, GTI IOC data
3. Background task uses `gemini-3.1-pro-preview` model (deep reasoning tier)
4. Task specifies webhook callback URL: `http://localhost:8090/webhook/analysis_complete`
5. Task specifies webhook event types: `COMPLETED`, `FAILED`, `TIMEOUT`
6. submitBackgroundAnalysis() returns task_id immediately (non-blocking)
7. Returned task_id stored in SQLiteThreatRepository with status `PENDING_WEBHOOK_CALLBACK`
8. No polling threads, no sleep loops, no status check timers launched
9. Method logs task submission with timestamp and task_id for audit trail
10. If submission fails (rate limit, connection error), fail-closed with QUARANTINE verdict on next interception attempt
11. Unit tests verify background task JSON structure
12. Unit tests verify webhook URL and event configuration
13. Unit tests verify non-blocking return of task_id
14. Integration tests verify task submission via mocked Gemini API

**Deliverables:**
- BackgroundTaskSubmitter.py (background task logic, 150-200 LOC)
- Webhook URL and event configuration module
- Task status tracking in SQLiteThreatRepository schema
- Unit tests (BackgroundTaskSubmitter_test.py)
- Integration tests with Gemini API mock

---

### TASK-AI-03: Verify and Enforce Event-Driven Analysis Invariant

**Priority:** HIGH
**Dependencies:** TASK-AI-01, TASK-AI-02
**Estimated Effort:** 1 day

**Description:**
The architecture was designed event-driven from the start — all async analysis is triggered by webhook callbacks from Gemini, never by background polling timers. This task codifies that invariant as an enforced, tested contract: a CI-runnable verification script plus a dedicated test suite that will catch any future regression where a developer accidentally introduces a polling pattern into the analysis path.

**Acceptance Criteria:**
1. Write `scripts/verify_no_polling.py` that greps the `src/` tree and fails with a non-zero exit code if any of the following patterns appear **outside** of approved locations (retry backoff in `resolver.py`/`gti_client.py`, the batch-flush timeout fence in `interception.py`, and the context hygiene worker loop in `middleware/context_hygiene.py`):
   - `asyncio.sleep()` in any file under `src/blackwall/analytics.py` or any future analytics module
   - `time.sleep()` anywhere in `src/`
   - `asyncio.create_task` with a name matching `.*poll.*`
2. Verification script prints a per-file report of all flagged occurrences before exiting
3. Write a pytest test (`tests/unit/test_event_driven_invariant.py`) that:
   - Imports `AgentBehavioralAnalytics` and asserts `generateSignature` carries no internal `asyncio.sleep` or `time.sleep` calls by inspecting its source via `inspect.getsource`
   - Asserts `submitBackgroundAnalysis` returns without blocking (completes in <10ms with a mocked Gemini client)
   - Asserts `WebhookListener` has no `asyncio.sleep` in its request handler path
4. Write an integration test that delivers a synthetic thin-payload webhook envelope (`{type, version, timestamp, data: {id}}`) to `POST /webhook/analysis_complete`, asserts `client.interactions.get(interaction_id)` is called to fetch the full output, and asserts `generateSignature` is called **exactly once** per threat signature candidate derived from the fetched output, with no timer-based delay between delivery and invocation
5. Integration test asserts end-to-end processing (webhook delivery → signature written to SQLiteThreatRepository) completes within 100ms
6. All tests pass under `pytest -v tests/unit/test_event_driven_invariant.py` and the verification script exits 0 on the current codebase

**Deliverables:**
- `scripts/verify_no_polling.py` (grep-based CI verification script)
- `tests/unit/test_event_driven_invariant.py` (unit + integration tests)
- One-line addition to `Makefile` or `pyproject.toml` `[tool.pytest]` so the script runs in CI alongside the test suite

---

- [x] 12. Checkpoint - Ensure core interception pipeline is functional
  - Run integration tests for Interception Queue + Batch Resolver + Hybrid Policy Server
  - Verify <300ms latency for semantic evaluation with GTI/CBM queries (99th percentile)
  - Verify <5ms latency for structural fast-path (99th percentile)
  - Verify batch efficiency: 80% of API calls use batch size >= 3
  - Verify synchronous path achieves <10ms with zero external API calls
  - Run `scripts/verify_no_polling.py` and confirm exit 0 (no polling patterns in analysis path)
  - Ask the user if questions arise

- [x] 13. Implement OpenTelemetry instrumentation and observability
  - [x] 13.1 Create OpenTelemetry tracer for distributed tracing
    - Initialize OpenTelemetry SDK with trace provider and OTLP exporter
    - Implement span creation for each SecurityEvent with unique trace ID
    - Include in spans: tool call details, verdict decision, threat score, signature match ID
    - Include GTI response summary (threat categories, detection rate)
    - Include CBM response summary (critical sinks, blast radius)
    - Implement distributed tracing across Blackwall, GTI_MCP, CBM, ADK components
    - Aggregate traces to visualize Vibe Trajectory (attack pattern evolution)
    - Compress spans before export to keep bandwidth < 100KB/s
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.8_

  - [x] 13.2 Implement Prometheus metrics export
    - Export metrics: total interceptions, verdicts by type (BLOCK/ALLOW/QUARANTINE)
    - Export average threat scores, API latency percentiles
    - Export batch sizes, cache hit rates (GTI, TSG), error counts
    - Expose metrics endpoint for Prometheus scraping (/metrics)
    - Create Grafana dashboard JSON for FRR/Evasion Rate trends
    - Visualize threat score distributions and signature match rates
    - _Requirements: 11.5, 11.6_

  - [x] 13.3 Create structured JSON logging for security events
    - Implement JSON logger using structlog with required fields
    - Log SecurityEvent with: event ID, timestamp, agent ID, verdict, telemetry span ID
    - Include all enrichment data: GTI campaigns, CBM chains, signatures, behavioral scores
    - Log Context Hygiene redaction metadata (pattern matched, SHA256 hashes)
    - Use append-only log files preventing modification
    - Implement daily log rotation with naming: blackwall-YYYY-MM-DD.log
    - Compress rotated logs with gzip
    - Retain logs for minimum 90 days
    - Support SIEM-compatible export formats (JSON, CEF)
    - _Requirements: 11.7, 5.12, 21.8, 21.9, 25.1, 25.2, 25.3, 25.4, 25.5, 25.6, 25.7, 25.8, 25.9, 25.11_

  - [x] 13.4 Write unit tests for observability components
    - Test OpenTelemetry span creation with unique trace IDs
    - Test span includes verdict and threat score fields
    - Test distributed tracing context propagation
    - Test Prometheus metrics increment correctly
    - Test metrics endpoint returns valid Prometheus format
    - Test JSON log format validation against schema
    - Test log rotation on date boundary
    - Test gzip compression of rotated logs
    - _Requirements: 11.1, 11.2, 11.5, 11.7, 25.4, 25.6, 25.7_

- [x] 14. Implement ADK integration and before_tool_callback hook
  - [x] 14.1 Create ADK callback integration layer with thread suspension
    - Implement before_tool_callback() hook intercepting all tool calls
    - Suspend execution thread and create CallbackToken with thread context
    - Enqueue CallbackToken to Interception Queue (async await)
    - Implement resumeCallback() function applying verdict to ADK
    - Handle ALLOW verdict: proceed with tool execution normally
    - Handle BLOCK verdict: return PermissionError to agent
    - Handle QUARANTINE verdict: execute in sandboxed mock environment, return sanitized response
    - Log all callback resolutions with correlation IDs
    - _Requirements: 1.1, 1.6, 16.1, 16.2, 16.5, 16.6, 16.8_

  - [x] 14.2 Implement Python Runtime Audit Hooks for bypass prevention
    - Register sys.addaudithook for os, subprocess, pty module calls
    - Deny raw execution attempts with PermissionError
    - Force all agent actions through ADK tool layer
    - Log bypass attempts as high-severity security events
    - _Requirements: 10.6, 10.7, 10.8_

  - [x] 14.3 Write integration tests for ADK callback hook
    - Test before_tool_callback suspends execution correctly
    - Test callback token creation and storage in queue
    - Test resumeCallback with ALLOW verdict executes tool
    - Test resumeCallback with BLOCK verdict returns PermissionError
    - Test resumeCallback with QUARANTINE verdict returns sanitized mock response
    - Test audit hook denies raw os/subprocess calls
    - Test bypass attempts logged as high-severity events
    - _Requirements: 1.1, 1.2, 1.6, 10.6, 10.7, 10.8, 16.1, 16.2_

- [x] 15. Implement evaluation metrics calculator for FRR and Evasion Rate
  - [x] 15.1 Create SecurityMetrics calculator with ground truth validation
    - Implement calculateMetrics() accepting TestResult array and GroundTruthLabel array
    - Validate input arrays have matching sizes
    - **EMPTY SUITE GUARD:** If test suite is empty, return zero metrics without division
    - **QUARANTINE MALICIOUS = TP:** Count MALICIOUS with BLOCK or QUARANTINE verdict as true positives
    - **QUARANTINE BENIGN = FP:** Count BENIGN with BLOCK or QUARANTINE verdict as false positives (impacts FRR)
    - Count true negatives: BENIGN with ALLOW verdict
    - Count false negatives: MALICIOUS with ALLOW verdict
    - Increment quarantineCount for all QUARANTINE verdicts (informational bucket)
    - **METRIC NAMES:** Calculate False Refusal Rate (FRR): (false positives / total benign) × 100
    - **METRIC NAMES:** Calculate Evasion Rate (False Negative Rate): (false negatives / total malicious) × 100
    - Calculate accuracy: ((TP + TN) / total tests) × 100
    - Calculate precision: (TP / (TP + FP)) × 100 with zero-division guard
    - Calculate recall: (TP / total malicious) × 100 with zero-division guard
    - Calculate F1 score: 2 × ((precision × recall) / (precision + recall)) with zero-division guard
    - Verify: TP + TN + FP + FN = total tests
    - Export metrics to JSON with keys: false_refusal_rate, evasion_rate, accuracy, precision, recall, f1_score, quarantine_count
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 9.10, 9.11, 9.12, 9.13, 9.14, 9.15_

  - [x] 15.2 Test metrics sum validation property
    - **Property 8: Evaluation Metrics Partition Invariant**
    - **Validates: Requirements 9.1, 9.10**
    - Generate random TestResult and GroundTruthLabel arrays using hypothesis

- [x] 16. Implement Zero Ambient Authority and JIT token downscoping
  - [x] 16.1 Create privilege management and credential handling system
    - Drop OS privileges for Blackwall agent process (run as unprivileged user)
    - Implement JIT (Just-In-Time) token downscoping per intercepted tool call
    - Fetch temporary scoped credentials from secure vault on-demand
    - Revoke credentials immediately after tool call completion
    - Never store long-lived API keys in process memory
    - Implement credential vault integration (HashiCorp Vault or local encrypted store)
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

  - [x] 16.2 Write security tests for Zero Ambient Authority
    - Test Blackwall process runs as unprivileged user (UID check)
    - Test temporary credentials are revoked after tool execution
    - Test no long-lived keys found in memory dump simulation
    - Test audit hook blocks raw execution bypasses
    - Test credentials fetched on-demand from vault
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6, 10.7_

- [x] 17. Implement error handling, circuit breakers, and resilience
  - [x] 17.1 Create comprehensive error handling with graceful degradation
    - GTI circuit breaker implementation (already in task 7.1)
    - SQLite write retry with exponential backoff (already in TASK-DB-01)
    - In-memory buffer for failed signature writes (already in TASK-DB-01)
    - **FAIL-CLOSED:** Implement emergency fallback for evaluation timeout > 10 seconds: return QUARANTINE verdicts (not ALLOW)
    - **THREAD-SAFE TIMEOUT:** Implement async task cancellation using asyncio.wait_for() with 30-second hard timeout — asyncio.wait_for() raises TimeoutError to the caller and internally cancels the wrapped coroutine; handle TimeoutError (not CancelledError) at the call site
    - **ALTERNATIVE THREAD-SAFE TIMEOUT:** OR use subprocess.Popen isolation with 30-second timeout and SIGKILL process termination if deadline exceeded
    - On TimeoutError or process termination, auto-restart evaluation pipeline and log critical error
    - Auto-disable regex patterns causing timeout > 100ms after 10 consecutive failures; emit operator alert on disable
    - Log all error recovery actions with severity levels
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.10, 12.11, 12.12_

  - [x] 17.2 Write resilience and failure mode tests
    - Test SQLite retry logic on transient lock errors
    - Test in-memory buffer overflow handling (drop oldest entries)
    - **FAIL-CLOSED:** Test emergency fallback on 10-second evaluation timeout returns QUARANTINE (not ALLOW)
    - **THREAD-SAFE TIMEOUT:** Test asyncio.wait_for() on frozen evaluation raises TimeoutError at call site (not CancelledError)
    - Test subprocess termination if using process isolation (30-second timeout with SIGKILL)
    - Test auto-restart after timeout-induced termination
    - Test regex pattern auto-disable on 10 consecutive timeouts with operator alert
    - Test GTI circuit breaker degraded mode (already covered in 7.2)
    - _Requirements: 12.4, 12.5, 12.6, 12.7, 12.8, 12.10, 12.11, 12.12_

- [x] 18. Checkpoint - Ensure complete system is functional
  - Run end-to-end integration tests with all components connected
  - Verify FRR < 10% and Evasion Rate < 10% on test suite
  - Verify all latency targets met: 5ms structural, 300ms semantic (99th percentile)
  - Verify memory usage < 512MB RSS during sustained operation
  - Verify CPU usage < 50% on 2-core VM during sustained 300 RPM load
  - Ask the user if questions arise

- [~] 19. Implement Gemini Embedding API client for similarity vector generation
  - [ ] 19.1 Create GeminiEmbeddingClient with async call and FTS5 fallback
    - Implement `embed(text: str) -> list[float]` using `gemini-embedding-001` model
    - Pass `output_dimensionality=768` and `task_type="SEMANTIC_SIMILARITY"` in every request
    - Reuse the existing paid-tier Gemini API key (no separate credential)
    - Apply 5-second timeout using asyncio.wait_for() on every embedding call
    - On timeout or API error: store signature without vector blob, fall back to FTS5 search for that signature
    - When falling back to FTS5, reduce similarity threshold from 0.85 to 0.7 for affected queries
    - Log every FTS5 fallback with signature_id, error type, and timestamp
    - Validate all stored vectors have exactly 768 floats before executing cosine similarity
    - Exclude signatures with incorrect dimensionality from vector queries and log a warning with the signature_id
    - Embedding is called exclusively from the async Tier 3 webhook processing flow — never in the synchronous interception path
    - _Requirements: 27.1, 27.2, 27.3, 27.4, 27.5, 27.6, 27.7, 27.8, 27.9, 27.10_

  - [ ] 19.2 Write unit tests for GeminiEmbeddingClient
    - Test successful embedding call returns list of exactly 768 floats
    - Test output_dimensionality=768 and task_type="SEMANTIC_SIMILARITY" sent in every request
    - Test 5-second timeout triggers FTS5 fallback path
    - Test API error (non-200) triggers FTS5 fallback path
    - Test FTS5 fallback reduces threshold to 0.7 for the affected signature
    - Test fallback is logged with signature_id and reason
    - Test dimension validation rejects stored blobs that are not 768 floats
    - Test inconsistent-dimension signatures excluded from cosine similarity queries
    - Mock Gemini Embedding API responses for deterministic testing
    - _Requirements: 27.1, 27.2, 27.4, 27.5, 27.6, 27.7, 27.8, 27.9, 27.10_

### TASK-PERF-01: Build Graph LFU/TTL Eviction Routine

**Priority:** MEDIUM
**Dependencies:** TASK-DB-01, Task 19 (Gemini Embedding Client)
**Estimated Effort:** 2-3 days

**Description:**
Implement an asynchronous background loop that runs every 60 seconds. Delete threat nodes older than 15 minutes with hit-counts < 3 when total node volume exceeds 10,000, ensuring local query evaluation remains <10ms.

**Acceptance Criteria:**
1. Background eviction routine runs asynchronously every 60 seconds (non-blocking)
2. TTL eviction: delete signatures with `last_matched_at` older than 15 minutes (900 seconds)
3. LFU eviction: when total signatures > 10,000, delete lowest match_count signatures until count falls below 10,000
4. Preserve high-value signatures: all signatures with match_count > 10 are retained (never evicted)
5. Cascade-delete related edges in signature_relationships when node deleted
6. Update FTS5 index to remove deleted signature content
7. GraphStatistics updated with eviction counts and reasons
8. Query latency remains <10ms @ 99th percentile after eviction
9. Unit tests verify TTL logic (delete nodes > 15 min old)
10. Unit tests verify LFU logic (delete lowest match_count when > 10k)
11. Unit tests verify high-value signatures (match_count > 10) preserved
12. Load tests verify <10ms query latency maintained

**Deliverables:**
- EvictionManager.py (TTL and LFU logic, 250-350 LOC)
- Background scheduler integration
- Unit tests (EvictionManager_test.py)
- Load tests for query latency
- GraphStatistics eviction tracking

---

- [ ] 20. Create comprehensive test data sets for evaluation
  - [ ] 20.1 Generate malicious test cases (minimum 50)
    - Create SQL injection payloads (various techniques)
    - Create command injection payloads (shell metacharacters)
    - Create malicious IP/URL tool calls (known C2 servers)
    - Create file path traversal attacks (../../../etc/passwd)
    - Create reverse shell attempts (curl | bash, nc listeners)
    - Create credential exfiltration attempts
    - Create obfuscated payload variants (base64, URL encoding)
    - Label all with ground truth: MALICIOUS
    - _Requirements: 9.1, 15.1, 15.2, 15.3, 15.4_

  - [ ] 20.2 Generate benign test cases (minimum 50)
    - Create legitimate database query tool calls
    - Create valid file read operations within allowed paths
    - Create authorized network requests to known safe endpoints
    - Create normal agent tool usage patterns from AGENTS.md specification
    - Create edge cases: unusual but valid operations
    - Label all with ground truth: BENIGN
    - _Requirements: 9.1, 15.5, 15.6_

  - [ ] 20.3 Generate adaptive evasion test cases (minimum 20)
    - Create second-attempt variants of blocked attacks
    - Apply obfuscation transformations to known malicious payloads
    - Test structural similarity detection against existing signatures
    - Verify signature-based blocking catches modified attacks
    - _Requirements: 9.7, 15.7, 15.8, 26.1, 26.2_

- [ ] 21. Run formal evaluation and generate metrics report
  - [ ] 21.1 Build ADK evalset from ground-truth test cases
    - Convert all test cases from task 20 into ADK `.evalset.json` format
    - Each eval scenario encodes: the attacker's tool call as the user turn, the expected `before_tool_callback` trajectory (tool name + verdict), and the expected final response (BLOCK/ALLOW/QUARANTINE string)
    - Malicious cases: expected trajectory ends with `before_tool_callback` returning a BLOCK or QUARANTINE verdict
    - Benign cases: expected trajectory ends with `before_tool_callback` returning an ALLOW verdict
    - Evasion cases: expected trajectory ends with BLOCK via signature match (not semantic evaluation) — verifying the self-learning loop fires correctly on second-wave variants
    - Write `tests/eval/evalsets/blackwall_security.evalset.json` containing all labelled scenarios
    - Write `tests/eval/eval_config.json` configuring two criteria:
      * `tool_trajectory_avg_score: 1.0` — exact match enforcement that `before_tool_callback` fires and returns the correct verdict on every interception
      * `rubric_based_tool_use_quality_v1` — LLM-as-judge rubrics asserting: (1) `before_tool_callback` is always the first tool called, (2) BLOCK verdict is never followed by tool execution, (3) QUARANTINE verdict is followed by sandboxed mock execution, not real execution
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 15.1, 15.2_

  - [ ] 21.2 Execute evalset via agents-cli and collect raw results
    - Start Blackwall daemon with `adk run` against the local sandbox environment
    - Run `agents-cli eval run` against `tests/eval/evalsets/blackwall_security.evalset.json` with `--config tests/eval/eval_config.json --print_detailed_results`
    - Capture raw ADK eval output (per-scenario pass/fail, tool trajectory traces, rubric scores) to `tests/eval/results/raw_adk_results.json`
    - For any scenario where `tool_trajectory_avg_score < 1.0`, log the actual vs. expected trajectory diff to a failures report
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 15.1, 15.2_

  - [ ] 21.3 Generate SecurityMetrics report from eval results
    - Parse `raw_adk_results.json` to extract per-scenario verdicts
    - Map ADK pass/fail results back to TP/TN/FP/FN ground truth labels from task 20
    - Calculate FRR, Evasion Rate, accuracy, precision, recall, F1 using `SecurityMetrics` calculator from task 15
    - **METRIC NAMES:** Export JSON with standardized keys: `false_refusal_rate`, `evasion_rate`, `accuracy`, `precision`, `recall`, `f1_score`, `quarantine_count`
    - Verify FRR < 10% target achieved
    - Verify Evasion Rate < 10% target achieved
    - Generate human-readable summary embedding ADK rubric scores alongside FRR/Evasion metrics for demo README — the rubric scores serve as reproducible, third-party-verifiable evidence for Kaggle judges
    - _Requirements: 9.5, 9.6, 9.7, 9.8, 9.9, 9.10, 9.11, 9.12, 9.13, 9.14, 9.15_

  - [ ] 21.4 Package evasion evalset as a self-contained judge-reproducible proof
    - Create `tests/eval/evalsets/blackwall_evasion_proof.evalset.json` as a standalone two-wave evalset:
      * Wave 1 scenarios: novel attacks with expected trajectory ending in semantic evaluation → BLOCK
      * Wave 2 scenarios: structurally similar variants of wave-1 attacks with expected trajectory ending in TSG signature match → BLOCK (signature path, not semantic path)
      * Each scenario includes a `description` field explaining in plain English what the attack is and what the expected defense mechanism is, so judges understand what they are observing without reading source code
    - Write `tests/eval/eval_config_evasion.json` with:
      * `tool_trajectory_avg_score: 1.0` asserting exact trajectory match on both waves
      * `rubric_based_tool_use_quality_v1` rubrics asserting: (1) wave-1 trajectory includes a semantic evaluation tool call, (2) wave-2 trajectory does NOT include a semantic evaluation tool call (signature match short-circuits it), (3) both waves end in BLOCK with no downstream tool execution
    - Write `scripts/run_evasion_eval.sh` as the single judge-facing entry point:
      * Starts a fresh Blackwall daemon with a clean empty TSG (`adk run --reset-state`)
      * Runs wave-1 eval: `agents-cli eval run` against wave-1 scenarios
      * Waits for TSG write confirmation (polls SQLite signature count until > 0, max 5s)
      * Runs wave-2 eval: `agents-cli eval run` against wave-2 scenarios against the now-populated TSG
      * Prints a plain-English summary: wave-1 pass rate, wave-2 pass rate, and the latency delta between semantic-path and signature-path blocks
      * Exits non-zero if either wave fails, so CI and judges get a clear pass/fail signal
    - Document `run_evasion_eval.sh` as the primary reproducibility command in README.md under a **"Reproduce the Evaluation"** section — judges clone the repo, set API keys in `.env`, and run one script
    - _Requirements: 5.1, 5.2, 5.3, 26.1, 26.2, 26.3_

  - [ ] 21.5 Implement free-tier evaluation mode for judge reproducibility
    - **Goal:** Enable zero-friction judge reproduction by shipping a free-tier mode (15 RPM Gemini API) that bypasses all paid-tier optimizations while preserving core security mechanisms
    - Create `SyncResolver` class in `src/blackwall/sync_resolver.py`:
      * Implements synchronous single-request evaluation via `client.models.generate_content()` (not `interactions.create()`)
      * Applies Context Hygiene sanitization to tool context before API call
      * Queries GTI MCP and CBM MCP serially (not in parallel batches)
      * Computes threat score using same weighted aggregation (GTI 40%, CBM 30%, Context 30%)
      * Returns single `Verdict` object (not batched array)
      * No `InterceptionQueue`, no batch accumulation, no webhook listener dependencies
      * Signature generation happens inline (blocking) after BLOCK verdict instead of async via webhook
    - Add `BLACKWALL_TIER` env var detection in `src/blackwall/resolver.py`:
      * Read `BLACKWALL_TIER` from environment (valid values: `"free"` or `"paid"`)
      * If `free`: instantiate `SyncResolver` and skip `InterceptionQueue`/`BatchResolver` initialization
      * If `paid`: instantiate `BatchResolver` with async batching (existing behavior)
      * Default to `free` if env var not set (judge-friendly default)
    - Update `src/blackwall/interception.py` to handle tier detection:
      * If `free` tier: `before_tool_callback` directly calls `SyncResolver.evaluate()` and blocks until verdict returned
      * If `paid` tier: `before_tool_callback` enqueues to `InterceptionQueue` (existing async path)
    - Update signature generation trigger logic:
      * Free tier: after `SyncResolver` returns BLOCK, immediately call `AgentBehavioralAnalytics.generateSignature()` inline (adds ~200-500ms latency)
      * Paid tier: after `BatchResolver` returns BLOCK, submit background task via webhook (existing behavior, zero added latency)
    - Add unit tests for `SyncResolver`:
      * Test single-request evaluation with mocked Gemini API response
      * Test GTI/CBM queries execute serially
      * Test threat score calculation matches `BatchResolver` formula
      * Test inline signature generation after BLOCK verdict
      * Test 15 RPM rate limit enforcement (reject requests exceeding limit with QUARANTINE verdict)
    - Write `scripts/run_evasion_eval_free.sh` as free-tier entry point:
      * Sets `BLACKWALL_TIER=free` before launching `adk run`
      * Runs identical evalset as `run_evasion_eval.sh` but with free-tier backend
      * Includes warning in output: "Running in FREE TIER mode (15 RPM). Eval will take ~X minutes. Set BLACKWALL_TIER=paid for faster execution."
      * Otherwise identical to paid-tier script (same pass/fail logic, same metrics output)
    - Update README.md with tier comparison table:
      * Document free vs. paid tier feature matrix (what works, what's missing)
      * Highlight that core security mechanisms (hybrid gating, self-learning, audit hooks, Zero Ambient Authority) are identical across tiers
      * Explain paid-tier optimizations: async batching (300 RPM), server-side context caching (50%+ token savings), background webhook analysis (zero latency signature generation)
      * Default judge instructions to free tier with paid tier as optional performance upgrade
    - Update `.env.example` with `BLACKWALL_TIER` variable and explanatory comments
    - **VERIFY ENV COVERAGE:** Review if any eval-specific paths need to be added to `.env.example` (e.g., `EVAL_RESULTS_DIR`, `ADK_AGENT_PATH`). If new variables are discovered during implementation, add them with clear comments indicating whether they're needed for free tier or paid tier only.
    - **UPDATE JUDGE_EVALUATION.md:** After successfully running the free-tier evaluation, update `JUDGE_EVALUATION.md` with:
      * Actual timing results from `run_evasion_eval_free.sh` (wave-1 avg latency, wave-2 avg latency, speedup ratio)
      * Actual FRR and Evasion Rate percentages from the full 120-case eval
      * Any judge-facing gotchas discovered during testing (e.g., common errors, timing expectations)
      * Screenshots or terminal recordings of successful eval runs (optional but recommended for visual proof)
    - _Requirements: 2.1, 9.1, 9.2, 15.1, 15.2, 26.1, 26.2_

- [ ] 22. Implement demo harness and dual-agent showdown setup
  - [ ] 22.1 Create demo orchestration script for dual-agent showdown
    - Write scripts/run_demo.sh launching Blackwall as ambient daemon via adk run
    - Write scripts/run_rogue.py launching adversarial agent with configured attack sequences
    - Implement split-screen terminal recording setup
    - Configure Blackwall daemon to log to visible terminal output
    - Configure rogue agent to show attempt outputs and failures
    - _Requirements: 27.1, 27.2, 27.3, 28.1, 28.2_

  - [ ] 22.2 Configure sandbox environment with Python audit hooks
    - Register sys.addaudithook blocking raw os/subprocess/pty calls at process start
    - Configure Blackwall to run as unprivileged user (dropped OS privileges)
    - Set up mock vulnerable target application (simple Flask app with SQL injection surface)
    - Configure rogue agent (Qwen3-Coder via Hyperbolic API) with attack tool set
    - Validate audit hooks active before demo execution
    - _Requirements: 10.6, 10.7, 10.8, 27.4, 27.5_

  - [ ] 22.3 Write smoke tests for demo harness
    - Test Blackwall daemon starts successfully via adk run
    - Test audit hook blocks raw subprocess calls
    - Test rogue agent tool calls are intercepted by before_tool_callback
    - Test first-attempt attack blocked by semantic evaluation
    - Test second-attempt attack blocked by signature match
    - _Requirements: 27.1, 27.2, 26.1, 26.2_

- [ ] 23. Implement YAML policy configuration for demo scenarios
  - [ ] 23.1 Create policy.yaml with production-ready rules for demo
    - Define environment roles: PRODUCTION, STAGING, DEVELOPMENT, SANDBOX
    - Write structural rules blocking known dangerous tool names immediately (BLOCK)
    - Write structural rules for privileged operations requiring semantic review (ESCALATE_TO_SEMANTIC)
    - Write structural rules for safe read-only operations in DEVELOPMENT (ALLOW)
    - Set semantic thresholds in config: block_threshold=0.75, quarantine_threshold=0.5
    - Configure MCP endpoints: GTI_MCP URL, CBM_MCP URL
    - Set policy version with semantic versioning (1.0.0)
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7_

  - [ ] 23.2 Write YAML policy validation tests
    - Test all rule IDs are unique in policy.yaml
    - Test schema validation passes for all rules
    - Test priority ordering covers expected evaluation sequence
    - Test BLOCK rules fire for known malicious tool names
    - Test ESCALATE rules fire for write/network operations
    - Test ALLOW rules fire for safe read-only operations
    - _Requirements: 14.1, 14.2, 14.10, 22.1, 22.2, 22.7_

- [ ] 24. Write project documentation and README
  - [ ] 24.1 Create comprehensive README.md
    - Write project overview describing Blackwall's mission and architecture
    - Include architecture diagram (Mermaid) showing all components and data flow
    - Provide setup instructions: dependencies, environment variables, API keys
    - Document demo execution steps with expected outputs
    - Include evaluation results table showing FRR and Evasion Rate
    - Add security architecture section explaining Zero Ambient Authority
    - Include BDD scenario examples from design.md for context
    - _Requirements: 28.1, 28.2, 28.3_

  - [ ] 24.2 Create ARCHITECTURE.md with technical deep-dive
    - Document Hybrid Policy Server dual-layer evaluation flow
    - Explain asynchronous batching architecture and callback queue management
    - Describe SQLite Threat Signature Graph schema and query patterns
    - Document GTI MCP and codebase-memory MCP integration patterns
    - Explain Agent Behavioral Analytics signature generation pipeline
    - Include OpenTelemetry distributed tracing design
    - Document security constraints: fail-closed defaults, Zero Ambient Authority
    - _Requirements: 28.3, 28.4_

  - [ ] 24.3 Write KAGGLE_SUBMISSION.md with competition narrative
    - Describe the dual-agent showdown scenario and key design decisions
    - Highlight innovative aspects: self-learning signatures, runtime AgBOM, LLM-as-judge scoring
    - Summarize evaluation results and what they demonstrate
    - Include lessons learned and potential extensions
    - _Requirements: 28.5_

- [ ] 25. Implement self-learning loop integration and end-to-end validation
  - [ ] 25.1 Integrate signature generation into live interception pipeline
    - Wire ABA.generateSignature() to fire after every BLOCK verdict in the pipeline
    - Wire ABA.triggerRefactoring() to fire after every QUARANTINE verdict
    - Confirm ThreatSignature written to TSG with correct 768-dimensional embedding vector and metadata
    - Confirm OpenTelemetry span records signature creation event
    - Confirm SecurityEvent logged with eventType=SIGNATURE_CREATED and verdict=None
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.12, 11.1_

  - [ ] 25.2 Validate adaptive defense against repeated attacks
    - Execute first novel attack → verify BLOCK via semantic evaluation
    - Verify ThreatSignature created in TSG for that attack
    - Execute structurally-similar second attack → verify BLOCK via signature match (TSG)
    - Verify signature match faster than first-attempt semantic evaluation
    - Verify match_count incremented on signature after second match
    - _Requirements: 5.1, 6.9, 6.10, 6.11, 26.1, 26.2, 26.3_

  - [ ] 25.3 Write end-to-end integration tests for self-learning loop
    - Test full pipeline: intercept → evaluate → block → generate signature → block similar
    - Test signature 768-dimensional embedding generated correctly from BLOCK event fields via Gemini Embedding API
    - Test second attack matches with similarity >= 0.85
    - Test signature match_count increments on repeated attack patterns
    - Test QUARANTINE events trigger Green Team refactoring hints
    - _Requirements: 5.1, 5.2, 5.3, 5.7, 5.8, 6.9, 16.3_

- [ ] 26. Performance benchmarking and resource validation
  - [ ] 26.1 Create performance benchmark suite
    - Benchmark structural gating latency under simulated load (100 concurrent requests)
    - Benchmark semantic gating latency with GTI/CBM mock responses
    - Benchmark TSG query latency with 10,000 signatures in database
    - Measure memory RSS during sustained 300 RPM processing
    - Measure CPU utilization during sustained 300 RPM processing
    - Generate percentile report: p50, p95, p99 for all latency measurements
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9_

  - [ ] 26.2 Validate performance targets
    - Assert structural gating p99 latency < 5ms
    - Assert semantic gating p99 latency < 300ms
    - Assert TSG query p99 latency < 10ms
    - Assert memory RSS < 512MB under sustained load
    - Assert CPU usage < 50% on 2-core under 300 RPM
    - Assert average batch size >= 3 at full load
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9_

- [ ] 27. Final integration, packaging, and submission preparation
  - Ensure all tests pass: pytest --asyncio-mode=auto -v
  - Ensure pre-commit hooks pass: ruff, black, mypy
  - Build Docker image and verify container starts cleanly
  - Verify demo script executes without errors in sandbox environment
  - Confirm evaluation report shows FRR < 10% and Evasion Rate < 10%
  - Tag git release v1.0.0 for Kaggle submission
  - Verify README.md renders correctly on GitHub
  - Ask the user if questions arise

## Notes

- **Property-Based Testing:** Tasks marked with property tests (e.g., "Property 1: Callback Resolution Completeness") validate universal correctness properties from the design document using Hypothesis with 1,000+ generated examples per property.
- **Optional Tasks:** Tasks marked with `*` are optional test tasks and may be skipped for faster MVP delivery. Core implementation tasks (without `*`) must be completed.
- **Fail-Closed Defaults:** All error handling and timeout scenarios default to QUARANTINE verdicts (never ALLOW) to maintain conservative security posture.
- **Async Timeout Behavior:** asyncio.wait_for() raises TimeoutError to the caller (not CancelledError). The wrapped coroutine is cancelled internally, but the TimeoutError is what must be caught at the call site.
- **Thread-Safe Concurrency:** All concurrent access to SQLite, InterceptionQueue, and Context Hygiene uses asyncio locks or connection pooling to prevent race conditions.
- **Checkpoint Tasks:** Tasks 12 and 18 are checkpoints for user feedback. Pause at these points to verify system functionality before proceeding.
- **Kaggle Submission Requirements:** Tasks 20-27 focus on demo preparation, evaluation, and documentation for the Kaggle AI Agents hackathon.
- **12 Correctness Properties:** The design document defines 12 formal correctness properties with explicit requirements traceability. Property tests in this task list validate these properties.
- **28 Requirements with EARS Criteria:** All 28 requirements from requirements.md have EARS-compliant acceptance criteria (WHEN/IF/WHILE/WHERE/FOR ANY conditions with THE system SHALL actions).

## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["TASK-DB-01"]
    },
    {
      "id": 1,
      "tasks": ["1", "2"]
    },
    {
      "id": 2,
      "tasks": ["3", "TASK-SEC-01", "4", "5", "6"]
    },
    {
      "id": 3,
      "tasks": ["7", "8", "TASK-MCP-01", "9", "10"]
    },
    {
      "id": 4,
      "tasks": ["11", "TASK-AI-01", "TASK-AI-02", "TASK-AI-03", "12", "13", "14", "15"]
    },
    {
      "id": 5,
      "tasks": ["16", "17", "18"]
    },
    {
      "id": 6,
      "tasks": ["19", "TASK-PERF-01", "20", "21"]
    },
    {
      "id": 7,
      "tasks": ["22", "23"]
    },
    {
      "id": 8,
      "tasks": ["24", "25", "26"]
    },
    {
      "id": 9,
      "tasks": ["27"]
    }
  ]
}
```
