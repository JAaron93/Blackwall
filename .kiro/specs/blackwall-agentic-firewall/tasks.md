# Implementation Plan: Blackwall Agentic Firewall

## Overview

This implementation plan breaks down the Blackwall Agentic Firewall into discrete, testable tasks following a test-driven development approach. The system will be implemented in **Python** using ADK 2.0, with asynchronous processing via asyncio, SQLite for threat signature storage with WAL mode, and integration with GTI and codebase-memory MCPs. The architecture addresses the critical API rate constraint (300 RPM Gemini vs 600 RPM attacker) through asynchronous batched evaluation with callback queue management, maintaining sub-10% false positive/negative rates while demonstrating Zero Ambient Authority, Agent Behavioral Analytics, and runtime AgBOM tracing for production-grade agentic security.

**Key Architectural Constraints:**
- All rate limit fallbacks use fail-closed QUARANTINE verdicts (never ALLOW)
- SecurityEvent.verdict is nullable (None only for SIGNATURE_CREATED events)
- Thread-safe timeout handling via asyncio.wait_for() raising TimeoutError (not CancelledError)
- Atomic signature_id uniqueness enforced by SQLite PRIMARY KEY + INSERT OR IGNORE
- Single-instance local daemon architecture (no Redis/Kubernetes/horizontal scaling)
- Standardized metric naming: False Refusal Rate (FRR), Evasion Rate (False Negative Rate)
- QUARANTINE on benign inputs counts as false positive (impacts FRR)
- Empty test suite returns zero metrics without division errors
- 12 correctness properties from design with explicit requirements traceability
- 28 requirements all with EARS-compliant acceptance criteria

Tasks are ordered by dependency (foundational → integration → evaluation → demo) and include both implementation and testing sub-tasks.

## Tasks

- [ ] 1. Set up project structure and core infrastructure
  - Create Python project with pyproject.toml and Poetry/pip requirements
  - Define project directory structure (src/blackwall/, tests/, config/, docs/, scripts/)
  - Set up pytest testing framework with asyncio support and hypothesis plugin
  - Configure pre-commit hooks for linting (ruff/black), type checking (mypy)
  - Create base YAML policy configuration file template
  - Set up structlog logging framework with JSON output format
  - Initialize git repository with .gitignore for Python
  - Create Dockerfile for containerized deployment with non-root user
  - _Requirements: 14.1, 14.2, 27.1, 27.2, 27.3, 28.1_

- [ ] 2. Implement core data models and type definitions
  - [ ] 2.1 Create Pydantic data model classes with validation
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
  
  - [ ]* 2.2 Write unit tests for data model validation
    - Test valid model instantiation with correct fields
    - Test invalid inputs trigger Pydantic ValidationError
    - Test threat score bounds [0.0, 1.0] enforcement
    - Test semantic versioning format validation (MAJOR.MINOR.PATCH)
    - Test Enum value restrictions
    - Test timestamp validation (within 5 seconds of current time for SecurityEvent)
    - **NULLABLE VERDICT:** Test SecurityEvent with verdict=None is valid for eventType=SIGNATURE_CREATED
    - **NULLABLE VERDICT:** Test SecurityEvent with verdict=None raises error for eventType in {INTERCEPTION, BLOCK, ALLOW, QUARANTINE}
    - _Requirements: 1.2, 3.10, 3.11, 14.12, 25.2_

- [ ] 3. Implement Context Hygiene middleware with regex sanitization
  - [ ] 3.1 Create ContextHygiene class with regex-based redaction
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
  
  - [ ] 3.2 Test sanitization idempotence property
    - **Property 4: Sanitization Idempotence**
    - **Validates: Requirements 4.10**
    - Generate random ToolCallContext with sensitive data using hypothesis
    - Apply sanitization twice: result1 = sanitize(context), result2 = sanitize(result1)
    - Assert result1 == result2 (idempotent property)
    - Verify no raw secrets remain in sanitized output

  - [ ] 3.3b Test sanitization structure preservation property
    - **Property 5: Sanitization Structure Preservation**
    - **Validates: Requirements 4.11**
    - Generate ToolCallContext instances with valid JSON arguments using hypothesis
    - Apply Context_Hygiene sanitization
    - Assert sanitizedArguments is parseable JSON (json.loads does not throw)
    - Assert top-level key set in sanitizedArguments matches key set in rawArguments
  
  - [ ]* 3.3 Write unit tests for Context Hygiene
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

- [ ] 4. Implement SQLite Threat Signature Graph with WAL mode and concurrency
  - [ ] 4.1 Create ThreatSignatureGraph class with SQLite backend and connection pooling
    - Initialize SQLite connection pool with max 10 connections
    - Enable WAL mode: PRAGMA journal_mode=WAL
    - Configure PRAGMA synchronous=NORMAL for faster writes
    - Configure PRAGMA wal_autocheckpoint=1000
    - Create signatures table schema with all required fields
    - **ATOMIC UNIQUENESS:** Define signature_id as PRIMARY KEY (enforces uniqueness atomically at database level)
    - **SEPARATE INDEX STATEMENTS:** Create indexes on target_tool and last_matched_at using separate CREATE INDEX statements (not inline in CREATE TABLE)
    - Create signature_relationships table for SIMILAR_TO and MITIGATED_BY edges
    - Create FTS5 virtual table for full-text search on payload_pattern and attacker_intent
    - Implement connection pool acquire/release logic with proper cleanup
    - Initialize GraphStatistics tracking total signatures, query times, cache hits, evictions
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 18.1, 18.2, 18.3, 18.4, 18.10_
  
  - [ ] 4.2 Implement writeSignature() with transactional safety and retry logic
    - **ATOMIC UNIQUENESS:** Use INSERT OR IGNORE for atomic duplicate prevention (signature_id PRIMARY KEY enforces uniqueness; application-level checks are advisory only)
    - Serialize similarity vector to BLOB format (384 float array)
    - Use IMMEDIATE transaction isolation level for efficient lock acquisition
    - Insert signature into signatures table within transaction
    - Update FTS5 index with payload_pattern and attacker_intent
    - Query existing signatures and create SIMILAR_TO edges for cosine similarity > 0.85
    - Handle database lock errors with exponential backoff retry (max 3 attempts)
    - Implement in-memory buffer (capacity 100) for failed writes during lock contention
    - Spawn background worker to flush buffer when locks become available
    - _Requirements: 6.8, 6.12, 12.4, 12.5, 17.6, 17.7, 18.5, 18.6, 18.7, 18.8, 18.9, 18.11, 19.6_
  
  - [ ] 4.3 Implement querySimilar() with vector similarity search and caching
    - Encode query context using embedding model (sentence-transformers)
    - Compute cosine similarity against all stored signature vectors
    - Return signatures with similarity >= threshold (default 0.85)
    - Sort results by similarity descending (highest match first)
    - Implement LRU cache for query results (max 1000 entries)
    - Target <10ms query latency for 99th percentile
    - Implement FTS5 fallback when embedding model unavailable (degraded mode with threshold 0.7)
    - _Requirements: 6.9, 6.10, 6.11, 13.4, 17.1, 17.3, 17.4, 17.5, 17.9, 24.4, 24.5_
  
  - [ ] 4.4 Implement TTL-based pruning and LFU eviction policies
    - Create pruneStale() method deleting signatures with last_matched_at older than 30 days (2592000 seconds)
    - Schedule TTL eviction as background job running every 24 hours
    - Cascade-delete related edges in signature_relationships table
    - Update FTS5 index to remove deleted signature content
    - Create evictLFU() method removing lowest match_count signatures when total > 10,000
    - Preserve high-value signatures with match_count > 10 during eviction
    - Update GraphStatistics with eviction counts and reasons
    - _Requirements: 6.13, 6.14, 14.8, 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8, 20.9, 20.10, 20.11, 20.12_
  
  - [ ] 4.5 Test signature uniqueness property
    - **Property 7: Signature Uniqueness via Atomic Write**
    - **Validates: Requirements 6.9, 18.5**
    - Generate 100 ThreatSignature objects with unique signature_id using hypothesis
    - Write all signatures to TSG database
    - Query all signatures and verify no duplicate signature_id values exist
    - **ATOMIC UNIQUENESS:** Verify INSERT OR IGNORE silently drops duplicate attempts without error
    - Verify concurrent writes with same signature_id result in exactly one database entry

  - [ ] 4.5b Test signature vector dimension consistency property
    - **Property 6: Signature Vector Dimension Consistency**
    - **Validates: Requirements 5.6, 17.2, 24.1, 24.9**
    - Generate diverse SecurityEvent instances with BLOCK verdicts using hypothesis
    - For each event, call ABA.generateSignature() to produce ThreatSignature
    - Assert every signature.similarityVector has exactly 384 floats
    - Verify consistency holds across all generated signatures
  
  - [ ]* 4.6 Write unit tests for Threat Signature Graph
    - Test WAL mode initialization with PRAGMA verification
    - Test connection pool creates 10 connections
    - Test signature insertion and retrieval round-trip
    - Test cosine similarity computation correctness (range [-1.0, 1.0])
    - Test signature update atomically increments match_count
    - Test TTL pruning removes signatures older than 30 days
    - Test LFU eviction when count exceeds 10,000
    - Test SIMILAR_TO edge creation for similarity > 0.85
    - Test database integrity check (PRAGMA integrity_check)
    - Test in-memory buffer overflow handling (drop oldest when > 100)
    - _Requirements: 6.1, 6.2, 6.3, 6.8, 6.12, 6.13, 6.14, 6.15, 17.4, 17.6, 18.10, 18.11_

  - [ ] 4.7 Test cosine similarity symmetry and bounds property
    - **Property 10: Cosine Similarity Symmetry and Bounds**
    - **Validates: Requirements 17.4**
    - Using hypothesis, generate pairs of random 384-dimensional float vectors
    - Compute cosine similarity in both directions: sim(A, B) and sim(B, A)
    - Assert |sim(A, B) - sim(B, A)| <= float tolerance (1e-6)
    - Assert all similarity values are in range [-1.0, 1.0]

  - [ ] 4.8 Test SIMILAR_TO edge consistency property
    - **Property 11: SIMILAR_TO Edge Consistency**
    - **Validates: Requirements 17.6**
    - Using hypothesis, generate pairs of ThreatSignature objects
    - Compute cosine similarity between their similarityVectors
    - Write both signatures to Threat_Signature_Graph
    - For pairs with cosine similarity >= 0.85, assert a SIMILAR_TO edge exists in signature_relationships
    - For pairs with cosine similarity < 0.85, assert no SIMILAR_TO edge exists between them

  - [ ] 4.9 Test LFU eviction preserves high-value signatures property
    - **Property 12: LFU Eviction Preserves High-Value Signatures**
    - **Validates: Requirements 20.8**
    - Using hypothesis, generate signature sets where total count > maxSignatures threshold
    - Mark a subset of signatures with matchCount > 10 (high-value)
    - Trigger LFU eviction pass via evictLFU()
    - Assert every signature with matchCount > 10 still exists in the graph after eviction
    - Assert total signature count is now <= maxSignatures

- [ ] 5. Implement Interception Queue with callback management and batching
  - [ ] 5.1 Create InterceptionQueue class with asyncio.Queue and batch accumulation
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
  
  - [ ] 5.2 Test callback resolution completeness property
    - **Property 1: Callback Resolution Completeness**
    - **Validates: Requirements 1.6, 19.7**
    - Generate random sequences of 1-100 callback tokens using hypothesis
    - Enqueue all tokens to InterceptionQueue
    - Process batches and generate verdicts
    - Assert each callback is resumed exactly once (no duplicates, no missed tokens)
    - Verify no callbacks remain in queue after resolution
  
  - [ ]* 5.3 Write unit tests for Interception Queue
    - Test enqueue and dequeue operations with asyncio
    - Test batch accumulation reaches maxSize=5 and flushes
    - Test timeout flushing with maxWaitMs=100 for partial batches
    - Test verdict array mapping correctness (index i → callback i)
    - Test emergency flushing when queue size > 50
    - Test array size mismatch triggers critical error and batch rejection
    - **FAIL-CLOSED:** Test emergency fallback returns BLOCK verdicts on batch rejection (not ALLOW)
    - Test correlation ID tracking for debugging
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 19.2, 19.3, 19.4, 19.5, 19.9_

- [ ] 6. Implement Batch Resolver with rate limiting and exponential backoff
  - [ ] 6.1 Create BatchResolver class with token bucket rate limiter
    - Implement token bucket algorithm tracking 300 RPM sliding 60-second window
    - Implement processBatch() accepting array of CallbackTokens
    - Apply Context Hygiene sanitization to all contexts before API submission
    - Create BatchPayload with batch ID, timestamp, sanitized contexts, policy snapshot
    - Implement submitToGemini() using Gemini Interactions API with server-side context caching
    - Leverage caching headers to reduce token costs on repeated evaluations
    - Return BatchResponse with verdicts array, processing time, tokens consumed
    - Track batch metrics: total processed, average size, average latency, rate limit hits, cache hit rate
    - _Requirements: 2.1, 2.6, 2.7, 5.2_
  
  - [ ] 6.2 Implement exponential backoff for APIRateLimitException handling
    - Detect APIRateLimitException from Gemini API response
    - Apply exponential backoff delays: 100ms, 200ms, 400ms for retries 1, 2, 3
    - Retry batch submission maximum 3 times
    - **FAIL-CLOSED:** If all retries fail, apply fail-closed policy: return QUARANTINE verdicts (not ALLOW) with warning logs and elevated monitoring flags
    - Log all rate limit hits with timestamp and batch details
    - _Requirements: 2.2, 2.3, 2.4, 12.3_
  
  - [ ] 6.3 Implement batch processing metrics tracking and reporting
    - Track ResolverMetrics: total batches, average batch size, average latency
    - Track rate limit hits and cache hit rate from Gemini API responses
    - Expose getMetrics() method returning ResolverMetrics structure
    - Target average batch size >= 3 (batch efficiency requirement)
    - Target 99th percentile latency < 300ms
    - Log metrics periodically for monitoring dashboards
    - _Requirements: 2.6, 2.7, 2.8, 13.6, 13.8_
  
  - [ ]* 6.4 Write unit tests for Batch Resolver
    - Test token bucket rate limiter enforces 300 RPM cap (sliding window)
    - Test exponential backoff on APIRateLimitException (100ms, 200ms, 400ms)
    - **FAIL-CLOSED:** Test fallback to QUARANTINE verdicts (not ALLOW) after 3 failed retries
    - Test batch metrics tracking correctness
    - Test server-side context caching integration
    - Test Context Hygiene sanitization applied before API call
    - Mock Gemini API responses for deterministic testing
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

  - [ ] 6.5 Test rate limit compliance property
    - **Property 9: Rate Limit Compliance**
    - **Validates: Requirements 2.1, 13.7**
    - Using hypothesis, generate sequences of up to 600 batch submissions within any 60-second window
    - Assert total API calls submitted by Batch_Resolver within any 60-second sliding window is at most 300
    - Verify token bucket algorithm enforces the 300 RPM ceiling across randomized burst patterns

- [ ] 7. Implement Structural Gating Engine with YAML policy evaluation
  - [ ] 7.1 Create StructuralGatingEngine with YAML policy loader and rule evaluation
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
  
  - [ ] 7.2 Implement hot-reload for YAML policy updates without restart
    - Watch policy file for modifications using file system events (watchdog library)
    - Reload policy automatically on file change detection
    - Validate new policy before applying (schema check, rule ID uniqueness)
    - Atomically swap policy state to prevent race conditions during reload
    - Log policy reload events with version change
    - Reject invalid configurations and retain previous valid policy
    - _Requirements: 3.14, 14.9_
  
  - [ ]* 7.3 Write unit tests for Structural Gating Engine
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

- [ ] 8. Implement GTI MCP integration with circuit breaker pattern
  - [ ] 8.1 Create GTIMCPClient for VirusTotal API queries with caching and resilience
    - Implement queryIOC() for IP/domain/URL/hash reputation checks
    - Support indicator types: IP_ADDRESS, DOMAIN, URL, FILE_HASH
    - Parse GTIResponse with: isMalicious, threatCategories, detectionRate, confidence score
    - Include related malware campaign identifiers and last analysis date
    - Implement 24-hour TTL caching for responses (86400 seconds) stored in local SQLite (no Redis)
    - Handle 5-second query timeout using asyncio.wait_for() (cooperative cancellation)
    - Implement circuit breaker: switch to degraded mode after 5 consecutive failures
    - Apply default threat score penalty of 0.3 in degraded mode (missing GTI signal)
    - Auto-retry after 60-second cooldown period
    - Restore full GTI integration after 3 consecutive successful retries
    - Handle API rate limit responses with exponential backoff
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 7.10, 7.11, 12.1, 12.2, 21.1, 21.2, 21.3_
  
  - [ ]* 8.2 Write unit tests for GTI MCP integration
    - Test IOC query for malicious IP returns isMalicious=true
    - Test threat categories extraction (malware, botnet, C2, phishing)
    - Test detection rate calculation
    - Test 24-hour cache TTL reduces redundant API calls
    - Test 5-second timeout via asyncio.wait_for() triggers circuit breaker
    - Test circuit breaker switches to degraded mode after 5 failures
    - Test 60-second cooldown period before retry
    - Test threat score penalty of 0.3 applied in degraded mode
    - Test 3 successful retries restore full integration
    - Mock VirusTotal API responses for deterministic testing
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.11, 12.1, 12.2, 21.2, 21.3_

- [ ] 9. Implement codebase-memory MCP integration with AST analysis
  - [ ] 9.1 Create CodebaseMemoryClient for AST-based structural analysis
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
  
  - [ ]* 9.2 Write unit tests for codebase-memory integration
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

- [ ] 10. Implement Semantic Gating Engine with multi-source threat scoring
  - [ ] 10.1 Create SemanticGatingEngine with LLM-based intent analysis and signal aggregation
    - Implement evaluate() querying Threat Signature Graph first (cheapest check)
    - Extract IOCs from context: IP addresses, URLs, domains, file hashes
    - Query GTI MCP for each IOC if no signature match found
    - Query codebase-memory MCP if context.targetFunction is present
    - Implement computeThreatScore() with weighted signal aggregation:
      * GTI signal: 40% weight (isMalicious, detectionRate, threat category severity)
      * CBM signal: 30% weight (critical sinks, unsafe flag, blast radius risk score)
      * Context signal: 30% weight (tool name risk, argument novelty, environment role)
    - Normalize final threat score to [0.0, 1.0] range
    - Apply verdict thresholds: >=0.75 BLOCK, >=0.5 QUARANTINE, <0.5 ALLOW
    - Redistribute signal weights proportionally when GTI or CBM unavailable
    - Return GateResult with verdict, reason, threat score, signature ID
    - Ensure deterministic scoring: same inputs → same score
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8, 23.9, 23.10_
  
  - [ ] 10.2 Test threat score bounded property
    - **Property 3: Threat Score Bounded**
    - **Validates: Requirements 3.10, 23.6, 23.7**
    - Generate diverse ToolCallContext samples with hypothesis
    - Generate random GTIResponse and CBMResponse combinations
    - Compute threat score for each combination
    - Assert all scores are in range [0.0, 1.0]
    - Verify BLOCK verdict only when score >= 0.75
    - Verify QUARANTINE verdict when 0.5 <= score < 0.75
    - Verify ALLOW verdict when score < 0.5
  
  - [ ]* 10.3 Write unit tests for Semantic Gating Engine
    - Test signature matching returns BLOCK with signatureId
    - Test signature match count increment on successful match
    - Test GTI malicious IOC increases threat score appropriately
    - Test CBM critical sink detection increases threat score
    - Test weighted threat score aggregation formula (GTI 40%, CBM 30%, Context 30%)
    - Test verdict thresholds: 0.75 BLOCK, 0.5 QUARANTINE, <0.5 ALLOW
    - Test signal weight redistribution when GTI unavailable
    - Test signal weight redistribution when CBM unavailable
    - Test deterministic scoring for identical inputs
    - Test threat score included in verdict structure
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 23.1, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8, 23.9, 23.10_

- [ ] 11. Implement Hybrid Policy Server orchestrating structural and semantic gating
  - [ ] 11.1 Create HybridPolicyServer coordinating dual-layer evaluation
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
  
  - [ ] 11.2 Test verdict array order correspondence property
    - **Property 2: Verdict Array Correspondence**
    - **Validates: Requirements 3.1, 1.5, 19.1, 19.2**
    - Generate batch of 10-50 diverse ToolCallContext objects using hypothesis
    - Process batch through HybridPolicyServer.evaluateBatch()
    - Assert verdict array length equals input context array length
    - Verify verdict[i] corresponds to context[i] for all i in range
    - Test with random mix of BLOCK, ALLOW, ESCALATE conditions
  
  - [ ]* 11.3 Write integration tests for Hybrid Policy Server
    - Test structural BLOCK skips semantic evaluation (fast path)
    - Test structural ALLOW without review skips semantic (fast path)
    - Test structural ESCALATE triggers semantic gating
    - Test batch processing returns correctly ordered verdicts
    - Test end-to-end flow with mocked GTI and CBM queries
    - Test policy hot-reload updates rules without restart
    - Test parallel batch processing maintains order consistency
    - **FAIL-CLOSED:** Test rate limit or timeout returns QUARANTINE verdicts (not ALLOW)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.14, 19.1, 19.2_

- [ ] 12. Checkpoint - Ensure core interception pipeline is functional
  - Run integration tests for Interception Queue + Batch Resolver + Hybrid Policy Server
  - Verify <300ms latency for semantic evaluation with GTI/CBM queries (99th percentile)
  - Verify <5ms latency for structural fast-path (99th percentile)
  - Verify batch efficiency: 80% of API calls use batch size >= 3
  - Ask the user if questions arise

- [ ] 13. Implement Agent Behavioral Analytics for signature generation and drift detection
  - [ ] 13.1 Create AgentBehavioralAnalytics with signature generation pipeline
    - Implement scoreEvent() calculating behavioral drift using LLM-as-judge (0-5 scale)
    - Implement detectDrift() analyzing agent behavior across time windows
    - Detect anomalies when drift exceeds tolerance band ±0.5 from baseline
    - Implement generateSignature() extracting attacker intent from BLOCK verdict events
    - Use semantic gating reason field to extract LLM-derived intent summary
    - Generalize payload patterns: replace specific values (IPs, paths) with typed placeholders
    - **NO REDUNDANT CBM QUERY:** Read dependency chain from SecurityEvent.cbmResponse if present (populated upstream by Hybrid_Policy_Server during evaluation); do NOT issue a new Codebase_Memory_MCP query
    - Generate 384-dimensional embedding vector using sentence-transformers model
    - Combine attacker intent + generalized payload + tool name for embedding
    - Determine mitigation action based on critical sinks and GTI threat categories
    - Create ThreatSignature with all required fields and metadata
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 17.1, 17.2, 17.10, 24.1, 24.2_
  
  - [ ] 13.2 Implement Green Team auto-refactoring for QUARANTINE verdicts
    - Implement triggerRefactoring() analyzing quarantined code paths
    - Identify specific vulnerability type from CBM critical sink type
    - Generate RefactoringHint with: target code, vulnerability description, suggested fix, confidence
    - Provide concrete remediation: "Use parameterized queries" for SQL injection
    - Complete analysis within 5 seconds to avoid blocking agent execution
    - Write threat signature with refactoring hint in metadata
    - _Requirements: 5.10, 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.9_
  
  - [ ] 13.3 Implement Runtime AgBOM tracking and capability drift detection
    - Implement updateAgBOM() recording tool usage, frequencies, argument patterns
    - Maintain real-time inventory of agent capabilities
    - Track external APIs called by agent tools
    - Detect capability drift: new tools used without policy approval
    - Log anomaly events when unexpected tools appear
    - Export AgBOM as structured JSON for audit and compliance
    - _Requirements: 5.11, 10.9_
  
  - [ ]* 13.4 Write unit tests for Agent Behavioral Analytics
    - Test signature generation from BLOCK verdict event
    - Test payload generalization (IPs → [[IP_ADDRESS]], paths → [[FILE_PATH]])
    - Test attacker intent extraction from semantic gating reason
    - Test embedding vector generation (384 dimensions)
    - Test mitigationAction determination based on signals
    - Test behavioral drift detection with tolerance band ±0.5
    - Test Green Team refactoring hint generation for SQL injection
    - Test refactoring analysis completes within 5 seconds
    - Test AgBOM update on new tool usage
    - Test capability drift anomaly logging
    - Test no redundant CBM query when cbmResponse is present
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 16.3, 16.4, 16.9, 17.1, 17.2_

- [ ] 14. Implement OpenTelemetry instrumentation and observability
  - [ ] 14.1 Create OpenTelemetry tracer for distributed tracing
    - Initialize OpenTelemetry SDK with trace provider and OTLP exporter
    - Implement span creation for each SecurityEvent with unique trace ID
    - Include in spans: tool call details, verdict decision, threat score, signature match ID
    - Include GTI response summary (threat categories, detection rate)
    - Include CBM response summary (critical sinks, blast radius)
    - Implement distributed tracing across Blackwall, GTI_MCP, CBM, ADK components
    - Aggregate traces to visualize Vibe Trajectory (attack pattern evolution)
    - Compress spans before export to keep bandwidth < 100KB/s
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.8_
  
  - [ ] 14.2 Implement Prometheus metrics export
    - Export metrics: total interceptions, verdicts by type (BLOCK/ALLOW/QUARANTINE)
    - Export average threat scores, API latency percentiles
    - Export batch sizes, cache hit rates (GTI, TSG), error counts
    - Expose metrics endpoint for Prometheus scraping (/metrics)
    - Create Grafana dashboard JSON for FRR/Evasion Rate trends
    - Visualize threat score distributions and signature match rates
    - _Requirements: 11.5, 11.6_
  
  - [ ] 14.3 Create structured JSON logging for security events
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
  
  - [ ]* 14.4 Write unit tests for observability components
    - Test OpenTelemetry span creation with unique trace IDs
    - Test span includes verdict and threat score fields
    - Test distributed tracing context propagation
    - Test Prometheus metrics increment correctly
    - Test metrics endpoint returns valid Prometheus format
    - Test JSON log format validation against schema
    - Test log rotation on date boundary
    - Test gzip compression of rotated logs
    - _Requirements: 11.1, 11.2, 11.5, 11.7, 25.4, 25.6, 25.7_

- [ ] 15. Implement ADK integration and before_tool_callback hook
  - [ ] 15.1 Create ADK callback integration layer with thread suspension
    - Implement before_tool_callback() hook intercepting all tool calls
    - Suspend execution thread and create CallbackToken with thread context
    - Enqueue CallbackToken to Interception Queue (async await)
    - Implement resumeCallback() function applying verdict to ADK
    - Handle ALLOW verdict: proceed with tool execution normally
    - Handle BLOCK verdict: return PermissionError to agent
    - Handle QUARANTINE verdict: execute in sandboxed mock environment, return sanitized response
    - Log all callback resolutions with correlation IDs
    - _Requirements: 1.1, 1.6, 16.1, 16.2, 16.5, 16.6, 16.8_
  
  - [ ] 15.2 Implement Python Runtime Audit Hooks for bypass prevention
    - Register sys.addaudithook for os, subprocess, pty module calls
    - Deny raw execution attempts with PermissionError
    - Force all agent actions through ADK tool layer
    - Log bypass attempts as high-severity security events
    - _Requirements: 10.6, 10.7, 10.8_
  
  - [ ]* 15.3 Write integration tests for ADK callback hook
    - Test before_tool_callback suspends execution correctly
    - Test callback token creation and storage in queue
    - Test resumeCallback with ALLOW verdict executes tool
    - Test resumeCallback with BLOCK verdict returns PermissionError
    - Test resumeCallback with QUARANTINE verdict returns sanitized mock response
    - Test audit hook denies raw os/subprocess calls
    - Test bypass attempts logged as high-severity events
    - _Requirements: 1.1, 1.2, 1.6, 10.6, 10.7, 10.8, 16.1, 16.2_

- [ ] 16. Implement evaluation metrics calculator for FRR and Evasion Rate
  - [ ] 16.1 Create SecurityMetrics calculator with ground truth validation
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
  
  - [ ] 16.2 Test metrics sum validation property
    - **Property 8: Evaluation Metrics Partition Invariant**
    - **Validates: Requirements 9.1, 9.10**
    - Generate random TestResult and GroundTruthLabel arrays using hypothesis
    - Calculate SecurityMetrics for generated data
    - Assert TP + TN + FP + FN equals total tests (sum validation)
    - Verify all percentage values in [0.0, 100.0] range
    - Test empty test suite returns zeros without errors
  
  - [ ]* 16.3 Write unit tests for metrics calculator
    - Test FRR calculation with known benign/malicious counts
    - Test Evasion Rate calculation correctness
    - Test accuracy, precision, recall formulas
    - Test F1 score calculation
    - Test JSON export format matches required schema with correct key names
    - **QUARANTINE MALICIOUS = TP:** Test QUARANTINE on MALICIOUS counts as true positive
    - **QUARANTINE BENIGN = FP:** Test QUARANTINE on BENIGN counts as false positive (affects FRR)
    - Test quarantineCount increments for all QUARANTINE verdicts
    - Test metrics meet targets: FRR < 10%, Evasion Rate < 10%
    - **EMPTY SUITE GUARD:** Test empty suite returns zeros without errors or division by zero
    - Test zero-division guards for precision, recall, F1 when denominators are zero
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 9.11, 9.13, 9.14, 9.15_

- [ ] 17. Implement Zero Ambient Authority and JIT token downscoping
  - [ ] 17.1 Create privilege management and credential handling system
    - Drop OS privileges for Blackwall agent process (run as unprivileged user)
    - Implement JIT (Just-In-Time) token downscoping per intercepted tool call
    - Fetch temporary scoped credentials from secure vault on-demand
    - Revoke credentials immediately after tool call completion
    - Never store long-lived API keys in process memory
    - Implement credential vault integration (HashiCorp Vault or local encrypted store)
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_
  
  - [ ]* 17.2 Write security tests for Zero Ambient Authority
    - Test Blackwall process runs as unprivileged user (UID check)
    - Test temporary credentials are revoked after tool execution
    - Test no long-lived keys found in memory dump simulation
    - Test audit hook blocks raw execution bypasses
    - Test credentials fetched on-demand from vault
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6, 10.7_

- [ ] 18. Implement error handling, circuit breakers, and resilience
  - [ ] 18.1 Create comprehensive error handling with graceful degradation
    - GTI circuit breaker implementation (already in task 8.1)
    - SQLite write retry with exponential backoff (already in task 4.2)
    - In-memory buffer for failed signature writes (already in task 4.2)
    - **FAIL-CLOSED:** Implement emergency fallback for evaluation timeout > 10 seconds: return QUARANTINE verdicts (not ALLOW)
    - **THREAD-SAFE TIMEOUT:** Implement async task cancellation using asyncio.wait_for() with 30-second hard timeout — asyncio.wait_for() raises TimeoutError to the caller and internally cancels the wrapped coroutine; handle TimeoutError (not CancelledError) at the call site
    - **ALTERNATIVE THREAD-SAFE TIMEOUT:** OR use subprocess.Popen isolation with 30-second timeout and SIGKILL process termination if deadline exceeded
    - On TimeoutError or process termination, auto-restart evaluation pipeline and log critical error
    - Auto-disable regex patterns causing timeout > 100ms after 10 consecutive failures; emit operator alert on disable
    - Log all error recovery actions with severity levels
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.10, 12.11, 12.12_
  
  - [ ]* 18.2 Write resilience and failure mode tests
    - Test SQLite retry logic on transient lock errors
    - Test in-memory buffer overflow handling (drop oldest entries)
    - **FAIL-CLOSED:** Test emergency fallback on 10-second evaluation timeout returns QUARANTINE (not ALLOW)
    - **THREAD-SAFE TIMEOUT:** Test asyncio.wait_for() on frozen evaluation raises TimeoutError at call site (not CancelledError)
    - Test subprocess termination if using process isolation (30-second timeout with SIGKILL)
    - Test auto-restart after timeout-induced termination
    - Test regex pattern auto-disable on 10 consecutive timeouts with operator alert
    - Test GTI circuit breaker degraded mode (already covered in 8.2)
    - _Requirements: 12.4, 12.5, 12.6, 12.7, 12.8, 12.10, 12.11, 12.12_

- [ ] 19. Checkpoint - Ensure complete system is functional
  - Run end-to-end integration tests with all components connected
  - Verify FRR < 10% and Evasion Rate < 10% on test suite
  - Verify all latency targets met: 5ms structural, 300ms semantic (99th percentile)
  - Verify memory usage < 512MB RSS during sustained operation
  - Verify CPU usage < 50% on 2-core VM during sustained 300 RPM load
  - Ask the user if questions arise

- [ ] 20. Implement embedding model management with fallback strategies
  - [ ] 20.1 Create embedding model lifecycle with degraded mode fallback
    - Load Sentence Transformers model on startup (384-dimensional vectors)
    - Cache model in memory for fast inference
    - Implement fallback to FTS5 full-text search on model failure
    - Reduce similarity threshold to 0.7 in degraded mode
    - Log all queries using FTS5 fallback
    - Implement background job to regenerate vectors when model restored
    - Validate all vectors have exactly 384 dimensions
    - Exclude signatures with inconsistent dimensionality from queries
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7, 24.8, 24.9, 24.10_
  
  - [ ]* 20.2 Write unit tests for embedding model management
    - Test model loads successfully on startup
    - Test degraded mode switches to FTS5 on model crash
    - Test similarity threshold reduces to 0.7 in degraded mode
    - Test vector regeneration background job
    - Test dimension consistency validation (384 floats)
    - Test exclusion of inconsistent vectors from queries
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.9, 24.10_

- [ ] 21. Create comprehensive test data sets for evaluation
  - [ ] 21.1 Generate malicious test cases (minimum 50)
    - Create SQL injection payloads (various techniques)
    - Create command injection payloads (shell metacharacters)
    - Create malicious IP/URL tool calls (known C2 servers)
    - Create file path traversal attacks (../../../etc/passwd)
    - Create reverse shell attempts (curl | bash, nc listeners)
    - Create credential exfiltration attempts
    - Create obfuscated payload variants (base64, URL encoding)
    - Label all with ground truth: MALICIOUS
    - _Requirements: 9.1, 15.1, 15.2, 15.3, 15.4_
  
  - [ ] 21.2 Generate benign test cases (minimum 50)
    - Create legitimate database query tool calls
    - Create valid file read operations within allowed paths
    - Create authorized network requests to known safe endpoints
    - Create normal agent tool usage patterns from AGENTS.md specification
    - Create edge cases: unusual but valid operations
    - Label all with ground truth: BENIGN
    - _Requirements: 9.1, 15.5, 15.6_
  
  - [ ] 21.3 Generate adaptive evasion test cases (minimum 20)
    - Create second-attempt variants of blocked attacks
    - Apply obfuscation transformations to known malicious payloads
    - Test structural similarity detection against existing signatures
    - Verify signature-based blocking catches modified attacks
    - _Requirements: 9.7, 15.7, 15.8, 26.1, 26.2_

- [ ] 22. Run formal evaluation and generate metrics report
  - [ ] 22.1 Execute full evaluation suite against test data sets
    - Run all malicious test cases through complete interception pipeline
    - Run all benign test cases through complete interception pipeline
    - Run all adaptive evasion test cases through complete pipeline
    - Collect all verdicts with timestamps and processing times
    - Save raw results to JSON for analysis
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 15.1, 15.2_
  
  - [ ] 22.2 Generate SecurityMetrics report with FRR and Evasion Rate
    - Calculate FRR, Evasion Rate, accuracy, precision, recall, F1 from collected results
    - **METRIC NAMES:** Export JSON with standardized keys: false_refusal_rate, evasion_rate, accuracy, precision, recall, f1_score, quarantine_count
    - Verify FRR < 10% target achieved
    - Verify Evasion Rate < 10% target achieved
    - Generate human-readable summary for demo README
    - _Requirements: 9.5, 9.6, 9.7, 9.8, 9.9, 9.10, 9.11, 9.12, 9.13, 9.14, 9.15_
  
  - [ ] 22.3 Validate self-learning signature effectiveness
    - Run initial attack wave and verify signatures generated
    - Run modified second-wave attacks and verify blocked by generated signatures
    - Measure signature match rate improvement over time
    - Log all dynamically generated signatures with timestamps
    - _Requirements: 5.1, 5.2, 5.3, 26.1, 26.2, 26.3_

- [ ] 23. Implement demo harness and dual-agent showdown setup
  - [ ] 23.1 Create demo orchestration script for dual-agent showdown
    - Write scripts/run_demo.sh launching Blackwall as ambient daemon via adk run
    - Write scripts/run_rogue.py launching adversarial agent with configured attack sequences
    - Implement split-screen terminal recording setup
    - Configure Blackwall daemon to log to visible terminal output
    - Configure rogue agent to show attempt outputs and failures
    - _Requirements: 27.1, 27.2, 27.3, 28.1, 28.2_
  
  - [ ] 23.2 Configure sandbox environment with Python audit hooks
    - Register sys.addaudithook blocking raw os/subprocess/pty calls at process start
    - Configure Blackwall to run as unprivileged user (dropped OS privileges)
    - Set up mock vulnerable target application (simple Flask app with SQL injection surface)
    - Configure rogue agent (Qwen3-Coder via Hyperbolic API) with attack tool set
    - Validate audit hooks active before demo execution
    - _Requirements: 10.6, 10.7, 10.8, 27.4, 27.5_
  
  - [ ]* 23.3 Write smoke tests for demo harness
    - Test Blackwall daemon starts successfully via adk run
    - Test audit hook blocks raw subprocess calls
    - Test rogue agent tool calls are intercepted by before_tool_callback
    - Test first-attempt attack blocked by semantic evaluation
    - Test second-attempt attack blocked by signature match
    - _Requirements: 27.1, 27.2, 26.1, 26.2_

- [ ] 24. Implement YAML policy configuration for demo scenarios
  - [ ] 24.1 Create policy.yaml with production-ready rules for demo
    - Define environment roles: PRODUCTION, STAGING, DEVELOPMENT, SANDBOX
    - Write structural rules blocking known dangerous tool names immediately (BLOCK)
    - Write structural rules for privileged operations requiring semantic review (ESCALATE_TO_SEMANTIC)
    - Write structural rules for safe read-only operations in DEVELOPMENT (ALLOW)
    - Set semantic thresholds in config: block_threshold=0.75, quarantine_threshold=0.5
    - Configure MCP endpoints: GTI_MCP URL, CBM_MCP URL
    - Set policy version with semantic versioning (1.0.0)
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7_
  
  - [ ] 24.2 Write YAML policy validation tests
    - Test all rule IDs are unique in policy.yaml
    - Test schema validation passes for all rules
    - Test priority ordering covers expected evaluation sequence
    - Test BLOCK rules fire for known malicious tool names
    - Test ESCALATE rules fire for write/network operations
    - Test ALLOW rules fire for safe read-only operations
    - _Requirements: 14.1, 14.2, 14.10, 22.1, 22.2, 22.7_

- [ ] 25. Write project documentation and README
  - [ ] 25.1 Create comprehensive README.md
    - Write project overview describing Blackwall's mission and architecture
    - Include architecture diagram (Mermaid) showing all components and data flow
    - Provide setup instructions: dependencies, environment variables, API keys
    - Document demo execution steps with expected outputs
    - Include evaluation results table showing FRR and Evasion Rate
    - Add security architecture section explaining Zero Ambient Authority
    - Include BDD scenario examples from design.md for context
    - _Requirements: 28.1, 28.2, 28.3_
  
  - [ ] 25.2 Create ARCHITECTURE.md with technical deep-dive
    - Document Hybrid Policy Server dual-layer evaluation flow
    - Explain asynchronous batching architecture and callback queue management
    - Describe SQLite Threat Signature Graph schema and query patterns
    - Document GTI MCP and codebase-memory MCP integration patterns
    - Explain Agent Behavioral Analytics signature generation pipeline
    - Include OpenTelemetry distributed tracing design
    - Document security constraints: fail-closed defaults, Zero Ambient Authority
    - _Requirements: 28.3, 28.4_
  
  - [ ] 25.3 Write KAGGLE_SUBMISSION.md with competition narrative
    - Describe the dual-agent showdown scenario and key design decisions
    - Highlight innovative aspects: self-learning signatures, runtime AgBOM, LLM-as-judge scoring
    - Summarize evaluation results and what they demonstrate
    - Include lessons learned and potential extensions
    - _Requirements: 28.5_

- [ ] 26. Implement self-learning loop integration and end-to-end validation
  - [ ] 26.1 Integrate signature generation into live interception pipeline
    - Wire ABA.generateSignature() to fire after every BLOCK verdict in the pipeline
    - Wire ABA.triggerRefactoring() to fire after every QUARANTINE verdict
    - Confirm ThreatSignature written to TSG with correct embedding and metadata
    - Confirm OpenTelemetry span records signature creation event
    - Confirm SecurityEvent logged with eventType=SIGNATURE_CREATED and verdict=None
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.12, 11.1_
  
  - [ ] 26.2 Validate adaptive defense against repeated attacks
    - Execute first novel attack → verify BLOCK via semantic evaluation
    - Verify ThreatSignature created in TSG for that attack
    - Execute structurally-similar second attack → verify BLOCK via signature match (TSG)
    - Verify signature match faster than first-attempt semantic evaluation
    - Verify match_count incremented on signature after second match
    - _Requirements: 5.1, 6.9, 6.10, 6.11, 26.1, 26.2, 26.3_
  
  - [ ]* 26.3 Write end-to-end integration tests for self-learning loop
    - Test full pipeline: intercept → evaluate → block → generate signature → block similar
    - Test signature embedding generated correctly from BLOCK event fields
    - Test second attack matches with similarity >= 0.85
    - Test signature match_count increments on repeated attack patterns
    - Test QUARANTINE events trigger Green Team refactoring hints
    - _Requirements: 5.1, 5.2, 5.3, 5.7, 5.8, 6.9, 16.3_

- [ ] 27. Performance benchmarking and resource validation
  - [ ] 27.1 Create performance benchmark suite
    - Benchmark structural gating latency under simulated load (100 concurrent requests)
    - Benchmark semantic gating latency with GTI/CBM mock responses
    - Benchmark TSG query latency with 10,000 signatures in database
    - Measure memory RSS during sustained 300 RPM processing
    - Measure CPU utilization during sustained 300 RPM processing
    - Generate percentile report: p50, p95, p99 for all latency measurements
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9_
  
  - [ ]* 27.2 Validate performance targets
    - Assert structural gating p99 latency < 5ms
    - Assert semantic gating p99 latency < 300ms
    - Assert TSG query p99 latency < 10ms
    - Assert memory RSS < 512MB under sustained load
    - Assert CPU usage < 50% on 2-core under 300 RPM
    - Assert average batch size >= 3 at full load
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9_

- [ ] 28. Final integration, packaging, and submission preparation
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
- **Checkpoint Tasks:** Tasks 12 and 19 are checkpoints for user feedback. Pause at these points to verify system functionality before proceeding.
- **Kaggle Submission Requirements:** Tasks 21-28 focus on demo preparation, evaluation, and documentation for the Kaggle AI Agents hackathon.
- **12 Correctness Properties:** The design document defines 12 formal correctness properties with explicit requirements traceability. Property tests in this task list validate these properties.
- **28 Requirements with EARS Criteria:** All 28 requirements from requirements.md have EARS-compliant acceptance criteria (WHEN/IF/WHILE/WHERE/FOR ANY conditions with THE system SHALL actions).

## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["1", "2.1"]
    },
    {
      "id": 1,
      "tasks": ["2.2", "3.1", "4.1"]
    },
    {
      "id": 2,
      "tasks": ["3.2", "3.3", "3.3b", "4.2", "4.3", "4.4", "5.1", "7.1"]
    },
    {
      "id": 3,
      "tasks": ["4.5", "4.5b", "4.6", "4.7", "4.8", "4.9", "5.2", "5.3", "7.2", "7.3", "8.1"]
    },
    {
      "id": 4,
      "tasks": ["6.1", "8.2", "9.1"]
    },
    {
      "id": 5,
      "tasks": ["6.2", "6.3", "6.4", "6.5", "9.2", "10.1"]
    },
    {
      "id": 6,
      "tasks": ["10.2", "10.3", "11.1"]
    },
    {
      "id": 7,
      "tasks": ["11.2", "11.3", "12"]
    },
    {
      "id": 8,
      "tasks": ["13.1", "13.2", "13.3", "14.1", "15.1"]
    },
    {
      "id": 9,
      "tasks": ["13.4", "14.2", "14.3", "15.2"]
    },
    {
      "id": 10,
      "tasks": ["14.4", "15.3", "16.1", "17.1"]
    },
    {
      "id": 11,
      "tasks": ["16.2", "16.3", "17.2", "18.1", "20.1"]
    },
    {
      "id": 12,
      "tasks": ["18.2", "19", "20.2"]
    },
    {
      "id": 13,
      "tasks": ["21.1", "21.2"]
    },
    {
      "id": 14,
      "tasks": ["21.3", "22.1", "24.1"]
    },
    {
      "id": 15,
      "tasks": ["22.2", "22.3", "23.1", "24.2"]
    },
    {
      "id": 16,
      "tasks": ["23.2", "23.3", "25.1", "26.1"]
    },
    {
      "id": 17,
      "tasks": ["25.2", "25.3", "26.2", "27.1"]
    },
    {
      "id": 18,
      "tasks": ["26.3", "27.2"]
    },
    {
      "id": 19,
      "tasks": ["28"]
    }
  ]
}
```

