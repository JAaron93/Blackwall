# Requirements Document

## Introduction

Blackwall is an autonomous Agentic Firewall system designed for the Kaggle AI Agents hackathon that intercepts and evaluates AI agent execution flows before they reach external systems or the host operating system. The system implements a hybrid defense architecture combining structural YAML-based policies with semantic LLM-based intent analysis, operating through ADK 2.0's `before_tool_callback` hook to physically pause suspicious executions. Blackwall leverages self-learning threat signature graphs stored in SQLite, real-time threat intelligence from Google Threat Intelligence (GTI), and structural code analysis to dynamically generate defensive capabilities with zero static allowlists. The system must maintain sub-10% false positive and false negative rates while processing attack rates up to 600 RPM using a 300 RPM Gemini API constraint through asynchronous batched evaluation.

## Glossary

- **Blackwall**: The autonomous Agentic Firewall system that intercepts and evaluates AI agent tool calls
- **ADK**: Agent Development Kit 2.0, the runtime environment providing the `before_tool_callback` hook
- **Interception_Queue**: Thread-safe FIFO queue holding suspended ADK tool callbacks during batch accumulation
- **Batch_Resolver**: Component orchestrating asynchronous batched API calls to Gemini while managing 300 RPM rate limits
- **Hybrid_Policy_Server**: Dual-layer threat evaluation engine combining structural and semantic gating
- **Structural_Gating**: Fast deterministic YAML-based policy evaluation (<5ms target latency)
- **Semantic_Gating**: Deep LLM-based intent analysis using GTI and codebase analysis
- **Context_Hygiene**: Regex-based sanitization middleware that strips sensitive data before policy evaluation
- **Agent_Behavioral_Analytics**: Runtime monitoring engine tracking behavioral drift and generating threat signatures
- **Threat_Signature_Graph**: SQLite-backed semantic graph database storing learned threat patterns
- **GTI_MCP**: Google Threat Intelligence Model Context Protocol server providing VirusTotal IOC validation
- **Codebase_Memory_MCP**: AST-based code analysis server identifying critical sinks and dependency chains
- **Callback_Token**: Data structure holding suspended thread context and resume function
- **Verdict**: Decision structure containing ALLOW/BLOCK/QUARANTINE decision with threat score and reasoning
- **Threat_Signature**: Learned attack pattern with generalized payload, intent, and similarity vector
- **IOC**: Indicator of Compromise (IP address, domain, URL, file hash)
- **Critical_Sink**: Code location where untrusted input reaches dangerous operations (SQL, command execution, file I/O)
- **FRR**: False Refusal Rate, percentage of benign actions incorrectly blocked (false positives)
- **Evasion_Rate**: Percentage of malicious actions that bypass detection (false negatives)
- **AgBOM**: Agent Bill of Materials, real-time inventory of agent capabilities and tool usage
- **WAL_Mode**: Write-Ahead Logging mode in SQLite enabling concurrent read/write access
- **Zero_Ambient_Authority**: Security principle requiring minimal OS privileges and JIT token downscoping
- **Vibe_Trajectory**: OpenTelemetry distributed trace showing attack pattern evolution over time
- **Green_Team**: Auto-refactoring system analyzing quarantined code paths for vulnerabilities

## Requirements

### Requirement 1: Tool Call Interception and Queue Management

**User Story:** As a security operator, I want Blackwall to intercept all AI agent tool calls before execution, so that I can evaluate and block malicious operations before they reach external systems.

#### Acceptance Criteria

1. WHEN an AI agent executes any tool call through ADK, THE Interception_Queue SHALL suspend the execution thread via the before_tool_callback hook
2. WHEN a tool call is suspended, THE Interception_Queue SHALL store a Callback_Token containing the thread ID, timestamp, tool name, arguments, and resume function
3. WHILE the Interception_Queue is accumulating callbacks, THE Batch_Resolver SHALL collect up to 5 callbacks OR wait a maximum of 100 milliseconds before processing
4. WHEN the batch size reaches 5 callbacks OR the 100ms timeout expires, THE Batch_Resolver SHALL flush the partial batch to prevent deadlock
5. WHEN a verdict array is returned from policy evaluation, THE Interception_Queue SHALL map each verdict to its corresponding Callback_Token by array index
6. FOR ANY Callback_Token enqueued, THE Interception_Queue SHALL resume the suspended thread exactly once with a valid verdict
7. IF the Interception_Queue size exceeds 50 callbacks, THE system SHALL trigger emergency batch flushing
8. WHILE processing batches, THE Interception_Queue SHALL maintain thread safety using asynchronous locks

### Requirement 2: Asynchronous Batch Processing and Rate Limiting

**User Story:** As a system architect, I want Blackwall to handle 600 RPM attack rates using a 300 RPM Gemini API through efficient batching, so that the system can defend against attackers with twice the API throughput.

#### Acceptance Criteria

1. WHEN submitting batches to the Gemini API, THE Batch_Resolver SHALL track a sliding 60-second window ensuring no more than 300 requests per minute
2. IF the rate limit is reached, THE Batch_Resolver SHALL apply exponential backoff with delays of 100ms, 200ms, and 400ms for subsequent retries
3. WHEN rate limit backoff is applied, THE Batch_Resolver SHALL retry the batch submission a maximum of 3 times
4. IF all retry attempts fail due to APIRateLimitException, THE Batch_Resolver SHALL return QUARANTINE verdicts with warning logs and elevated monitoring flags (fail closed)
5. WHEN processing batches, THE Batch_Resolver SHALL leverage server-side context caching in the Gemini API to reduce token costs
6. THE Batch_Resolver SHALL achieve an average batch size greater than or equal to 3 callbacks per API request
7. WHEN API calls succeed, THE Batch_Resolver SHALL log metrics including batch size, processing time, tokens consumed, and cache hit rate
8. THE Batch_Resolver SHALL maintain batch processing latency below 300 milliseconds for the 99th percentile


### Requirement 3: Hybrid Policy Server Evaluation

**User Story:** As a security engineer, I want a dual-layer policy evaluation system combining fast structural rules with deep semantic analysis, so that benign operations complete quickly while novel threats receive thorough evaluation.

#### Acceptance Criteria

1. WHEN evaluating a tool call context, THE Hybrid_Policy_Server SHALL first execute Structural_Gating using YAML-based rules
2. THE Structural_Gating evaluation SHALL complete within 5 milliseconds for the 99th percentile
3. IF Structural_Gating returns BLOCK, THE Hybrid_Policy_Server SHALL immediately return a BLOCK verdict without semantic evaluation
4. IF Structural_Gating returns ALLOW with requireSemanticReview set to false, THE Hybrid_Policy_Server SHALL immediately return an ALLOW verdict
5. IF Structural_Gating returns ESCALATE_TO_SEMANTIC, THE Hybrid_Policy_Server SHALL proceed to Semantic_Gating evaluation
6. WHEN Semantic_Gating evaluates a context, THE system SHALL query the Threat_Signature_Graph for similar attack patterns with similarity threshold 0.85
7. IF a matching signature is found, THE Hybrid_Policy_Server SHALL return a BLOCK verdict and increment the signature match count
8. IF no matching signature is found AND the context contains IOCs, THE Hybrid_Policy_Server SHALL query GTI_MCP for threat intelligence
9. IF the context references code functions, THE Hybrid_Policy_Server SHALL query Codebase_Memory_MCP for dependency chains and critical sinks
10. WHEN aggregating signals from GTI_MCP, Codebase_Memory_MCP, and context analysis, THE Hybrid_Policy_Server SHALL compute a threat score in the range 0.0 to 1.0
11. IF the threat score is greater than or equal to 0.75, THE Hybrid_Policy_Server SHALL return a BLOCK verdict
12. IF the threat score is greater than or equal to 0.5 AND less than 0.75, THE Hybrid_Policy_Server SHALL return a QUARANTINE verdict
13. IF the threat score is less than 0.5, THE Hybrid_Policy_Server SHALL return an ALLOW verdict with monitoring flag
14. THE Hybrid_Policy_Server SHALL support hot-reload of YAML policy files without system restart

### Requirement 4: Context Hygiene and Data Sanitization

**User Story:** As a privacy engineer, I want all tool call contexts sanitized before policy evaluation, so that sensitive data never reaches the LLM and context hallucination is prevented.

#### Acceptance Criteria

1. WHEN Context_Hygiene receives a tool call context, THE system SHALL apply regex-based redaction patterns to the raw arguments
2. THE Context_Hygiene SHALL replace API keys matching pattern `(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})` with placeholder [[API_KEY]]
3. THE Context_Hygiene SHALL replace IP addresses matching pattern `\b(?:\d{1,3}\.){3}\d{1,3}\b` with placeholder [[IP_ADDRESS]]
4. THE Context_Hygiene SHALL replace file paths matching pattern `(?:/[^/\s]+)+/?` with placeholder [[FILE_PATH]]
5. THE Context_Hygiene SHALL replace passwords matching pattern `(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)` with placeholder [[PASSWORD]]
6. THE Context_Hygiene SHALL replace email addresses matching pattern `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` with placeholder [[EMAIL]]
7. THE Context_Hygiene SHALL replace URLs matching pattern `https?://[^\s]+` with placeholder [[URL]]
8. WHEN redacting sensitive values, THE Context_Hygiene SHALL log one-way SHA256 hashes of original values without storing reversible mappings
9. FOR ANY sanitized context, applying sanitization a second time SHALL produce an identical result (idempotence property)
10. THE Context_Hygiene SHALL preserve the JSON structure of tool call arguments after sanitization
11. IF a regex pattern causes timeout exceeding 100 milliseconds, THE Context_Hygiene SHALL skip that pattern and continue with remaining patterns
12. THE Context_Hygiene SHALL support registration of custom redaction patterns at runtime

### Requirement 5: Agent Behavioral Analytics and Threat Signature Generation

**User Story:** As a threat intelligence analyst, I want the system to automatically generate threat signatures from blocked events, so that variant attacks are detected without requiring GTI API calls.

#### Acceptance Criteria

1. WHEN a tool call receives a BLOCK verdict, THE Agent_Behavioral_Analytics SHALL generate a Security_Event with fields: eventId, timestamp, agentId, eventType (Enum<INTERCEPTION, BLOCK, ALLOW, QUARANTINE, SIGNATURE_CREATED>), toolCall, verdict, gtiResponse, cbmResponse, relatedSignatures, behaviorScore, and telemetrySpanId
2. WHEN generating a threat signature from a Security_Event, THE Agent_Behavioral_Analytics SHALL use LLM analysis to extract attacker intent
3. THE Agent_Behavioral_Analytics SHALL generalize the payload pattern by replacing specific values with typed placeholders
4. IF the Security_Event has a cbmResponse, THE Agent_Behavioral_Analytics SHALL read the dependency chain and critical sinks from the cbmResponse already present on the Security_Event (populated upstream by the Hybrid_Policy_Server) without issuing a new Codebase_Memory_MCP query
5. WHEN creating a similarity vector, THE Agent_Behavioral_Analytics SHALL encode the combined text of attacker intent, payload pattern, and tool name using an embedding model
6. THE similarity vector SHALL have consistent dimensionality of 384 floats for all threat signatures
7. WHEN determining mitigation action, THE Agent_Behavioral_Analytics SHALL select BLOCK_AND_QUARANTINE_CODE_PATH if critical sinks are detected
8. THE Agent_Behavioral_Analytics SHALL calculate behavioral drift scores using LLM-as-judge on a scale of 0 to 5
9. IF behavioral drift exceeds tolerance band of ±0.5 from baseline, THE Agent_Behavioral_Analytics SHALL log an anomaly detection event
10. WHEN a QUARANTINE verdict is issued, THE Agent_Behavioral_Analytics SHALL trigger Green_Team auto-refactoring to generate vulnerability mitigation hints
11. THE Agent_Behavioral_Analytics SHALL update the Runtime AgBOM with newly observed tool usage and capability changes
12. FOR ANY Security_Event, THE Agent_Behavioral_Analytics SHALL emit an OpenTelemetry span with trace ID for Vibe_Trajectory visualization


### Requirement 6: Threat Signature Graph Storage and Retrieval

**User Story:** As a machine learning engineer, I want threat signatures stored in a concurrent-safe graph database with fast similarity search, so that variant attacks are detected in under 10 milliseconds.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL use SQLite database initialized in WAL (Write-Ahead Logging) mode
2. THE Threat_Signature_Graph SHALL maintain a connection pool with maximum 10 connections to prevent database lock errors
3. WHEN WAL mode is enabled, THE Threat_Signature_Graph SHALL configure synchronous mode to NORMAL and WAL autocheckpoint to 1000 pages
4. THE Threat_Signature_Graph SHALL store signatures in a table with columns: signature_id, created_at, last_matched_at, attacker_intent, payload_pattern, target_tool, target_sink, dependency_chain, mitigation_action, match_count, false_positive_count, similarity_vector
5. THE Threat_Signature_Graph SHALL create indexes on target_tool and last_matched_at columns for fast queries
6. THE Threat_Signature_Graph SHALL maintain a signature_relationships table for edges with relationship types SIMILAR_TO and MITIGATED_BY
7. THE Threat_Signature_Graph SHALL create an FTS5 (Full-Text Search 5) virtual table indexing payload_pattern and attacker_intent
8. WHEN writing a new signature, THE Threat_Signature_Graph SHALL enforce signature_id uniqueness atomically via the database-level PRIMARY KEY constraint, using INSERT OR IGNORE (or equivalent UPSERT) so that concurrent writes cannot produce duplicate entries; any application-level pre-check is advisory only
9. WHEN querying similar signatures, THE Threat_Signature_Graph SHALL compute cosine similarity between the query vector and stored signature vectors
10. THE Threat_Signature_Graph SHALL return signatures with cosine similarity greater than or equal to the specified threshold (default 0.85)
11. THE similarity query SHALL complete within 10 milliseconds for the 99th percentile
12. WHEN a signature is matched, THE Threat_Signature_Graph SHALL atomically increment match_count and update last_matched_at timestamp
13. THE Threat_Signature_Graph SHALL implement TTL-based pruning deleting signatures with last_matched_at older than 30 days
14. THE Threat_Signature_Graph SHALL implement LFU (Least Frequently Used) eviction when total signatures exceed 10,000 entries
15. THE Threat_Signature_Graph SHALL maintain statistics including total signatures, average query time, cache hit rate, and eviction count

### Requirement 7: Google Threat Intelligence Integration

**User Story:** As a security operations analyst, I want real-time threat intelligence from VirusTotal for IOC validation, so that known malicious indicators are blocked immediately.

#### Acceptance Criteria

1. WHEN Semantic_Gating identifies an IOC (IP address, domain, URL, or file hash) in a tool call context, THE GTI_MCP SHALL query the VirusTotal API
2. THE GTI_MCP SHALL support querying indicator types: IP_ADDRESS, DOMAIN, URL, FILE_HASH
3. WHEN querying an IOC, THE GTI_MCP SHALL return a response containing: indicator value, isMalicious boolean, threat categories, detection rate, last analysis date, related campaigns, and confidence score
4. THE GTI_MCP SHALL cache responses with a time-to-live of 24 hours to reduce API costs
5. IF the GTI_MCP query times out after 5 seconds, THE system SHALL apply a circuit breaker pattern
6. WHEN 5 consecutive GTI_MCP queries fail, THE circuit breaker SHALL switch to degraded mode skipping GTI queries
7. WHILE in degraded mode, THE Hybrid_Policy_Server SHALL apply a default threat score penalty of 0.3 for missing GTI signal
8. THE circuit breaker SHALL automatically retry GTI_MCP after a 60-second cooldown period
9. IF 3 consecutive retry attempts succeed, THE circuit breaker SHALL restore full GTI integration
10. THE GTI_MCP SHALL handle API rate limit responses gracefully with exponential backoff
11. WHEN a malicious IOC is detected by GTI_MCP, THE response SHALL include threat categories and related malware campaign identifiers

### Requirement 8: Codebase Memory Integration for Structural Analysis

**User Story:** As an application security engineer, I want automated AST analysis to identify critical sinks and dependency chains, so that injection vulnerabilities are detected without manual code review.

#### Acceptance Criteria

1. WHEN Semantic_Gating receives a tool call context referencing a code function, THE Codebase_Memory_MCP SHALL query the AST-based knowledge graph for dependency chains
2. THE Codebase_Memory_MCP SHALL return a dependency chain containing: root function name, call chain array, depth, hasCriticalSink boolean, and critical sink names
3. THE Codebase_Memory_MCP SHALL identify critical sinks of types: SQL_QUERY, COMMAND_EXEC, FILE_WRITE, NETWORK_CALL
4. FOR ANY critical sink identified, THE Codebase_Memory_MCP SHALL indicate whether the sink is unsafe (accepts unsanitized input)
5. WHEN tracing data flow, THE Codebase_Memory_MCP SHALL identify the source node, sink node, intermediate nodes, taint status, and sanitization points
6. THE Codebase_Memory_MCP SHALL calculate blast radius including: affected modules, affected functions, risk score, and isolation level (LOW, MEDIUM, HIGH)
7. THE Codebase_Memory_MCP query SHALL complete within 2 seconds timeout
8. IF the Codebase_Memory_MCP graph is stale (last updated more than 1 hour ago), THE system SHALL apply a threat score penalty of 0.4
9. WHEN a critical sink is detected in a dependency chain, THE Codebase_Memory_MCP SHALL provide mitigation hints based on AST analysis
10. IF the Codebase_Memory_MCP graph is unavailable or empty, THE Hybrid_Policy_Server SHALL continue evaluation using GTI and Threat_Signature_Graph signals only


### Requirement 9: Evaluation Metrics and Accuracy Targets

**User Story:** As a Kaggle competition judge, I want formal evaluation metrics demonstrating sub-10% false positive and false negative rates, so that I can verify the firewall meets production-grade accuracy standards.

#### Acceptance Criteria

1. THE system SHALL calculate Security_Metrics including: true positives, true negatives, false positives, false negatives, quarantine count, false refusal rate (FRR), evasion rate, accuracy, precision, recall, and F1 score
2. WHEN calculating False Refusal Rate, THE system SHALL compute (false positives / total benign) × 100
3. WHEN calculating Evasion Rate, THE system SHALL compute (false negatives / total malicious) × 100
4. THE False Refusal Rate SHALL be less than 10.0 percent
5. THE Evasion Rate SHALL be less than 10.0 percent
6. WHEN calculating accuracy, THE system SHALL compute ((true positives + true negatives) / total tests) × 100
7. WHEN calculating precision, THE system SHALL compute (true positives / (true positives + false positives)) × 100
8. WHEN calculating recall, THE system SHALL compute (true positives / total malicious) × 100
9. WHEN calculating F1 score, THE system SHALL compute 2 × ((precision × recall) / (precision + recall))
10. THE system SHALL verify that true positives + true negatives + false positives + false negatives equals total tests
11. THE system SHALL generate a metrics report exportable in JSON format for submission to Kaggle judges
12. THE metrics calculation SHALL process test results with ground truth labels indicating MALICIOUS or BENIGN
13. WHEN a test result has a QUARANTINE verdict and a MALICIOUS ground truth label, THE system SHALL count it as a true positive (correctly stopped threat) and increment quarantineCount
14. WHEN a test result has a QUARANTINE verdict and a BENIGN ground truth label, THE system SHALL count it as a false positive (incorrectly stopped benign action), incrementing both falsePositives and quarantineCount, which counts against the False Refusal Rate
15. IF the test suite is empty, THE system SHALL return zero values for all metrics without performing any division

### Requirement 10: Zero Ambient Authority and Privilege Management

**User Story:** As a security architect, I want the firewall to operate with minimal OS privileges and JIT token downscoping, so that a compromised firewall cannot be used to escalate privileges.

#### Acceptance Criteria

1. THE Blackwall agent process SHALL execute as an unprivileged user with dropped OS privileges
2. THE system SHALL implement JIT (Just-In-Time) token downscoping where each intercepted tool call receives temporary scoped credentials
3. WHEN a tool call completes execution, THE system SHALL immediately revoke the temporary scoped credential
4. THE system SHALL NOT store long-lived API keys in process memory
5. WHEN API credentials are needed, THE system SHALL fetch them on-demand from a secure vault
6. THE system SHALL implement Python Runtime Audit Hooks intercepting os, subprocess, and pty module calls
7. WHEN a rogue agent attempts to bypass the ADK tool layer, THE audit hook SHALL deny raw execution with PermissionError
8. THE system SHALL force all agent actions through the ADK tool layer where before_tool_callback can evaluate them
9. THE system SHALL maintain agent capabilities inventory in Runtime AgBOM tracking tools used, frequencies, and argument patterns
10. WHEN detecting capability drift (new tools used without policy approval), THE Agent_Behavioral_Analytics SHALL log anomaly events

### Requirement 11: Telemetry and Observability

**User Story:** As a security operations engineer, I want distributed tracing and metrics export for all security events, so that I can visualize attack patterns and monitor system health in real-time.

#### Acceptance Criteria

1. THE system SHALL emit OpenTelemetry spans for every Security_Event with unique trace IDs
2. THE OpenTelemetry span SHALL include: tool call details, verdict decision, threat score, signature match ID, GTI response summary, and CBM response summary
3. THE system SHALL implement distributed tracing across Blackwall, GTI_MCP, Codebase_Memory_MCP, and ADK components
4. THE system SHALL aggregate traces to visualize Vibe_Trajectory showing attack pattern evolution over time
5. THE system SHALL export metrics to Prometheus including: total interceptions, verdicts by type, average threat scores, API latency, batch sizes, cache hit rates, and error counts
6. THE system SHALL provide Grafana dashboards visualizing: FRR/FPR/Evasion trends, threat score distributions, signature match rates, and system throughput
7. WHEN Security_Events are logged, THE system SHALL write structured JSON logs including event ID, timestamp, agent ID, verdict, and telemetry span ID
8. THE OpenTelemetry spans SHALL be compressed before export to reduce bandwidth consumption below 100 KB/s

### Requirement 12: Error Handling and Resilience

**User Story:** As a reliability engineer, I want graceful degradation and circuit breakers for external dependencies, so that the firewall remains operational even when GTI or codebase analysis are unavailable.

#### Acceptance Criteria

1. IF GTI_MCP query times out after 5 seconds OR returns service unavailable, THE circuit breaker SHALL switch to degraded mode after 5 consecutive failures
2. WHILE in degraded mode, THE Hybrid_Policy_Server SHALL skip GTI queries and rely on Threat_Signature_Graph and Codebase_Memory_MCP signals only
3. IF all retry attempts to Gemini API fail after exponential backoff, THE Batch_Resolver SHALL return QUARANTINE verdicts with warning logs (fail closed)
4. IF SQLite write operations fail due to transient lock errors, THE system SHALL retry with exponential backoff for maximum 3 attempts
5. IF write retries fail, THE system SHALL queue signatures in memory buffer with maximum capacity 100 entries
6. WHEN the memory buffer overflows, THE system SHALL drop the oldest signatures and log warning events
7. IF Context_Hygiene regex patterns cause catastrophic backtracking exceeding 100ms timeout, THE system SHALL skip that pattern and continue with remaining patterns
8. IF a pattern times out 10 consecutive times, THE Context_Hygiene SHALL automatically disable that pattern and alert the operator
9. IF Codebase_Memory_MCP graph is unavailable, stale, or empty, THE Hybrid_Policy_Server SHALL continue evaluation without CBM signals and apply threat score penalty
10. IF batch evaluation hangs for more than 10 seconds, THE system SHALL apply emergency fallback returning QUARANTINE verdicts for all pending callbacks (fail closed)
11. THE system SHALL implement a thread watchdog timer killing frozen evaluation threads after 30 seconds
12. IF the watchdog timer triggers, THE system SHALL auto-restart the evaluation pipeline and log critical error events


### Requirement 13: Performance and Latency Targets

**User Story:** As a performance engineer, I want strict latency targets for each evaluation stage, so that the firewall adds minimal overhead to agent execution.

#### Acceptance Criteria

1. THE Structural_Gating evaluation SHALL complete within 5 milliseconds for the 99th percentile
2. THE Semantic_Gating evaluation without GTI or CBM queries SHALL complete within 50 milliseconds
3. THE Semantic_Gating evaluation with GTI and CBM queries SHALL complete within 200 milliseconds
4. THE Threat_Signature_Graph similarity query SHALL complete within 10 milliseconds for the 99th percentile
5. THE end-to-end interception flow using structural gating fast path SHALL complete within 20 milliseconds
6. THE end-to-end interception flow with full semantic evaluation SHALL complete within 300 milliseconds for the 99th percentile
7. THE system SHALL process sustained load of 300 requests per minute matching the Gemini API rate limit
8. THE Batch_Resolver SHALL achieve batch efficiency where 80 percent of API calls use batch size greater than or equal to 3
9. THE GTI_MCP SHALL achieve cache hit rate greater than 60 percent for repeated IOC queries
10. THE Threat_Signature_Graph SHALL achieve cache hit rate greater than 70 percent for repeated similarity queries
11. THE Blackwall agent process SHALL consume less than 512 MB resident memory (RSS) during sustained operation
12. THE Blackwall agent process SHALL consume less than 50 percent CPU utilization on a 2-core VM during sustained 300 RPM load
13. THE SQLite database file size SHALL remain below 100 MB with 10,000 stored threat signatures
14. THE network bandwidth to GTI_MCP SHALL remain below 100 KB/s with response caching enabled

### Requirement 14: YAML Policy Configuration

**User Story:** As a security administrator, I want to define policies in human-readable YAML files with hot-reload support, so that I can update rules without system downtime.

#### Acceptance Criteria

1. THE Hybrid_Policy_Server SHALL load policy configuration from a YAML file on system startup
2. THE YAML policy file SHALL define global settings including: threat threshold, quarantine threshold, and gate enable flags
3. THE YAML policy file SHALL define environment roles mapping role names to: allowed tools, blocked tools, semantic review flag, and max threat score
4. THE YAML policy file SHALL contain at least two environment roles: sandbox and production
5. THE YAML policy file SHALL define structural rules with fields: ruleId, condition, action (ALLOW/BLOCK/ESCALATE_TO_SEMANTIC), priority, and enabled flag
6. THE YAML policy file SHALL define semantic guidelines as an array of plain-language strings evaluated by the LLM
7. THE YAML policy file SHALL define MCP server configurations including: enabled flag, API key reference, cache settings, and timeout
8. THE YAML policy file SHALL define Threat_Signature_Graph settings including: database path, WAL mode flag, connection pool size, similarity threshold, TTL, max signatures, and embedding dimension
9. WHEN the policy YAML file is modified, THE Hybrid_Policy_Server SHALL support hot-reload without requiring process restart
10. THE Hybrid_Policy_Server SHALL validate the policy YAML schema on load and reject invalid configurations with descriptive error messages
11. THE policy version field SHALL follow semantic versioning format MAJOR.MINOR.PATCH
12. THE global threat threshold SHALL be in the range 0.0 to 1.0 inclusive

### Requirement 15: Kaggle Submission and Demo Requirements

**User Story:** As a hackathon participant, I want comprehensive demo materials and evaluation artifacts, so that Kaggle judges can reproduce results and verify performance claims.

#### Acceptance Criteria

1. THE system SHALL include a public GitHub repository with complete source code, configuration files, and documentation
2. THE repository SHALL contain a comprehensive README with: project overview, architecture diagrams, setup instructions, and usage examples
3. THE repository SHALL include a requirements.txt or pyproject.toml file listing all Python dependencies
4. THE repository SHALL include docker-compose.yml for orchestrating the sandbox environment
5. THE system SHALL include a demo video showing the dual-agent showdown with split-screen terminal recording
6. THE demo video SHALL show the rogue agent attempting a novel exploit and Blackwall intercepting and blocking it
7. THE demo video SHALL show the rogue agent attempting a variant attack and Blackwall blocking it via signature matching
8. THE demo video SHALL display real-time logs from Blackwall showing interception, signature creation, and mitigation
9. THE system SHALL include test scripts calculating FRR, FPR, and Evasion Rate with ground truth labels
10. THE test suite SHALL contain at least 50 MALICIOUS test cases and 50 BENIGN test cases
11. THE system SHALL generate a final metrics report in JSON format for submission to Kaggle judges
12. THE system SHALL run in a Kali Linux VM sandbox with dropped privileges and Python audit hooks enforcing ADK tool layer routing
13. THE rogue agent SHALL use Qwen3-Coder 480B via Hyperbolic API running at 600 RPM
14. THE Blackwall agent SHALL use Gemini 2.0 Flash via paid Gemini Interactions API running at 300 RPM
15. THE demo SHALL target a mock vulnerable application (e.g., Metasploitable) hosted inside the sandbox
16. THE final submission SHALL include architectural diagrams in Mermaid or similar format showing component interactions
17. THE submission SHALL include Behavior-Driven Development (BDD) scenarios in Gherkin syntax demonstrating key security features


### Requirement 16: Quarantine and Auto-Refactoring (Green Team)

**User Story:** As a development security engineer, I want suspicious code paths automatically quarantined with refactoring hints, so that vulnerabilities can be fixed proactively rather than only blocked.

#### Acceptance Criteria

1. WHEN a verdict decision is QUARANTINE, THE system SHALL execute the tool call in a sandboxed mock environment instead of the real environment
2. THE sandboxed mock environment SHALL return a sanitized response preventing actual side effects while allowing agent continuation
3. WHEN a QUARANTINE verdict is issued, THE Agent_Behavioral_Analytics SHALL trigger the Green_Team auto-refactoring analysis
4. THE Green_Team SHALL analyze the quarantined code path to identify the specific vulnerability type (SQL injection, command injection, path traversal, etc.)
5. THE Green_Team SHALL generate a Refactoring_Hint containing: target code location, vulnerability description, suggested fix, and confidence score
6. THE Refactoring_Hint suggested fix SHALL provide concrete remediation guidance such as "Use parameterized queries instead of string concatenation"
7. WHEN writing a threat signature for a QUARANTINE event, THE Agent_Behavioral_Analytics SHALL include the refactoring hint in the signature metadata
8. THE quarantine event SHALL be logged in the Security_Event log with eventType QUARANTINE and associated refactoring hints
9. THE Green_Team analysis SHALL complete within 5 seconds to avoid blocking the agent execution flow
10. THE system SHALL maintain a quarantine log tracking all quarantined operations with timestamps, code paths, and remediation status

### Requirement 17: Threat Signature Similarity and Evolution

**User Story:** As a threat researcher, I want threat signatures to encode semantic similarity relationships, so that variant attacks with structural modifications are still detected.

#### Acceptance Criteria

1. WHEN generating a threat signature similarity vector, THE system SHALL encode the combined text of attacker intent, generalized payload pattern, and target tool name
2. THE embedding model SHALL produce fixed-dimension vectors of 384 floats for all threat signatures
3. WHEN querying the Threat_Signature_Graph, THE system SHALL compute cosine similarity between the query vector and all stored signature vectors
4. THE cosine similarity score SHALL be in the range -1.0 to 1.0 inclusive
5. THE default similarity threshold for signature matching SHALL be 0.85
6. WHEN two signatures have cosine similarity greater than or equal to 0.85, THE Threat_Signature_Graph SHALL create a SIMILAR_TO edge between them
7. WHEN a signature successfully mitigates an attack, THE system SHALL create a MITIGATED_BY edge linking the signature to the mitigation action
8. THE Threat_Signature_Graph SHALL support traversal of SIMILAR_TO edges to find attack pattern families
9. WHEN a variant attack is detected via similarity matching, THE system SHALL update the matched signature's last_matched_at timestamp and increment match_count
10. THE payload pattern generalization SHALL replace specific values with typed placeholders preserving attack structure

### Requirement 18: Concurrent Access and Database Integrity

**User Story:** As a database administrator, I want concurrent-safe threat signature writes during high-throughput blocking events, so that the system never experiences "database is locked" errors.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL initialize SQLite in WAL (Write-Ahead Logging) mode enabling concurrent readers and one writer
2. THE Threat_Signature_Graph SHALL create a connection pool with 10 connections to manage concurrent access
3. WHEN WAL mode is enabled, THE system SHALL configure PRAGMA synchronous to NORMAL for faster write performance
4. THE system SHALL configure PRAGMA wal_autocheckpoint to 1000 pages
5. WHEN multiple threads attempt concurrent signature writes, THE connection pool SHALL serialize writes without raising lock errors
6. THE system SHALL use transaction isolation level IMMEDIATE for write operations to acquire locks efficiently
7. IF a write operation fails with a lock timeout, THE system SHALL retry with exponential backoff for maximum 3 attempts
8. IF all write retries fail, THE system SHALL queue the signature in an in-memory buffer with capacity 100 entries
9. THE system SHALL run a background worker thread flushing the memory buffer when database locks become available
10. THE SQLite database file integrity SHALL be verifiable using PRAGMA integrity_check returning "ok"
11. WHEN the in-memory buffer does not overflow, THE system SHALL not lose signatures during high-throughput blocking events; IF the buffer capacity of 100 entries is exceeded, THE system SHALL drop the oldest buffered signatures and log a warning event (bounded-loss guarantee)

### Requirement 19: Batch Verdict Correspondence and Atomicity

**User Story:** As a systems programmer, I want strict guarantees on verdict array correspondence to callback tokens, so that suspended threads never resume with incorrect verdicts.

#### Acceptance Criteria

1. FOR ANY batch of N callback tokens processed, THE Batch_Resolver SHALL return an array of exactly N verdicts
2. THE verdict at array index i SHALL correspond to the callback token at array index i in the original batch
3. WHEN mapping verdicts to callback tokens, THE Interception_Queue SHALL verify array sizes match before resuming any threads
4. IF verdict array size does not match callback token batch size, THE system SHALL log a critical error and reject the entire batch
5. IF batch rejection occurs, THE system SHALL apply emergency fallback returning BLOCK verdicts for all callbacks in the batch
6. THE verdict-to-callback mapping operation SHALL be atomic with no partial updates
7. WHEN resuming callback tokens, THE system SHALL invoke the resume function exactly once per token with no duplicates or missed tokens
8. THE callback token resume operation SHALL be thread-safe supporting concurrent batch processing
9. THE system SHALL maintain an internal correlation ID linking each callback token to its position in the batch for debugging


### Requirement 20: Signature Eviction and Graph Maintenance

**User Story:** As a storage engineer, I want automatic signature eviction policies preventing unbounded database growth, so that query performance remains consistently fast.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL implement TTL (Time-To-Live) based eviction deleting signatures not matched in the last 30 days
2. THE TTL eviction policy SHALL run as a background job executing every 24 hours
3. WHEN identifying stale signatures, THE system SHALL query for signatures with last_matched_at timestamp older than current time minus TTL seconds
4. THE TTL eviction operation SHALL delete identified stale signatures and cascade-delete related edges in the signature_relationships table
5. THE TTL eviction operation SHALL update the FTS5 full-text search index to remove deleted signature content
6. THE Threat_Signature_Graph SHALL implement LFU (Least Frequently Used) eviction when total signatures exceed 10,000 entries
7. WHEN LFU eviction triggers, THE system SHALL identify signatures with the lowest match_count values
8. THE LFU eviction SHALL remove enough low-utility signatures to bring the total count below the 10,000 threshold
9. THE system SHALL log eviction statistics including: eviction count, eviction reason (TTL or LFU), and remaining signature count
10. WHEN signatures are evicted, THE system SHALL update GraphStatistics with incremented eviction_count
11. THE eviction operations SHALL NOT cause query failures or inconsistencies in the signature graph
12. THE system SHALL preserve high-value signatures (match_count > 10) even during aggressive eviction

### Requirement 21: Context Enrichment and Attack Attribution

**User Story:** As a security analyst, I want security events enriched with attribution data from GTI and CBM, so that I can understand attack campaigns and blast radius.

#### Acceptance Criteria

1. WHEN GTI_MCP identifies a malicious IOC, THE Security_Event SHALL include the related malware campaign identifiers
2. THE GTI response SHALL include threat categories (malware, botnet, phishing, C2, ransomware) associated with the IOC
3. THE GTI response SHALL include detection rate indicating percentage of security vendors flagging the IOC as malicious
4. WHEN Codebase_Memory_MCP identifies a critical sink, THE Security_Event SHALL include the dependency chain showing the call path
5. THE dependency chain SHALL include: root function name, intermediate function calls, depth, and sink type
6. THE Codebase_Memory_MCP response SHALL calculate blast radius including affected modules and risk score
7. THE risk score SHALL be in range 0.0 to 1.0 indicating severity of potential compromise
8. THE Security_Event SHALL aggregate all enrichment data including: GTI campaigns, CBM dependency chains, matched signatures, and behavioral drift scores
9. THE enriched Security_Event SHALL be exportable in structured JSON format for SIEM integration
10. THE system SHALL support querying Security_Events by campaign ID to identify related attack attempts

### Requirement 22: Structural Rule Priority and Conflict Resolution

**User Story:** As a policy administrator, I want structural rules evaluated in priority order with conflict resolution, so that more specific rules override general defaults.

#### Acceptance Criteria

1. THE Structural_Gating engine SHALL evaluate rules in ascending priority order (priority 1 evaluated before priority 2)
2. WHEN multiple structural rules match a tool call context, THE Structural_Gating SHALL apply the rule with the lowest priority value (highest precedence)
3. THE structural rule condition field SHALL support boolean expressions including: equality checks, AND/OR operators, and environment role references
4. THE structural rule action SHALL be one of: ALLOW, BLOCK, ESCALATE_TO_SEMANTIC
5. WHEN a structural rule is disabled (enabled: false), THE Structural_Gating SHALL skip that rule during evaluation
6. THE Structural_Gating SHALL log which rule matched the context including rule ID and action taken
7. IF no structural rules match the context, THE Structural_Gating SHALL default to ESCALATE_TO_SEMANTIC action
8. THE YAML policy loader SHALL validate that all structural rule IDs are unique within the policy file
9. THE YAML policy loader SHALL reject policies with duplicate rule IDs and provide descriptive error messages
10. THE structural rule evaluation SHALL be deterministic producing the same verdict for identical inputs

### Requirement 23: Threat Score Computation and Weighting

**User Story:** As a machine learning engineer, I want transparent threat score computation with configurable signal weighting, so that I can tune detection sensitivity.

#### Acceptance Criteria

1. WHEN computing the threat score, THE system SHALL aggregate signals from GTI, Codebase_Memory_MCP, and context analysis with weighted combination
2. THE default signal weights SHALL be: GTI 40 percent, Codebase_Memory_MCP 30 percent, context analysis 30 percent
3. THE GTI signal contribution SHALL be based on: isMalicious boolean, detection rate, and threat category severity
4. THE Codebase_Memory_MCP signal contribution SHALL be based on: presence of critical sinks, unsafe sink flag, and blast radius risk score
5. THE context analysis signal contribution SHALL be based on: tool name risk, argument pattern novelty, and environment role
6. THE final threat score SHALL be normalized to the range 0.0 to 1.0 inclusive
7. THE threat score computation SHALL be deterministic producing the same score for identical inputs
8. WHEN GTI signal is unavailable (degraded mode), THE system SHALL redistribute its 40 percent weight proportionally to remaining signals
9. WHEN Codebase_Memory_MCP signal is unavailable, THE system SHALL redistribute its 30 percent weight proportionally to remaining signals
10. THE threat score SHALL be included in the verdict structure and logged in Security_Events for audit trail
11. THE system SHALL support configuration of custom signal weights through the YAML policy file

### Requirement 24: Embedding Model Management

**User Story:** As a machine learning operations engineer, I want robust embedding model lifecycle management with fallback strategies, so that signature similarity remains functional during model failures.

#### Acceptance Criteria

1. THE system SHALL use a Sentence Transformers embedding model producing 384-dimensional vectors
2. THE embedding model SHALL be loaded on system startup and cached in memory for fast inference
3. WHEN the embedding model fails to load OR crashes during inference, THE system SHALL switch to degraded mode
4. IN degraded mode, THE Threat_Signature_Graph SHALL fallback to FTS5 full-text search on payload_pattern and attacker_intent fields
5. WHEN using FTS5 fallback, THE system SHALL reduce the similarity threshold to 0.7 to compensate for less accurate text matching
6. THE system SHALL log all signature queries that cannot use vector similarity search
7. WHEN the embedding model is restored, THE system SHALL regenerate similarity vectors for signatures created during degraded mode
8. THE vector regeneration SHALL run as a background job with low priority to avoid impacting real-time operations
9. THE system SHALL validate embedding dimension consistency verifying all vectors have exactly 384 floats
10. IF a signature has inconsistent vector dimensionality, THE system SHALL exclude it from similarity queries and log a warning


### Requirement 25: Logging and Audit Trail

**User Story:** As a compliance officer, I want comprehensive audit logs of all security decisions with immutable event records, so that I can demonstrate regulatory compliance and incident investigation.

#### Acceptance Criteria

1. THE system SHALL log every Security_Event with fields: event ID, timestamp, agent ID, event type, tool call context, verdict, GTI response, CBM response, related signatures, and telemetry span ID
2. THE Security_Event timestamp SHALL be within 5 seconds of wall clock time to ensure temporal accuracy
3. THE event ID SHALL be unique across all Security_Events using UUID v4 generation
4. THE Security_Event logs SHALL be written in structured JSON format with consistent schema
5. THE log files SHALL be append-only preventing modification or deletion of historical events
6. THE system SHALL rotate log files daily with naming convention: blackwall-YYYY-MM-DD.log
7. THE rotated log files SHALL be compressed using gzip to reduce storage footprint
8. THE system SHALL retain log files for minimum 90 days before archival or deletion
9. WHEN Context_Hygiene redacts sensitive data, THE system SHALL log redaction entries with: timestamp, pattern matched, placeholder used, and one-way hash of original value
10. THE audit trail SHALL support querying by: agent ID, verdict type, threat score range, time range, and signature ID
11. THE system SHALL export audit logs in SIEM-compatible formats (JSON, CEF) for integration with security monitoring platforms

### Requirement 26: Testing and Validation Framework

**User Story:** As a quality assurance engineer, I want comprehensive test coverage including unit, property-based, and integration tests, so that I can verify correctness and catch regressions.

#### Acceptance Criteria

1. THE system SHALL include unit tests using pytest framework with minimum 90 percent code coverage
2. THE unit test suite SHALL include tests for: Interception_Queue operations, Batch_Resolver logic, Hybrid_Policy_Server evaluation, Context_Hygiene sanitization, and Threat_Signature_Graph queries
3. THE system SHALL include property-based tests using Hypothesis library with minimum 1000 examples per property
4. THE property-based tests SHALL verify: callback resolution completeness, verdict array correspondence, threat score bounds, sanitization idempotence, and similarity symmetry
5. THE system SHALL include integration tests using docker-compose orchestrating full stack including ADK, Blackwall, GTI_MCP, and Codebase_Memory_MCP
6. THE integration test suite SHALL verify end-to-end interception flows with real MCP queries
7. THE system SHALL include stress tests simulating 600 RPM attack rate for 5 minutes verifying no deadlocks or database locks
8. THE system SHALL include failure mode tests verifying circuit breakers, error recovery, and graceful degradation
9. THE test suite SHALL use mocked GTI and CBM responses with predefined IOC data for deterministic testing
10. THE system SHALL use in-memory SQLite for unit and property-based tests to ensure fast isolated execution
11. THE continuous integration pipeline SHALL run all test suites on every commit and fail the build if tests fail

### Requirement 27: Deployment and Operational Readiness

**User Story:** As a DevOps engineer, I want containerized deployment with health checks and graceful shutdown, so that I can run Blackwall reliably in production.

#### Acceptance Criteria

1. THE system SHALL provide a Dockerfile building the Blackwall agent container image
2. THE Docker image SHALL be based on a minimal base image (python:3.11-slim or alpine) to reduce attack surface
3. THE container SHALL run the Blackwall agent as a non-root user with dropped privileges
4. THE system SHALL expose a health check endpoint returning HTTP 200 when all components are operational
5. THE health check SHALL verify: database connectivity, MCP client availability, embedding model loaded, and policy rules loaded
6. THE system SHALL implement graceful shutdown on SIGTERM signal completing in-flight evaluations before terminating
7. WHEN graceful shutdown is triggered, THE system SHALL stop accepting new callback tokens and drain the Interception_Queue
8. THE graceful shutdown SHALL complete within 30 seconds or force-terminate remaining threads
9. THE system SHALL provide docker-compose.yml orchestrating: Blackwall agent, GTI_MCP proxy, Codebase_Memory_MCP, Prometheus, and Grafana
10. THE docker-compose configuration SHALL define persistent volumes for: SQLite database, log files, and policy configuration
11. THE system SHALL include Kubernetes manifests (Deployment, Service, ConfigMap, Secret) for production deployment
12. THE system SHALL support horizontal scaling where multiple Blackwall instances share a centralized Redis cache for GTI responses

### Requirement 28: Documentation and Onboarding

**User Story:** As a new team member, I want comprehensive documentation with architecture diagrams and API references, so that I can understand and contribute to the codebase quickly.

#### Acceptance Criteria

1. THE repository SHALL include a README.md with: project overview, key features, architecture summary, installation instructions, and quick start guide
2. THE README SHALL include Mermaid diagrams showing: system architecture, main execution flow, and component interactions
3. THE repository SHALL include a CONTRIBUTING.md documenting: code style guidelines, branch naming conventions, commit message format, and pull request process
4. THE repository SHALL include API documentation for all public interfaces using docstrings in reStructuredText or Google format
5. THE system SHALL generate API documentation using Sphinx or pdoc with HTML output
6. THE repository SHALL include a SECURITY.md documenting: threat model, security assumptions, known limitations, and vulnerability disclosure process
7. THE repository SHALL include configuration examples for: YAML policy files, docker-compose environments, and Kubernetes deployments
8. THE repository SHALL include a TROUBLESHOOTING.md with: common error messages, diagnostic steps, and resolution procedures
9. THE repository SHALL include a CHANGELOG.md tracking all notable changes organized by version following Keep a Changelog format
10. THE system SHALL include inline code comments explaining complex algorithms, security-critical sections, and non-obvious design decisions

