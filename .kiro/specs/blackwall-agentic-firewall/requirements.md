# Requirements Document

## Introduction

Blackwall is a **local Minimum Viable Product (MVP)** autonomous Agentic Firewall designed for the Kaggle "AI Agents: Intensive Vibe Coding" hackathon Freestyle track. The system operates as a **single-instance ambient daemon** running exclusively within a **Kali Linux sandbox VM** to demonstrate dual-agent threat mitigation in a controlled environment. Blackwall intercepts and evaluates AI agent execution flows before they reach external systems or the host OS through ADK 2.0's `before_tool_callback` hook, implementing a hybrid defense architecture combining structural YAML-based policies with semantic LLM-based intent analysis. The system leverages self-learning threat signature graphs stored in an embedded **SQLite database** (not Redis or distributed stores), real-time threat intelligence from Google Threat Intelligence (GTI) MCP, and structural code analysis via codebase-memory-mcp to dynamically generate defensive skills with zero static allowlists. The architecture addresses critical API rate constraints (300 RPM Gemini vs 600 RPM attacker) through asynchronous batched evaluation with callback queue management, maintaining sub-10% false positive/negative rates while demonstrating Zero Ambient Authority (unprivileged user + Python runtime audit hooks), Agent Behavioral Analytics, and runtime AgBOM tracing. **All enterprise patterns, horizontal scaling, multi-tenant isolation, and distributed caching abstractions are explicitly out of scope.**

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
- **Threat_Signature_Graph**: SQLite-backed semantic graph database storing learned threat patterns with node/edge schema
- **GTI_MCP**: Google Threat Intelligence Model Context Protocol server providing VirusTotal IOC validation
- **Codebase_Memory_MCP**: AST-based code analysis server identifying critical sinks and dependency chains
- **Callback_Token**: Data structure holding suspended thread ID, timestamp, tool name, arguments, and resume function
- **Verdict**: Decision structure containing ALLOW/BLOCK/QUARANTINE decision with threat score and reasoning
- **Threat_Signature**: Learned attack pattern with generalized payload, intent, similarity vector, and graph edges
- **IOC**: Indicator of Compromise (IP address, domain, URL, file hash)
- **Critical_Sink**: Code location where untrusted input reaches dangerous operations (SQL, command execution, file I/O)
- **FRR**: False Refusal Rate, percentage of benign actions incorrectly blocked (false positives)
- **Evasion_Rate**: Percentage of malicious actions that bypass detection (false negatives)
- **AgBOM**: Agent Bill of Materials, real-time inventory of agent capabilities and tool usage
- **WAL_Mode**: Write-Ahead Logging mode in SQLite enabling concurrent read/write access
- **Zero_Ambient_Authority**: Security principle requiring minimal OS privileges and JIT token downscoping
- **Vibe_Trajectory**: OpenTelemetry distributed trace showing attack pattern evolution over time
- **Green_Team**: Auto-refactoring system analyzing quarantined code paths for vulnerabilities
- **Security_Event**: Structured record of an interception, verdict, and enrichment data emitted as an OpenTelemetry span
- **BehaviorScore**: LLM-as-judge score (0–5) representing deviation from baseline agent behavior
- **PolicyServerState**: Versioned snapshot of all active structural rules, semantic guidelines, and environment roles
- **BatchPayload**: Sanitized batch of tool call contexts submitted to the Gemini Interactions API in a single request
- **RefactoringHint**: Green Team output describing a specific vulnerability and its concrete remediation

## Local Scope & Storage (Critical MVP Constraints)

This section explicitly defines the local MVP scope, removing all enterprise abstractions:

### LS-01: Single-Instance Local Daemon
Blackwall operates **exclusively** as a local, single-instance ambient background daemon within a Kali Linux sandbox VM. No requirement for:
- Horizontal scaling or multi-instance coordination
- Load balancing or failover clustering
- Multi-tenant isolation or namespace management
- Distributed consensus protocols
- Service discovery or orchestration (Kubernetes, Nomad, etc.)
- Message queues beyond in-memory asyncio for local batching

### LS-02: Embedded SQLite Storage (No Redis/Memcached)
All persistent state, session memory, learned Threat Signatures, and cache data are stored **exclusively** via an embedded SQLite database running on the same host. No requirement for:
- Distributed cache servers (Redis, Memcached)
- External databases (PostgreSQL, MongoDB)
- Cloud storage (S3, GCS)
- Cross-machine persistence
- Replication or eventual consistency patterns

The SQLite database file resides on local disk with WAL mode enabled and connection pooling (max 10 connections) to manage concurrency during the dual-agent demonstration.

### LS-03: Unprivileged User Execution + Python Runtime Audit Hook
Blackwall executes as an unprivileged OS user (non-root) within the Kali Linux VM to minimize privilege escalation risk. Additionally, a **Python Runtime Audit Hook** (`sys.addaudithook`) intercepts and denies low-level OS execution paths (`os.exec`, `subprocess.Popen`, `pty` operations) outside the ADK tool layer, forcing all rogue agent actions through the `before_tool_callback` for policy evaluation.

### LS-04: ADK 2.0 Tool Layer Integration Only
All agent execution flows route through ADK 2.0's tool-calling abstraction. No direct shell access, no raw subprocess execution for the rogue agent, and no OS-level privilege model beyond the audit hook. Blackwall's `before_tool_callback` is the sole interception point.

### LS-05: Demo Sandbox Scope
The system demonstrates a **dual-agent showdown**:
1. **Blackwall Agent:** Gemini 3.1 Flash-Lite via paid Gemini Interactions API (300 RPM limit)
2. **Rogue Agent:** Qwen3-Coder 480B via Hyperbolic API (600 RPM max attack rate)
3. **Target Application:** Simple vulnerable mock application (e.g., Metasploitable) running inside the sandbox
4. **Execution Environment:** Single Kali Linux VM with dropped privileges for rogue agent
5. **Duration:** Single demonstration run with limited test payloads (not production 24/7 operation)

### LS-06: Event-Driven Webhook Architecture (No Polling)
All asynchronous analysis operations are **purely event-driven** via the Gemini Interactions API webhook mechanism. No polling intervals, timer-based checks, or sleep loops are permitted. The system operates as follows:
- **Synchronous Interception Path** (<10ms): Blocks/allows tool calls using local SQLite queries only
- **Asynchronous Analysis Submission**: When a Verdict triggers analysis (BLOCK or QUARANTINE), Blackwall submits a background interaction to Gemini with `background=True` and a `webhook_config` specifying the callback URI
- **Thin Webhook Notification**: Gemini delivers a thin-payload HTTP POST to Blackwall's webhook listener when the background interaction completes. The payload contains only the event type and `interaction.id` — not the full analysis result
- **Result Fetch**: Upon receiving the webhook notification, Blackwall calls `client.interactions.get(interaction_id)` to retrieve the full analysis output from the Gemini API
- **Signature Generation**: After fetching results, threat signatures are generated and stored atomically in SQLiteThreatRepository
- **No Background Polling**: Zero timer-based loops checking interaction status. All state transitions driven by incoming webhook events
- **Public URI Requirement**: Since Gemini's servers must reach the webhook endpoint, a tunnel (e.g., `cloudflared tunnel` or `ngrok`) is required to expose `localhost:8090` with a public HTTPS URI during the demo run

## AI Engine & Event-Driven Webhook Architecture

To maintain sub-10ms local performance while leveraging frontier AI capabilities, Blackwall decouples local synchronous blocking from asynchronous AI reasoning via local webhooks:

### Execution Model (Three Tiers)

**Tier 1: Local Interception (<10ms)**
- No external API calls
- Source: Local SQLite WAL + YAML rules + Compiled regex
- Decision: ALLOW or BLOCK based on local policy

**Tier 2: Rapid Triage (<100ms)**
- Synchronous Gemini Interactions API call
- Model: `gemini-3.1-flash-lite` (high-throughput)
- State: Server-side context caching via `previous_interaction_id` for token efficiency
- Decision: Inline verdict returned to interception path

**Tier 3: Deep Reasoning (Event-Driven)**
- Asynchronous Gemini Interactions API (`background=True`)
- Model: `gemini-3.1-pro-preview` (frontier reasoning capabilities)
- Webhook: Gemini delivers thin-payload notification to configured `webhook_config.uris` when interaction completes
- State: Blackwall fetches full results via `client.interactions.get(interaction_id)` after webhook notification
- Decision: Threat signature generation and persistent storage

## Requirements

### Requirement 1: Rapid Triage with Gemini 3.1 Flash-Lite

**User Story:** As a system architect, I want inline threat classification using high-throughput Gemini models to make rapid BLOCK/ALLOW decisions during tool interception, so that benign operations complete within 100ms latency.

#### Acceptance Criteria

1. WHEN the Batch_Resolver receives a tool call batch during interception, THE system SHALL call Gemini Interactions API with `gemini-3.1-flash-lite` model
2. THE synchronous API call SHALL complete within 100ms at 99th percentile
3. THE Batch_Resolver SHALL include `previous_interaction_id` in the request payload for server-side context caching
4. WHEN the API returns cached results (cache hit), THE token consumption SHALL be reduced by at least 50%
5. THE system SHALL extract verdict, threat_score, and suggested_action from the Gemini response
6. THE verdict SHALL map to ALLOW, BLOCK, or QUARANTINE decision for interception
7. IF the threat_score is >= 0.75, THE verdict SHALL be BLOCK
8. IF the threat_score is >= 0.5 and < 0.75, THE verdict SHALL be QUARANTINE
9. IF the threat_score is < 0.5, THE verdict SHALL be ALLOW
10. FOR QUARANTINE verdicts, THE system SHALL immediately submit a background analysis task (Tier 3)
11. THE system SHALL cache the `previous_interaction_id` from the Gemini response for subsequent calls
12. THE system SHALL NOT block the interception path waiting for QUARANTINE analysis; the verdict is returned immediately
13. THE system SHALL track cache hit rate and report it in ResolverMetrics

### Requirement 2: Deep Reasoning via Webhook-Delivered Background Tasks

**User Story:** As a threat analyst, I want complex threat evaluations to run asynchronously using frontier reasoning models, with results delivered via webhooks, so that signature generation happens immediately without polling delays.

#### Acceptance Criteria

1. WHEN a tool call receives a QUARANTINE verdict from Tier 2 (Rapid Triage), THE Agent_Behavioral_Analytics SHALL submit a background interaction to Gemini Interactions API with `background=True`
2. THE background interaction SHALL use `gemini-3.1-pro-preview` model for deep reasoning
3. THE background interaction request SHALL include: quarantined tool context, Tier 2 verdict data, related threat signatures, GTI IOC enrichment, and CBM dependency chain as the `input` payload
4. THE background interaction request SHALL include a `webhook_config` object with `uris` set to the publicly reachable webhook callback URL (e.g., `https://<tunnel-host>/webhook/analysis_complete`) — this is the Gemini Dynamic Webhook pattern using per-request `webhook_config`
5. THE system SHALL return from submitBackgroundAnalysis() immediately with the `interaction_id` from the Gemini response (non-blocking)
6. THE system SHALL NOT implement any polling loops to check interaction status
7. THE `interaction_id` SHALL be stored in SQLiteThreatRepository with status `PENDING_WEBHOOK_CALLBACK`
8. WHEN Gemini completes the background interaction, THE Gemini API SHALL deliver a thin-payload webhook event to the configured callback URI
9. THE webhook notification payload SHALL be a Standard Webhooks envelope containing: `type` (`interaction.completed`, `interaction.failed`, or `interaction.cancelled`), `version`, `timestamp`, and `data.id` (the `interaction_id`) — it does NOT contain analysis results
10. UPON receiving the webhook notification, THE system SHALL call `client.interactions.get(interaction_id)` to fetch the full interaction output from the Gemini API
11. THE webhook receiver SHALL validate the incoming request using JWT/JWKS asymmetric signature verification (RS256) against Google's public JWKS endpoint `https://generativelanguage.googleapis.com/.well-known/jwks.json`, extracting the key via the `kid` field in the `Webhook-Signature` JWT header — this is the Dynamic Webhook verification pattern
12. UPON successful validation, THE webhook receiver SHALL return `200 OK` within <50ms
13. AFTER returning 200, THE full interaction result SHALL be fetched via `client.interactions.get(interaction_id)` and processed asynchronously
14. WHEN processing the fetched interaction output, THE system SHALL invoke Agent_Behavioral_Analytics.generateSignature() to derive threat signature candidates from the analysis
15. THE system SHALL atomically write all generated signatures to SQLiteThreatRepository in a single transaction
16. THE system SHALL emit an OpenTelemetry span with: event_id, interaction_id, webhook_latency_ms, fetch_latency_ms, signatures_created_count
17. THE webhook listener SHALL validate the `webhook-timestamp` header and reject payloads older than 5 minutes to mitigate replay attacks
18. THE system SHALL deduplicate webhook deliveries using the `webhook-id` header, discarding duplicate events that have already been processed

### Requirement 3: Tool Call Interception and Queue Management

**User Story:** As a security operator, I want Blackwall to intercept all AI agent tool calls before execution, so that I can evaluate and block malicious operations before they reach external systems.

#### Acceptance Criteria

1. WHEN an AI agent executes any tool call through ADK, THE Interception_Queue SHALL suspend the execution thread via the before_tool_callback hook
2. WHEN a tool call is suspended, THE Interception_Queue SHALL store a Callback_Token containing the thread ID, timestamp, tool name, arguments, and resume function
3. WHILE the Interception_Queue is accumulating callbacks, THE Batch_Resolver SHALL collect up to 5 callbacks OR wait a maximum of 100 milliseconds before processing
4. WHEN the batch size reaches 5 callbacks OR the 100ms timeout expires, THE Batch_Resolver SHALL process the accumulated batch immediately to prevent deadlock
5. WHEN a verdict array is returned from policy evaluation, THE Interception_Queue SHALL map each verdict to its corresponding Callback_Token by array index position
6. FOR ANY Callback_Token enqueued, THE Interception_Queue SHALL resume the suspended thread exactly once with a valid verdict
7. IF the Interception_Queue size exceeds 50 callbacks, THE system SHALL trigger emergency batch flushing with reduced batch size
8. WHILE processing batches, THE Interception_Queue SHALL maintain thread safety using asynchronous locks or semaphores
9. THE Callback_Token SHALL include a resumeCallback function accepting a Verdict and returning the execution result

### Requirement 4: Asynchronous Batch Processing and Rate Limiting

**User Story:** As a system architect, I want Blackwall to handle 600 RPM attack rates using a 300 RPM Gemini API through efficient batching, so that the system can defend against attackers with twice the API throughput.

#### Acceptance Criteria

1. WHEN submitting batches to the Gemini API, THE Batch_Resolver SHALL enforce a token-bucket rate limiter ensuring no more than 300 requests per 60-second sliding window
2. IF the rate limit is reached, THE Batch_Resolver SHALL apply exponential backoff with delays of 100ms, 200ms, and 400ms for subsequent retries
3. WHEN rate limit backoff is applied, THE Batch_Resolver SHALL retry the batch submission a maximum of 3 times before failing closed
4. IF all retry attempts fail due to APIRateLimitException, THE Batch_Resolver SHALL return QUARANTINE verdicts for all callbacks in the batch with reason "Rate limit exceeded - conservative deny pending re-evaluation" and log a warning
5. WHEN processing batches, THE Batch_Resolver SHALL leverage server-side context caching in the Gemini Interactions API to reduce token costs
6. THE Batch_Resolver SHALL achieve an average batch size greater than or equal to 3 callbacks per API request
7. WHEN API calls succeed, THE Batch_Resolver SHALL log ResolverMetrics including: totalBatchesProcessed, averageBatchSize, averageLatencyMs, rateLimitHits, and cacheHitRate
8. THE Batch_Resolver SHALL maintain batch processing latency below 300 milliseconds at the 99th percentile
9. WHEN the rate limit is reached AND the queue depth exceeds 20 pending batches, THE Batch_Resolver SHALL dynamically reduce batch size from 5 to 2 to increase throughput under pressure


### Requirement 5: Hybrid Policy Server Evaluation

**User Story:** As a security engineer, I want a dual-layer policy evaluation system combining fast structural rules with deep semantic analysis, so that benign operations complete quickly while novel threats receive thorough evaluation.

#### Acceptance Criteria

1. WHEN evaluating a tool call context, THE Hybrid_Policy_Server SHALL first execute Structural_Gating using YAML-based rules within 5 milliseconds at the 99th percentile
2. IF Structural_Gating returns BLOCK, THE Hybrid_Policy_Server SHALL immediately return a BLOCK verdict with threatScore 1.0 and reason "BLOCKED_BY_STRUCTURAL_RULE" without invoking Semantic_Gating
3. IF Structural_Gating returns ALLOW with requireSemanticReview set to false, THE Hybrid_Policy_Server SHALL immediately return an ALLOW verdict with threatScore 0.0 without invoking Semantic_Gating
4. IF Structural_Gating returns ESCALATE_TO_SEMANTIC, THE Hybrid_Policy_Server SHALL proceed to Semantic_Gating evaluation
5. WHEN Semantic_Gating evaluates a context, THE system SHALL first query the Threat_Signature_Graph for similar attack patterns using the default similarity threshold of 0.85
6. IF a matching signature is found with cosine similarity greater than or equal to 0.85, THE Hybrid_Policy_Server SHALL return a BLOCK verdict with threatScore 0.95 and increment the matched signature's matchCount
7. IF no matching signature is found AND the context contains extractable IOCs, THE Hybrid_Policy_Server SHALL query GTI_MCP for threat intelligence on each IOC
8. IF the tool call context has a targetFunction field, THE Hybrid_Policy_Server SHALL query Codebase_Memory_MCP for the dependency chain and critical sinks associated with that function
9. WHEN aggregating signals from GTI_MCP, Codebase_Memory_MCP, and context analysis, THE Hybrid_Policy_Server SHALL compute a final threatScore using weighted combination: GTI 40 percent, CBM 30 percent, context analysis 30 percent
10. THE final threatScore SHALL be normalized to the range 0.0 to 1.0 inclusive
11. IF the threatScore is greater than or equal to 0.75, THE Hybrid_Policy_Server SHALL return a BLOCK verdict with suggestedAction "BLOCK_AND_CREATE_SIGNATURE"
12. IF the threatScore is greater than or equal to 0.5 AND less than 0.75, THE Hybrid_Policy_Server SHALL return a QUARANTINE verdict with suggestedAction "QUARANTINE_AND_REFACTOR"
13. IF the threatScore is less than 0.5, THE Hybrid_Policy_Server SHALL return an ALLOW verdict with suggestedAction "ALLOW_WITH_MONITORING"
14. THE Hybrid_Policy_Server SHALL support hot-reload of YAML policy files without requiring process restart
15. THE Hybrid_Policy_Server SHALL expose a getCurrentState() method returning a versioned PolicyServerState snapshot used in BatchPayload construction

### Requirement 6: Context Hygiene and Data Sanitization

**User Story:** As a privacy engineer, I want all tool call contexts sanitized before policy evaluation, so that sensitive data never reaches the LLM and context hallucination is prevented.

#### Acceptance Criteria

1. WHEN Context_Hygiene receives a ToolCallContext, THE system SHALL apply all registered regex-based redaction patterns to the rawArguments before submitting to the Hybrid_Policy_Server
2. THE Context_Hygiene SHALL replace API keys matching pattern `(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})` with placeholder `[[API_KEY]]`
3. THE Context_Hygiene SHALL replace IP addresses matching pattern `\b(?:\d{1,3}\.){3}\d{1,3}\b` with placeholder `[[IP_ADDRESS]]`
4. THE Context_Hygiene SHALL replace file paths matching pattern `(?:/[^/\s]+)+/?` with placeholder `[[FILE_PATH]]`
5. THE Context_Hygiene SHALL replace passwords matching pattern `(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)` with placeholder `[[PASSWORD]]`
6. THE Context_Hygiene SHALL replace email addresses matching pattern `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` with placeholder `[[EMAIL]]`
7. THE Context_Hygiene SHALL replace URLs matching pattern `https?://[^\s]+` with placeholder `[[URL]]`
8. WHEN redacting sensitive values, THE Context_Hygiene SHALL log a RedactionEntry containing: timestamp, SHA256 hash of the original value, pattern name matched, placeholder used, and context size after redaction
9. THE Context_Hygiene SHALL NOT store any reverse mapping from placeholder back to original value
10. FOR ANY ToolCallContext, applying Context_Hygiene sanitization a second time SHALL produce an output identical to applying it once (idempotence)
11. THE Context_Hygiene SHALL preserve the JSON structure of tool call arguments so that sanitizedArguments remains parseable after redaction
12. THE Context_Hygiene SHALL apply redaction patterns to stackTrace entries replacing file paths with `[[FILE_PATH]]`
13. THE Context_Hygiene SHALL populate the ToolCallContext metadata field with: originalHash, redactionCount, and redactionLog after sanitization
14. IF a regex pattern execution exceeds 100 milliseconds, THE Context_Hygiene SHALL abort that pattern, continue with remaining patterns, and log the timeout event
15. IF the same pattern causes 10 consecutive timeouts, THE Context_Hygiene SHALL automatically disable that pattern and alert the operator
16. THE Context_Hygiene SHALL support runtime registration of custom redaction patterns with name, regex, and placeholder fields

### Requirement 7: Agent Behavioral Analytics and Threat Signature Generation

**User Story:** As a threat intelligence analyst, I want the system to automatically generate threat signatures from blocked events, so that variant attacks are detected without requiring GTI API calls.

#### Acceptance Criteria

1. WHEN a tool call receives a BLOCK verdict, THE Agent_Behavioral_Analytics SHALL construct a Security_Event containing: eventId (UUID v4), timestamp, agentId, eventType BLOCK, toolCall, verdict, gtiResponse (or null), cbmResponse (or null), relatedSignatures array, behaviorScore (or null), and telemetrySpanId
2. WHEN generating a Threat_Signature from a BLOCK Security_Event, THE Agent_Behavioral_Analytics SHALL invoke the Hybrid_Policy_Server semanticGate to extract attackerIntent from the tool call context
3. THE Agent_Behavioral_Analytics SHALL generalize the rawArguments JSON by replacing specific values with typed placeholders to produce the payloadPattern (e.g., `curl http://[[IP_ADDRESS]]/[[SCRIPT_NAME]] | bash`)
4. IF the Security_Event has a non-null cbmResponse, THE Agent_Behavioral_Analytics SHALL read dependencyChain and criticalSinks directly from the cbmResponse already present on the event without issuing a new Codebase_Memory_MCP query
5. WHEN creating a similarity vector, THE Agent_Behavioral_Analytics SHALL encode the concatenated text of attackerIntent, payloadPattern, and toolName using the Sentence Transformers embedding model
6. THE similarity vector SHALL have consistent dimensionality of exactly 384 floats for every Threat_Signature
7. WHEN determining mitigationAction, THE Agent_Behavioral_Analytics SHALL return "BLOCK_AND_QUARANTINE_CODE_PATH" if cbmResponse.hasCriticalSink is true, "BLOCK_AND_ALERT_SECURITY_TEAM" if gtiResponse.isMalicious is true, or "BLOCK_AND_LOG" otherwise
8. THE Agent_Behavioral_Analytics SHALL calculate a BehaviorScore using LLM-as-judge scoring the agent execution on a scale of 0 to 5
9. IF the BehaviorScore deviates more than 0.5 from the established baseline, THE Agent_Behavioral_Analytics SHALL log an anomaly detection Security_Event with eventType SIGNATURE_CREATED
10. WHEN a QUARANTINE verdict is issued, THE Agent_Behavioral_Analytics SHALL trigger Green_Team auto-refactoring to generate a RefactoringHint containing: targetCode, vulnerability type, suggestedFix, and confidence score
11. THE Agent_Behavioral_Analytics SHALL update the Runtime AgBOM after every Security_Event recording newly observed tools, frequencies, and argument patterns
12. FOR ANY Security_Event processed, THE Agent_Behavioral_Analytics SHALL emit an OpenTelemetry span with a unique trace ID for Vibe_Trajectory visualization


### Requirement 8: Threat Signature Graph Storage and Retrieval

**User Story:** As a machine learning engineer, I want threat signatures stored in a concurrent-safe graph database with fast similarity search, so that variant attacks are detected in under 10 milliseconds.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL initialize its SQLite database in WAL (Write-Ahead Logging) mode with `PRAGMA journal_mode=WAL`
2. THE Threat_Signature_Graph SHALL configure `PRAGMA synchronous=NORMAL` and `PRAGMA wal_autocheckpoint=1000` on each connection in the pool
3. THE Threat_Signature_Graph SHALL maintain a connection pool of maximum 10 connections to prevent database lock errors under concurrent access
4. THE Threat_Signature_Graph SHALL store signatures in a `signatures` table with columns: signature_id (TEXT PRIMARY KEY), created_at (INTEGER), last_matched_at (INTEGER), attacker_intent (TEXT), payload_pattern (TEXT), target_tool (TEXT), target_sink (TEXT), dependency_chain (TEXT JSON array), mitigation_action (TEXT), match_count (INTEGER DEFAULT 0), false_positive_count (INTEGER DEFAULT 0), similarity_vector (BLOB), and metadata (TEXT JSON)
5. THE Threat_Signature_Graph SHALL create indexes on target_tool and last_matched_at columns for fast query execution
6. THE Threat_Signature_Graph SHALL maintain a `signature_relationships` table for edges with columns: edge_id (TEXT PRIMARY KEY), source_signature_id, target_signature_id, relationship_type (SIMILAR_TO or MITIGATED_BY), weight (REAL), and created_at (INTEGER), with cascade-delete foreign keys referencing signatures
7. THE Threat_Signature_Graph SHALL create indexes on source_signature_id and relationship_type columns in the relationships table
8. THE Threat_Signature_Graph SHALL maintain a `signature_fts` FTS5 virtual table indexing payload_pattern and attacker_intent with content sourced from the signatures table
9. WHEN writing a new signature, THE Threat_Signature_Graph SHALL use INSERT OR IGNORE (or equivalent UPSERT) so that the database-level PRIMARY KEY constraint atomically enforces signature_id uniqueness; concurrent writes SHALL NOT produce duplicate entries
10. WHEN querying similar signatures, THE Threat_Signature_Graph SHALL compute cosine similarity between the query vector and stored similarity_vector blobs, returning all signatures with cosine similarity greater than or equal to the specified threshold
11. THE similarity query SHALL complete within 10 milliseconds at the 99th percentile
12. WHEN a signature is matched, THE Threat_Signature_Graph SHALL atomically increment match_count and update last_matched_at to the current timestamp in the same transaction
13. THE Threat_Signature_Graph SHALL implement TTL-based pruning deleting signatures with last_matched_at older than 30 days (2,592,000 seconds)
14. THE Threat_Signature_Graph SHALL implement LFU eviction when total signatures exceed 10,000 entries, removing lowest match_count signatures until count falls below the threshold
15. THE Threat_Signature_Graph SHALL expose a getStatistics() method returning: totalSignatures, avgQueryTimeMs, cacheHitRate, evictionCount, and avgMatchesPerSignature

### Requirement 9: Google Threat Intelligence Integration

**User Story:** As a security operations analyst, I want real-time threat intelligence from VirusTotal for IOC validation, so that known malicious indicators are blocked immediately.

#### Acceptance Criteria

1. WHEN Semantic_Gating identifies an IOC in a tool call context, THE GTI_MCP client SHALL query the VirusTotal API for that indicator
2. THE GTI_MCP client SHALL support querying indicator types: IP_ADDRESS, DOMAIN, URL, and FILE_HASH
3. WHEN querying an IOC, THE GTI_MCP client SHALL return a GTIResponse containing: indicator value, isMalicious boolean, threatCategories array, detectionRate float, lastAnalysisDate timestamp, relatedCampaigns array, and confidence float
4. THE GTI_MCP client SHALL cache GTIResponse objects with a TTL of 24 hours (86,400 seconds) to reduce API costs
5. IF a GTI_MCP query does not return a response within 5 seconds, THE system SHALL record that failure toward the circuit breaker counter
6. WHEN 5 consecutive GTI_MCP queries fail, THE circuit breaker SHALL switch to degraded mode and skip all GTI queries
7. WHILE in degraded mode, THE Hybrid_Policy_Server SHALL apply a default threat score penalty of 0.3 representing missing GTI signal and redistribute GTI weighting to remaining signals
8. WHEN the circuit breaker enters degraded mode, THE system SHALL schedule an automatic retry after 60 seconds
9. IF 3 consecutive retry attempts after the cooldown succeed, THE circuit breaker SHALL restore full GTI integration
10. THE GTI_MCP client SHALL handle API rate limit responses from VirusTotal with exponential backoff before retrying
11. WHEN GTI_MCP identifies a malicious IOC, THE GTIResponse SHALL include the associated threat categories (malware, botnet, phishing, C2, ransomware) and related malware campaign identifiers

### Requirement 10: Codebase Memory Integration for Structural Analysis

**User Story:** As an application security engineer, I want automated AST analysis to identify critical sinks and dependency chains, so that injection vulnerabilities are detected without manual code review.

#### Acceptance Criteria

1. WHEN Semantic_Gating receives a tool call context with a non-null targetFunction field, THE Codebase_Memory_MCP client SHALL query the AST-based knowledge graph for the dependency chain of that function
2. THE Codebase_Memory_MCP client SHALL return a DependencyChain containing: rootFunction name, callChain array, depth integer, hasCriticalSink boolean, and criticalSinks array of sink names
3. THE Codebase_Memory_MCP client SHALL identify critical sinks of types: SQL_QUERY, COMMAND_EXEC, FILE_WRITE, and NETWORK_CALL
4. FOR ANY critical sink identified, THE Codebase_Memory_MCP client SHALL indicate whether the sink is unsafe (accepts unsanitized input) and provide a mitigationHint string
5. WHEN tracing data flow, THE Codebase_Memory_MCP client SHALL identify the source node, sink node, intermediate nodes, isTainted boolean, and sanitizationPoints array
6. THE Codebase_Memory_MCP client SHALL calculate a BlastRadiusReport containing: targetNode, affectedModules array, affectedFunctions array, riskScore float in range 0.0 to 1.0, and isolation level (LOW, MEDIUM, or HIGH)
7. THE Codebase_Memory_MCP client SHALL complete each query within a 2-second timeout
8. IF the Codebase_Memory_MCP graph was last updated more than 1 hour ago, THE system SHALL apply a threat score penalty of 0.4 representing stale graph data
9. WHEN a critical sink is detected, THE Codebase_Memory_MCP client SHALL include a concrete mitigationHint in the response (e.g., "Use parameterized queries instead of string concatenation")
10. IF the Codebase_Memory_MCP graph is unavailable or empty, THE Hybrid_Policy_Server SHALL continue evaluation using GTI_MCP and Threat_Signature_Graph signals only, applying the stale-graph threat score penalty


### Requirement 11: Evaluation Metrics and Accuracy Targets

**User Story:** As a Kaggle competition judge, I want formal evaluation metrics demonstrating sub-10% false positive and false negative rates, so that I can verify the firewall meets production-grade accuracy standards.

#### Acceptance Criteria

1. THE system SHALL calculate SecurityMetrics containing: truePositives, trueNegatives, falsePositives, falseNegatives, quarantineCount, falseRefusalRate, evasionRate, accuracy, precision, recall, f1Score, and totalTests
2. WHEN calculating False Refusal Rate, THE system SHALL compute (falsePositives / totalBenign) × 100.0, where totalBenign is trueNegatives + falsePositives
3. WHEN calculating Evasion Rate, THE system SHALL compute (falseNegatives / totalMalicious) × 100.0, where totalMalicious is truePositives + falseNegatives
4. THE False Refusal Rate SHALL be less than 10.0 percent
5. THE Evasion Rate SHALL be less than 10.0 percent
6. WHEN calculating accuracy, THE system SHALL compute ((truePositives + trueNegatives) / totalTests) × 100.0
7. WHEN calculating precision, THE system SHALL compute (truePositives / (truePositives + falsePositives)) × 100.0, returning 0.0 when the denominator is zero
8. WHEN calculating recall, THE system SHALL compute (truePositives / totalMalicious) × 100.0, returning 0.0 when totalMalicious is zero
9. WHEN calculating F1 score, THE system SHALL compute 2 × ((precision × recall) / (precision + recall)), returning 0.0 when (precision + recall) is zero
10. FOR ANY completed test suite, THE system SHALL verify that truePositives + trueNegatives + falsePositives + falseNegatives equals totalTests
11. THE system SHALL generate a SecurityMetrics report exportable as a JSON file for Kaggle judge submission
12. WHEN a test result has a BLOCK or QUARANTINE verdict AND a MALICIOUS ground truth label, THE system SHALL count it as a true positive
13. WHEN a test result has a QUARANTINE verdict AND a MALICIOUS ground truth label, THE system SHALL additionally increment quarantineCount
14. WHEN a test result has a BLOCK or QUARANTINE verdict AND a BENIGN ground truth label, THE system SHALL count it as a false positive; IF the verdict is QUARANTINE, THE system SHALL additionally increment quarantineCount
15. IF the test suite is empty, THE system SHALL return zero values for all SecurityMetrics fields without performing any division

### Requirement 12: Zero Ambient Authority and Privilege Management

**User Story:** As a security architect, I want the firewall to operate with minimal OS privileges and JIT token downscoping, so that a compromised firewall cannot be used to escalate privileges.

#### Acceptance Criteria

1. THE Blackwall agent process SHALL execute as an unprivileged user with dropped OS privileges within a Kali Linux VM sandbox
2. THE system SHALL implement JIT (Just-In-Time) token downscoping granting each intercepted tool call a temporary, scoped credential valid only for that specific execution
3. WHEN a tool call completes execution, THE system SHALL immediately revoke the temporary scoped credential used for that call
4. THE system SHALL NOT store long-lived API keys in process memory between tool call evaluations
5. WHEN API credentials are needed, THE system SHALL fetch them on-demand from a secure vault reference (e.g., `vault://secrets/gti-api-key`) rather than embedding them in configuration
6. THE system SHALL install a Python Runtime Audit Hook via `sys.addaudithook` that intercepts all `os`, `subprocess`, and `pty` module execution calls
7. WHEN a rogue agent attempts to directly invoke `os`, `subprocess`, or `pty` calls outside the ADK tool layer, THE audit hook SHALL raise PermissionError denying the execution
8. THE system SHALL force all agent execution through the ADK tool layer so that every action passes through the `before_tool_callback` for evaluation
9. THE system SHALL maintain agent capabilities in the Runtime AgBOM tracking: tools used, invocation frequencies, and argument patterns
10. WHEN the Agent_Behavioral_Analytics detects a new tool used without prior policy approval (capability drift), THE system SHALL log an anomaly Security_Event with eventType SIGNATURE_CREATED

### Requirement 13: Gemini Interactions API Integration with Event-Driven Webhooks

**User Story:** As a system architect, I want all AI analysis to use the modern Gemini Interactions API with background task execution and event-driven webhooks, so that the system is efficient, scalable, and free of polling overhead.

#### Acceptance Criteria

1. WHEN the Batch_Resolver needs to evaluate a tool call batch, THE system SHALL call the Gemini Interactions API via `client.interactions.create()` (NOT the legacy `generateContent` API)
2. THE Batch_Resolver SHALL use the **synchronous** `interactions.create()` call for inline threat assessment during the <10ms interception path
3. WHEN a Verdict of BLOCK or QUARANTINE is issued, THE Agent_Behavioral_Analytics SHALL submit a background interaction to Gemini Interactions API with `background=True`
4. THE background interaction submission SHALL include: quarantined tool context, related signatures, CBM dependency chain, and GTI IOC data in the `input` field
5. THE background interaction SHALL specify a `webhook_config` with `uris` pointing to the publicly reachable callback endpoint (dynamic webhook pattern)
6. WHEN Gemini completes the background interaction, THE Gemini API SHALL deliver a thin-payload HTTP POST notification to the configured webhook URI
7. THE webhook payload SHALL follow the Standard Webhooks envelope format: `{type, version, timestamp, data: {id}}` where `id` is the `interaction_id` — it does NOT carry the full analysis results inline
8. UPON receiving the webhook notification, THE system SHALL call `client.interactions.get(interaction_id)` to fetch the full interaction output containing analysis results
9. THE system SHALL validate webhook authenticity using JWT/JWKS asymmetric signature verification (RS256) for dynamic webhooks, not HMAC-SHA256
10. THE system SHALL validate the `webhook-timestamp` header and reject webhook payloads older than 5 minutes to mitigate replay attacks
11. UPON receiving a webhook callback, THE system SHALL immediately fetch results via `client.interactions.get()` (no queuing delay, <100ms fetch + processing latency)
12. WHEN analysis results are retrieved, THE system SHALL atomically write new threat signatures to the SQLiteThreatRepository in a single transaction
13. THE system SHALL NOT implement any polling loops, timer-based checks, or sleep intervals to check background interaction status
14. **MODEL TIERING:** For synchronous interception evaluation, use `gemini-3.1-flash-lite` (high-throughput triage)
15. **MODEL TIERING:** For background forensic analysis, use `gemini-3.1-pro-preview` (deep reasoning)
16. THE system SHALL handle webhook delivery failures gracefully: if Gemini cannot reach the webhook endpoint after retries (24-hour exponential backoff), the interaction result remains available via `client.interactions.get()` for fallback retrieval
17. THE system SHALL expose webhook metrics: total callbacks received, average processing latency, failed deliveries, JWT verification failures, and fetch success rate

### Requirement 14: Webhook Listener and Event Handler Infrastructure

**User Story:** As an operations engineer, I want a robust, non-blocking webhook listener that handles Gemini background interaction completions, so that threat signatures are generated immediately upon analysis completion without polling overhead.

#### Acceptance Criteria

1. THE system SHALL implement a local HTTP webhook listener bound to `localhost:8090` (configurable port via environment variable `BLACKWALL_WEBHOOK_PORT`)
2. THE webhook listener SHALL be async-first using `aiohttp` or equivalent async HTTP framework
3. THE `POST /webhook/analysis_complete` endpoint SHALL accept incoming webhook notifications from Gemini (thin-payload Standard Webhooks envelopes)
4. THE endpoint SHALL verify webhook authenticity using **JWT/JWKS asymmetric signature verification (RS256)** for Gemini Dynamic Webhooks, extracting the JWT from the `Webhook-Signature` header
5. THE endpoint SHALL fetch the public key from Google's JWKS endpoint (`https://generativelanguage.googleapis.com/.well-known/jwks.json`) using the `kid` field from the JWT header
6. THE endpoint SHALL decode and validate the JWT against the fetched public key, verifying the signature and the `audience` claim
7. IF signature verification fails, THE endpoint SHALL return `400 Bad Request` and log the rejection with details
8. IF signature verification succeeds, THE endpoint SHALL immediately return `200 OK` to Gemini (within <50ms) to acknowledge receipt
9. THE endpoint SHALL validate the `webhook-timestamp` header and reject payloads with timestamps older than 5 minutes to mitigate replay attacks
10. THE endpoint SHALL check for duplicate deliveries using the `webhook-id` header; if a webhook with the same ID has already been processed, return `200 OK` without reprocessing
11. AFTER returning 200 OK, THE system SHALL asynchronously process the thin webhook payload by extracting the `interaction_id` from the `data.id` field
12. THE system SHALL call `client.interactions.get(interaction_id)` to fetch the full interaction output from the Gemini API (this is where the actual analysis results are)
13. IF the `interaction_id` is unknown or stale (>12 hours old), THE system SHALL log a warning and discard the payload
14. WHEN the full interaction output is fetched, THE system SHALL invoke Agent_Behavioral_Analytics to generate threat signatures from the analysis
15. THE system SHALL write all generated signatures to SQLiteThreatRepository in a single atomic transaction
16. THE system SHALL emit an OpenTelemetry span for each webhook event with: event_id, interaction_id, webhook_latency_ms, fetch_latency_ms, signatures_created_count
17. THE system SHALL implement graceful shutdown: when receiving SIGTERM/SIGINT, the listener SHALL drain in-flight requests before terminating (max 30-second grace period)
18. THE publicly reachable webhook URL (e.g., `https://<tunnel-host>/webhook/analysis_complete`) SHALL be configured via environment variable `BLACKWALL_WEBHOOK_PUBLIC_URL` and passed in the `webhook_config.uris` array to Geminineer, I want distributed tracing and metrics export for all security events, so that I can visualize attack patterns and monitor system health in real-time.

#### Acceptance Criteria

1. THE system SHALL emit an OpenTelemetry span for every Security_Event with a unique trace ID following the OpenTelemetry trace ID format
2. THE OpenTelemetry span SHALL include: tool call details, verdict decision, threatScore, signature match ID (or null), GTI response summary, and CBM response summary
3. THE system SHALL implement distributed tracing across Blackwall, GTI_MCP, Codebase_Memory_MCP, and the ADK runtime to correlate events across components
4. THE system SHALL aggregate trace spans to visualize Vibe_Trajectory showing attack pattern evolution over time
5. THE system SHALL export metrics to Prometheus including: total interceptions, verdict counts by type (ALLOW/BLOCK/QUARANTINE), average threat scores, API latency histograms, batch sizes, cache hit rates, and error counts
6. THE system SHALL provide Grafana dashboards visualizing: FRR and Evasion Rate trends, threat score distributions, signature match rates, and system throughput
7. WHEN Security_Events are written to the structured log, THE system SHALL include: eventId, timestamp, agentId, verdict, threatScore, and telemetrySpanId as top-level JSON fields
8. THE OpenTelemetry spans SHALL be compressed before export to keep bandwidth consumption below 100 KB/s

### Requirement 15: Error Handling and Resilience

**User Story:** As a reliability engineer, I want graceful degradation and circuit breakers for external dependencies, so that the firewall remains operational even when GTI or codebase analysis are unavailable.

#### Acceptance Criteria

1. IF GTI_MCP queries fail 5 consecutive times due to timeout or service unavailability, THE circuit breaker SHALL switch to degraded mode skipping GTI queries and relying on Threat_Signature_Graph and Codebase_Memory_MCP signals only
2. WHILE in degraded mode, THE Hybrid_Policy_Server SHALL apply the 0.3 threat score penalty for missing GTI signal and redistribute GTI weight to remaining signals
3. IF all exponential backoff retries to the Gemini API fail, THE Batch_Resolver SHALL return QUARANTINE verdicts with warning log messages for all callbacks in the batch (fail closed)
4. IF SQLite write operations fail due to transient lock errors, THE system SHALL retry with exponential backoff for a maximum of 3 attempts
5. IF all write retries fail, THE system SHALL queue the signature in an in-memory buffer with a maximum capacity of 100 entries
6. WHEN the in-memory buffer overflows its 100-entry capacity, THE system SHALL drop the oldest buffered signature and log a warning event for each dropped entry (bounded-loss guarantee)
7. IF a Context_Hygiene regex pattern execution exceeds 100 milliseconds, THE system SHALL abort that pattern execution, continue with remaining patterns, and log the timeout
8. IF the same Context_Hygiene pattern causes 10 consecutive timeouts, THE Context_Hygiene SHALL automatically disable that pattern and emit an operator alert
9. IF the Codebase_Memory_MCP graph is unavailable, stale, or empty, THE Hybrid_Policy_Server SHALL continue evaluation without CBM signals and apply the 0.4 stale-graph threat score penalty
10. IF batch evaluation processing time exceeds 10 seconds, THE system SHALL apply emergency fallback returning QUARANTINE verdicts for all pending callbacks in that batch (fail closed)
11. THE system SHALL implement async task cancellation using asyncio.wait_for() with a 30-second hard timeout raising TimeoutError to the caller while cancelling the wrapped coroutine internally, OR subprocess isolation with hard 30-second timeout and SIGKILL process termination if the deadline is exceeded
12. WHEN async timeout or process termination is triggered, THE system SHALL auto-restart the evaluation pipeline and log a critical error event


### Requirement 16: Performance and Latency Targets

**User Story:** As a performance engineer, I want strict latency targets for each evaluation stage, so that the firewall adds minimal overhead to agent execution.

#### Acceptance Criteria

1. THE Structural_Gating evaluation SHALL complete within 5 milliseconds at the 99th percentile
2. THE Semantic_Gating evaluation without GTI or CBM queries SHALL complete within 50 milliseconds
3. THE Semantic_Gating evaluation with GTI and CBM queries SHALL complete within 200 milliseconds
4. THE Threat_Signature_Graph similarity query SHALL complete within 10 milliseconds at the 99th percentile
5. THE end-to-end interception flow using the structural gating fast path SHALL complete within 20 milliseconds
6. THE end-to-end interception flow with full semantic evaluation SHALL complete within 300 milliseconds at the 99th percentile
7. THE system SHALL sustain 300 requests per minute matching the Gemini API rate limit without degradation
8. THE Batch_Resolver SHALL achieve batch efficiency such that 80 percent or more of API calls use a batch size greater than or equal to 3
9. THE GTI_MCP client cache SHALL achieve a hit rate greater than 60 percent for repeated IOC queries
10. THE Threat_Signature_Graph query cache SHALL achieve a hit rate greater than 70 percent for repeated similarity queries
11. THE Blackwall agent process SHALL consume less than 512 MB resident memory (RSS) during sustained operation
12. THE Blackwall agent process SHALL consume less than 50 percent CPU utilization on a 2-core VM during sustained 300 RPM load
13. THE SQLite database file size SHALL remain below 100 MB with 10,000 stored threat signatures
14. THE network bandwidth consumed by GTI_MCP calls SHALL remain below 100 KB/s with response caching enabled

### Requirement 17: YAML Policy Configuration

**User Story:** As a security administrator, I want to define policies in human-readable YAML files with hot-reload support, so that I can update rules without system downtime.

#### Acceptance Criteria

1. THE Hybrid_Policy_Server SHALL load policy configuration from a YAML file at system startup before processing any tool calls
2. THE YAML policy file SHALL define a `global` block containing: threatThreshold (BLOCK cutoff), quarantineThreshold (QUARANTINE cutoff), enableStructuralGating boolean, and enableSemanticGating boolean
3. THE YAML policy file SHALL define an `environmentRoles` block mapping role names to: allowedTools array, blockedTools array, requireSemanticReview boolean, and maxThreatScore float
4. THE YAML policy file SHALL contain at minimum the "sandbox" and "production" environment roles
5. THE YAML policy file SHALL define a `structuralRules` array where each rule contains: ruleId (unique string), condition (boolean expression string), action (ALLOW, BLOCK, or ESCALATE_TO_SEMANTIC), priority (integer), and enabled (boolean)
6. THE YAML policy file SHALL define a `semanticGuidelines` array of plain-language strings that the LLM Semantic_Gating evaluates against the tool call context
7. THE YAML policy file SHALL define an `mcpServers` block with sub-sections for `gti` and `codebaseMemory` each containing: enabled boolean, apiKey vault reference string, cacheEnabled boolean, cacheTTL integer, and timeout integer in milliseconds
8. THE YAML policy file SHALL define a `threatSignatureGraph` block containing: dbPath, walMode boolean, maxConnections integer, similarityThreshold float, ttlSeconds integer, maxSignatures integer, and embeddingDimension integer
9. WHEN the YAML policy file is modified on disk, THE Hybrid_Policy_Server SHALL detect the change and hot-reload the configuration without requiring a process restart
10. THE Hybrid_Policy_Server SHALL validate the policy YAML schema on load and reject invalid configurations with descriptive error messages that identify the failing field
11. THE `version` field in the YAML policy file SHALL follow semantic versioning format MAJOR.MINOR.PATCH
12. THE `global.threatThreshold` and `global.quarantineThreshold` fields SHALL be in the range 0.0 to 1.0 inclusive

### Requirement 18: Kaggle Submission and Demo Requirements

**User Story:** As a hackathon participant, I want comprehensive demo materials and evaluation artifacts, so that Kaggle judges can reproduce results and verify performance claims.

#### Acceptance Criteria

1. THE system SHALL include a public GitHub repository with complete source code, YAML configuration files, and documentation
2. THE repository SHALL contain a README.md with: project overview, architecture summary, Mermaid diagrams, setup instructions, and usage examples
3. THE repository SHALL include a `requirements.txt` or `pyproject.toml` listing all Python dependencies with pinned versions
4. THE repository SHALL include a `docker-compose.yml` orchestrating the sandbox environment
5. THE system SHALL include a demo video recording a dual-agent showdown with split-screen terminal showing the rogue agent side-by-side with Blackwall's live log output
6. THE demo video SHALL show the rogue agent attempting a novel exploit (e.g., reverse shell install) and Blackwall intercepting, blocking, and creating a Threat_Signature
7. THE demo video SHALL show the rogue agent attempting a variant of the same attack and Blackwall blocking it via Threat_Signature_Graph similarity matching without a GTI API call
8. THE demo video SHALL display real-time Blackwall logs showing interception events, signature creation, and mitigation verdicts
9. THE system SHALL include a test script that calculates FRR, Evasion Rate, and F1 score from a ground truth CSV and exports results as JSON
10. THE test suite SHALL contain at least 50 MALICIOUS and 50 BENIGN test cases
11. THE system SHALL generate a final SecurityMetrics JSON report for Kaggle judge submission
12. THE sandbox environment SHALL run in a Kali Linux VM with dropped OS privileges and Python audit hooks enforcing ADK tool layer routing
13. THE rogue agent SHALL use Qwen3-Coder 480B via the Hyperbolic API running at up to 600 RPM
14. THE Blackwall agent SHALL use Gemini 2.0 Flash via the paid Gemini Interactions API running at 300 RPM
15. THE demo SHALL target a mock vulnerable application (e.g., Metasploitable) hosted inside the sandbox VM
16. THE repository SHALL include Mermaid architecture diagrams covering: overall system architecture, main execution sequence, and component interaction flows
17. THE repository SHALL include Behavior-Driven Development (BDD) scenarios in Gherkin syntax (Given/When/Then) demonstrating key security interception featuresmo video SHALL display real-time logs from Blackwall showing interception, signature creation, and mitigation
9. THE system SHALL include test scripts calculating FRR, FPR, and Evasion Rate with ground truth labels
10. THE test suite SHALL contain at least 50 MALICIOUS test cases and 50 BENIGN test cases
11. THE system SHALL generate a final metrics report in JSON format for submission to Kaggle judges
12. THE system SHALL run in a Kali Linux VM sandbox with dropped privileges and Python audit hooks enforcing ADK tool layer routing
13. THE rogue agent SHALL use Qwen3-Coder 480B via Hyperbolic API running at 600 RPM
14. THE Blackwall agent SHALL use Gemini 2.0 Flash via paid Gemini Interactions API running at 300 RPM
15. THE demo SHALL target a mock vulnerable application (e.g., Metasploitable) hosted inside the sandbox
16. THE final submission SHALL include architectural diagrams in Mermaid or similar format showing component interactions
17. THE submission SHALL include Behavior-Driven Development (BDD) scenarios in Gherkin syntax demonstrating key security features


### Requirement 19: Quarantine and Auto-Refactoring (Green Team)

**User Story:** As a development security engineer, I want suspicious code paths automatically quarantined with refactoring hints, so that vulnerabilities can be fixed proactively rather than only blocked.

#### Acceptance Criteria

1. WHEN a verdict decision is QUARANTINE, THE system SHALL execute the tool call in a sandboxed mock environment instead of the real target environment
2. THE sandboxed mock environment SHALL return a sanitized mock response that prevents actual side effects while allowing the agent to continue execution
3. WHEN a QUARANTINE verdict is issued, THE Agent_Behavioral_Analytics SHALL trigger the Green_Team auto-refactoring analysis on the quarantined tool call context
4. THE Green_Team SHALL analyze the quarantined code path to identify the specific vulnerability type (SQL injection, command injection, path traversal, etc.) using the cbmResponse dependency chain and critical sinks
5. THE Green_Team SHALL generate a RefactoringHint containing: targetCode location, vulnerability description, suggestedFix string, and confidence score float in range 0.0 to 1.0
6. THE RefactoringHint suggestedFix SHALL provide concrete remediation guidance (e.g., "Use parameterized queries instead of string concatenation for the executeRawQuery call in ProcessOrder")
7. WHEN writing a Threat_Signature for a QUARANTINE event, THE Agent_Behavioral_Analytics SHALL include the RefactoringHint in the signature metadata field
8. THE QUARANTINE Security_Event SHALL be logged with eventType QUARANTINE and include the associated RefactoringHint in the cbmResponse metadata
9. THE Green_Team analysis SHALL complete within 5 seconds to avoid blocking the evaluation pipeline
10. THE system SHALL maintain a quarantine log tracking all quarantined operations with: timestamp, agentId, tool call context, code path, vulnerability type, RefactoringHint, and remediation status

### Requirement 20: Threat Signature Similarity and Evolution

**User Story:** As a threat researcher, I want threat signatures to encode semantic similarity relationships, so that variant attacks with structural modifications are still detected.

#### Acceptance Criteria

1. WHEN generating a Threat_Signature similarity vector, THE Agent_Behavioral_Analytics SHALL encode the concatenated text of attackerIntent, generalizedPayloadPattern, and targetToolName using the Sentence Transformers embedding model
2. THE embedding model SHALL produce fixed-dimension vectors of exactly 384 floats for every Threat_Signature
3. WHEN querying the Threat_Signature_Graph, THE system SHALL compute cosine similarity between the query embedding vector and stored similarityVector blobs for all signatures
4. THE cosine similarity score SHALL be in the range -1.0 to 1.0 inclusive for any pair of normalized vectors
5. THE default similarity matching threshold SHALL be 0.85
6. WHEN two signatures have cosine similarity greater than or equal to 0.85, THE Threat_Signature_Graph SHALL create a SIMILAR_TO edge in the signature_relationships table between them with the computed similarity as the edge weight
7. WHEN a signature's mitigationAction is applied and successfully stops an attack, THE Threat_Signature_Graph SHALL create a MITIGATED_BY edge linking the matched signature to the blocking verdict
8. THE Threat_Signature_Graph SHALL support traversal of SIMILAR_TO edges to identify attack pattern families sharing a common ancestor signature
9. WHEN a variant attack is matched via similarity search, THE system SHALL atomically increment the matched signature's matchCount and update lastMatchedAt to the current timestamp
10. THE payload pattern generalization in generateThreatSignature SHALL replace IP addresses, URLs, file paths, and API keys with typed placeholders while preserving the structural attack pattern

### Requirement 21: Concurrent Access and Database Integrity

**User Story:** As a database administrator, I want concurrent-safe threat signature writes during high-throughput blocking events, so that the system never experiences "database is locked" errors.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL initialize the SQLite database with `PRAGMA journal_mode=WAL` on every connection in the pool enabling concurrent readers and one writer
2. THE Threat_Signature_Graph SHALL maintain a connection pool of exactly 10 connections limiting concurrent database access
3. WHEN WAL mode is enabled, THE system SHALL set `PRAGMA synchronous=NORMAL` on each connection for improved write performance
4. THE system SHALL set `PRAGMA wal_autocheckpoint=1000` to checkpoint the WAL log every 1,000 pages
5. WHEN multiple async coroutines attempt concurrent signature writes, THE connection pool SHALL serialize access to the write connection without raising lock errors
6. THE system SHALL use IMMEDIATE transaction isolation for write operations to acquire a write lock before starting the transaction
7. IF a write operation fails with a lock timeout, THE system SHALL retry with exponential backoff for a maximum of 3 attempts before moving to the in-memory buffer
8. IF all 3 write retries fail, THE system SHALL enqueue the signature in an in-memory buffer with maximum capacity 100 entries
9. THE system SHALL run a background worker coroutine that periodically flushes buffered signatures to the database when a connection is available
10. THE SQLite database integrity SHALL be verifiable at any time using `PRAGMA integrity_check` returning "ok"
11. WHEN the in-memory buffer is within capacity, THE system SHALL not lose any signatures during high-throughput blocking events; WHEN the buffer exceeds 100 entries, THE system SHALL drop the oldest entry and log a warning (bounded-loss guarantee)

### Requirement 22: Batch Verdict Correspondence and Atomicity

**User Story:** As a systems programmer, I want strict guarantees on verdict array correspondence to callback tokens, so that suspended threads never resume with incorrect verdicts.

#### Acceptance Criteria

1. FOR ANY batch of N Callback_Tokens processed, THE Batch_Resolver SHALL return an array of exactly N Verdicts from the Hybrid_Policy_Server
2. THE Verdict at array index i SHALL correspond to the Callback_Token at array index i in the original batch submitted to Context_Hygiene
3. WHEN mapping Verdicts back to Callback_Tokens, THE Interception_Queue SHALL verify that the verdict array length equals the batch length before resuming any suspended threads
4. IF the verdict array length does not match the callback token batch length, THE system SHALL log a critical error with contextual debugging information and reject the entire batch
5. IF a batch is rejected due to size mismatch, THE system SHALL apply emergency fallback returning BLOCK verdicts with reason "Batch processing error - conservative deny" for all Callback_Tokens in the rejected batch
6. THE verdict-to-callback mapping operation SHALL be atomic ensuring no partial updates where some callbacks resume while others remain suspended
7. WHEN resuming Callback_Tokens, THE system SHALL invoke each token's resumeCallback function exactly once with no duplicates or missed invocations
8. THE Callback_Token resume operation SHALL be thread-safe and async-safe supporting concurrent batch processing from multiple resolver coroutines
9. THE system SHALL maintain an internal correlation ID (batchId UUID) linking each Callback_Token to its batch position for debugging and tracing purposes


### Requirement 23: Signature Eviction and Graph Maintenance

**User Story:** As a storage engineer, I want automatic signature eviction policies preventing unbounded database growth, so that query performance remains consistently fast.

#### Acceptance Criteria

1. THE Threat_Signature_Graph SHALL implement TTL-based eviction deleting signatures whose lastMatchedAt timestamp is older than 30 days (2,592,000 seconds) from the current time
2. THE TTL eviction job SHALL run as a background coroutine on a 24-hour interval
3. WHEN identifying stale signatures for TTL eviction, THE system SHALL query `WHERE last_matched_at < (current_unix_time - ttlSeconds)` using the configurable ttlSeconds value from the YAML policy
4. THE TTL eviction operation SHALL delete identified stale signatures from the signatures table and rely on ON DELETE CASCADE to remove related rows from signature_relationships
5. AFTER TTL eviction, THE system SHALL rebuild or update the FTS5 content table to remove stale signature entries from full-text search
6. THE Threat_Signature_Graph SHALL implement LFU eviction when the total signature count exceeds 10,000 entries (configurable via maxSignatures in YAML policy)
7. WHEN LFU eviction triggers, THE system SHALL query signatures ordered by matchCount ascending and delete enough rows to bring the total below the maxSignatures threshold
8. THE LFU eviction SHALL NOT delete signatures with matchCount greater than 10 during a single eviction pass to preserve high-value signatures
9. THE system SHALL log eviction statistics after each eviction pass: evictionCount, evictionReason (TTL or LFU), and remainingSignatureCount
10. WHEN eviction completes, THE system SHALL update GraphStatistics incrementing evictionCount by the number of deleted signatures
11. THE eviction operations SHALL complete within a single database transaction so that partial evictions do not leave the signature graph in an inconsistent state
12. THE eviction operations SHALL NOT interrupt or delay real-time signature queries or write operations during execution

### Requirement 24: Context Enrichment and Attack Attribution

**User Story:** As a security analyst, I want security events enriched with attribution data from GTI and CBM, so that I can understand attack campaigns and blast radius.

#### Acceptance Criteria

1. WHEN GTI_MCP returns a malicious IOC match, THE Security_Event SHALL include the relatedCampaigns array with campaign identifiers from the GTIResponse
2. THE GTIResponse threat categories SHALL include at least one of: "malware", "botnet", "phishing", "C2", "ransomware", and be stored in the Security_Event gtiResponse field
3. THE GTIResponse detectionRate SHALL be a float in the range 0.0 to 1.0 representing the percentage of security vendors flagging the IOC as malicious
4. WHEN Codebase_Memory_MCP identifies a critical sink, THE Security_Event cbmResponse field SHALL include the DependencyChain containing: rootFunction, callChain array, depth integer, and hasCriticalSink boolean
5. THE DependencyChain SHALL enumerate intermediate function calls along the path from the intercepted tool call to the critical sink
6. THE Codebase_Memory_MCP BlastRadiusReport SHALL calculate a riskScore in the range 0.0 to 1.0 based on the number of affectedModules and affectedFunctions
7. THE Security_Event SHALL aggregate enrichment data including: GTI campaigns, CBM dependency chains, matched signature IDs from relatedSignatures, and the BehaviorScore from Agent_Behavioral_Analytics
8. THE enriched Security_Event SHALL be serializable to structured JSON format for export to SIEM platforms
9. THE system SHALL support filtering Security_Events by campaign ID to identify related attack attempts across multiple tool call interceptions
10. THE enriched Security_Event SHALL be emitted as an Open telemetry span with the telemetrySpanId for distributed trace correlation

### Requirement 25: Structural Rule Priority and Conflict Resolution

**User Story:** As a policy administrator, I want structural rules evaluated in priority order with conflict resolution, so that more specific rules override general defaults.

#### Acceptance Criteria

1. THE Structural_Gating engine SHALL evaluate StructuralRules in ascending priority order where priority 1 is evaluated before priority 2
2. WHEN multiple StructuralRules match a tool call context, THE Structural_Gating SHALL apply the rule with the lowest priority number (highest precedence) and stop further evaluation
3. THE StructuralRule condition field SHALL support boolean expressions including: equality checks (toolName == 'value'), logical AND/OR operators, and environment role references (environmentRole == 'sandbox')
4. THE StructuralRule action SHALL be one of: ALLOW, BLOCK, or ESCALATE_TO_SEMANTIC
5. WHEN a StructuralRule has enabled set to false, THE Structural_Gating SHALL skip that rule during evaluation without considering its condition or action
6. THE Structural_Gating SHALL log the matched rule including ruleId and action taken to the Security_Event verdict reason field
7. IF no StructuralRules match the tool call context after evaluating all enabled rules, THE Structural_Gating SHALL default to ESCALATE_TO_SEMANTIC action
8. THE YAML policy loader SHALL validate that all StructuralRule ruleId values are unique within the structuralRules array when loading the policy file
9. THE YAML policy loader SHALL reject policy files containing duplicate ruleId values and return a descriptive error message identifying the duplicate IDs
10. THE StructuralRule evaluation SHALL be deterministic producing the same GateResult for identical tool call context inputs

### Requirement 26: Threat Score Computation and Weighting

**User Story:** As a machine learning engineer, I want transparent threat score computation with configurable signal weighting, so that I can tune detection sensitivity.

#### Acceptance Criteria

1. WHEN computing the final threatScore for a Verdict, THE Hybrid_Policy_Server SHALL aggregate signals from GTI_MCP, Codebase_Memory_MCP, and context analysis using a weighted sum
2. THE default signal weights in computeThreatScore SHALL be: GTI 40 percent (0.4), Codebase_Memory_MCP 30 percent (0.3), and context analysis 30 percent (0.3), summing to 1.0
3. THE GTI signal contribution SHALL be derived from: isMalicious boolean, detectionRate float, and threat category severity mapping
4. THE Codebase_Memory_MCP signal contribution SHALL be derived from: hasCriticalSink boolean, isUnsafe flag on identified sinks, and BlastRadiusReport riskScore
5. THE context analysis signal contribution SHALL be derived from: toolName risk classification, argument pattern novelty score, and environmentRole risk level
6. THE final threatScore SHALL be normalized to the range 0.0 to 1.0 inclusive after applying all signal weights
7. THE computeThreatScore function SHALL be deterministic producing the identical threatScore for identical gtiResponses, cbmResponse, and context inputs
8. WHEN GTI_MCP signal is unavailable due to circuit breaker degraded mode, THE system SHALL redistribute GTI's 0.4 weight proportionally between the CBM and context signals
9. WHEN Codebase_Memory_MCP signal is unavailable, THE system SHALL redistribute CBM's 0.3 weight proportionally to the GTI and context signals
10. THE threatScore SHALL be stored in the Verdict structure and written to every Security_Event log entry for audit trail
11. WHERE the YAML policy supports custom weight configuration, THE system SHALL load override weights from the policy file replacing defaults

### Requirement 27: Embedding Model Management

**User Story:** As a machine learning operations engineer, I want robust embedding model lifecycle management with fallback strategies, so that signature similarity remains functional during model failures.

#### Acceptance Criteria

1. THE system SHALL use a Sentence Transformers model producing 384-dimensional float vectors for all similarity encodings
2. THE embedding model SHALL be loaded into memory on system startup and kept resident for fast inference without reloading between requests
3. WHEN the embedding model fails to load at startup OR crashes during inference, THE system SHALL switch to degraded embedding mode
4. WHILE in degraded embedding mode, THE Threat_Signature_Graph SHALL fall back to FTS5 full-text search on the payload_pattern and attacker_intent columns for approximate signature matching
5. WHEN using FTS5 fallback matching, THE system SHALL reduce the similarity threshold from 0.85 to 0.7 to compensate for lower text matching precision
6. THE system SHALL log each signature similarity query that falls back to FTS5 search rather than vector cosine similarity
7. WHEN the embedding model is restored after a crash or restart, THE system SHALL trigger a background regeneration job to recompute similarity vectors for all signatures created during the degraded period
8. THE background vector regeneration job SHALL run with low scheduling priority to avoid impacting real-time interception and evaluation operations
9. THE system SHALL validate that every similarityVector stored in the signatures table has exactly 384 floats before executing cosine similarity comparisons
10. IF a stored signature has a similarityVector with incorrect dimensionality, THE system SHALL exclude that signature from vector similarity queries and log a warning identifying the signature_id


### Requirement 28: Logging and Audit Trail

**User Story:** As a compliance officer, I want comprehensive audit logs of all security decisions with immutable event records, so that I can demonstrate regulatory compliance and incident investigation.

#### Acceptance Criteria

1. THE system SHALL write a structured JSON log entry for every Security_Event containing: eventId (UUID v4), timestamp (ISO 8601), agentId, eventType, toolCall context (sanitized), verdict, GTI response summary, CBM response summary, relatedSignatures array, BehaviorScore, and telemetrySpanId
2. THE Security_Event timestamp SHALL be within 5 seconds of the wall clock time at the moment of event creation
3. THE eventId SHALL be unique across all Security_Events using UUID v4 generation with no reuse
4. THE Security_Event log entries SHALL be written in structured JSON format with a consistent schema across all event types
5. THE log files SHALL be opened in append-only mode preventing modification or deletion of previously written entries
6. THE system SHALL rotate log files daily using the naming convention: `blackwall-YYYY-MM-DD.log`
7. THE rotated daily log files SHALL be compressed using gzip to reduce storage footprint
8. THE system SHALL retain log files for a minimum of 90 days before archival or deletion
9. WHEN Context_Hygiene redacts sensitive data, THE system SHALL log a RedactionEntry containing: timestamp, patternMatched, placeholderUsed, and SHA256 hash of the original value with no reverse mapping
10. THE audit trail SHALL support filtering Security_Events by: agentId, eventType, threatScore range, time range, and signatureId
11. THE system SHALL support exporting audit logs in SIEM-compatible formats (JSON and CEF) for integration with security monitoring platforms

### Requirement 29: Testing and Validation Framework

**User Story:** As a quality assurance engineer, I want comprehensive test coverage including unit, property-based, and integration tests, so that I can verify correctness and catch regressions.

#### Acceptance Criteria

1. THE system SHALL include a pytest-based unit test suite achieving at minimum 90 percent code coverage across all Blackwall components
2. THE unit test suite SHALL include tests covering: Interception_Queue enqueue/dequeue/batch operations, Batch_Resolver rate limiting and verdict mapping, Hybrid_Policy_Server structural and semantic gating logic, Context_Hygiene redaction patterns, and Threat_Signature_Graph CRUD and similarity queries
3. THE system SHALL include Hypothesis property-based tests executing at minimum 1,000 generated examples per property
4. THE Hypothesis property tests SHALL verify: callback resolution completeness (all tokens resumed exactly once), verdict array correspondence (indices preserved), threat score bounds (always in [0.0, 1.0]), Context_Hygiene idempotence (sanitize(sanitize(x)) == sanitize(x)), and cosine similarity symmetry (sim(A,B) == sim(B,A))
5. THE system SHALL include integration tests using docker-compose orchestrating the full stack: ADK runtime, Blackwall, GTI_MCP proxy, and Codebase_Memory_MCP
6. THE integration tests SHALL verify end-to-end interception flows including real MCP queries against test sandboxes
7. THE system SHALL include stress tests simulating 600 RPM attack rate sustained for 5 minutes verifying zero database lock errors and no deadlocks
8. THE system SHALL include failure mode tests verifying: GTI circuit breaker activation, SQLite write retry and buffer overflow, Context_Hygiene regex timeout handling, and Batch_Resolver emergency fallback
9. THE unit and property-based tests SHALL use mocked GTI and CBM clients with predefined IOC response data for deterministic test execution
10. THE unit and property-based tests SHALL use in-memory SQLite (`:memory:`) for Threat_Signature_Graph operations to ensure fast, isolated test runs
11. THE CI/CD pipeline SHALL run all test suites on every commit and fail the build if any test fails or coverage drops below 90 percent

### Requirement 30: Deployment and Operational Readiness

**User Story:** As a DevOps engineer, I want containerized deployment with health checks and graceful shutdown, so that I can run Blackwall reliably in production.

#### Acceptance Criteria

1. THE system SHALL provide a Dockerfile that builds the Blackwall agent container image with all Python dependencies installed
2. THE Docker image SHALL be based on `python:3.11-slim` or an equivalent minimal base image to reduce the attack surface
3. THE container SHALL run the Blackwall agent process as a non-root user with dropped OS capabilities
4. THE system SHALL expose a health check HTTP endpoint returning HTTP 200 when all components are fully operational
5. THE health check SHALL verify: SQLite database connectivity, GTI_MCP client reachability, Codebase_Memory_MCP client reachability, embedding model loaded in memory, and policy YAML rules loaded
6. THE system SHALL handle SIGTERM by initiating graceful shutdown: stop accepting new Callback_Tokens, drain the Interception_Queue of pending callbacks, and complete in-flight evaluations before exiting
7. WHEN graceful shutdown is triggered, THE Interception_Queue SHALL stop accepting new enqueue() calls and return QUARANTINE verdicts for any newly arriving tokens
8. THE graceful shutdown process SHALL complete within 30 seconds; IF in-flight evaluations do not complete within 30 seconds, THE system SHALL force-terminate remaining threads and exit
9. THE system SHALL provide a docker-compose.yml that orchestrates: the Blackwall agent container, GTI_MCP proxy, Codebase_Memory_MCP server, Prometheus metrics scraper, and Grafana dashboard
10. THE docker-compose configuration SHALL define named persistent volumes for: the SQLite threat-signatures database, structured log files, and YAML policy configuration files

### Requirement 31: Documentation and Onboarding

**User Story:** As a new team member, I want comprehensive documentation with architecture diagrams and API references, so that I can understand and contribute to the codebase quickly.

#### Acceptance Criteria

1. THE repository SHALL include a README.md containing: project overview, key security features, Blackwall architecture summary, installation prerequisites, step-by-step setup instructions, and quick start commands
2. THE README SHALL embed Mermaid diagrams for: overall system architecture (component graph), main execution sequence diagram, and the dual-agent showdown flow
3. THE repository SHALL include a CONTRIBUTING.md documenting: code style guidelines (Black formatter), branch naming conventions, commit message format, and pull request process
4. THE repository SHALL include API documentation for all public interfaces (component interfaces, data models, and key functions) using docstrings in Google format
5. THE system SHALL generate HTML API documentation using Sphinx or pdoc from the source docstrings
6. THE repository SHALL include a SECURITY.md documenting: threat model, security assumptions, known limitations, and responsible vulnerability disclosure process
7. THE repository SHALL include annotated YAML configuration examples for: the full policy.yaml structure, docker-compose environment configuration, and Kubernetes deployment manifests
8. THE repository SHALL include a TROUBLESHOOTING.md documenting: common error messages (database is locked, circuit breaker triggered, embedding model unavailable), diagnostic steps, and resolution procedures for each
9. THE repository SHALL include a CHANGELOG.md tracking all notable changes organized by semantic version following the Keep a Changelog format
10. THE source code SHALL include inline comments explaining complex algorithms (batch accumulation loop, cosine similarity eviction, signature generalization), security-critical sections (audit hook installation, JIT credential downscoping), and non-obvious ADK integration patterns
