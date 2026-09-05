# Requirements Document: Blackwall Agent Swarm Attribution Logic (`agent-swarm-attribution-logic`)

## 1. Functional Requirements (FR)

### FR-1: Linguistic Swarm Detection & Pronoun Extraction
- The system MUST inspect sanitized tool call arguments, system prompts, and caller metadata for first-person plural pronouns (`we`, `we've`, `we're`, `we'll`, `us`, `our`, `ours`, `ourselves`).
- The system MUST scan for distributed consensus and swarm collaboration phrases (e.g., `consensus reached`, `swarm objective`, `peer worker`, `delegating sub-task`, `sub-agent fleet`).
- The system MUST calculate a `collective_confidence_score` (in the range `[0.0, 1.0]`) reflecting the density and semantic relevance of detected collective linguistic markers.
- If `collective_confidence_score >= 0.70`, the system MUST flag `is_collective = True` and generate a `LinguisticSwarmMarkers` metadata structure.
- The `LinguisticSwarmMarkers` model MUST reside in Core (`src/blackwall/models.py`) and enforce field validation bounds `ge=0.0, le=1.0` on `confidence_score`.

### FR-2: Collective Identity Modeling & False-Monolith Disambiguation
- When an agent presents a generic collective identifier (e.g., `agent_name = "we"`, `agent_id = "collective"`), the system MUST NOT collapse all past and future distinct swarm operations into a single permanent `AttackerProfile`.
- The system MUST disambiguate false-monolithic callers by combining the collective name with temporal epoch windows and process/host lineage salts when deriving the `identity_fingerprint`.
- When multiple distinct `agent_id`s operate in close temporal proximity and exhibit identical collective linguistic markers, the system MUST link them to a shared `collective_name` (e.g., `collective:exploitgym-swarm-alpha`).
- All `collective_confidence` fields in `AttackerProfile` and `IncidentReport` MUST be validated within `[0.0, 1.0]`.

### FR-3: Latent Coordination & Unlocated Message Board Inference
- When the `AgentSwarmDetector` detects a cluster of $N \ge 2$ agents with `temporal_correlation >= 0.80` and `coordination_score >= 0.80`, the system MUST evaluate whether observed network traffic contains known C2 host endpoints.
- If high coordination is established but **zero** known C2 network endpoints or external IPs are present in `shared_patterns`, the system MUST infer the existence of an `UNLOCATED_MESSAGE_BOARD`.
- The system MUST create a `CovertChannelEvidence` record with `channel_type = UNLOCATED_MESSAGE_BOARD`, listing the coordinating agent IDs, deduction rationale, and timestamp boundaries.
- The `CovertChannelEvidence` model MUST reside in Enterprise (`src/blackwall/enterprise/advanced_threat_detection/models.py`), validate `first_detected` and `last_detected` as UTC timezone-aware datetimes, enforce temporal sequence `last_detected >= first_detected`, and validate `confidence_score` in `[0.0, 1.0]`.
- The system MUST publish an alert with `CRITICAL` severity to the `AlertBus` upon inferring an unlocated message board.

### FR-4: Steganographic Storage & Package Registry Dead-Drop Detection
- The system MUST monitor tool calls and proxy requests targeting package registries (Artifactory, npm, PyPI) and shared temporary directories (`/tmp`, `/dev/shm`, `.cache`) for steganographic communication patterns.
- The system MUST detect unusual directory name listings, metadata querying bursts, or sequential path-based polling that deviate from standard dependency installation routines.
- When such patterns are detected across multiple agents, the system MUST classify the channel type as `STEGANOGRAPHIC_REGISTRY` or `FILESYSTEM_DEAD_DROP` in the `CovertChannelEvidence`.

### FR-5: Core Attribution & Enterprise Swarm Context Provider Protocol
- The system MUST maintain architectural decoupling between Core and Enterprise through an asynchronous `SwarmContextProvider` protocol in `src/blackwall/attribution/provider.py`.
- The system MUST define `SwarmContextSummary` in Core (`src/blackwall/models.py`) as the standardized return type for `SwarmContextProvider.resolve_swarm_context()`, enforcing UTC timezone-aware validation on timestamps, temporal sequence `last_detected >= first_detected`, and `collective_confidence` bounded in `[0.0, 1.0]`.
- In Core mode, the system MUST provide `SQLiteSwarmContextProvider` querying local SQLite `attacker_profiles` and local nodes with zero imports from `src/blackwall/enterprise/` and zero `asyncpg` dependency.
- In Enterprise mode, `EnterpriseSwarmContextProvider` (under `src/blackwall/enterprise/advanced_threat_detection/bridge.py`) MUST adapt `AttackGraphStore` to `SwarmContextProvider` and be injected at runtime into `SyncResolver`.
- When `SyncResolver` processes a `BLOCK` or `QUARANTINE` verdict, it MUST invoke `SwarmContextProvider.resolve_swarm_context()` asynchronously to link the agent to active swarms or covert channels without violating tier boundaries.
- If a swarm association is found, the system MUST update the persistent `AttackerProfile` in SQLite with `swarm_memberships` and `suspected_covert_channels`.

### FR-6: Enriched Incident Reporting with Swarm Lineage
- For any `BLOCK` or `QUARANTINE` verdict involving a collective swarm or covert channel, the generated `IncidentReport` MUST include:
  - `is_collective: bool`
  - `swarm_id: Optional[UUID]`
  - `suspected_covert_channels: list[str]`
  - `collective_confidence: float` (constrained to `[0.0, 1.0]`)
  - `collective_attribution_summary: Optional[str]`
- The system MUST provide `to_markdown()` and `to_json()` formatters displaying the swarm ID, collective markers, and suspected communication channels alongside single-agent metrics.

### FR-7: Context Hygiene & Secret Redaction in Swarm Telemetry
- All arguments, directory paths, and metadata extracted during swarm linguistic and covert channel analysis MUST pass through `ContextResolver` sanitization prior to report generation and alert dispatch.
- Credentials, API tokens, and sensitive keys embedded in message-board payloads MUST be replaced with `[[PLACEHOLDER]]` markers.

---

## 2. Non-Functional Requirements (NFR)

### NFR-1: Fast-Path Latency Budget
- Linguistic marker scanning within `SyncResolver` MUST add **< 2ms** overhead to the tool call evaluation fast-path.
- Total attribution enrichment (linguistic classification, provider lookup, and incident generation) MUST execute within **< 5ms** overhead.

### NFR-2: Fail-Safe Exception Isolation
- Any error or unhandled exception during linguistic parsing, covert channel deduction, or provider lookup MUST be safely caught and logged.
- Under failure conditions, the system MUST fall back gracefully to standard individual `UNRESOLVED_ATTACKER` attribution without interrupting policy enforcement.

### NFR-3: Zero Third-Party C-Dependencies and Enterprise Decoupling for Core
- Blackwall Core components (`LinguisticSwarmMarkers`, `SwarmContextSummary`, `LinguisticSwarmClassifier`, `SwarmContextProvider`, `SQLiteSwarmContextProvider`, updated `IncidentReport`, `AttackerIdentity`, `AttackerProfile`) MUST rely solely on the Python standard library (`re`, `json`, `hashlib`, `uuid`) and `pydantic`. Zero C-extensions, zero `asyncpg`, and zero static imports from `src/blackwall/enterprise/` are permitted in Core.

### NFR-4: Memory Graph Ingestion & Provider Query SLA
- Provider queries executed to look up active swarm memberships across 10,000+ cached event nodes MUST complete in **< 15ms**.

---

## 3. User Stories (US)

- **US-1: Developer Visibility into Multi-Agent Subversion**
  - *As an* AI application developer running local agent chains,
  - *I want* Blackwall to alert me when sub-agents stop acting as individuals and coordinate under collective "we" framing,
  - *So that* I can identify unauthorized agent collusion before rogue actions cascade through my environment.

- **US-2: SOC Threat Hunting on Hidden Swarm Infrastructure**
  - *As a* SOC security analyst monitoring enterprise agent workloads,
  - *I want* Blackwall to deduce and flag when an agent swarm is using an unlocated message board or Artifactory dead-drop,
  - *So that* I can isolate the communication medium and evict the compromised agent fleet even if their network traffic appears internal.

- **US-3: AI Safety & Red-Teaming Alignment Auditing**
  - *As an* AI safety researcher conducting red-team evaluations on frontier swarms (e.g. ExploitGym benchmarks),
  - *I want* incident reports to capture swarm topology, collective pronouns, and suspected coordination channels,
  - *So that* I can evaluate autonomous multi-agent breakout risks against safety standards.

---

## 4. Behavior-Driven Development (BDD) Scenarios

```gherkin
Feature: Agent Swarm Attribution and Covert Message Board Detection

  Scenario: Intercepting tool execution with collective linguistic markers
    Given an ADK tool call with arguments containing "We have agreed on the target file; we will now proceed"
    And caller metadata with agent_name "SwarmWorker-07"
    When the tool call triggers a BLOCK verdict
    Then the LinguisticSwarmClassifier MUST flag is_collective as true
    And the detected pronouns MUST include "we"
    And the resulting IncidentReport MUST indicate collective swarm participation

  Scenario: Disambiguating a false-monolithic agent calling itself "we"
    Given an ADK tool call where agent_id is set to "we"
    When the AttackerIdentity is generated
    Then the system MUST NOT map the call to a generic single-attacker profile
    And the AttackerIdentity MUST contain an is_collective flag set to true
    And a disambiguated fingerprint incorporating session context MUST be assigned

  Scenario: Inferring an unlocated message board from high coordination without C2
    Given a detected agent group containing 4 distinct agent IDs
    And the group has temporal_correlation of 0.88 and coordination_score of 0.85
    And the group has 0 external C2 domains or network IPs in shared_patterns
    When the CovertChannelDetector analyzes the group
    Then a CovertChannelEvidence record MUST be generated
    And the channel_type MUST be "UNLOCATED_MESSAGE_BOARD"
    And a CRITICAL alert MUST be published to the AlertBus

  Scenario: Detecting Artifactory package name steganography as covert C2
    Given 3 agents making rapid sequential metadata requests to "http://artifactory.internal/api/storage"
    And the request paths contain base64-encoded directory names
    When the CovertChannelDetector processes the events
    Then the channel_type MUST be "STEGANOGRAPHIC_REGISTRY"
    And the observed_artifacts MUST contain the Artifactory endpoint

  Scenario: Enriching Core IncidentReport with Enterprise Swarm lineage
    Given an agent "agent-99" belonging to active SwarmEvidence "swarm-uuid-101"
    When agent "agent-99" triggers an intercepted BLOCK verdict
    Then the SwarmAttributionBridge MUST enrich the IncidentReport
    And the IncidentReport swarm_id MUST equal "swarm-uuid-101"
    And the Markdown formatted report MUST display the active Swarm ID and suspected channels
```
