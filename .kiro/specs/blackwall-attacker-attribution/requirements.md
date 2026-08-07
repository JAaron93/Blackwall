# Requirements Document: Blackwall Attacker Identification & Reporting (`blackwall-attacker-attribution`)

## 1. Functional Requirements (FR)

- **FR-1: Identity Extraction from Intercept Context**
  - The system MUST extract caller identity tokens (`agent_id`, `agent_name`, `agent_model`, `thread_id`) from ADK `ToolCallContext.metadata`.
  - The system MUST fall back to local process inspection (`PID`, `UID`, `cmdline`) if ADK metadata is incomplete.
  - In Enterprise mode, the system MUST enrich identity with container IDs, Kubernetes namespaces, and Vault token accessors.

- **FR-2: Deterministic Identity Fingerprinting**
  - The system MUST generate a SHA-256 identity fingerprint string derived from primary identity attributes (`agent_id`, `thread_id`, `process_uid`, `source_ip`).
  - Identical identity attributes MUST yield the exact same `identity_fingerprint`.

- **FR-3: Attacker Profile Tracking & Risk Scoring**
  - The system MUST maintain attacker profiles in the SQLite Threat Graph database (`attacker_profiles` table).
  - When an attack occurs, the system MUST update `last_seen`, increment `total_attacks`, recalculate `threat_score`, and append newly targeted tools.

- **FR-4: Standardized Incident Report Generation**
  - The system MUST generate an `IncidentReport` model for every `BLOCK` or `QUARANTINE` verdict.
  - The system MUST provide serialization helper functions to format incident reports as Markdown summaries (`to_markdown()`) and JSON objects (`to_json()`).

- **FR-5: Real-Time User Notification Sinks**
  - The system MUST output formatted attacker alerts to stdout/stderr in CLI mode.
  - The system MUST invoke registered user callback functions (`on_attacker_identified(report)`).
  - The system MUST emit OpenTelemetry security event spans (`blackwall.attacker_identified`) containing attribution attributes.

- **FR-6: Context Hygiene & Secret Redaction**
  - The system MUST ensure all arguments, commands, and metadata attached to `IncidentReport` pass through `ContextResolver` sanitization prior to output.

---

## 2. Non-Functional Requirements (NFR)

- **NFR-1: Latency Budget**
  - Attacker identity extraction and profile update MUST execute in **< 5ms** overhead per intercepted event.

- **NFR-2: Fail-Safe Exception Isolation**
  - Failures during identity extraction or reporting MUST NOT crash the main interception pipeline or cause unhandled exceptions. If extraction fails, a generic `UNRESOLVED_ATTACKER` identity MUST be assigned.

- **NFR-3: Zero Third-Party C-Dependencies for Core Tier**
  - Blackwall Core attribution features MUST rely purely on standard Python library constructs (`hashlib`, `os`, `psutil`, `sqlite3`, `pydantic`).

---

## 3. User Stories (US)

- **US-1: Station Developer Incident Clarity**
  - *As a* developer running an AI agent locally,
  - *I want* Blackwall to output a clear alert naming the rogue agent and tool when an attack is blocked,
  - *So that* I immediately know which sub-agent or script performed the unauthorized operation.

- **US-2: Security Operations Center (SOC) Forensics**
  - *As a* SOC engineer monitoring an Enterprise Blackwall cluster,
  - *I want* incident reports exported with OpenTelemetry spans and ZeroMQ signatures,
  - *So that* I can trace attacker behavior across distributed nodes in Jaeger/Grafana.

---

## 4. Behavior-Driven Development (BDD) Scenarios

```gherkin
Feature: Attacker Identification and Reporting

  Scenario: Extracting ADK Agent Identity on Block Verdict
    Given an ADK tool call with metadata containing agent_name "MaliciousScriptAgent" and thread_id "th-991"
    When the tool call triggers a BLOCK verdict
    Then an AttackerIdentity MUST be created with agent_name "MaliciousScriptAgent"
    And an IncidentReport MUST be generated containing a valid identity_fingerprint
    And the CLI alert sink MUST output the attacker report to stderr

  Scenario: Updating Attacker Profile Threat Score
    Given an existing AttackerProfile for fingerprint "fp-123" with total_attacks 2
    When a new BLOCK verdict is assigned to fingerprint "fp-123"
    Then the total_attacks count for "fp-123" MUST increment to 3
    And the last_seen timestamp MUST be updated to current UTC time
```
