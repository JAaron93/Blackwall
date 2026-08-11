@attribution
Feature: Attacker Attribution Model Integrity and Contract Validation
  As a security engineer
  I want Blackwall to enforce deterministic identity fingerprinting, UTC timestamp awareness, score boundaries, and structured report serialization
  So that rogue agent identities are accurately attributed, incident reports are reliably generated, and temporal drift or invalid threat scores cannot corrupt security telemetry

  Scenario: Generate deterministic SHA-256 fingerprint for identical identity attributes
    Given two identical attacker identity attributes with agent_id "agent-007" and thread_id "th-100"
    When the AttackerIdentity objects are instantiated
    Then both identity objects MUST produce the exact same 64-character SHA-256 identity_fingerprint

  Scenario: Generate distinct fingerprints for different attacker identities
    Given two attacker identities with different agent_ids "agent-001" and "agent-002"
    When the AttackerIdentity objects are instantiated
    Then their identity_fingerprint strings MUST be distinct

  Scenario: Validate AttackerProfile accepts valid score bounds and UTC timestamps
    Given a valid UTC timestamp and threat_score 0.85
    When the AttackerProfile object is instantiated
    Then the profile MUST store the threat_score 0.85 and UTC timestamp without error

  Scenario: Validate AttackerProfile rejects out-of-bounds threat score
    Given an invalid threat_score 1.5
    When the AttackerProfile object is instantiated
    Then a ValidationError MUST be raised for threat_score out of bounds

  Scenario: Validate AttackerProfile rejects naive timestamp without timezone info
    Given a naive timestamp without timezone info for AttackerProfile
    When the AttackerProfile object is instantiated
    Then a ValidationError MUST be raised for non-UTC timestamp

  Scenario: Serialize IncidentReport to Markdown and JSON formats
    Given a valid IncidentReport with BLOCK verdict for agent "InfiltratorAgent"
    When the report serialization helpers to_json and to_markdown are executed
    Then to_json MUST return a valid JSON string containing "InfiltratorAgent"
    And to_markdown MUST return a formatted Markdown string containing "# Blackwall Incident Attribution Report"

  # ─── Track 2A: Identity Extractor BDD Scenarios ───────────────────────────

  @extractor
  Scenario: Extract attacker identity from full ADK metadata
    Given an ADK tool call metadata containing agent_id "agent-007" and agent_name "MaliciousScriptAgent" and thread_id "th-991"
    When the AttackerIdentityExtractor processes the metadata
    Then the extracted AttackerIdentity MUST have agent_id "agent-007"
    And the extracted identity MUST have primary_source "ADK_METADATA"
    And the extracted identity MUST have a 64-character SHA-256 identity_fingerprint

  @extractor
  Scenario: Fallback to process inspection when ADK metadata is absent
    Given an empty ADK metadata dictionary
    When the AttackerIdentityExtractor processes the metadata
    Then the extracted identity MUST have primary_source "SYSTEM_PROCESS"
    And the extracted identity MUST contain the current process PID
    And the extracted identity MUST have a 64-character SHA-256 identity_fingerprint

  @extractor
  Scenario: Extraction gracefully returns UNRESOLVED_ATTACKER on internal failure
    Given a tool call context where extraction will fail due to injected errors
    When the AttackerIdentityExtractor processes the metadata with forced failures
    Then the result MUST be a valid AttackerIdentity with agent_id "UNRESOLVED_ATTACKER"
    And no exception MUST propagate from the extractor

  # ─── Track 2B: Incident Report Generator BDD Scenarios ────────────────────

  @reporter
  Scenario: Building an incident report sanitizes sensitive API key arguments
    Given a tool call context with a sensitive OPENAI_API_KEY argument "sk-supersecrettest1234"
    When the IncidentReportGenerator builds a BLOCK verdict report
    Then the report sanitized_arguments MUST NOT contain "sk-supersecrettest1234"
    And the report sanitized_arguments MUST contain a redaction placeholder

  @reporter
  Scenario: Incident report to_markdown produces required header and agent name
    Given a valid tool call context for agent "InfiltratorAgent" with verdict BLOCK
    When the IncidentReportGenerator builds a BLOCK verdict report
    Then the report to_markdown output MUST contain "# Blackwall Incident Attribution Report"
    And the report to_markdown output MUST contain "InfiltratorAgent"
