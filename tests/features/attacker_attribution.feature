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
