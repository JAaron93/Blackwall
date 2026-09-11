@attribution @swarm_models
Feature: Agent Swarm Attribution Data Models and Schema Invariants
  As a security engineer
  I want Blackwall to enforce strict validation, score boundaries, temporal sequences, and UTC timezone awareness on swarm models
  So that collective agent swarms and covert channels are accurately modeled without corrupted telemetry or tier coupling

  Scenario: Validate LinguisticSwarmMarkers default values and confidence score boundaries
    Given a linguistic swarm classifier detecting collective pronouns
    When LinguisticSwarmMarkers is instantiated with valid score 0.85 and pronouns "we,our"
    Then the markers object MUST store is_collective True and confidence_score 0.85
    And the markers object MUST contain "we" in detected_pronouns

  Scenario: Validate SwarmContextSummary enforces UTC timestamps and temporal ordering
    Given a SwarmContextSummary with first_detected 5 minutes ago and last_detected now in UTC
    When the SwarmContextSummary object is instantiated
    Then the summary MUST store is_collective True and collective_confidence 0.90
    And first_detected and last_detected MUST be valid UTC timestamps

  Scenario: Reject SwarmContextSummary with inverted temporal timestamps
    Given a SwarmContextSummary with first_detected after last_detected
    When the SwarmContextSummary object is instantiated with inverted timestamps
    Then a ValidationError MUST be raised for inverted temporal ordering

  Scenario: Validate CovertChannelEvidence requires minimum 2 coordinating agents and valid UTC
    Given a covert channel of type "UNLOCATED_MESSAGE_BOARD" with coordinating agents "agent-alpha,agent-beta"
    When the CovertChannelEvidence object is instantiated
    Then the evidence MUST store channel_type "UNLOCATED_MESSAGE_BOARD"
    And coordinating_agents MUST contain 2 agents

  Scenario: Reject CovertChannelEvidence with fewer than 2 coordinating agents
    Given a covert channel with only 1 coordinating agent "solo-agent"
    When the CovertChannelEvidence object is instantiated
    Then a ValidationError MUST be raised for insufficient coordinating agents

  Scenario: Validate Core AttackerProfile and IncidentReport collective extensions maintain backward compatibility
    Given an AttackerProfile and IncidentReport instantiated without collective fields
    When the profile and report are inspected
    Then the profile swarm_memberships MUST be an empty list
    And the report is_collective MUST be False
    And the report collective_confidence MUST be 0.0
