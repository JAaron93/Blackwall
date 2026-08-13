Feature: Advanced Threat Detection Data Models Validation
  As a Security Engineer
  I want to ensure data models enforce strict validation rules
  So that invalid security events, attack paths, and swarm evidence are rejected at model boundaries

  Scenario: NormalizedEvent creation assigns valid UUID v4 and UTC timezone-aware timestamp
    Given a request to create a NormalizedEvent with valid parameters
    When the NormalizedEvent is instantiated
    Then the event_id is a valid UUID v4
    And the timestamp is timezone-aware and set to UTC

  Scenario: risk_score outside [0.0, 1.0] is rejected with a validation error
    Given risk scores outside the range 0.0 to 1.0
    When NormalizedEvent instances are created with invalid risk scores
    Then a ValidationError is raised for each invalid risk score

  Scenario: AttackPath with fewer than 2 nodes is rejected with a validation error
    Given an AttackPath with fewer than 2 nodes
    When the AttackPath is instantiated
    Then a ValidationError is raised indicating minimum nodes requirement

  Scenario: SwarmEvidence with fewer than 2 agent_ids is rejected with a validation error
    Given a SwarmEvidence with fewer than 2 agent IDs
    When the SwarmEvidence is instantiated
    Then a ValidationError is raised indicating minimum agent IDs requirement
