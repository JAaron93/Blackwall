Feature: System Integration and Wiring for Advanced Threat Detection
  As a security administrator
  I want a unified Advanced Threat Detection orchestrator
  So that multi-pillar event streams are normalized, correlated, and alerted without impacting execution flow.

  Scenario: Unified orchestrator component wiring and lifecycle
    Given an AdvancedThreatDetectionConfig with in_memory enabled
    When the AdvancedThreatDetection orchestrator is initialized and started
    Then all core subsystems and detection engines are properly wired
    And the orchestrator enters running state

  Scenario: Passive event observation without payload mutation
    Given a running AdvancedThreatDetection orchestrator
    And a raw caller event payload dictionary
    When the raw event is ingested via ingest_event
    Then a valid NormalizedEvent is returned
    And the original caller dictionary is not modified in-place
    And the event is persisted in the AttackGraphStore

  Scenario: Multi-pillar ingestion and real-time alert generation
    Given a running AdvancedThreatDetection orchestrator with alert subscribers
    When multiple threat events from different pillars are ingested for an agent
    And threat correlation is executed for the agent
    Then correlated threat alerts are published to the AlertBus
    And the attack graph contains all ingested nodes

  Scenario: Safe detection execution crash containment
    Given a running AdvancedThreatDetection orchestrator
    And a failing detector that raises an unexpected runtime exception
    When threat correlation is triggered for an agent
    Then the orchestrator handles the failure safely without raising an unhandled exception
