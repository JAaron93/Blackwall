@enterprise @advanced_threat_detection @evaluation
Feature: Evaluation Environment Support
  As a security researcher and red team operator
  I want to execute attack simulations in isolated evaluation environments
  So that I can validate detection capabilities without triggering production incident responses or corrupting live attack graphs

  Scenario: events in evaluation mode carry the eval environment identifier in metadata
    Given an EvaluationEnvironmentManager initialized with evaluation mode active
    When a security event is processed in evaluation environment "eval-sandbox-01"
    Then the normalized event metadata contains "evaluation_env_id" with value "eval-sandbox-01"
    And the normalized event is flagged as an evaluation event

  Scenario: alerts generated in evaluation mode do not trigger production incident response
    Given an alert generated from an attack detection within evaluation environment "eval-sandbox-02"
    When the AlertBus evaluates production containment rules for the alert
    Then the alert is marked as an evaluation alert
    And production mitigation and incident response workflows are suppressed

  Scenario: two evaluation environments use isolated attack graph instances with no shared state
    Given two separate evaluation environments "eval-team-alpha" and "eval-team-beta"
    When "eval-team-alpha" ingests an attack path event for agent "agent-red-alpha"
    And "eval-team-beta" ingests an attack path event for agent "agent-red-beta"
    Then the attack graph for "eval-team-alpha" contains only events from "eval-team-alpha"
    And the attack graph for "eval-team-beta" contains only events from "eval-team-beta"
    And neither evaluation environment shares nodes with each other or production

  Scenario: resetting evaluation state returns the environment to a clean initial state
    Given an evaluation environment "eval-ephemeral-01" with 3 ingested attack events
    When the evaluation environment "eval-ephemeral-01" is reset
    Then the attack graph for "eval-ephemeral-01" contains 0 nodes
    And the alert history for "eval-ephemeral-01" is completely empty
