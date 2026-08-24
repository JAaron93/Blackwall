@enterprise @advanced_threat_detection @evaluation @lifecycle
Feature: Evaluation Environment Lifecycle
  As a security researcher
  I want to manage isolated evaluation environments through their full lifecycle
  So that I can create, list, reset, delete, and close environments safely
  without affecting production data or other concurrent evaluations

  Scenario: Create a new evaluation environment
    Given an EvaluationEnvironmentManager with in-memory storage
    When I call get_or_create_environment with id "lifecycle-env-new"
    Then a new EvaluationEnvironment is returned with env_id "lifecycle-env-new"
    And the environment is present in the manager's environment list

  Scenario: Retrieve existing evaluation environment
    Given an EvaluationEnvironmentManager with in-memory storage
    And I have already created evaluation environment "lifecycle-env-existing"
    When I call get_or_create_environment again with id "lifecycle-env-existing"
    Then the same EvaluationEnvironment instance is returned

  Scenario: List all active evaluation environments
    Given an EvaluationEnvironmentManager with in-memory storage
    When I create 3 evaluation environments with ids "lifecycle-list-a", "lifecycle-list-b", and "lifecycle-list-c"
    Then list_environments returns exactly 3 environment ids
    And the list contains "lifecycle-list-a", "lifecycle-list-b", and "lifecycle-list-c"

  Scenario: Delete an evaluation environment
    Given an EvaluationEnvironmentManager with in-memory storage
    And evaluation environment "lifecycle-env-to-delete" exists in the manager
    When I delete evaluation environment "lifecycle-env-to-delete"
    Then "lifecycle-env-to-delete" is no longer in list_environments

  Scenario: Reset an evaluation environment
    Given an EvaluationEnvironmentManager with in-memory storage
    And evaluation environment "lifecycle-env-reset" has 2 inserted events
    When I reset evaluation environment "lifecycle-env-reset"
    Then the attack graph for "lifecycle-env-reset" has 0 nodes

  Scenario: Evaluation mode suppresses production actions
    Given an EvaluationEnvironmentManager with in-memory storage
    When I create evaluation environment "lifecycle-env-suppress"
    Then is_production_action_suppressed returns True for "lifecycle-env-suppress"

  Scenario: Close all evaluation environments
    Given an EvaluationEnvironmentManager with in-memory storage
    And I have created environments "lifecycle-close-x" and "lifecycle-close-y"
    When I call close_all on the manager
    Then the environment list is empty
    And operations on "lifecycle-close-x" raise a RuntimeError

  Scenario: Label events in evaluation mode
    Given an EvaluationEnvironmentManager with in-memory storage
    And evaluation environment "lifecycle-env-label" exists in the manager
    When I label an event with event_id in environment "lifecycle-env-label"
    And I label an alert in environment "lifecycle-env-label"
    Then the labeled event has evaluation_env_id "lifecycle-env-label" in metadata
    And the labeled alert has evaluation_env_id "lifecycle-env-label" in metadata
