Feature: Weave Evaluation Tracking Integration
  As a security engineer
  I want to track threat detection evaluations using Weave with strict sanitization
  So that model benchmark traces are auditable and privacy-preserving

  Scenario: Weave offline mode enables local tracking without cloud credentials
    Given the environment variable "WEAVE_OFFLINE" is set to "true"
    And the environment variable "WEAVE_DISABLED" is not set
    When checking if Weave should be enabled
    Then Weave is enabled

  Scenario: Weave disabled environment variable takes highest precedence
    Given the environment variable "WEAVE_DISABLED" is set to "true"
    And the environment variable "WEAVE_OFFLINE" is set to "true"
    When checking if Weave should be enabled
    Then Weave is disabled

  Scenario: Event trace serialization drops sensitive and raw event payloads
    Given a normalized security event with secret tokens and raw actions
    When the event is serialized for Weave tracing
    Then raw action and target fields are excluded
    And the event ID and timestamp are preserved
    And sensitive metadata keys are redacted

  Scenario: Metric collector computes accurate precision recall and F1 scores
    Given a scenario evaluation with 80 true positives 20 false positives and 10 false negatives
    When detection metrics are computed
    Then the precision is approximately 0.80
    And the recall is approximately 0.8889
    And the F1 score is approximately 0.8421
