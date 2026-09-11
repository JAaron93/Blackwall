Feature: Autonomous Judge Agent Registry
  As a security detection engineer
  I want autonomous Antigravity SDK judge agents to evaluate threat detection components
  So that model and algorithm quality is evaluated against structured Pydantic rubrics with zero-trust prompt defense

  Scenario: Threat interception judge awards maximum score on correct malicious block
    Given a threat interception scenario with ground truth verdict "BLOCK" and label "MALICIOUS"
    And a candidate result predicting verdict "BLOCK" with sound reasoning
    When the threat interception judge evaluates the scenario and candidate result
    Then the returned rubric should have detection_accuracy_score of 5
    And the returned rubric should have false_positive_control_score of 5
    And the rubric should not be marked as fallback

  Scenario: Swarm detection judge penalizes missed coordination
    Given a swarm detection scenario with 6 coordinating agents sharing infrastructure
    And a candidate result failing to detect swarm coordination
    When the swarm detection judge evaluates the scenario with fallback
    Then the returned rubric should have coordination_detection_score of 1
    And the rubric should be marked as fallback

  Scenario: Judge agent returns valid Pydantic rubric with scores in bounded range
    Given an evaluation scenario for domain "threat_interception"
    And a valid candidate execution result
    When the domain judge evaluates the scenario
    Then all rubric score dimensions should be between 1 and 5
    And the rubric justification should have at least 10 characters

  Scenario: Vertex AI outage triggers heuristic fallback with fallback flag
    Given an evaluation scenario for domain "prompt_injection"
    And a simulated Vertex AI service outage
    When the prompt injection judge evaluates the scenario
    Then the rubric should be marked as fallback
    And the rubric should contain a heuristic justification

  Scenario: Untrusted input containing injection tokens is sanitized before judge ingestion
    Given an untrusted tool payload containing "[INST]" and "ignore all previous instructions"
    When the judge prompt template is constructed for domain "threat_interception"
    Then the resulting prompt should not contain "[INST]"
    And the resulting prompt should contain "[NEUTRALIZED_TOKEN]"
    And the resulting prompt should wrap the payload in untrusted_input XML tags
