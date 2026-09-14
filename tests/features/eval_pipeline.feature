@gcp_eval
Feature: Evaluation Pipeline Integration and CI Gating
  As a CI/CD engineer
  I want an automated evaluation pipeline that executes scenarios, aggregates judge scores, exports telemetry, and gates on thresholds
  So that threat detection quality regressions are prevented before merging

  Scenario: Full pipeline with all domains above threshold exits with code 0
    Given an evaluation pipeline configured with paid tier credentials and threshold 3.5
    And evaluation scenarios for domains "threat_interception, context_hygiene, prompt_injection"
    When the evaluation pipeline executes with passing judge rubrics
    Then the pipeline exits with code 0
    And the aggregate summary reports all_passed as true
    And all evaluated domain mean scores are at least 3.5

  Scenario: Pipeline with one domain below threshold exits with code 1
    Given an evaluation pipeline configured with paid tier credentials and threshold 3.5
    And evaluation scenarios for domains "threat_interception"
    When the evaluation pipeline executes with a failing judge rubric scoring 2.0
    Then the pipeline exits with code 1
    And the aggregate summary reports all_passed as false
    And the domain "threat_interception" is marked as failed

  Scenario: Pipeline under Vertex AI outage produces fallback verdicts and reports fallback_rate
    Given an evaluation pipeline configured with paid tier credentials and threshold 3.5
    And evaluation scenarios for domains "threat_interception"
    When the evaluation pipeline executes during a Vertex AI service outage
    Then the evaluation report contains fallback verdicts
    And the domain fallback rate is 1.0
    And the domain quality mean score is isolated as null

  Scenario: Cloud Trace receives spans with gen_ai.evaluation.domain attributes
    Given an evaluation pipeline configured with paid tier credentials and threshold 3.5
    And evaluation scenarios for domains "context_hygiene"
    When the evaluation pipeline executes with active trace instrumentation
    Then Cloud Trace spans are recorded in memory
    And at least one span contains the "gen_ai.evaluation.domain" attribute matching "context_hygiene"
    And the span attributes include "gen_ai.system" set to "vertex_ai"

  Scenario: Second pipeline run compares against stored baseline and reports no regression
    Given an evaluation pipeline configured with paid tier credentials and threshold 3.5
    And a clean historical evaluation baseline with score 4.8 for domain "threat_interception"
    And evaluation scenarios for domains "threat_interception"
    When the evaluation pipeline executes with a candidate rubric scoring 4.8
    Then the historical regression tracker detects no regression
    And the regression report confirms the baseline was compared
    And the pipeline exits with code 0
