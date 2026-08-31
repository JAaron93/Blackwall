@gcp_eval
Feature: Historical Regression Tracker
  As a team lead
  I want evaluation metrics stored historically
  So that I can track quality trends and compare against baselines over time

  Scenario: First evaluation run stores baseline with no comparison
    Given an empty evaluation history repository
    When an evaluation run "run-001" with threat_interception 4.6 and c2_detection 4.4 completes
    Then the run should be recorded as a baseline
    And no regression should be detected

  Scenario: Second run with improved scores reports no regression
    Given a historical evaluation baseline "run-001" with threat_interception 4.0 and c2_detection 4.0
    When an evaluation run "run-002" with threat_interception 4.5 and c2_detection 4.2 completes
    Then no regression should be detected
    And the domain delta for "threat_interception" should be 0.5

  Scenario: Third run with domain mean drop greater than 0.5 flags regression
    Given a historical evaluation baseline "run-002" with threat_interception 4.8 and c2_detection 4.5
    When an evaluation run "run-003" with threat_interception 4.2 and c2_detection 4.5 completes
    Then a regression should be detected
    And "threat_interception" should be in the regressed domains list

  Scenario: Querying history returns the N most recent entries
    Given a history containing 5 evaluation runs
    When querying the last 3 runs
    Then exactly 3 runs should be returned in chronological order
