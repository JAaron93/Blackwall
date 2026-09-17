Feature: Native CLI Threat Intelligence Triage
  As a security engineer or automated agent
  I want to triage network and payload indicators using the native "blackwall check" command
  So that malicious, suspicious, and benign indicators are accurately classified in both terminal table and JSON formats

  Scenario: Triaging a malicious domain indicator in terminal table format
    Given a known malicious domain indicator "malicious-c2.xyz" with risk score 0.85
    When the user runs "blackwall check malicious-c2.xyz"
    Then the command exit code must be 0
    And the output table must display verdict "BLOCK"
    And the output table must display risk score "0.85"
    And the output table must display provider "otx"

  Scenario: Triaging a suspicious IPv4 indicator in JSON format
    Given a known suspicious IPv4 indicator "198.51.100.42" with risk score 0.40
    When the user runs "blackwall check 198.51.100.42 --format json"
    Then the command exit code must be 0
    And the output must be valid JSON
    And the JSON response must have verdict "WARN"
    And the JSON response must have risk_score 0.40
    And the JSON response must have indicator_type "IPV4"

  Scenario: Triaging a benign file hash indicator in JSON format
    Given a known benign file hash indicator "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" with risk score 0.0
    When the user runs "blackwall check e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --format json"
    Then the command exit code must be 0
    And the output must be valid JSON
    And the JSON response must have verdict "ALLOW"
    And the JSON response must have risk_score 0.0
