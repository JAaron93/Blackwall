Feature: Supplementary Threat Intelligence Feeds and Cascade Orchestration
  As an AI agent security firewall
  I want external indicators evaluated across multi-source threat intelligence feeds
  So that malicious network infrastructure and payloads are detected with high confidence and circuit-breaker resilience

  Scenario: Multi-provider cascade detects malicious C2 infrastructure and aggregates highest risk score
    Given a Threat Intelligence Orchestrator configured with OTX, AbuseIPDB, and abuse.ch providers
    When the orchestrator queries an IP indicator "198.51.100.200" with multiple feed responses
    Then the aggregated risk score must match the highest confidence provider rating
    And the aggregated verdict must be flagged as malicious
    And the malware family "Cobalt Strike" must be present in the response
    And the response must be cached for subsequent queries

  Scenario: Circuit breaker transitions to OPEN and bypasses failing threat intelligence provider
    Given a Threat Intelligence Provider protected by a 3-state Circuit Breaker
    When the provider encounters 5 consecutive connection failures
    Then the circuit breaker state must become "OPEN"
    And subsequent queries must immediately return fallback heuristics without calling the provider

  Scenario: AbuseIPDB enforces strict IP scoping and linear confidence score mapping
    Given an AbuseIPDB threat intelligence provider
    When an IP indicator "198.51.100.50" has an abuse confidence score of 80
    Then the calculated risk score must be 0.80
    And the indicator must be flagged as malicious
    And querying a domain indicator "malicious-c2.net" must raise ValueError without network requests
