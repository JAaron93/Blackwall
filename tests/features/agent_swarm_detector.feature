Feature: Agent Swarm Detector End-to-End Contract Validation
  As an Enterprise Security Engineer
  I want the AgentSwarmDetector to analyze multi-agent behaviors, fingerprints, and shared infrastructure
  So that coordinated agent swarms and high-confidence coordination scores are identified dynamically

  Scenario: Agent behavioral fingerprint is consistent for the same action sequence over a time window
    Given an agent with a set of action events in a time window
    When fingerprint_agent is called over the time window
    Then a deterministic 64-character SHA-256 behavioral fingerprint is generated

  Scenario: Two agents with temporal_correlation >= 0.75 are grouped into a swarm
    Given two agents executing correlated actions closely in time
    When detect_swarms is called with correlation threshold 0.75
    Then a SwarmEvidence instance is returned containing both agent IDs

  Scenario: Fewer than 2 agents cannot form a swarm
    Given a single agent executing security events
    When detect_swarms is called with min_agents set to 2
    Then an empty swarm list is returned

  Scenario: Shared IP addresses and domains are identified in SwarmEvidence.shared_patterns
    Given two agents sharing IP address "192.168.1.50" and domain "evil.c2.org"
    When detect_swarms is executed
    Then SwarmEvidence.shared_patterns contains the shared IP and domain

  Scenario: SwarmEvidence with coordination_score >= 0.75 is classified as high-confidence
    Given a set of agents with highly aligned timestamps and identical actions
    When compute_coordination_score is executed
    Then a coordination score of at least 0.75 is returned
