Feature: Autonomous Threat Learning and Graph Hygiene
  As the Blackwall Agentic Firewall
  I want to dynamically generate reusable Threat Signatures from quarantined anomalies
  So that future identical attacks are blocked locally while maintaining sub-10ms database latency

  Scenario: Generational learning and LFU/TTL eviction under high load
    Given an unverified edge-case payload is evaluated by Gemini 3.1 Pro as malicious
    When the Gemini Interactions API pushes the structured result to the local HTTP webhook
    Then a new node must be inserted into the "SQLiteThreatRepository" with verdict "BLOCK"
    And if total active nodes in the database exceed the hard cap of 10,000 the background maintenance routine must execute eviction
    And transient nodes older than 15 minutes with hit-counts below 3 must be deleted
    And permanent hardcoded IOC signatures must be preserved
