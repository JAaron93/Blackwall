@enterprise @advanced_threat_detection @retrospective
Feature: Retrospective Analysis and Historical Queries
  As a forensic analyst and detection engineer
  I want to query historical attack paths, detect missed patterns, correlate delayed multi-agent swarms, and export graphs
  So that I can investigate past security incidents and integrate with external graph analysis tools

  Scenario: historical time window query spanning 7 days returns all attack paths in that period
    Given an AttackGraphStore populated with multi-day event history for agent "agent-retro-01"
    When the RetrospectiveAnalyzer queries attack paths for "agent-retro-01" across a 7-day historical window
    Then all returned attack paths start and end within the 7-day historical window
    And the number of identified attack paths is at least 1

  Scenario: retrospective analysis identifies attack paths missed during real-time processing
    Given a stealth multi-hop attack campaign spread across 3 days with causal links for agent "agent-stealth-02"
    When the RetrospectiveAnalyzer performs batch retrospective detection over a 5-day window
    Then the multi-day attack path is successfully reconstructed with at least 2 nodes
    And the attack path risk_score reflects the accumulated threat severity

  Scenario: multi-agent correlation across 30-day history detects delayed swarm patterns
    Given multiple agents "agent-sw-1,agent-sw-2,agent-sw-3" executing coordinated actions spaced days apart
    When the RetrospectiveAnalyzer correlates multi-agent history across the 30-day window
    Then a SwarmEvidence record is produced containing at least 2 coordinated agents
    And the coordination_score is strictly positive

  Scenario: attack graph export produces valid JSON and GraphML output
    Given an attack graph with 2 nodes and a causal edge
    When the AttackGraphExporter exports the graph in "json" format
    Then the JSON output parses into valid graph nodes and edges
    When the AttackGraphExporter exports the graph in "graphml" format
    Then the GraphML output parses into a valid XML tree with directed graph elements
