Feature: Multi-Stage Attack Path Correlation
  As a security engine
  I want security events correlated into multi-stage attack paths
  So that multi-step attacks and technique progressions are identified across time

  Scenario: events within 5 minutes of each other are linked in the temporal adjacency graph
    Given two events for an agent occurring 3 minutes apart
    When building the temporal adjacency graph
    Then an edge should exist between the first event node and the second event node

  Scenario: events more than 5 minutes apart are not linked
    Given two events for an agent occurring 10 minutes apart
    When building the temporal adjacency graph
    Then no edge should exist between the first event node and the second event node

  Scenario: DFS finds all paths meeting the minimum length requirement
    Given a sequence of 3 temporally adjacent events for an agent
    When correlating attack paths with min_path_length 2
    Then DFS should find attack paths of length at least 2

  Scenario: returned paths are ordered by risk_score descending
    Given multiple attack paths generated for an agent with varying risk scores
    When correlating attack paths for the agent
    Then the returned attack paths should be ordered by risk_score descending

  Scenario: agent with fewer events than min_path_length returns an empty list
    Given an agent with 1 event in the store
    When correlating attack paths with min_path_length 2
    Then an empty list of attack paths should be returned

  Scenario: attack stages are mapped to valid MITRE ATT&CK technique IDs
    Given attack nodes with actions "exec command" and "sudo elevate"
    When mapping MITRE techniques for the attack path
    Then the attack stages should contain valid MITRE technique IDs "T1059" and "T1068"
