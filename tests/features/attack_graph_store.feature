Feature: Attack Graph Store Temporal Graph Operations
  As an Enterprise Security Engineer
  I want the AttackGraphStore to ingest normalized events, manage directed causal edges, and query attack paths efficiently
  So that multi-hop threats and high-volume event graphs are analyzed accurately with fast performance

  Scenario: inserting a NormalizedEvent creates a node with temporal ordering preserved
    Given an initialized AttackGraphStore instance
    When multiple NormalizedEvents with different timestamps are inserted
    Then each event creates an AttackNode in the store
    And querying nodes returns them ordered by timestamp ascending

  Scenario: linking two events creates a directed edge with the specified relationship type
    Given an initialized AttackGraphStore containing two inserted events
    When link_events is called with relationship type "EXECUTES_NEXT"
    Then a directed edge is created connecting the source node outgoing_edges to target node incoming_edges

  Scenario: querying paths returns only paths with at least min_path_length nodes within the time window
    Given an initialized AttackGraphStore with events forming paths of varying lengths
    When query_paths is called with min_path_length of 3
    Then only attack paths containing at least 3 nodes within the time window are returned

  Scenario: path query on a 17K+ event graph completes in under 500ms (warmup run excluded)
    Given an initialized AttackGraphStore populated with over 17000 normalized events
    When query_paths is executed with a warmup run followed by a benchmark run
    Then the benchmark query execution time is under 500 milliseconds

  Scenario: non-positive limit parameter raises ValueError
    Given an initialized AttackGraphStore instance
    When query_nodes is called with a non-positive limit parameter
    Then a ValueError is raised stating limit must be positive
