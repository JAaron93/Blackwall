Feature: Performance Optimization and SLA Validation
  As a platform engineer
  I want the threat detection system to handle high event volumes with low latency
  So that it can protect large-scale deployments without degrading agent performance

  Scenario: event processing latency is under 100ms (warmup run excluded from measurement)
    Given an EventStreamCollector receiving events from all five Blackwall pillars
    When raw events from each pillar are normalized after a warmup run
    Then the event normalization latency for each pillar should be under 100 milliseconds

  Scenario: path query on 17K+ event graph completes in under 500ms
    Given an AttackGraphStore populated with over 17000 events
    When a multi-hop attack path query is executed for a target agent after a warmup query
    Then the attack path query latency should be under 500 milliseconds and return valid paths

  Scenario: system sustains 1,000 events/second for at least 5 minutes without errors
    Given an event stream workload of 1000 events per second
    When the system processes and ingests the sustained batch workload
    Then the processing throughput should exceed 1000 events per second without errors

  Scenario: behavioral fingerprint for a 1-hour window is computed in under 2 seconds
    Given an agent with 600 events across a 1-hour time window
    When the behavioral fingerprint is computed after a warmup run
    Then the fingerprint calculation should complete in under 2 seconds and produce a valid 64-character hash

  Scenario: incremental fingerprint update computes in under 2 seconds for a 1-hour window
    Given an agent with existing behavioral fingerprint state
    When new events are incrementally added to the agent fingerprint
    Then the incremental update should complete in under 2 seconds and produce an updated hash
