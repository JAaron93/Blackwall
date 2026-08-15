Feature: Error Handling and Resilience
  As an autonomous security engine
  I want resilient multi-pillar ingestion, database transaction retry, detection crash isolation, and load throttling
  So that threat detection operations remain available and robust during transient failures or high load

  Scenario: Multi-pillar stream collector continues ingestion when one pillar fails
    Given a multi-pillar collector with one failing pillar and one healthy pillar
    When the collector ingests from all pillar streams concurrently
    Then events from the healthy pillar are successfully received without pipeline interruption

  Scenario: Attack graph store retries transactions on transient database failures
    Given an attack graph store with transient transaction failures
    When an event is inserted into the attack graph store
    Then the store retries the database operation and commits successfully

  Scenario: Detection runner isolates crashes in faulty detection algorithms
    Given a safe detection runner and a faulty detection algorithm
    When the detection algorithm raises an unhandled runtime error
    Then the safe detection runner captures the error and returns the fallback value

  Scenario: Resource throttler dynamically degrades analysis depth under high event load
    Given a resource throttler under high event load
    When querying for recommended analysis depth
    Then the throttler reduces the analysis depth to maintain pipeline throughput
