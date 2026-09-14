Feature: Performance Benchmarking and Resource Validation
  As the Blackwall platform engineer
  I want to validate that the firewall satisfies all latency, throughput, and resource consumption SLAs
  So that high-throughput agent operations proceed without latency degradation or resource exhaustion

  Scenario: Structural gating satisfies sub-5ms p99 latency SLA under concurrent load
    Given a StructuralGatingEngine configured with production rules
    When 100 concurrent tool call requests are evaluated
    Then the structural gating p99 latency must be under 5.0 milliseconds

  Scenario: Semantic gating satisfies sub-300ms p99 latency SLA
    Given a SyncResolver with mock GTI and CBM intelligence
    When 50 semantic tool calls are evaluated
    Then the semantic gating p99 latency must be under 300.0 milliseconds

  Scenario: Threat Signature Graph query with 10000 signatures satisfies sub-10ms p99 latency SLA
    Given a Threat Signature Graph populated with 10000 signatures
    When 100 similarity queries are executed
    Then the TSG query p99 latency must be under 10.0 milliseconds

  Scenario: Firewall resource consumption remains under 512MB RSS and 50% CPU during sustained load
    Given an active Blackwall firewall instance under sustained 300 RPM load
    When 100 tool calls are processed at sustained rate
    Then the resident memory RSS must remain under 512.0 megabytes
    And the CPU utilization on a 2-core baseline must remain under 50.0 percent

  Scenario: Batch Resolver achieves average batch size of at least 3 under full load
    Given a BatchResolver receiving concurrent tool call batches
    When full batch load is processed
    Then the average batch size must be at least 3.0
