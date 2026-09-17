Feature: High-Throughput Threat Intelligence Resolution
  As an AI agent security firewall
  I want external network indicators resolved at machine speed without rate-limiting bottlenecks
  So that high-frequency tool invocations are evaluated within strict latency SLAs

  Scenario: 20 consecutive network tool calls complete without throttling
    Given a high-capacity threat intelligence resolver with SQLite caching enabled
    When an AI agent executes 20 consecutive network tool calls within 10 seconds
    Then all 20 calls must be evaluated successfully without query throttling
    And live queries must complete within 2.0 seconds
    And subsequent cached queries must complete in less than 1.0 milliseconds
