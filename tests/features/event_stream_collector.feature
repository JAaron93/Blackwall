Feature: Event Stream Collector
  As a security analyst
  I want heterogeneous event streams normalized into standard threat events
  So that threat detection algorithms can process unified security telemetry

  Scenario: kernel syscall event is normalized to KERNEL_SYSCALL source with UTC timestamp and UUID v4
    Given a raw kernel syscall event payload
    When the event stream collector normalizes the event for KERNEL_SYSCALL
    Then the normalized event source should be KERNEL_SYSCALL
    And the normalized event timestamp should be in UTC timezone
    And the normalized event ID should be a valid UUID v4

  Scenario: each of the five pillar sources maps to the correct EventSource enum value
    Given raw event payloads for all five pillar sources
    When the event stream collector normalizes each raw event for its pillar source
    Then each normalized event source matches its corresponding EventSource enum value

  Scenario: event is enriched with temporal context and agent metadata
    Given a raw event payload with agent ID "agent-007" and metadata
    When the event stream collector normalizes the event
    Then the normalized event metadata should contain ingested_at and pillar_source
    And the normalized event agent_id should be "agent-007"

  Scenario: pillar stream disconnection triggers exponential backoff and reconnection attempt
    Given a failing stream factory that succeeds on retry
    When collecting events with reconnect enabled for KERNEL_SYSCALL
    Then events should be successfully collected after reconnect attempt
