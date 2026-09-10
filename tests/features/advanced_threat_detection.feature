Feature: Blackwall Advanced Threat Detection Pillar Data Validation
  As an Enterprise Security Engineer
  I want the Advanced Threat Detection pillar to strictly validate event and threat evidence models
  So that invalid UUIDs, naive or non-UTC timestamps, invalid risk scores, and corrupted attack paths are rejected before reaching graph storage

  Scenario: Normalized Event UUID and UTC timestamp enforcement
    Given a raw event payload with event ID "550e8400-e29b-41d4-a716-446655440000" and UTC timestamp
    When the event is normalized into a NormalizedEvent model
    Then the NormalizedEvent model accepts the valid UUID v4 and UTC timestamp
    And invalid UUIDs or non-UTC timestamps are rejected with a validation error

  Scenario: Attack Path node sequence and temporal ordering validation
    Given a set of normalized attack nodes
    When an AttackPath is constructed with at least 2 nodes and valid temporal sequence
    Then the AttackPath model is created successfully
    And AttackPaths with fewer than 2 nodes or end_time earlier than start_time are rejected

  Scenario: Swarm Evidence agent count and time window validation
    Given a group of correlated agent identifiers
    When SwarmEvidence is constructed with 2 or more distinct agent IDs and valid time window
    Then the SwarmEvidence model is created successfully
    And SwarmEvidence with fewer than 2 agents or last_seen earlier than first_seen is rejected

  Scenario: Attack Graph Store event ingestion, causal linking, and path query
    Given an initialized AttackGraphStore instance
    When security events are ingested and causally linked
    Then the AttackGraphStore persists node edges and returns correlated multi-hop attack paths

  Scenario: Event Stream Collector cross-pillar normalization and stream recovery
    Given an EventStreamCollector instance and heterogeneous raw events from 5 pillars
    When the raw events are ingested through the EventStreamCollector
    Then each event is normalized with UUID v4 ID, UTC timestamp, and pillar source enum
    And malformed events or non-callable reconnect attempts are rejected cleanly

  Scenario: Path Correlator multi-stage attack path correlation and MITRE mapping
    Given an agent with a temporal sequence of security events
    When the PathCorrelator correlates attack paths within the time window
    Then correlated AttackPath instances are returned with valid risk scores, correlation scores, and mapped MITRE technique IDs

  Scenario: Agent Swarm Detector fingerprinting and temporal swarm detection
    Given an initialized AgentSwarmDetector instance and correlated security events for multiple agents
    When agent action sequences are fingerprinted and swarms are detected
    Then deterministic SHA-256 behavioral fingerprints are generated
    And SwarmEvidence is produced with temporal correlation, coordination score, and shared infrastructure patterns

  Scenario: Retrospective Analysis historical query and graph export compliance
    Given a RetrospectiveAnalyzer instance with multi-day historical events
    When historical time windows are queried and graphs are exported in JSON and GraphML formats
    Then retrospective attack paths are identified across the multi-day window
    And the exported graph outputs match standard JSON and GraphML schemas

  Scenario: Error Handling and Resilience engine crash isolation and resource throttling
    Given an Advanced Threat Detection resilience runner and resource throttler
    When a detector encounters an unhandled exception or pipeline load exceeds thresholds
    Then the SafeDetectionRunner captures the error without crashing the pipeline
    And the ResourceThrottler degrades analysis depth to preserve real-time throughput

  Scenario: Indirect Prompt Injection and Data Poisoning Defense
    Given a Prompt Injection Scanner instance
    When an external payload containing a system prompt override is scanned
    Then the PromptInjectionEvidence confirms detection and returns sanitized text
    And an alert is emitted to the Alert Bus

  Scenario: Agent Fleet Resource and Token Velocity Enforcement
    Given an Agent Quota Enforcer instance configured with a token burn rate limit of 500
    When an agent consumes 1000 tokens in 1 second
    Then the agent is placed into quarantine and a Denial of Wallet alert is dispatched to the Alert Bus



