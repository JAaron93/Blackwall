@covert_channel
Feature: Covert Channel and Latent Message Board Detection

  Scenario: Inferring an unlocated message board from high coordination without C2
    Given a detected agent group containing 4 distinct agent IDs
    And the group has temporal_correlation of 0.88 and coordination_score of 0.85
    And the group has 0 external C2 domains or network IPs in shared_patterns
    When the CovertChannelDetector analyzes the group
    Then a CovertChannelEvidence record MUST be generated
    And the channel_type MUST be "UNLOCATED_MESSAGE_BOARD"
    And the confidence score MUST be at least 0.90
    And a CRITICAL alert MUST be published to the AlertBus

  Scenario: Detecting Artifactory package name steganography as covert C2
    Given 3 agents making rapid sequential metadata requests to "http://artifactory.internal/api/storage"
    And the request paths contain base64-encoded directory names
    When the CovertChannelDetector processes the events
    Then a CovertChannelEvidence record MUST be generated
    And the channel_type MUST be "STEGANOGRAPHIC_REGISTRY"
    And the observed_artifacts MUST contain the Artifactory endpoint
    And the coordinating agents MUST contain all 3 agents

  Scenario: Detecting local filesystem dead-drop in staging directories
    Given 2 agents accessing a shared staging file "/tmp/.covert_sync_drop"
    And agent "agent-writer" performs a "write" action
    And agent "agent-reader" performs a "read" action
    When the CovertChannelDetector processes the events
    Then a CovertChannelEvidence record MUST be generated
    And the channel_type MUST be "FILESYSTEM_DEAD_DROP"
    And the confidence score MUST be at least 0.85
    And the observed_artifacts MUST contain "/tmp/.covert_sync_drop"

  Scenario: Rejecting covert channel detection for single-agent events
    Given 1 agent accessing a staging file "/tmp/.single_agent_drop"
    When the CovertChannelDetector processes the events
    Then no CovertChannelEvidence record MUST be generated
