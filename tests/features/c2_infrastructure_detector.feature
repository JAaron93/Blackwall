Feature: Command-and-Control (C2) Infrastructure Detector
  As a security engineer
  I want to detect C2 infrastructure endpoints, periodic beaconing, persistence indicators, and cross-pillar correlations
  So that malicious Command-and-Control activities are intercepted and recorded in C2Evidence

  Scenario: a Pastebin URL is classified as a known C2 endpoint
    Given a URL string "https://pastebin.com/raw/abc12345"
    When the C2 detector classifies the endpoint
    Then the classification result should be "pastebin"

  Scenario: an agent accessing a C2 endpoint generates C2Evidence with the endpoint in c2_endpoints
    Given an agent "agent-c2-1" accessing a C2 endpoint "https://pastebin.com/raw/malicious_payload"
    When the C2 detector detects C2 establishment for "agent-c2-1" over the time window
    Then C2 evidence should be generated containing "https://pastebin.com/raw/malicious_payload" in c2_endpoints

  Scenario: periodic connections at regular intervals are identified as beaconing
    Given an agent "agent-c2-2" making periodic connections to "https://c2.example.com/heartbeat" at regular 10 second intervals
    When the C2 detector detects beaconing for "agent-c2-2" and endpoint "https://c2.example.com/heartbeat"
    Then the beaconing detection result should be true

  Scenario: a process that recreates itself after termination is identified as a persistence indicator
    Given an agent "agent-c2-3" executing a process with action "auto-restart" and target "/usr/local/bin/backdoor"
    When the C2 detector detects persistence indicators for "agent-c2-3" over the time window
    Then the persistence indicators should contain "Self-respawning process loop"

  Scenario: C2 evidence includes cross-pillar correlation between Pillar 1 network events and tool calls
    Given an agent "agent-c2-4" with a Pillar 1 network syscall event targeting "https://pastebin.com/raw/cmd"
    And the agent "agent-c2-4" with a tool call event targeting "https://pastebin.com/raw/cmd"
    When the C2 detector detects C2 establishment for "agent-c2-4" over the time window
    Then C2 evidence should include cross-pillar correlation between Pillar 1 network events and tool calls
