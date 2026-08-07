Feature: Blackwall Enterprise Security Mesh End-to-End Integration
  As an Enterprise Security Systems Engineer
  I want to verify the Blackwall Enterprise Security Mesh across all defensive pillars and local open-source MCP adapters
  So that enterprise clusters are protected against agentic zero-day exploits, credential exfiltration, and multi-node attack vectors

  Scenario: Core vs Enterprise product tier packaging and modular isolation
    Given the Blackwall suite is installed on a host workstation
    When Blackwall Core operates in single-host mode
    Then Core has zero external network or eBPF kernel dependencies
    And Enterprise modules are modularized under "blackwall.enterprise" package

  Scenario: Open-source local MCP server suite integration
    Given a local developer workstation running open-source MCP servers
    When the Enterprise MCP adapters connect to Falco, Vault, Sandbox, and OpenTelemetry local runners
    Then all 4 MCP adapters report active connection status
    And the total software license cost is "$0.00"

  Scenario: ZeroMQ threat signature broadcast across cluster nodes
    Given an Enterprise Threat Mesh node with ZeroMQ broadcaster and receiver
    And a local SQLite threat signature graph operating in WAL mode
    When Node 1 generates a dynamic threat signature "sig_rce_nc_001"
    Then the signature is published over ZeroMQ pub/sub sockets
    And Node 2 ingests the signature into its local SQLite database within 15 ms

  Scenario: Secret masking sidecar and Vault JIT token exchange
    Given an Ephemeral Identity Sidecar initialized on a worker node
    And environment variables containing sensitive keys "AWS_SECRET_ACCESS_KEY=BW_SYNTHETIC_MOCK_SECRET_0192"
    When the sidecar sterilizes the host environment
    Then real credentials are replaced with synthetic honey-tokens "BW_SYNTHETIC_AWS_SECRET_ACCESS_KEY"
    And any exfiltration attempt of "BW_SYNTHETIC_" triggers a "CRITICAL" threat alert
    And authorized calls receive a 15 minute JIT token from HashiCorp Vault MCP

  Scenario: Application pipeline wrapper and AST micro-sandbox containment
    Given a Python application guarded by "@blackwall.guard_pipeline"
    And an AST pipeline filter parsing dataset loader code
    When an untrusted loader attempts indirect function call "runner = os.system; runner('rm -rf /')"
    Then the AST filter detects the indirect function alias
    And the loader execution is routed to an isolated container sandbox via Sandbox MCP

  Scenario: Dual-mode local forensic triage engine and OpenTelemetry export
    Given a Forensic Triage Manager configured with Ollama LLM and Standalone Fallback Parser
    When an incident log event is ingested for triage
    Then if Ollama is online the primary LLM analyzes the log without safety refusals
    And if Ollama is offline the standalone lightweight parser achieves 100% fallback availability
    And the incident triage report is exported as a trace span via OpenTelemetry MCP

  Scenario: Pillar 6 Advanced Threat Detection data model and temporal validation
    Given an Advanced Threat Detection engine receiving cross-pillar events
    When a threat event is ingested with UUID v4 "550e8400-e29b-41d4-a716-446655440000" and UTC timestamp
    Then the NormalizedEvent model accepts valid UUID v4 and UTC timestamp
    And invalid UUIDs, naive timestamps, and out-of-bound risk scores are rejected
    And AttackPaths enforce minimum 2 nodes and temporal ordering end_time >= start_time

  Scenario: Pillar 6 EventStreamCollector multi-pillar ingestion and resilient normalization
    Given an EventStreamCollector engine ingesting streams across all 5 Blackwall pillars
    When heterogeneous events from kernel, tool, identity, pipeline, and forensic sources are collected
    Then events are normalized into standard NormalizedEvents with UUID v4 IDs, UTC timestamps, and risk scores
    And malformed payloads or invalid stream factories fail cleanly without corrupting telemetry
