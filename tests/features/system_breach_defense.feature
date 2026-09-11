Feature: System-Wide Breach Defense Integration
  As an Enterprise Security Operator
  I want the Advanced Threat Detection orchestrator to coordinate active breach defenses, protocol filtering, prompt injection neutralization, and token quota enforcement
  So that malicious agent swarms, protocol attacks, indirect prompt injections, and resource exhaustion attacks are automatically thwarted across all pillars.

  Scenario: CRITICAL swarm detection triggers eBPF drop, ZeroMQ mesh broadcast, and Vault token revocation
    Given a running AdvancedThreatDetection orchestrator configured with active reactions
    And mock kernel driver, mesh broadcaster, and Vault adapter attached to the reaction engine
    When coordinated security events from multiple agents trigger a CRITICAL swarm detection
    Then automated eBPF socket drops are injected for all participating agents
    And zero-latency threat signatures are broadcasted across the ZeroMQ mesh
    And short-lived JIT identity tokens are revoked in HashiCorp Vault

  Scenario: Incoming unauthorized A2A request is rate-limited and sanitized
    Given an AdvancedThreatDetection orchestrator with an InboundProtocolFilter
    When an incoming A2A RPC request containing sensitive credentials in parameters is received
    Then the sensitive credentials in the RPC arguments are sanitized with redaction placeholders
    And when the sender exceeds the configured rate limit, subsequent requests are rejected with an MCP error response

  Scenario: Git diff with prompt injection is neutralized before execution
    Given an AdvancedThreatDetection orchestrator with PromptInjectionScanner
    When an external git diff containing a hidden system prompt override is scanned
    Then the prompt injection attempt is detected with high confidence
    And the malicious injection spans are neutralized and replaced with redaction placeholders
    And a prompt injection alert is published to the AlertBus

  Scenario: Token velocity surge triggers agent quarantine and Denial of Wallet defense
    Given an AdvancedThreatDetection orchestrator with AgentQuotaEnforcer
    When an agent consumes tokens exceeding the configured velocity and burn rate limits
    Then the agent is placed into quarantine
    And a Denial of Wallet surge alert is published to the AlertBus
