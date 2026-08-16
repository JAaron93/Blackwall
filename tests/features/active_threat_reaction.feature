Feature: Active Threat Reaction Engine (Feedback Loop to Pillars 1, 2, 3)
  As an autonomous security operations system
  Blackwall Active Reaction Engine must execute real-time automated mitigations across kernel, mesh, and identity tiers
  while ensuring evaluation environments are quarantined from production actions

  Scenario: Dynamic eBPF socket drop injection on critical threat detection
    Given an ActiveReactionEngine configured with Pillar 1 Kernel Probe Driver
    When a critical threat reaction payload with action "EBPF_DROP" is dispatched for PID 5542 and IP "10.0.0.50"
    Then the kernel driver injects a drop rule for PID 5542 and IP "10.0.0.50"
    And the reaction execution completes in less than 50 milliseconds with status "SUCCESS"

  Scenario: Zero-latency threat mesh signature broadcast across peer nodes
    Given an ActiveReactionEngine configured with Pillar 2 Threat Mesh Broadcaster
    When a critical threat reaction payload with action "MESH_SIGNATURE_BROADCAST" is dispatched for agent "c2-infiltrator"
    Then the Threat Mesh broadcaster transmits the signature across cluster nodes
    And the broadcast reaction completes in less than 15 milliseconds with status "SUCCESS"

  Scenario: Identity credential invalidation upon lateral movement or token theft
    Given an ActiveReactionEngine configured with Pillar 3 Ephemeral Identity Sidecar and Vault MCP
    And an active JIT credential issued for agent "lateral-agent-01"
    When an active reaction payload with action "REVOKE_IDENTITY_TOKENS" is dispatched for agent "lateral-agent-01"
    Then the active JIT credential is revoked and synthetic honey-tokens are rotated
    And the reaction status is "SUCCESS"

  Scenario: Mitigation actions are suppressed when evidence originates in evaluation mode
    Given an ActiveReactionEngine connected to an EvaluationEnvironmentManager
    And security evidence generated within evaluation environment "eval-sandbox-01"
    When an active reaction payload is dispatched referencing the evaluation evidence
    Then the production mitigation action is suppressed with status "SUPPRESSED"
    And zero drop rules or mesh signatures are injected into production

  Scenario: Active reactions are logged to attack graph and emitted to alert bus
    Given an ActiveReactionEngine configured with AttackGraphStore and AlertBus
    When an active reaction payload is dispatched for compromised agent "agent-compromised-99"
    Then the reaction execution record is inserted into the AttackGraphStore
    And an audit notification alert is published to the AlertBus
