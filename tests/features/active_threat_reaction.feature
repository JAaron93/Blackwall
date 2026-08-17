Feature: Active Threat Reaction and Fleet Containment Feedback Loop
  As an enterprise security engineer
  I want high-confidence threat evidence detected by ATD to trigger automated mitigation actions across Pillars 1, 2, and 3
  So that rogue agent attacks are halted at machine speed before breaching host environments or expanding across the enterprise fleet

  Scenario: CRITICAL swarm detection injects eBPF socket drop rule into Pillar 1 within 50ms
    Given an Active Reaction Engine configured with a kernel probe driver
    When a CRITICAL swarm detection payload is dispatched for target process 1234 on IP "192.168.1.100"
    Then the kernel probe driver injects socket drop rules for PID 1234 and IP "192.168.1.100"
    And the reaction execution duration is less than 50 milliseconds
    And the reaction status is "COMPLETED"

  Scenario: CRITICAL exploit chain broadcasts ZeroMQ signature across Threat Mesh in <15ms
    Given an Active Reaction Engine configured with a threat mesh broadcaster
    When a CRITICAL exploit chain payload is dispatched for agent "rogue-agent-x"
    Then the threat mesh broadcaster publishes the zero-latency block signature
    And the reaction execution duration is less than 15 milliseconds
    And the reaction status is "COMPLETED"

  Scenario: AILM breach revokes JIT tokens via Pillar 3 Vault sidecar
    Given an Active Reaction Engine configured with a Vault MCP adapter
    And active JIT credentials issued for compromised agent "agent-breached-ailm"
    When an AILM breach mitigation payload is dispatched for agent "agent-breached-ailm"
    Then the Vault MCP adapter revokes all active JIT tokens for agent "agent-breached-ailm"
    And the reaction status is "COMPLETED"

  Scenario: CRITICAL evidence originating from an evaluation environment suppresses production eBPF drop, Threat Mesh broadcast, and Vault credential revocation
    Given an Active Reaction Engine configured with kernel driver, mesh broadcaster, Vault adapter, and evaluation environment manager
    And an evaluation environment "eval-sandbox-bdd" with an event node
    When an eBPF drop payload derived from the evaluation event is dispatched
    And a Threat Mesh broadcast payload derived from the evaluation event is dispatched
    And a Vault revocation payload derived from the evaluation event is dispatched
    Then all three reaction payloads have status "SUPPRESSED_EVALUATION"
    And no production socket drop rules are injected
    And no threat signatures are broadcast to the production mesh
