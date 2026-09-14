Feature: Self-Learning Loop Integration and Adaptive Threat Defense
  As the Blackwall Agentic Firewall
  I want to automatically generate threat signatures from blocked events and refactoring hints from quarantined events
  So that structurally-similar attacks are blocked rapidly via the Threat Signature Graph and insecure code is remediated

  Scenario: Novel attack triggers inline threat signature generation with 768-dimensional vector
    Given a clean Threat Signature Graph repository with zero signatures
    When a novel attack tool call is evaluated and blocked
    Then a threat signature must be written to the Threat Signature Graph with a 768-dimensional embedding vector
    And the signature match count must be initialized to 0

  Scenario: Structurally-similar attack is blocked via Threat Signature Graph with lower latency
    Given an active Threat Signature Graph containing a signature for a previous attack
    When a structurally-similar variant attack tool call is evaluated
    Then the variant attack must be blocked via Threat Signature Graph signature match
    And the signature match latency must be faster than semantic evaluation
    And the matched signature match count must be incremented by 1

  Scenario: Quarantine event triggers Green Team refactoring hint generation
    Given an intercepted tool call with ambiguous security risk
    When the tool call receives a QUARANTINE verdict
    Then a Green Team refactoring hint must be generated with vulnerability type and suggested fix
