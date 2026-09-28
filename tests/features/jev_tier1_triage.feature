Feature: Tier-1 Jev Triage Acceptance
  As the Blackwall Agentic Firewall
  I want Tier-1 Jev P(threat) signals feeding Score Aggregation with Tier-2 Gemini escalation
  So that clear cases resolve without deep-reasoning spend and ambiguous cases get a final verdict

  Scenario: Clear-low Jev signal resolves ALLOW without Tier-2 spend
    Given a SyncResolver with a stubbed Jev backend returning P "0.02"
    When a benign tool call is evaluated
    Then the verdict decision is "ALLOW"
    And Tier-2 escalation is never invoked

  Scenario: Clear-high Jev signal aggregates to BLOCK without Tier-2 spend
    Given a SyncResolver with a stubbed Jev backend returning P "0.98" and a malicious threat-intel response
    When a high-risk tool call is evaluated
    Then the verdict decision is "BLOCK"
    And Tier-2 escalation is never invoked

  Scenario: Ambiguous C2 beacon escalates to Tier-2 for the final verdict
    Given a SyncResolver with a stubbed Jev backend returning P "0.51"
    And Tier-2 returns "BLOCK" with threat_score "0.90"
    When a C2-beacon-like tool call is evaluated
    Then the verdict decision is "BLOCK"
    And Tier-2 escalation was invoked exactly "1" times
    And the verdict reasoning records Tier-2 provenance

  Scenario: Deterministic-vs-semantic disagreement escalates to Tier-2
    Given a SyncResolver with a stubbed Jev backend returning P "0.10"
    And Tier-2 returns "ALLOW" with threat_score "0.20"
    When a high-risk tool call is evaluated
    Then the verdict decision is "ALLOW"
    And Tier-2 escalation was invoked exactly "1" times

  Scenario: Novel block still writes a threat signature off the hot path
    Given a SyncResolver with repository and behavioral-analytics mocks and a stubbed Jev backend returning P "0.51"
    And Tier-2 returns "BLOCK" with threat_score "0.90"
    When a C2-beacon-like tool call is evaluated
    Then the verdict decision is "BLOCK"
    And a threat signature is written to the graph with the blocked verdict

  Scenario: Sanitization-before-egress redacts secrets before the Gateway sees state
    Given a real Jev backend bound to a capturing gateway
    When a tool call containing the secret "AWS_SECRET_ACCESS_KEY=rawsecretvalue" is triaged
    Then the outbound state contains "[[AWS_SECRET_ACCESS_KEY]]"
    And the outbound state does not contain "rawsecretvalue"
    And the outbound request disallows prompt training

  Scenario: Bounded 429 storm fails closed to the gemini backend
    Given a real Jev backend rate-limited on every call with a Gemini fallback returning P "0.95"
    When a high-risk tool call is triaged through the failing gateway
    Then the triage signal backend is "gemini"
    And the jev_triage record marks the signal as fallback
