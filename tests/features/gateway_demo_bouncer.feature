# OWASP LLM01 (https://genai.owasp.org/) /
# MITRE ATLAS AML.T0051 (https://atlas.mitre.org/techniques/AML.T0051)
Feature: Gateway Demo Bouncer — Tier-1 Jev fast path and Tier-2 Gemini escalation
  As a security-conscious developer,
  I want Blackwall to allow benign queries via Tier-1 fast path,
  block high-confidence threats immediately via Tier-1 clear-high,
  and escalate ambiguous tool calls to Tier-2 Gemini deep reasoning,
  So that I see the full Jev → Gemini escalation pipeline in action.

  Scenario: Benign database query is allowed by Tier-1 fast path without escalation
    Given the bouncer demo isolation with synthetic credentials
    When the agent issues a benign database_query through the gateway
    Then the gateway returns ALLOW via the Tier-1 Jev fast path
    And no Tier-2 escalation is triggered after the benign query

  Scenario: SQL-injection payload is blocked by Tier-1 clear-high without escalation
    Given the bouncer demo isolation with synthetic credentials
    When the agent issues an execute_bash SQL-injection payload through the gateway
    Then the gateway returns BLOCK via the Tier-1 Jev clear-high path
    And no Tier-2 escalation is triggered after the SQL-injection block

  Scenario: C2 beacon in the ambiguity band is escalated to Tier-2 and blocked
    Given the bouncer demo isolation with synthetic credentials
    When the agent issues an http_request C2 beacon in the Jev ambiguity band
    Then the gateway escalates the call to Tier-2 Gemini deep reasoning
    And the Tier-2 verdict is BLOCK
    And a TSG threat signature is persisted after the Tier-2 block
