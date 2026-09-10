Feature: Indirect Prompt Injection and Data Poisoning Defense
  As an AI Safety Architect
  I want external data feeds such as git diffs, web scrapes, and incoming messages to be scanned for prompt injections
  So that data poisoning payloads cannot trick host agents into malicious tool execution

  Scenario: Git diff containing hidden system prompt override is detected and flagged
    Given a Prompt Injection Scanner instance with Alert Bus
    When a git diff containing a system prompt override is scanned
    Then the scan produces PromptInjectionEvidence with positive injection confidence
    And the detected patterns list includes "SYSTEM_OVERRIDE_INSTRUCTION"

  Scenario: Injection vectors are redacted before content enters agent context
    Given a Prompt Injection Scanner instance with Alert Bus
    When content with prompt injection vectors is scanned and redacted
    Then the sanitized content contains the redaction placeholder
    And the raw injection directives are removed from the sanitized output

  Scenario: Detected prompt injection attempt emits a HIGH severity alert to Alert Bus
    Given a Prompt Injection Scanner instance with Alert Bus
    When an incoming A2A message containing a single prompt injection vector is scanned for agent "agent-a2a"
    Then a HIGH severity alert is emitted to the Alert Bus for "agent-a2a"
    And the alert evidence ID matches the scan ID

  Scenario: Critical multi-vector injection attempt emits a CRITICAL severity alert to Alert Bus
    Given a Prompt Injection Scanner instance with Alert Bus
    When a payload containing multiple critical injection vectors is scanned for agent "agent-critical"
    Then a CRITICAL severity alert is emitted to the Alert Bus for "agent-critical"

  Scenario: Web scrape containing hidden HTML comments is sanitized
    Given a Prompt Injection Scanner instance with Alert Bus
    When a web scrape containing hidden HTML directive comments is scanned
    Then the hidden directive is neutralized in the sanitized content
    And the source context is recorded as "web_scrape"

  Scenario: Incoming A2A message with delimiter escape is neutralized
    Given a Prompt Injection Scanner instance with Alert Bus
    When an incoming A2A message containing delimiter injection "</system>" is scanned
    Then the delimiter breakout is detected and neutralized in the sanitized content
