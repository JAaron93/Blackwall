Feature: Fail-Closed Rate Limit Resilience
  As the Blackwall Agentic Firewall
  I want to default to a fail-closed posture when API rate limits are exceeded
  So that high-speed adversarial flood attacks cannot force open an unverified bypass

  Scenario: Attacker exhausts Gemini API rate limits during novel threat evaluation
    Given an incoming tool call requires asynchronous semantic evaluation via Gemini 3.1 Pro
    And the current Gemini API request volume has exceeded the 300 RPM threshold
    When all exponential backoff and retry attempts return an HTTP 429 Rate Limit Error
    Then the system must NOT default to an "ALLOW" verdict
    And the system must fail closed by issuing a "QUARANTINE" verdict
    And the quarantined event must be logged to the local Interception Queue for manual/later review
