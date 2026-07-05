Feature: Batch Resolver Security and Rate Limiting
  As the Blackwall Agentic Firewall
  I want to process batches of tool calls safely and within rate limits
  So that sensitive information is redacted and the system does not exceed the Gemini API throughput

  Scenario: Redacting sensitive data before submitting to Gemini API
    Given a Batch Resolver is initialized with a mock Gemini client
    And a tool call context contains sensitive "api_key=AIzaSyA1234567890BCDEF1" and "password:admin:supersecret123"
    When the batch is processed by the resolver
    Then the submitted payload must be redacted to "api_key=[[API_KEY]]" and "password:[[PASSWORD]]"

  Scenario: Context caching decreases token usage on subsequent calls
    Given a Batch Resolver is initialized with a mock Gemini client
    When a batch is processed for the first time
    Then the response indicates no cache hit
    When the same batch is processed a second time
    Then the response indicates a cache hit
    And the token consumption is reduced by at least 50%

  Scenario: Local rate limiting prevents exceeding the 300 RPM ceiling
    Given a Batch Resolver is initialized with a local rate limiter
    And the rate limiter has a capacity of 5 tokens and no refill
    When 5 requests are made to the rate limiter
    Then all 5 requests must be allowed
    When a 6th request is made
    Then the 6th request must be blocked by the rate limiter

  Scenario: Rate limit exhaustion triggers fail-closed quarantine
    Given a Batch Resolver is initialized with a mock Gemini client that always returns 429 errors
    When the batch is processed by the resolver
    Then the resolver must retry the submission 3 times with exponential backoff
    And the final verdicts must all be "QUARANTINE" with reason "Rate limit exceeded"
