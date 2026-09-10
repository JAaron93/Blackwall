@gti_rate_limiting
Feature: GTI Query Budget Rate Limiting and Degradation
  As the Blackwall security firewall
  I want to enforce the VirusTotal free-tier rate limit of 4 queries per 60-second window
  So that API quotas are not exhausted and high-risk queries degrade gracefully

  Scenario: High-risk event consumes GTI token
    Given a GTI MCP Client with a full budget of 4 tokens
    And an uncached high-risk indicator "http://malicious-command-control.xyz" with context "run_command"
    When the high-risk indicator is queried via GTI
    Then exactly 1 GTI budget token is consumed
    And the available budget token count is 3
    And the query executes successfully

  Scenario: Budget exhaustion triggers graceful degradation
    Given a GTI MCP Client with an exhausted budget of 0 tokens
    And an uncached high-risk indicator "http://malicious-payload-drop.xyz" with context "run_command"
    When the high-risk indicator is queried via GTI with budget enforcement
    Then the GTI query raises GTIBudgetExhaustedError
    And the budget metrics record 1 deferred query

  Scenario: Low-risk event skips GTI validation
    Given a GTI MCP Client with a full budget of 4 tokens
    And a low-risk indicator "127.0.0.1" with safe tool context "read_file"
    When the low-risk indicator is evaluated for GTI querying
    Then the GTI query is skipped without consuming a budget token
    And the available budget token count remains 4

  Scenario: Token replenishment restores capacity
    Given a GTI query budget tracker with capacity 4 and fast replenishment interval 0.05 seconds
    And all 4 tokens have been exhausted
    When the tracker waits for token replenishment
    Then the available token count increases above 0
    And subsequent query acquisition succeeds

  Scenario: Concurrent events respect 4-query/60s cap
    Given a GTI query budget tracker with capacity 4
    When 10 concurrent query acquisition requests are executed
    Then exactly 4 requests are permitted
    And exactly 6 requests are deferred
    And the available token count is 0
