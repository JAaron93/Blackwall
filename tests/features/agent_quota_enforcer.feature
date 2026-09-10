Feature: Agent Fleet Resource and Token Velocity Enforcement (Denial of Wallet Defense)
  As a Cloud Infrastructure Lead
  I want to monitor token burn rates and API call velocity across agent fleets
  So that rogue agent swarms cannot cause financial exhaustion or Denial of Wallet outages

  Scenario: Token burn rate exceeding 500 tokens/sec triggers agent quarantine
    Given an Agent Quota Enforcer instance with limit 500 tokens/sec and Alert Bus
    When agent "agent-burn-rogue" consumes 1000 tokens in 1 second
    Then the quota enforcer flags the quota as exceeded
    And agent "agent-burn-rogue" is placed into quarantine
    And a Denial of Wallet alert is emitted to the Alert Bus for "agent-burn-rogue"

  Scenario: API call velocity surge emits Denial of Wallet alert to Alert Bus
    Given an Agent Quota Enforcer instance with request velocity limit 10 calls/sec and Alert Bus
    When agent "agent-velocity-surge" executes 25 API calls in 1 second
    Then the quota enforcer detects the velocity surge
    And a Denial of Wallet alert with severity "HIGH" or "CRITICAL" is emitted for "agent-velocity-surge"

  Scenario: Normal token consumption within limits does not trigger quarantine or alerts
    Given an Agent Quota Enforcer instance with limit 500 tokens/sec and Alert Bus
    When agent "agent-benign" consumes 100 tokens with 1 API call
    Then the quota enforcer confirms the quota is not exceeded
    And agent "agent-benign" is not quarantined
    And zero Denial of Wallet alerts are emitted for "agent-benign"

  Scenario: Critical burn rate spike emits CRITICAL severity alert to Alert Bus
    Given an Agent Quota Enforcer instance with limit 200 tokens/sec and critical multiplier 2.0
    When agent "agent-critical-dow" consumes 1200 tokens in a single burst
    Then a CRITICAL severity alert is emitted to the Alert Bus for "agent-critical-dow"
    And the alert metadata contains total tokens consumed 1200

  Scenario: Quarantined agent blocks subsequent operations until unquarantined
    Given an Agent Quota Enforcer instance with limit 500 tokens/sec and Alert Bus
    When agent "agent-locked" is manually quarantined with reason "Administrative hold"
    Then agent "agent-locked" is verified as quarantined
    And enforcing quota on "agent-locked" immediately returns True
    When agent "agent-locked" is unquarantined
    Then agent "agent-locked" is no longer quarantined
