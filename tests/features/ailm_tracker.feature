Feature: AI-Induced Lateral Movement (AILM) Tracker
  As a security architect
  I want to track runtime permission grants and detect permission composition across trust boundaries
  So that I can detect unauthorized AI-induced lateral movement

  Scenario: A permission grant is recorded with all required fields
    Given a permission grant with permission "s3:GetObject", granted_by "admin-user", granted_to "agent-bdd-1", and scope "user_space"
    When the AILM tracker records the permission grant
    Then the recorded grant should contain permission "s3:GetObject", granted_by "admin-user", granted_to "agent-bdd-1", and scope "user_space"

  Scenario: An agent accumulating permissions across multiple time windows is detected
    Given an agent "agent-bdd-2" with permission grant "read_db" at current time minus 200 seconds
    And the agent "agent-bdd-2" receiving permission grant "write_db" at current time minus 50 seconds
    When the AILM tracker detects permission composition for "agent-bdd-2" over a 300 second window
    Then the AILM evidence should contain composed permissions "read_db" and "write_db"

  Scenario: Permissions spanning two trust boundaries are identified as a cross-boundary composition
    Given an agent "agent-bdd-3" with grant "read_user_data" in scope "user_space"
    And the agent "agent-bdd-3" with grant "kernel_exec" in scope "kernel_space"
    When the AILM tracker detects permission composition for "agent-bdd-3" over a 300 second window
    Then the AILM evidence should identify at least 1 boundary crossing transition

  Scenario: AILM evidence with 3 or more boundary crossings receives CRITICAL risk_level
    Given an agent "agent-bdd-4" with grants crossing 3 security boundaries
    When the AILM tracker detects permission composition for "agent-bdd-4" over a 300 second window
    Then the AILM evidence should have risk_level "CRITICAL"
