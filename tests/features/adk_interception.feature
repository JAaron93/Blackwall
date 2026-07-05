Feature: ADK Tool Execution Interception
  As the Blackwall Agentic Firewall
  I want to intercept and evaluate all ADK tool calls synchronously
  So that malicious execution attempts are blocked locally within 10ms without burning API tokens

  Scenario: Blocking a known malicious tool payload via local SQLite graph
    Given the Blackwall ambient daemon is running in local Kali Linux VM
    And the embedded SQLite threat repository is operating in WAL mode
    And an active Threat Signature exists with pattern "rm -rf /root/*" and verdict "BLOCK"
    When the untrusted Qwen3 execution agent attempts to call tool "execute_terminal"
    And the tool argument payload contains "rm -rf /root/*"
    Then the ADK "before_tool_callback" hook must intercept the call synchronously
    And the evaluation engine must query the SQLite threat repository
    And the tool execution must be aborted with verdict "BLOCK" within 10ms
    And zero external Gemini API calls must be initiated
