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

Feature: Low-Level OS Runtime Auditing
  As the Blackwall Agentic Firewall
  I want to trap native system calls at the Python runtime level
  So that adversarial agents cannot bypass ADK tool hooks using raw OS or subprocess imports

  Scenario: Intercepting unauthorized socket connections at the OS level
    Given the Python runtime audit hook "sys.addaudithook" is actively monitoring system events
    And the local SQLite IOC blacklist contains IP address "198.51.100.24"
    When an execution agent runs a Python script attempting "socket.connect" to "198.51.100.24:4444"
    Then the audit hook must trap the "socket.connect" event before OS kernel execution
    And the system must raise an immediate "PermissionError" exception
    And an incident telemetry record must be written atomically to the SQLite WAL database
    And the outbound network connection must be severed completely

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

Feature: Autonomous Threat Learning and Graph Hygiene
  As the Blackwall Agentic Firewall
  I want to dynamically generate reusable Threat Signatures from quarantined anomalies
  So that future identical attacks are blocked locally while maintaining sub-10ms database latency

  Scenario: Generational learning and LFU/TTL eviction under high load
    Given an unverified edge-case payload is evaluated by Gemini 3.1 Pro as malicious
    When the Gemini Interactions API pushes the structured result to the local HTTP webhook
    Then a new node must be inserted into the "SQLiteThreatRepository" with verdict "BLOCK"
    And if total active nodes in the database exceed the hard cap of 10,000 the background maintenance routine must execute eviction
    And transient nodes older than 15 minutes with hit-counts below 3 must be deleted
    And permanent hardcoded IOC signatures must be preserved
