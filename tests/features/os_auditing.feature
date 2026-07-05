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
