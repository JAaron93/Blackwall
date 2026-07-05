Feature: Python Runtime Audit Hook Enforcement
  As the Blackwall Agentic Firewall
  I want the Python runtime audit hook to block raw OS and subprocess execution paths
  So that adversarial agents cannot bypass the ADK tool layer by calling os or subprocess directly

  Scenario: Audit hook blocks subprocess.Popen execution attempt
    Given the Blackwall logging pipeline is initialised with the runtime audit hook
    When an adversarial agent attempts to spawn a process via "subprocess.Popen"
    Then the audit hook must raise a "PermissionError" before the OS executes the command
    And the structlog configuration must be restored to its original state

  Scenario: Audit hook blocks os.system execution attempt
    Given the Blackwall logging pipeline is initialised with the runtime audit hook
    When an adversarial agent attempts to spawn a process via "os.system"
    Then the audit hook must raise a "PermissionError" before the OS executes the command
    And the structlog configuration must be restored to its original state
