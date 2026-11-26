# OWASP LLM05 (https://genai.owasp.org/) /
# MITRE ATLAS AML.T0049 (https://atlas.mitre.org/techniques/AML.T0049)
Feature: Gateway Demo Poisoned Package blocks runtime escapes via Python audit hook
  As a security-conscious developer,
  I want runtime escape attempts in an installed package postinstall script to be caught by Blackwall's Python audit hook even when pip install passes the MCP Gateway,
  So that I see defense-in-depth across protocol and runtime layers.

  Scenario: Poisoned package install is allowed by gateway but runtime escapes are blocked by audit hook
    Given the poisoned package demo isolation with synthetic credentials and mock package
    When the agent installs the poisoned package through the gateway and the postinstall executes in an isolated audited child subprocess
    Then the run_command call is allowed by the MCP gateway
    And the Python audit hook blocks subprocess.Popen, os.system, and socket.connect independently
    And all three runtime escape blocks are recorded in the audit incident database
    And the parent test process audit hook state is unchanged
