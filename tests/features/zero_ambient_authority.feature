@zero_ambient_authority
Feature: Zero Ambient Authority and JIT Token Downscoping
  As a security architect
  I want the Blackwall agent to operate with dropped privileges and temporary credentials
  So that a compromised agent cannot escalate privileges or expose secrets

  Scenario: Drop process privileges to unprivileged user
    Given the Blackwall process is running
    When the privilege manager drops OS privileges
    Then the process UID must be unprivileged
    And the process GID must be unprivileged

  Scenario: JIT token downscoping per tool call
    Given a Local Vault is initialized with secret "gti-api-key" as "gti-real-key"
    And a JIT credential manager is active
    When an intercepted tool call begins execution
    Then a temporary scoped credential must be generated
    And the temporary credential must resolve to the real secret "gti-real-key"
    And the temporary credential must be revoked immediately after tool execution
    And resolving the revoked credential must fail

  Scenario: On-demand credential fetching without caching
    Given a Local Vault contains secret "cbm-api-key" as "cbm-real-key"
    When the system needs the credential for a secure vault reference "vault://secrets/cbm-api-key"
    Then the system must fetch the secret from the vault on-demand
    And the long-lived API key must not be stored in the client memory

  Scenario: Audit hook blocks raw execution bypasses
    Given the Python runtime audit hook is active
    When an adversarial agent attempts to call "pty.spawn" directly
    Then the audit hook must raise a PermissionError
    When an adversarial agent attempts to call "os.system" directly
    Then the audit hook must raise a PermissionError
    When an adversarial agent attempts to call "subprocess.run" directly
    Then the audit hook must raise a PermissionError
