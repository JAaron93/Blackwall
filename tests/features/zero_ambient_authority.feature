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

  Scenario: Enforce 100% GCP Vertex AI mode and purge legacy API keys
    Given a GCP project "test-gcp-project" is configured
    And legacy API keys "GEMINI_API_KEY" and "LLM_API_KEY" are present in environment
    When the provider environment is configured for Vertex AI mode
    Then Vertex AI mode variable "GOOGLE_GENAI_USE_VERTEXAI" must be set to "true"
    And Gemini tier variable "GEMINI_TIER" must be set to "paid"
    And legacy API key variables "GEMINI_API_KEY" and "LLM_API_KEY" must be purged from environment
