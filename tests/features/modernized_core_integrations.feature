@guardrails
Feature: Modernized Core Integrations and Performance Architecture
  As the Blackwall Agentic Firewall
  I want core subsystem integrations to run with modernized, non-blocking, and debounced patterns
  So that high-throughput agent operations remain resilient, secure, and performant

  Scenario: Policy watcher debounces rapid filesystem bursts and executes trailing updates
    Given a PolicyFileHandler initialized with a 50ms debounce window
    When 5 rapid filesystem modification events occur within 20 milliseconds
    Then only a single reload callback should execute during the debounce burst
    And the reload callback must not drop subsequent events if an initial parse fails

  Scenario: Policy watcher manages observer lifecycle via context manager
    Given a PolicyWatcher monitoring a temporary policy file
    When entering and exiting the PolicyWatcher context manager
    Then the observer must start on enter and stop cleanly on exit

  Scenario: Local vault secures secrets using HKDF key derivation and atomic permissions
    Given an EncryptedLocalStore with master key "vault-master-pass"
    When secret data is saved to the encrypted vault file
    Then the vault file on disk must have restricted 0o600 permissions
    And the saved secrets must decrypt losslessly with HKDF

  Scenario: Local vault transparently loads legacy SHA256 encrypted vaults
    Given a legacy encrypted vault file derived with raw SHA-256
    When the modern EncryptedLocalStore loads the legacy vault
    Then the legacy secrets must be decrypted successfully via dual-cipher fallback

  Scenario: MCP HTTP transport reuses cached certifi SSLContext
    Given the MCP transport client
    When multiple remote MCP tool calls are initiated
    Then all requests must share the same cached certifi SSLContext instance

  Scenario: SyncResolver and BatchResolver utilize native client.aio coroutines
    Given a Gemini client equipped with native client.aio interfaces
    When tool call contexts are evaluated through SyncResolver and BatchResolver
    Then the resolvers must directly await client.aio methods without thread pool offloading
