Feature: JIT Credential Lifecycle and Privilege Dropping Isolation
  As the Blackwall Security Engine
  I want Just-In-Time downscoped credentials and POSIX privilege dropping
  So that tool calls operate with zero ambient authority and temporary credentials automatically expire

  Scenario: JIT credential valid within TTL
    Given a LocalVault and a JITCredentialManager with 60-second TTL
    And a secret "vault://secrets/db_password" stored with value "super-secret-pass"
    When a temporary scoped token is created for scope "read"
    Then the token resolves the secret value within the TTL window

  Scenario: JIT credential revoked after TTL
    Given a LocalVault and a JITCredentialManager with 1-second TTL
    And a secret "vault://secrets/api_key" stored with value "live-key-12345"
    And a temporary scoped token created for reference "vault://secrets/api_key"
    When the TTL expiration duration elapses
    Then resolving the expired token raises an invalid or expired token error

  Scenario: JIT credential revoked on context exit
    Given a LocalVault and a JITCredentialManager are initialized
    And a secret "vault://secrets/service_token" stored with value "token-xyz"
    When a tool executes within a JITCredentialContext block
    Then the token is valid inside the context block
    And the token is automatically revoked and unresolvable upon context exit

  Scenario: Privilege drop removes elevated permissions
    Given a process running with simulated root UID 0
    When privilege drop is executed for user "nobody"
    Then supplementary groups are cleared and setgid and setuid are set to unprivileged IDs

  Scenario: Nested credential contexts maintain isolation
    Given a JITCredentialManager with stored secrets "vault://secrets/secret-A" and "vault://secrets/secret-B"
    When two nested JITCredentialContext blocks are entered
    Then each context possesses an isolated token mapped to its respective secret
    And exiting the inner context revokes only the inner token while preserving the outer token
