Feature: Blackwall Cross-Platform Service Management
  As a developer installing Blackwall as a background service
  I want launchd and systemd units generated with supervision and credentials
  So that the gateway starts on login with zero manual configuration

  Background:
    Given the Phase 5 service manager components are available

  Scenario: macOS plist generation supervises foreground gateway
    Given a macOS service install request with valid GCP project
    When the launchd plist is generated
    Then the plist is valid XML supervising serve foreground with throttle guards
    And the plist embeds GCP credentials and upstream config with zero tildes

  Scenario: Linux user unit generation uses correct sectioning
    Given a Linux service install request with valid GCP project
    When the systemd user unit is generated
    Then rate limits are under Unit and supervision bounds under Service
    And the unit ExecStart includes foreground and FHS-resolved flags

  Scenario: Linux system unit enforces non-root FHS execution
    Given a Linux system install request with derived service user
    When the systemd system unit is generated
    Then the unit configures non-root User and FHS directories
    And User root is strictly rejected

  Scenario: Install fails fast without GCP project
    Given a service install request without GCP project
    When install is attempted
    Then installation fails with a clear error
