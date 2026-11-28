Feature: macOS LaunchAgent Service Management
  As a Blackwall Core user on macOS
  I want a launchd LaunchAgent installed through the CLI
  So that the gateway is supervised at login without leaking credentials

  Scenario: Install produces a supervised LaunchAgent with absolute paths
    Given an isolated macOS home with standard gcloud ADC
    When the user runs "blackwall service install"
    Then the generated LaunchAgent supervises the foreground gateway with absolute paths

  Scenario: Install fails fast without a GCP project
    Given an isolated macOS home with standard gcloud ADC
    When the user runs "blackwall service install" without a GCP project
    Then installation fails with an actionable GCP project error

  Scenario: TypeSafe key is isolated from the LaunchAgent plist
    Given an isolated macOS home with standard gcloud ADC
    When the user runs "blackwall service install" with a TypeSafe API key
    Then the key exists only in a 0600 env file and never in the plist or CLI output
