Feature: Native CLI Threat Intelligence Triage and Harpoon Companion Bridge
  As a security engineer or automated AI agent
  I want direct CLI indicator triage and resilient Harpoon OSINT bridge integration
  So that threat intelligence is verified from the terminal and missing external dependencies never crash the system

  Scenario: Checking a malicious domain via CLI
    Given a known malicious C2 domain "malicious-c2.xyz" exists in OTX with 3 active pulses
    When the developer executes "blackwall check malicious-c2.xyz"
    Then the CLI must output a table displaying verdict "BLOCK"
    And the risk score must be greater than or equal to 0.50
    And the threat provider must indicate "otx"
    And the command exit code must be 0

  Scenario: Harpoon binary is not installed on the host
    Given the "harpoon" executable is absent from the host PATH
    When a threat intelligence lookup is triggered with deep enrichment requested
    Then Blackwall must log an informational notice about harpoon unavailability
    And Blackwall must fall back to the in-process AlienVaultOTXProvider
    And the lookup must succeed with standard pulse data

  Scenario: Inspecting cache status and purging cached records via CLI
    Given a threat intelligence cache with cached indicator records
    When the developer executes "blackwall threat-intel cache status"
    Then the CLI output must report positive cached entries
    And executing "blackwall threat-intel cache clear" must purge cached records

  Scenario: Provider quota inspection without secret key leakage
    Given configured threat intelligence providers with valid API credentials
    When the developer executes "blackwall threat-intel providers"
    Then provider status and remaining budget must be displayed
    And secret API keys must not be exposed in plaintext in the CLI output
