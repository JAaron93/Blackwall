@guardrails
Feature: Security Contract Centralized Validation Guardrails
  As a security engineer
  I want Blackwall to strictly validate semantic versioning strings and UTC timezone awareness
  So that invalid configuration headers or temporal drift cannot compromise security decisions

  Scenario: Validate semver format passes for valid versions
    Given a version string "1.0.0"
    When the semver validation helper is executed
    Then the validated version string should be "1.0.0"

  Scenario: Validate semver format fails for invalid version string
    Given a version string "v1.0.0-invalid"
    When the semver validation helper is executed
    Then a ValueError should be raised with "semantic versioning format"

  Scenario: Validate UTC datetime passes for timezone-aware UTC datetime
    Given a timezone-aware UTC datetime
    When the UTC datetime validation helper is executed
    Then the validated datetime should match the UTC input

  Scenario: Validate UTC datetime fails for naive datetime
    Given a naive datetime without timezone info
    When the UTC datetime validation helper is executed
    Then a ValueError should be raised with "UTC timezone-aware"
