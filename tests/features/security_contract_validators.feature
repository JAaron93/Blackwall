@guardrails
Feature: Security Contract Centralized Validation Guardrails
  As a security engineer
  I want Blackwall to strictly validate semantic versioning strings, UTC timezone awareness, UUID v4 format, non-empty strings, minimum item counts, and temporal sequences
  So that invalid configuration headers, corrupted IDs, empty fields, or temporal drift cannot compromise security decisions

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

  Scenario: Validate UTC datetime fails for non-UTC timezone-aware datetime
    Given a non-UTC timezone-aware datetime
    When the UTC datetime validation helper is executed
    Then a ValueError should be raised with "UTC timezone-aware"

  Scenario: Validate UUID v4 format passes for valid UUID v4
    Given a valid UUID v4 string
    When the UUID v4 validation helper is executed
    Then the validated UUID string should match the input

  Scenario: Validate UUID v4 format fails for invalid UUID string
    Given an invalid UUID string "not-a-uuid"
    When the UUID v4 validation helper is executed
    Then a ValueError should be raised with "Invalid UUID v4 format"

  Scenario: Validate non-empty string passes for non-whitespace string
    Given a non-empty string "agent-123"
    When the non-empty string validation helper is executed
    Then the validated string should be "agent-123"

  Scenario: Validate non-empty string fails for empty or whitespace string
    Given an empty string "   "
    When the non-empty string validation helper is executed
    Then a ValueError should be raised with "must not be empty"

  Scenario: Validate min items passes for collection meeting minimum size
    Given a collection with 3 items
    When the min items validation helper is executed with min size 2
    Then the validated collection should contain 3 items

  Scenario: Validate min items fails for collection below minimum size
    Given a collection with 1 items
    When the min items validation helper is executed with min size 2
    Then a ValueError should be raised with "must contain at least 2 items"

  Scenario: Validate temporal sequence passes when end time is at or after start time
    Given a valid UTC start time and a later UTC end time
    When the temporal sequence validation helper is executed
    Then the temporal sequence validation succeeds without error

  Scenario: Validate temporal sequence fails when end time is before start time
    Given a valid UTC start time and an earlier UTC end time
    When the temporal sequence validation helper is executed
    Then a ValueError should be raised with "end_time must be greater than or equal to start_time"
