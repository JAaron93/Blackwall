@guardrails
Feature: Security Contract SQL Injection Guardrails
  As a security engineer
  I want Blackwall to strictly prohibit dynamic SQL f-strings (Bandit B608)
  So that malicious input cannot exploit SQL injection vulnerabilities

  Scenario: Prevent f-string dynamic SQL injection
    Given an SQL injection payload
    When the parameterized IN clause eviction query is executed
    Then the SQL injection should fail and operate safely on candidates only
