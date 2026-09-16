@attribution @swarm_bridge
Feature: Swarm Attribution Provider Resolution and Tier Isolation
  As a Blackwall operator
  I want swarm lineage to resolve through the provider protocol
  So that collective attribution persists without coupling Core to Enterprise

  Scenario: Resolving an agent's active swarm via the SQLite provider
    Given an active swarm "collective:swarm-uuid-101" containing agent "agent-99"
    When agent "agent-99" triggers an intercepted BLOCK verdict
    Then the SwarmContextProvider MUST return a swarm summary
    And the swarm summary collective_name MUST equal "collective:swarm-uuid-101"
    And the swarm summary MUST list "agent-99" as a coordinating agent

  Scenario: Resolving swarm lineage through attacker profile membership
    Given an attacker profile with fingerprint "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" linked to swarm "collective:swarm-uuid-101"
    When the SwarmContextProvider resolves lineage for an unknown agent with that fingerprint
    Then the SwarmContextProvider MUST return the linked swarm summary
    And the swarm summary collective_name MUST equal "collective:swarm-uuid-101"

  Scenario: Enriching Enterprise agents with attack graph swarm lineage
    Given an agent "agent-99" belonging to active SwarmEvidence "swarm-uuid-101" in the attack graph store
    When the EnterpriseSwarmContextProvider resolves context for agent "agent-99"
    Then the provider MUST return a swarm summary with swarm_id "swarm-uuid-101"
    And the swarm summary MUST list suspected covert channels

  Scenario: Strict Core-to-Enterprise tier isolation
    Given the Blackwall Core attribution and persistence modules
    When their static imports are inspected
    Then Core MUST contain zero imports from blackwall.enterprise
    And Core MUST contain zero asyncpg dependencies
