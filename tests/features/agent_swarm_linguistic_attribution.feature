@attribution @linguistic_attribution
Feature: Agent Swarm Linguistic Attribution and False-Monolith Disambiguation
  As an AI application developer running agent workloads
  I want Blackwall to identify when sub-agents stop acting as individuals and coordinate under collective framing
  So that unauthorized agent collusion and false-monolithic profiles are accurately detected

  Scenario: Intercepting tool execution with collective linguistic markers
    Given an ADK tool call with arguments containing "We have agreed on the target file; we will now proceed"
    And caller metadata with agent_name "SwarmWorker-07"
    When the LinguisticSwarmClassifier analyzes the tool call
    Then the classifier MUST flag is_collective as True
    And the detected pronouns MUST include "we"
    And the confidence score MUST be at least 0.70

  Scenario: Disambiguating a false-monolithic agent calling itself "we"
    Given an ADK tool call where agent_id is set to "we" and session_id is "session-101"
    And another ADK tool call where agent_id is set to "we" and session_id is "session-102"
    When the AttackerIdentity is generated for both calls
    Then both identities MUST have is_collective flag set to True
    And the two identities MUST have distinct identity fingerprints

  Scenario: Benign tool execution with casual "we" does not trigger collective attribution
    Given an ADK tool call with arguments containing "Can we check the system uptime?"
    And caller metadata with agent_name "AdminHelper"
    When the LinguisticSwarmClassifier analyzes the tool call
    Then the classifier MUST flag is_collective as False
    And the confidence score MUST be less than 0.70
    And the detected pronouns MUST include "we"

  Scenario: Multi-agent coordinated swarm sharing collective keywords
    Given an ADK tool call with arguments containing "consensus reached; our swarm objective is active"
    And caller metadata with agent_id "agent-node-42"
    When the AttackerIdentity is generated
    Then the identity MUST have is_collective flag set to True
    And the identity MUST contain collective_name starting with "collective:"
