@guardrails
Feature: Blackwall Agentic Firewall Guardrails
  As a system administrator
  I want the Blackwall agent to enforce security guardrails
  So that rogue agents cannot bypass security boundaries

  # --- MCP Routing Boundary Scenarios ---

  Scenario: CodebaseMemoryRouter permits AST query operations
    Given a CodebaseMemoryRouter with a mock CBM client
    When a "query_dependency_chain" operation is routed
    Then the operation should be permitted
    And the CBM client should receive the delegated call

  Scenario: CodebaseMemoryRouter blocks prohibited operations
    Given a CodebaseMemoryRouter with a mock CBM client
    When a "list_files" operation is routed
    Then the operation should raise MCPRoutingViolation
    And the error should contain "list_files"

  Scenario: GTIRouter permits async analysis context
    Given a GTIRouter with a mock GTI client
    When a GTI query is routed in "async_analysis" context
    Then the operation should be permitted
    And the GTI client should receive the delegated call

  Scenario: GTIRouter blocks synchronous interception context
    Given a GTIRouter with a mock GTI client
    When a GTI query is routed in "sync_interception" context
    Then the operation should raise MCPRoutingViolation
    And the error should contain "sync_interception"

  Scenario: MCP router detects escape attempt in operation name
    Given a CodebaseMemoryRouter with a mock CBM client
    When an operation named "query_dependency_chain;exec('malicious')" is routed
    Then the operation should raise MCPRoutingViolation
    And the error should contain "ESCAPE_ATTEMPT"
