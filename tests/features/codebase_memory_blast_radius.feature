Feature: Codebase Memory AST Blast Radius and Sink Detection
  As the Blackwall Agentic Firewall
  I want to leverage structural AST analysis and blast radius reports from codebase memory
  So that tool calls interacting with critical sinks or high-impact modules are accurately scored and constrained

  Scenario: Critical sink identified increases threat score
    Given a Codebase Memory MCP client and a SyncResolver are initialized
    And a tool call context targets a function with critical unsafe sinks "ProcessOrder"
    When the tool call is evaluated by the resolver
    Then the CBM response contains critical sinks
    And the calculated threat score is higher than the baseline score without sinks

  Scenario: No critical sinks produces baseline score
    Given a Codebase Memory MCP client and a SyncResolver are initialized
    And a tool call context targets a safe function "safe_func" without critical sinks
    When the tool call is evaluated by the resolver
    Then the CBM response contains no critical sinks
    And the threat score remains at or below baseline threshold

  Scenario: MCP connection failure degrades gracefully
    Given a Codebase Memory MCP client configured to simulate connection failure
    And a SyncResolver is initialized with the failing CBM client
    When the tool call is evaluated by the resolver
    Then the evaluation completes without raising an unhandled exception
    And a valid verdict is returned with fallback CBM scoring

  Scenario: Stale graph triggers re-query
    Given a Codebase Memory MCP client with graph last updated more than 1 hour ago
    When staleness is checked on the codebase memory graph
    Then the graph is identified as stale
    And a threat score penalty of 0.4 is applied

  Scenario: Blast radius isolation report contains affected modules
    Given a Codebase Memory MCP client with indexed dependency graph
    When a blast radius report is generated for target node "ProcessOrder"
    Then the report contains affected modules and functions
    And the report includes a risk score and an isolation level
