Feature: Blackwall MCP Gateway Integration and Validation
  As a developer routing MCP tool calls through Blackwall
  I want malicious calls blocked over stdio and HTTP with proper auth enforcement
  So that rogue agent actions never reach downstream tools

  Background:
    Given the Phase 2 gateway components are available

  Scenario: stdio Gateway blocks malicious tool call with JSON-RPC error
    Given a stdio gateway subprocess with an isolated threat database
    When a malicious tools call targeting a credential path is sent over stdio
    Then the stdio response contains JSON-RPC error code -32603 with the incoming id
    And the error message is bounded and generic with zero threat reasoning leaked
    And the SQLite threat graph logs the redacted blocked payload

  Scenario: HTTP Gateway blocks malicious tool call over Streamable HTTP
    Given an HTTP gateway subprocess on localhost port 9229 with an isolated threat database
    When a malicious tools call is posted to /mcp with SSE accepted
    Then the SSE response contains JSON-RPC error code -32603 with the incoming id
    And the HTTP error message is bounded and generic with zero threat reasoning leaked

  Scenario: Authenticated non-loopback HTTP request is accepted and processed
    Given a non-loopback HTTP gateway subprocess with a valid auth token
    When a benign tools call is posted with a valid Bearer token
    Then the authenticated response is accepted and processed

  Scenario: Unauthenticated non-loopback HTTP request is rejected with 401
    Given a non-loopback HTTP gateway subprocess with a valid auth token
    When a tools call is posted without a valid Bearer token
    Then the HTTP response status is 401

  Scenario: Non-loopback gateway refuses to start without auth token
    When a non-loopback gateway is started without an auth token
    Then the gateway startup fails with a clear auth error

  Scenario: ALLOW verdict forwards benign call to upstream echo server
    Given a stdio gateway subprocess wrapping a mock echo downstream server
    When a benign tools call is sent over stdio
    Then the downstream echo server receives the forwarded request
    And the agent receives the downstream response unchanged
