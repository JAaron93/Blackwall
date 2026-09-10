Feature: Inbound Protocol Interception and Cross-Agent Inspection
  As an Enterprise Security Engineer
  I want incoming A2A and MCP protocol requests targeting host agents to be inspected, rate-limited, and sanitized
  So that external rogue agents cannot coerce local agents or inject secrets/exploits into host execution contexts

  Scenario: Incoming RPC request with invalid Origin header is rejected
    Given an Inbound Protocol Filter configured for loopback endpoints
    When an incoming request arrives from "127.0.0.1" with Origin "https://untrusted-origin.attacker.io"
    Then the header and origin validation rejects the request

  Scenario: Request surge exceeding sliding-window limit drops additional messages
    Given an Inbound Protocol Filter with a rate limit of 5 requests per 60 seconds
    When agent "rogue-agent-99" sends 6 consecutive incoming requests
    Then 5 requests are permitted and 1 request is dropped
    And an inbound rate limit alert is emitted to the Alert Bus

  Scenario: Valid incoming tools/call arguments are sanitized before execution
    Given an Inbound Protocol Filter instance
    When an incoming tools/call message is received containing "password" and "sk-proj-1234567890abcdef12345678"
    Then the message payload is sanitized with secret placeholders before host agent execution

  Scenario: Malformed JSON-RPC request synthesizes MCP compliant error response
    Given an Inbound Protocol Filter instance
    When a malformed JSON-RPC payload without a valid "jsonrpc" version is parsed
    Then an MCP compliant JSON-RPC error response with code -32600 is synthesized
