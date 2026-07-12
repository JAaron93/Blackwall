# Requirements Document: Protocol Integration (ACP/MCP)

## Introduction

As part of Blackwall's long-term maintenance and portability strategy, the firewall must decouple from framework-specific execution hooks (such as `sys.addaudithook` and ADK 2.0 callbacks) and operate as an independent middleware proxy. This document outlines the requirements for implementing a Model Context Protocol (MCP) and Agent Context Protocol (ACP) server/client layer. 

The goal is to allow Python-based OS-level agents, specifically **Hermes Agent**, to route their tool executions through Blackwall securely and transparently. Blackwall will intercept JSON-RPC protocol payloads, evaluate them using the existing Hybrid Policy Server (structural and semantic gating), and return synthesized errors for blocked actions—all while remaining entirely Python-exclusive.

## Glossary

*   **MCP (Model Context Protocol):** An open standard JSON-RPC protocol standardizing how AI models and agents communicate with external tools and data sources.
*   **ACP (Agent Context Protocol):** A related protocol (used primarily by Zed and similar environments) to interface with standalone AI Agent CLIs.
*   **Protocol Proxy:** The middleware layer in Blackwall that sits between the Agent and the execution environment, intercepting stdio/HTTP traffic.
*   **Hermes Agent:** An open-source, Python-based Agent OS that runs persistent background loops and manages local execution.
*   **JSON-RPC Synthesizer:** The Blackwall component responsible for translating firewall BLOCK verdicts into protocol-compliant JSON-RPC error responses.

## Functional Requirements

### FR-01: MCP/ACP Protocol Server (Python)
Blackwall MUST implement a standalone `asyncio`-based server capable of receiving, parsing, and routing JSON-RPC 2.0 messages conforming to the MCP/ACP specifications. No Node.js components are permitted.

### FR-02: Transport Layer Support
The proxy MUST support two primary transport methods for agent communication:
1.  **stdio:** Intercepting standard input/output streams for local CLI agents.
2.  **MCP Streamable HTTP (POST + SSE):** Intercepting network-bound tool requests. The proxy MUST define a POST endpoint (e.g., `/message`) for the agent to submit `tools/call` requests as bidirectional Streamable HTTP contracts. Responses and events MUST return asynchronously over the established SSE channel. This explicit HTTP/SSE transport contract connects directly to the interception requirements in FR-03.
    *   **Transport Security (Mandatory):** The HTTP/SSE endpoint MUST validate `Origin` and `Host` headers to prevent DNS rebinding attacks. Local deployments MUST bind to loopback interfaces only (127.0.0.1/::1). Network-bound requests MUST require authentication (e.g., bearer tokens, mutual TLS). Unauthenticated network access MUST be rejected to prevent unauthorized agent control.

### FR-03: Message Interception & Payload Extraction
When an agent attempts a `tools/call` request, Blackwall MUST pause the stream, extract the tool `name` and `arguments`, and pass them through the regex-based ContextResolver to replace sensitive values with generic placeholders before HybridPolicyServer evaluation or further agent processing. The redacted payload MUST then be formatted into a schema compatible with Blackwall's existing `HybridPolicyServer`. The original sensitive payload MUST NOT be forwarded during policy or agent processing.

### FR-04: Verdict Enforcement via Protocol Synthesis
*   **ALLOW:** If the Hybrid Policy Server returns an ALLOW verdict, the original JSON-RPC payload MUST be passed cleanly to the destination tool execution context.
*   **BLOCK:** If a BLOCK verdict is reached, Blackwall MUST NOT forward the request. It MUST synthesize an MCP-compliant JSON-RPC Error object (e.g., Error Code `-32603`). To prevent leaking redaction information to the agent, the error MUST be bounded and generic (e.g., "Blackwall Firewall: Execution blocked"), without exposing the internal threat reasoning or redacted context.

### FR-05: Threat Signature Logging
All blocked protocol payloads MUST be redacted (e.g., credentials, secrets, PII removed) before being logged into the embedded SQLite Threat Signature Graph, ensuring Blackwall's self-learning loop continues to function without persisting sensitive data. Detailed threat reasoning MUST be restricted to protected local diagnostics (e.g., structured logs, audit trails) and MUST NOT be included in the persistence layer. This persistence MUST be isolated from the error response returned to the agent.

## Non-Functional Requirements

### NFR-01: Zero Python Overhead Dependency
Blackwall MUST remain 100% Python-based. Integration with frameworks like OpenClaw (Node.js) is explicitly out of scope to prevent language fragmentation and maintenance burden.

### NFR-02: Latency Constraints
The serialization, parsing, and proxying of JSON-RPC messages MUST add no more than 10ms of overhead to the baseline Blackwall evaluation latency (which is <10ms for structural evaluation).

### NFR-03: Agent Agnosticism
The protocol proxy MUST NOT contain hardcoded rules specific to Hermes Agent. It must adhere strictly to the MCP/ACP specification, ensuring compatibility with any future Python-based agent that adopts these protocols.

### NFR-04: Test-Driven Development (TDD)
All implementation tasks MUST follow strict TDD. Developers MUST write failing unit tests or reproduction commands before generating the minimum code required to pass the test.

### NFR-05: Behavior-Driven Development (BDD)
End-to-end security and interception workflows MUST be defined authoritatively using Gherkin syntax in a `.feature` file. The execution MUST be validated using `pytest-bdd` to ensure human-readable contracts for firewall behavior.

## User Stories

### US-01: Seamless Integration for Hermes Admin
**As a system administrator running Hermes Agent,**
I want to configure Hermes to point its tool execution endpoint at Blackwall's local MCP port,
**So that** Blackwall can protect my OS from rogue agent actions without requiring me to maintain a custom, forked version of the Hermes repository.

### US-02: Graceful Agent Failure
**As an autonomous agent (like Hermes),**
I want to receive standard JSON-RPC error messages when my tool call is denied by the firewall,
**So that** my execution loop does not crash, and I can prompt the LLM to reflect on the failure and try a different, safer approach.

### US-03: Python Exclusivity for Maintainers
**As the lead maintainer of Blackwall,**
I want the entire proxy and integration layer to be built in Python (`asyncio`, `pydantic`),
**So that** I don't have to manage multiple runtime environments (like Node.js or npm) when deploying the firewall to my VPS infrastructure for years to come.
