# Design Document: Blackwall Protocol Integration (ACP/MCP)

## Overview

As the AI agent ecosystem evolves, hardcoded framework-specific hooks (like `sys.addaudithook` or ADK's `before_tool_callback`) become difficult to maintain at scale across disparate agent implementations. To achieve universal portability while retaining its Python-exclusive core, Blackwall is evolving into a **Protocol-Level Interceptor**.

This design document outlines the architecture for integrating Blackwall as a secure middleware proxy over standard agent communication protocols, specifically **Zed's Agent Context Protocol (ACP)** and the **Model Context Protocol (MCP)**. This shift guarantees day-zero compatibility with Python-based agents like **Hermes Agent** and establishes Blackwall as an Agentic Firewall capable of governing any protocol-compliant agent.

## Core Architectural Shift

Currently, Blackwall injects itself into the execution context (via ADK). In the new architecture, Blackwall runs as an independent daemon acting as a **Reverse Proxy / Middleware Server** for JSON-RPC messages (used by MCP/ACP).

1.  **The OS/Environment** (e.g., Zed editor or a local terminal) sends context or tool execution requests to the **Agent** (e.g., Hermes).
2.  **Blackwall** intercepts the stdio/HTTP/SSE traffic.
3.  **Blackwall's Engine** parses the MCP `call_tool` payload.
4.  If the action is benign, Blackwall forwards the payload to the actual Agent/Tool.
5.  If the action is malicious, Blackwall blocks the payload and returns an MCP-compliant JSON-RPC Error message to the Agent, simulating a tool failure without crashing the agent.

## Components

### 1. Protocol Gateway (The Proxy Layer)
A high-performance `asyncio` server designed to handle bidirectional JSON-RPC streams.
*   **Transports Supported:** `stdio` (standard input/output redirection) and `SSE` (Server-Sent Events over HTTP).
*   **Role:** Replaces the direct connection between the Agent and the Tool Server.

### 2. Message Parser & Interceptor
Extracts the semantic intent from the protocol payload.
*   **MCP Tool Calls:** Intercepts `tools/call` requests.
*   **Payload Reconstruction:** Extracts `name` and `arguments` from the JSON-RPC packet and reformats it into Blackwall's internal `Callback_Token` equivalent, ensuring compatibility with the existing Hybrid Policy Server.

### 3. Engine Router
Routes the extracted payload through Blackwall's existing defenses:
*   **Structural Gating:** Validates the tool name and arguments against `policy.yaml`.
*   **SQLite Threat Signature Graph:** Checks for structural similarities with known malicious payloads.
*   **Semantic Gating (GTI / Codebase Memory):** (Optional) Escalates to LLM evaluation if deemed high-risk.

### 4. Response Synthesizer
*   **ALLOW Verdict:** The proxy forwards the exact byte-stream to the destination and pipes the response back.
*   **BLOCK Verdict:** The proxy drops the request and synthesizes a valid JSON-RPC response. It explicitly extracts and reuses the incoming JSON-RPC request `id` in the synthesized error response. Furthermore, the stream layer tracks all in-flight requests by `id` to ensure that concurrent calls cannot be mismatched when responses are held, blocked, or resumed.
    ```json
    {
      "jsonrpc": "2.0",
      "id": "<extracted_request_id>",
      "error": {
        "code": -32603,
        "message": "Blackwall Firewall: Execution blocked due to threat signature match."
      }
    }
    ```

## Quality Assurance (TDD & BDD)
To strictly enforce behavior, all protocol interception logic must be developed using a **Test-Driven Development (TDD)** approach. Furthermore, end-to-end integration flows (such as simulating a rogue agent payload) must be governed by **Behavior-Driven Development (BDD)** using Gherkin syntax and `pytest-bdd`. No new middleware proxy features can be merged without corresponding `.feature` specifications.

## Python Exclusivity & Hermes Compatibility
This implementation will be 100% Python-based. Hermes Agent, being a Python-based Agent OS, relies heavily on background services and tool orchestration. By configuring Hermes to route its tool requests through Blackwall's local MCP/ACP port (or via stdio piping), Blackwall protects the host OS without requiring any Node.js gateways or custom forks of the Hermes codebase.

## Constraints & Assumptions
*   **No Node.js:** The entire proxy stack will be written using Python's `asyncio` and `pydantic`.
*   **Performance:** The proxy adds network/serialization overhead. The `asyncio` streaming must ensure <10ms overhead on top of Blackwall's core evaluation latency.
*   **State Persistence:** The Agent Behavioral Analytics and Threat Signatures will continue to use the embedded SQLite WAL database.
