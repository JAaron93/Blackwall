# Implementation Plan: Blackwall Protocol Integration (ACP/MCP)

## Overview

This document outlines the test-driven implementation plan for refactoring Blackwall from an environment-injected execution hook into a standalone, pure-Python Protocol Middleware (targeting MCP and ACP). **Strict adherence to Test-Driven Development (TDD) and Behavior-Driven Development (BDD) is required.**

Tasks are divided into execution tracks. **Tracks that share the same phase can be executed in parallel by different team members or agents.**

---

## 🛤️ Parallel Execution: Phase 1 (Foundation)

> [!TIP]  
> **PARALLEL EXECUTION**  
> `Track A` (Server Infrastructure) and `Track B` (Data Serialization) have no dependencies on each other and should be executed concurrently to accelerate delivery.

### Track A: Protocol Gateway Infrastructure

#### TASK-A01: Implement Asyncio JSON-RPC 2.0 Server
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-01, FR-02, US-03, NFR-01

**Description:**
Build a high-performance Python `asyncio` server capable of intercepting bidirectional JSON-RPC streams over both `stdio` and `MCP Streamable HTTP` (POST + SSE) transports. It MUST enforce Transport Security by validating `Origin` and `Host` headers, binding local deployments to loopback interfaces, and requiring authentication for network-bound requests.
**Acceptance Criteria:**
1. Write a failing unit test asserting server initialization (TDD).
2. Server initializes and accepts connections on both `stdio` and HTTP transports.
3. Server correctly parses valid JSON-RPC 2.0 messages from a continuous stream.
4. Zero Node.js dependencies are introduced.
5. Unit tests pass and verify transport initialization, message boundary parsing, and Transport Security (rejects unauthenticated requests, invalid origins, and enforces loopback when applicable).

#### TASK-A02: Interception & Flow Control
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-01, FR-02

**Description:**
Implement the flow control mechanism that holds intercepted requests in memory without dropping connections, waiting for external resolution before continuing the stream. The stream layer MUST track all in-flight requests by JSON-RPC `id` to ensure concurrent calls are not mismatched when held, blocked, or resumed. It MUST enforce a configurable maximum in-memory queue, per-request timeout handling, cancellation handling, partial-batch flushing, and deterministic cleanup of abandoned requests. Asynchronous `before_tool_callback` handlers MUST resolve without blocking or deadlocking.
**Acceptance Criteria:**
1. The server can pause an incoming tool execution request (`tools/call`).
2. In-flight requests are correctly tracked by their incoming JSON-RPC `id` and abandoned requests are deterministically cleaned up.
3. Async handlers return correctly formatted stream responses for timeout, cancellation, overflow, and successful resolution cases, matching the corresponding `id`.

---

### Track B: Data Serialization & Synthesis

#### TASK-B01: Payload Reconstructor (MCP to Blackwall)
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-03, FR-05

**Description:**
Create the translation layer that takes an MCP/ACP JSON-RPC payload and maps it directly to Blackwall's internal `Callback_Token` data structure so the existing Hybrid Policy Server can evaluate it without modification. It MUST ensure that payloads are redacted (e.g., credentials, secrets, PII removed) before they are passed to the logging layer, preserving threat reasoning only in local diagnostics.
**Acceptance Criteria:**
1. Given a valid MCP `tools/call` JSON, the reconstructor successfully outputs a `Callback_Token`.
2. Missing or malformed arguments raise specific serialization errors, not generic exceptions.
3. Blocked protocol payloads are successfully redacted (e.g. via `ContextResolver`) before being logged to the embedded SQLite Threat Signature Graph.

#### TASK-B02: JSON-RPC Error Synthesizer
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-04, US-02

**Description:**
Build the synthesizer that translates Blackwall `BLOCK` verdicts into valid MCP/ACP JSON-RPC Error objects. The synthesizer contract is restricted strictly to `BLOCK` verdicts: it must extract and reuse the incoming JSON-RPC `id` and return a bounded, generic error message (without leaking internal threat reasoning). Conversely, the proxy layer must pass `ALLOW` payloads through completely unchanged (the synthesizer is never invoked for `ALLOW` verdicts), and the synthesizer must reject `ALLOW` inputs or raise an exception if invoked with one. Threat signature persistence MUST be handled separately.
**Acceptance Criteria:**
1. Synthesizer accepts a `Verdict` object (strictly `BLOCK` state; raises an exception for `ALLOW`) and an incoming `id`, and outputs a valid JSON-RPC Error (e.g., Code `-32603`) using the matched `id`.
2. The proxy layer passes `ALLOW` payloads through unchanged without invoking the synthesizer. The synthesizer rejects `ALLOW` inputs (raises an exception) if incorrectly invoked with one.
3. Threat reasoning is NOT included in the `message` field, which instead contains a bounded, generic error string (e.g., "Execution blocked").

---

## 🛤️ Linear Execution: Phase 2 (Integration & E2E)

> [!IMPORTANT]  
> **LINEAR EXECUTION**  
> Phase 2 tasks require the completion of *both* Track A and Track B from Phase 1. They must be executed sequentially.

### Track C: The Proxy Engine

#### TASK-C01: Route to Hybrid Policy Server
**Status:** ⏳ Not Started
**Dependencies:** TASK-A02, TASK-B01, TASK-B02
**Requirements Satisfied:** FR-04, NFR-02, US-03

**Description:**
Wire the `Protocol Gateway` (A02) to the `Hybrid Policy Server` using the `Payload Reconstructor` (B01). Handle the return flow by either piping the allowed bytes through to the OS or using the `JSON-RPC Error Synthesizer` (B02) for blocked actions.
**Acceptance Criteria:**
1. End-to-end unit test simulating an MCP tool call successfully hits the Policy Server.
2. An `ALLOW` verdict returns the simulated tool's response.
3. A `BLOCK` verdict returns the synthesized JSON-RPC error.
4. Network and serialization overhead is demonstrably <10ms in benchmarking tests.

#### TASK-C02: Hermes Agent E2E Integration Test
**Status:** ⏳ Not Started
**Dependencies:** TASK-C01
**Requirements Satisfied:** US-01, NFR-03

**Description:**
Write a behavior-driven integration test simulating Hermes Agent attempting to execute a malicious shell command over the MCP protocol. The proxy MUST be launched in a new process group with guaranteed cleanup.
**Acceptance Criteria:**
1. Update existing Gherkin scenarios in `tests/features/blackwall_guardrails.feature` and implement direct step bindings in `tests/step_defs/test_guardrails.py` to cover the malicious Hermes Agent MCP tool call.
2. Spin up the Protocol Proxy in a subprocess configured with process-group isolation (e.g., `preexec_fn=os.setsid`).
3. Emit a malicious `tools/call` JSON-RPC payload imitating Hermes Agent.
4. Assert that Blackwall returns a `-32603` error.
5. Assert that the SQLite Threat Graph successfully logs the blocked payload.
6. The entire subprocess group MUST be terminated in a `finally` or `trap` handler, including complete cleanup on test failures.
7. `pytest-bdd` test executes the feature and passes.
