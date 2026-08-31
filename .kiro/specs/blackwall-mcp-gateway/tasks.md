# Implementation Tasks: Blackwall MCP Gateway

## Overview

This document outlines the test-driven implementation plan for building the Blackwall MCP Gateway — a standalone, pure-Python local security daemon that intercepts MCP tool calls, evaluates them against Blackwall's threat intelligence engine, and enforces security verdicts. **Strict adherence to Test-Driven Development (TDD) and Behavior-Driven Development (BDD) is required.**

Tasks are divided into parallel and sequential execution tracks. **Tracks that share the same phase can be executed concurrently.**

---

## 🛤️ Phase 1: Foundation (Parallel Execution)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track A` (Gateway Infrastructure) and `Track B` (Interceptor & Synthesizer) have no dependencies on each other and should be executed concurrently.

### Track A: Protocol Gateway Infrastructure

#### TASK-A01: Implement Asyncio MCP Gateway Server
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-01, FR-02, US-03, NFR-01

**Description:**
Build a Python `asyncio` server capable of receiving bidirectional JSON-RPC 2.0 streams over both `stdio` and `MCP Streamable HTTP` (POST `/mcp` + SSE) transports. Target the MCP 2025-03-26 revision. The HTTP transport MUST bind to `127.0.0.1:9229` by default and enforce Transport Security (Origin/Host header validation, reject unauthenticated network requests).

**Acceptance Criteria:**
1. Write a failing unit test asserting server initialization (TDD).
2. Server initializes and accepts connections on both `stdio` and HTTP transports.
3. Server correctly parses valid JSON-RPC 2.0 messages from a continuous stream.
4. HTTP transport validates `Origin` and `Host` headers; rejects invalid origins and unauthenticated requests.
5. HTTP transport binds to loopback (`127.0.0.1`) by default.
6. Zero Node.js dependencies are introduced.
7. All unit tests pass.

#### TASK-A02: Implement Flow Control & Request Tracking
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-01, FR-02, FR-04

**Description:**
Implement the flow control mechanism that holds intercepted `tools/call` requests in memory while awaiting verdict resolution. The stream layer MUST track all in-flight requests by JSON-RPC `id` to ensure concurrent calls are never mismatched when held, blocked, or resumed. Enforce a configurable maximum in-memory queue, per-request timeout handling, cancellation handling, and deterministic cleanup of abandoned requests.

**Acceptance Criteria:**
1. The server can pause an incoming `tools/call` request pending verdict resolution.
2. In-flight requests are tracked by their JSON-RPC `id`; abandoned requests are deterministically cleaned up.
3. Handlers return correctly formatted stream responses for timeout, cancellation, overflow, and successful resolution cases, all matching the corresponding `id`.
4. Non-tool methods (`initialize`, `notifications/*`, `tools/list`) are passed through unchanged.

---

### Track B: Interceptor & Synthesizer

#### TASK-B01: Implement Payload Interceptor (MCP → ToolCallContext)
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-03, FR-05

**Description:**
Create the interception layer that takes an MCP `tools/call` JSON-RPC payload, extracts `name` and `arguments`, passes them through `ContextResolver` for sensitive value redaction, and constructs a `ToolCallContext` compatible with the existing `SyncResolver` pipeline. Blocked payloads MUST be redacted before logging to the SQLite Threat Signature Graph.

**Acceptance Criteria:**
1. Given a valid MCP `tools/call` JSON, the interceptor outputs a `ToolCallContext`.
2. Sensitive values (credentials, env vars, PII) are redacted via `ContextResolver` before evaluation.
3. Missing or malformed arguments raise specific serialization errors, not generic exceptions.
4. Blocked payloads are redacted before persistence to the threat graph.
5. All unit tests pass (TDD).

#### TASK-B02: Implement JSON-RPC Response Synthesizer
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-04, US-02

**Description:**
Build the synthesizer that translates Blackwall verdicts into MCP-compliant JSON-RPC responses:
- **BLOCK:** Extract and reuse the incoming JSON-RPC `id`, return Error Code `-32603` with a bounded, generic message. No internal threat reasoning leaked.
- **QUARANTINE:** Return Error Code `-32001` with a generic message, log for manual review.
- **ALLOW:** The synthesizer MUST reject ALLOW inputs and raise an exception if invoked. The proxy layer handles ALLOW by forwarding unchanged.

**Acceptance Criteria:**
1. Synthesizer accepts a `Verdict` (BLOCK or QUARANTINE) and an incoming `id`, outputs a valid JSON-RPC Error.
2. Synthesizer raises an exception if invoked with an ALLOW verdict.
3. Error `message` field contains a bounded, generic string — no threat reasoning exposed.
4. All unit tests pass (TDD).

---

## 🛤️ Phase 2: Wiring (Sequential Execution)

> [!IMPORTANT]
> **SEQUENTIAL EXECUTION**
> Phase 2 tasks require completion of *both* Track A and Track B from Phase 1.

### Track C: End-to-End Pipeline & CLI

#### TASK-C01: Wire Gateway → Interceptor → SyncResolver → Synthesizer
**Status:** ⏳ Not Started
**Dependencies:** TASK-A02, TASK-B01, TASK-B02
**Requirements Satisfied:** FR-04, NFR-02, US-01

**Description:**
Wire the Protocol Gateway (A02) to the `SyncResolver` pipeline using the Payload Interceptor (B01). Handle the return flow by either piping ALLOW'd bytes through to the downstream tool server or using the JSON-RPC Synthesizer (B02) for blocked/quarantined actions.

**Acceptance Criteria:**
1. End-to-end unit test simulating an MCP `tools/call` successfully hits the `SyncResolver`.
2. An ALLOW verdict returns the downstream tool server's response.
3. A BLOCK verdict returns the synthesized JSON-RPC error (`-32603`).
4. A QUARANTINE verdict returns the synthesized JSON-RPC error (`-32001`).
5. Gateway overhead is demonstrably < 10ms in benchmarking tests.

#### TASK-C02: Implement Upstream Tool Server Manager
**Status:** ⏳ Not Started
**Dependencies:** TASK-C01
**Requirements Satisfied:** FR-07

**Description:**
Implement the upstream/downstream tool server management module:
- **Wrap Mode (`--wrap`):** Spawn a single downstream MCP server as a stdio child process. Manage lifecycle (start, health check, graceful shutdown on SIGTERM).
- **Multi-Server Mode (`gateway.yaml`):** Parse `gateway.yaml` config, manage multiple downstream servers (stdio and HTTP), route `tools/call` to the appropriate server based on tool name registration.
- Connection pooling for HTTP upstream targets.

**Acceptance Criteria:**
1. `--wrap` mode spawns downstream server, forwards ALLOW'd JSON-RPC, pipes responses back.
2. `gateway.yaml` mode correctly routes to multiple downstream servers.
3. Downstream processes are terminated cleanly on gateway shutdown (SIGTERM propagation).
4. All unit tests pass (TDD).

#### TASK-C03: Implement CLI Entry Point & Daemon Lifecycle
**Status:** ⏳ Not Started
**Dependencies:** TASK-C01
**Requirements Satisfied:** FR-06, FR-08, FR-09, US-04, US-05

**Description:**
Build the `click`-based CLI (`src/blackwall/cli.py`) and daemon lifecycle manager:
- `blackwall serve` — daemonize by default, write PID to `~/.blackwall/blackwall.pid`, redirect logs to `~/.blackwall/blackwall.log`. Support `--foreground`, `--transport`, `--port`, `--host`, `--wrap`, `--config`, `--policy`, `--db`, `--log-level`.
- `blackwall init` — scaffold `~/.blackwall/` with default `policy.yaml`, empty threat DB, starter `gateway.yaml`.
- `blackwall stop` — read PID, send SIGTERM, verify termination, clean up PID file.
- `blackwall status` — check PID liveness, report threat graph stats, recent verdicts.
- `blackwall version` — print version.
- Add `[project.scripts] blackwall = "blackwall.cli:main"` to `pyproject.toml`.
- Validate GCP Vertex AI credentials on startup; fail fast with clear error if not configured.

**Acceptance Criteria:**
1. `pip install -e .` makes the `blackwall` command available.
2. `blackwall init` creates `~/.blackwall/` with all expected files.
3. `blackwall serve` daemonizes, creates PID file, writes logs.
4. `blackwall serve --foreground` runs in terminal with live output.
5. `blackwall stop` terminates the daemon and cleans up the PID file.
6. `blackwall status` reports daemon state and threat graph statistics.
7. Missing GCP credentials produce a clear, actionable error message on startup.
8. All unit tests pass (TDD).

---

## 🛤️ Phase 3: Integration & Validation (Sequential Execution)

> [!IMPORTANT]
> **SEQUENTIAL EXECUTION**
> Phase 3 tasks require completion of Phase 2.

### Track D: End-to-End BDD Tests & Scaffolding

#### TASK-D01: BDD E2E Test — stdio Gateway Blocks Malicious Tool Call
**Status:** ⏳ Not Started
**Dependencies:** TASK-C02, TASK-C03
**Requirements Satisfied:** NFR-04, NFR-05, US-01

**Description:**
Write a behavior-driven integration test simulating a malicious `tools/call` over the stdio transport. The gateway MUST be launched in a new process group with guaranteed cleanup.

**Acceptance Criteria:**
1. Add Gherkin scenarios to `tests/features/blackwall_gateway.feature` covering malicious MCP tool call interception.
2. Implement step bindings in `tests/step_defs/test_gateway.py`.
3. Spin up the gateway in a subprocess with process-group isolation (`preexec_fn=os.setsid`).
4. Emit a malicious `tools/call` JSON-RPC payload over stdio.
5. Assert Blackwall returns a `-32603` JSON-RPC error.
6. Assert the SQLite Threat Graph logs the blocked payload.
7. The subprocess group MUST be terminated in a `finally` handler, including cleanup on test failures.
8. `pytest-bdd` executes the feature and passes.

#### TASK-D02: BDD E2E Test — HTTP Gateway Blocks Malicious Tool Call
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01
**Requirements Satisfied:** FR-02, NFR-05

**Description:**
Replicate TASK-D01 using the Streamable HTTP transport (`POST /mcp` on `localhost:9229`).

**Acceptance Criteria:**
1. Add Gherkin scenarios for HTTP transport interception.
2. Gateway starts on `localhost:9229` in test subprocess.
3. Send malicious `tools/call` via HTTP POST to `/mcp`.
4. Assert `-32603` JSON-RPC error in SSE response.
5. `pytest-bdd` passes.

#### TASK-D03: BDD E2E Test — ALLOW Verdict Forwards to Upstream
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01
**Requirements Satisfied:** FR-04, FR-07, US-01

**Description:**
Write a BDD test verifying that benign tool calls are forwarded to the downstream tool server and the response is piped back to the agent.

**Acceptance Criteria:**
1. Gateway wraps a mock downstream MCP server (simple echo server).
2. Send a benign `tools/call` JSON-RPC payload.
3. Assert the downstream server receives the forwarded request.
4. Assert the agent receives the downstream server's response unchanged.
5. `pytest-bdd` passes.

#### TASK-D04: Resource Profiling on Intel MacBook Baseline
**Status:** ⏳ Not Started
**Dependencies:** TASK-C03
**Requirements Satisfied:** NFR-06, US-04

**Description:**
Profile Blackwall Core daemon on the 2019 Intel MacBook Pro baseline to verify resource budgets.

**Acceptance Criteria:**
1. Measure idle RAM (target: ≤ 60MB).
2. Measure active RAM during SyncResolver evaluation (target: ≤ 150MB).
3. Measure idle CPU (target: ~0%).
4. Measure per-call CPU burst (target: < 5% single core).
5. Measure startup time (target: < 2s).
6. Document results and flag any budget violations.

---

## 🛤️ Phase 4: Documentation & Spec Finalization

#### TASK-E01: Finalize Spec Documentation
**Status:** ⏳ Not Started
**Dependencies:** All previous tasks
**Requirements Satisfied:** All

**Description:**
Review and finalize all three spec files (`design.md`, `requirements.md`, `tasks.md`) to reflect the implemented gateway architecture. Update task statuses, record any deviations, and archive the superseded `blackwall-acp-mcp-integration` spec.

**Acceptance Criteria:**
1. All task statuses are updated to reflect completion.
2. Any implementation deviations are documented.
3. The old `blackwall-acp-mcp-integration` spec directory is removed from the repository.
