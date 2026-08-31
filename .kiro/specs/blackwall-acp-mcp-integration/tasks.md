# Implementation Plan: Blackwall Protocol Integration (ACP/MCP) — Dual-Tier Revision

## Overview

This document outlines the test-driven implementation plan for evolving Blackwall from an environment-injected execution hook into a standalone, pure-Python Protocol Middleware (targeting MCP and ACP), integrated with the dual-tier Core/Enterprise architecture. **Strict adherence to Test-Driven Development (TDD) and Behavior-Driven Development (BDD) is required.**

> [!IMPORTANT]
> **REVISION CONTEXT (2026-08-30)**
> This plan re-baselines the original 2026-07-10 task list against **`origin/main` (`b6cb9b5`)** — 155 commits ahead of the worktree HEAD where drafting began. Key deltas:
> - Evaluation routes through **`SyncResolver`** (not `HybridPolicyServer`).
> - Verdict enforcement is **tri-state** (`ALLOW`/`BLOCK`/`QUARANTINE`), not two-state.
> - ATD Task 25 (`InboundProtocolFilter`) **is implemented on main**; the Admission track defines a Core hook port and **delegates** to it — no re-implementation.
> - The **Enterprise Protocol Bridge** track additionally injects the filter as admission authority and wires intercepted events into the ATD `EventSource.TOOL_CALL` stream without violating the Core→Enterprise import boundary.
> - The model is `CallbackToken` (not `Callback_Token`).
>
> All tasks below are **Not Started** — an audit against `origin/main` confirmed no `blackwall.protocol` module or protocol-gateway code exists yet. `InboundProtocolFilter` already exists on main and is reused, not recreated.

The gateway lives in a new **`blackwall.protocol`** package (Core). The Enterprise bridge lives in **`blackwall.enterprise.protocol_bridge`**. Core MUST NOT import from Enterprise; the bridge injects itself via a hook interface (NFR-06).

Tasks are divided into execution tracks. **Tracks that share the same phase can be executed in parallel by different team members or agents.**

---

## 🛤️ Parallel Execution: Phase 1 (Foundation)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track A` (Gateway Infrastructure), `Track B` (Payload Adapter), and `Track C` (Response Synthesizer) have no dependencies on each other and should be executed concurrently.

### Track A: Protocol Gateway Infrastructure (`blackwall.protocol.gateway`)

#### TASK-A01: Implement Asyncio JSON-RPC 2.0 Server with stdio + Streamable HTTP Transports
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-01, FR-02, NFR-01, NFR-03, US-03

**Description:**
Build a high-performance Python `asyncio` server capable of intercepting bidirectional JSON-RPC streams over both `stdio` and **MCP Streamable HTTP** (POST + SSE, targeting revision 2025-06-18+) transports. Local deployments MUST bind to loopback interfaces by default. This is the entry point of the `blackwall.protocol` package.
**Acceptance Criteria:**
1. Write a failing unit test asserting server initialization on both transports (TDD).
2. Server initializes and accepts connections on both `stdio` and HTTP transports.
3. Server correctly parses valid JSON-RPC 2.0 messages (request, response, notification) from a continuous stream.
4. Zero Node.js dependencies are introduced; only `asyncio`/`pydantic`/`aiohttp`.
5. Local bind defaults to `127.0.0.1`/`::1`; configurable via `BLACKWALL_PROTOCOL_PORT`/bind env.
**Verification:** `pytest tests/unit/test_protocol_gateway.py -v`

#### TASK-A02: Method Interception Registry
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-03, NFR-03

**Description:**
Implement the registry that decides which JSON-RPC methods are security-evaluated vs. passed through. `tools/call` is intercepted; `initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`, notifications, and responses pass through byte-for-byte. The registry MUST be extensible for future ACP methods without transport changes.
**Acceptance Criteria:**
1. Failing test: `tools/call` is routed to the interception pipeline; all other listed methods are marked pass-through (TDD).
2. Pass-through preserves byte-level fidelity (no re-serialization drift).
3. Registering a new intercepted method (e.g., a future ACP method) works without modifying transport code.
4. Unknown/registered-absent methods default to a safe, explicit policy (pass-through with a logged notice, not silent evaluation).
**Verification:** `pytest tests/unit/test_method_registry.py -v`

---

### Track B: Payload Adapter (`blackwall.protocol.adapter`)

#### TASK-B01: Payload Reconstructor (MCP `tools/call` → `CallbackToken`)
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-04, FR-08, NFR-08

**Description:**
Create the translation layer that takes an MCP/ACP `tools/call` JSON-RPC payload and maps it into a `ToolCallContext` wrapped in a `CallbackToken` so the existing `SyncResolver` can evaluate it without modification. Enrich `ToolCallContext.metadata` with transport provenance: `protocol` (mcp/acp), `transport` (stdio/http), `session_id`, `peer`, and `jsonrpc_id`. Do NOT log the unredacted payload; redaction happens inside `SyncResolver`'s `ContextHygiene` stage.
**Acceptance Criteria:**
1. Given a valid MCP `tools/call` JSON, the adapter outputs a `CallbackToken` whose `tool_context` is a `ToolCallContext` with correct `tool_name` and `arguments` (TDD).
2. Missing or malformed `params`/`name`/`arguments` raise specific serialization errors (subclass of a `ProtocolSerializationError`), not generic exceptions.
3. Metadata enrichment is asserted: `protocol`, `transport`, `session_id`, `peer`, `jsonrpc_id` all present and correct.
4. No unredacted payload is written to logs or persistence at the adapter layer.
**Verification:** `pytest tests/unit/test_payload_adapter.py -v`

---

### Track C: Response Synthesizer (`blackwall.protocol.synthesizer`)

#### TASK-C01: Tri-State Verdict Synthesizer
**Status:** ⏳ Not Started
**Dependencies:** None
**Requirements Satisfied:** FR-05, NFR-03, US-02

**Description:**
Build the synthesizer that translates Blackwall verdicts into valid MCP/ACP JSON-RPC responses.
*   **BLOCK** → JSON-RPC Error (Code `-32603`), bounded generic message, reusing the incoming `id`.
*   **QUARANTINE** → a successful MCP tool result carrying a sandboxed mock payload (mirrors ADK `_execute_quarantined`), generic content, no scoring/signature/redaction leakage.
*   **ALLOW** → the synthesizer is NEVER invoked; it MUST reject `ALLOW` inputs by raising.
**Acceptance Criteria:**
1. Failing test: `BLOCK` verdict + incoming `id` → valid JSON-RPC Error with Code `-32603` and matched `id` (TDD).
2. `QUARANTINE` verdict + incoming `id` → a valid successful tool result with generic sandboxed content; no threat reasoning present.
3. `ALLOW` input raises an exception (the proxy passes `ALLOW` through unchanged without invoking the synthesizer).
4. The BLOCK error `message` is bounded and generic; no internal reasoning, signature, or redacted context appears in any synthesized output.
**Verification:** `pytest tests/unit/test_response_synthesizer.py -v`

---

## 🛤️ Parallel Execution: Phase 2 (Admission & Flow Control)

> [!TIP]
> **PARALLEL EXECUTION**
> `Track D` (Admission Port & Core Fallback) and `Track E` (Flow Control) depend only on Phase 1's gateway skeleton and can run concurrently with each other.

### Track D: Admission Port & Core Fallback (`blackwall.protocol.admission`)

> [!IMPORTANT]
> **DELEGATES TO ATD TASK 25 — DO NOT RE-IMPLEMENT**
> `InboundProtocolFilter` (ATD Task 25) is already implemented and fully tested on `main` (header/Origin validation, per-sender sliding-window rate limiting, JSON-RPC schema validation, two-pass sanitization, MCP error synthesis — fulfilling ATD Requirements 23.1–23.4 and Properties 93–96). This track MUST NOT duplicate any of that logic. It defines only (a) the Core-side `ProtocolAdmissionHook` port the gateway delegates to, and (b) a conservative Core-only fallback so standalone deployments stay fail-safe. The Enterprise injection of `InboundProtocolFilter` into this port is TASK-G02.

#### TASK-D01: Define the `ProtocolAdmissionHook` Port (Core Interface)
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01
**Requirements Satisfied:** FR-07 (ATD 23.1–23.4), NFR-06

**Description:**
Define an abstract `ProtocolAdmissionHook` interface in Core (`blackwall.protocol.admission`) whose contract mirrors the capabilities of the existing `InboundProtocolFilter`: header/Origin validation, per-sender rate-limit check, RPC parse + schema validation, payload sanitization, and bounded MCP error synthesis. The gateway MUST call every inbound frame through this port. Core MUST NOT import `blackwall.enterprise` here.
**Acceptance Criteria:**
1. Failing test: the gateway routes an inbound frame through the injected `ProtocolAdmissionHook` before evaluation (TDD).
2. The port exposes methods matching `InboundProtocolFilter`'s surface (validate_headers_and_origin, check_inbound_rate_limit, parse_and_validate_rpc, sanitize_incoming_rpc, synthesize_error_response) so the Enterprise adapter is a thin delegation.
3. `blackwall.protocol.admission` has zero imports from `blackwall.enterprise` (asserted by a static import-boundary test).
4. When a hook rejects a frame, the gateway emits the hook-supplied bounded error and does not evaluate.
**Verification:** `pytest tests/unit/test_admission_port.py -v`

#### TASK-D02: Conservative Core-Only Fallback Admission
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01
**Requirements Satisfied:** FR-07, US-04, NFR-06

**Description:**
Provide the default `ProtocolAdmissionHook` used when no Enterprise bridge is attached (Core-only deployments). It MUST be deliberately conservative and MUST NOT duplicate Enterprise policy logic: enforce loopback bind, require bearer auth for non-loopback, perform minimal JSON-RPC parse rejection, and return bounded generic errors. It does not implement the full ATD allow-list / sliding-window / two-pass-sanitization behavior — that is the injected `InboundProtocolFilter`'s job in Enterprise mode.
**Acceptance Criteria:**
1. Failing test: with no bridge attached, the fallback rejects non-loopback unauthenticated requests and malformed JSON-RPC (TDD).
2. Loopback + authenticated requests proceed to evaluation.
3. The fallback contains no re-implementation of `InboundProtocolFilter`'s allow-list, sliding-window, or two-pass sanitization logic (verified by review + absence of duplicated patterns).
4. Core-only end-to-end interception still works with the fallback (US-04).
**Verification:** `pytest tests/unit/test_admission_fallback.py -v`

---

### Track E: Flow Control & Concurrency Integrity (`blackwall.protocol.flow_control`)

#### TASK-E01: In-Flight Request Tracker & Hold/Resume Semantics
**Status:** ⏳ Not Started
**Dependencies:** TASK-A01, TASK-A02, TASK-B01
**Requirements Satisfied:** FR-06

**Description:**
Implement flow control that holds intercepted `tools/call` requests in memory without dropping connections, awaiting verdict resolution. Track all in-flight requests by JSON-RPC `id`. Enforce: configurable max in-memory hold queue (overflow → fail-closed `QUARANTINE` synthesis), per-request verdict timeout (timeout → fail-closed `QUARANTINE`), cancellation propagation, and deterministic cleanup of abandoned requests. Async verdict handlers MUST resolve without deadlock (mirror `FreeTierADKIntegration` loop-bridging discipline).
**Acceptance Criteria:**
1. Failing test: concurrent `tools/call` requests are tracked by `id` and responses match their originating `id` (TDD).
2. Queue overflow produces a fail-closed `QUARANTINE` synthesis, not a dropped connection.
3. Verdict timeout produces a fail-closed `QUARANTINE` synthesis.
4. Cancellation and abandoned-request cleanup are deterministic (no leaked tasks/futures).
5. No deadlock when the verdict handler runs on the same event loop as the gateway.
**Verification:** `pytest tests/unit/test_flow_control.py -v`

---

## 🛤️ Linear Execution: Phase 3 (Core Integration)

> [!IMPORTANT]
> **LINEAR EXECUTION**
> Phase 3 requires Phase 1 and Phase 2 completion. `Track F` (Core routing) must precede `Track G` (Enterprise bridge).

### Track F: Core Engine Routing (`blackwall.protocol.router`)

#### TASK-F01: Route to SyncResolver & Enforce Tri-State Enforcement
**Status:** ⏳ Not Started
**Dependencies:** TASK-B01, TASK-C01, TASK-D01, TASK-E01
**Requirements Satisfied:** FR-04, FR-05, FR-07, FR-08, NFR-02, NFR-07

**Description:**
Wire the Protocol Gateway to the canonical **`SyncResolver.evaluate()`** path using the Payload Adapter (B01). Handle the return flow: `ALLOW` pipes bytes through; `BLOCK` uses the BLOCK branch of the Synthesizer (C01); `QUARANTINE` uses the QUARANTINE branch. Ensure non-blocking Attacker Attribution fires on BLOCK/QUARANTINE using enriched metadata, and emit OpenTelemetry spans via `blackwall.telemetry`.
**Acceptance Criteria:**
1. Failing end-to-end unit test: a mocked MCP `tools/call` reaches `SyncResolver.evaluate()` (TDD).
2. An `ALLOW` verdict forwards the simulated tool response byte-for-byte.
3. A `BLOCK` verdict returns the synthesized `-32603` JSON-RPC error.
4. A `QUARANTINE` verdict returns the synthesized sandboxed mock result (real tool NOT invoked).
5. Attribution (`AttackerIdentityExtractor` → `IncidentReport`) fires on BLOCK/QUARANTINE using `NETWORK_IP` (http) or process metadata (stdio) without `IdentitySource` enum changes.
6. Network + serialization overhead is demonstrably <10ms in a benchmark test.
**Verification:** `pytest tests/unit/test_protocol_router.py -v`

---

### Track G: Enterprise Protocol Bridge (`blackwall.enterprise.protocol_bridge`)

> [!IMPORTANT]
> **DUAL-TIER BOUNDARY**
> The bridge lives under `blackwall.enterprise` and attaches via an injected hook. `blackwall.protocol` MUST NOT import `blackwall.enterprise` (NFR-06). The bridge MUST gracefully no-op when Enterprise is absent (Core-only deployments, US-04).

#### TASK-G01: Emit NormalizedEvents on the TOOL_CALL Stream
**Status:** ⏳ Not Started
**Dependencies:** TASK-F01
**Requirements Satisfied:** FR-09, NFR-06, US-04, US-05

**Description:**
Implement the Enterprise bridge that converts each intercepted event into a `NormalizedEvent` emitted on the existing `EventSource.TOOL_CALL` stream consumed by `EventStreamCollector.collect_from_tool_intercepts()`. The bridge must define a hook interface the Core gateway accepts via dependency injection, and must not be imported by Core.
**Acceptance Criteria:**
1. Failing test: with the bridge attached, an intercepted `tools/call` produces a `NormalizedEvent` with `source == EventSource.TOOL_CALL` consumable by `collect_from_tool_intercepts()` (TDD).
2. `blackwall.protocol` has zero imports from `blackwall.enterprise` (asserted by a static import-boundary test).
3. With the bridge detached (Core-only), interception still works end-to-end.
4. The bridge no-ops cleanly if ATD components are unavailable.
**Verification:** `pytest tests/unit/test_enterprise_protocol_bridge.py -v`

#### TASK-G02: Enterprise Admission Adapter (Inject `InboundProtocolFilter`)
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01, TASK-G01
**Requirements Satisfied:** FR-07 (ATD 23.1–23.4), FR-09, NFR-06

**Description:**
Implement the Enterprise-side adapter that wraps the existing `InboundProtocolFilter` (ATD Task 25, already on `main`) and injects it into the gateway's `ProtocolAdmissionHook` port as the **sole admission authority**. The adapter is a thin delegation — header/Origin validation, per-sender sliding-window rate limiting, JSON-RPC schema validation, two-pass sanitization, and MCP error synthesis all route to the existing filter; this task MUST NOT re-implement any of that policy. When the adapter attaches, the Core fallback (TASK-D02) MUST be bypassed.
**Acceptance Criteria:**
1. Failing test: with the bridge attached, every inbound frame is admitted by the injected `InboundProtocolFilter` (single-authority assertion — the Core fallback is not consulted) (TDD).
2. Adapter methods delegate 1:1 to `InboundProtocolFilter` (validate_headers_and_origin, check_inbound_rate_limit, parse_and_validate_rpc, sanitize_incoming_rpc, synthesize_error_response) with no duplicated policy logic.
3. Rate-limit denials surface the filter's existing `AlertBus` HIGH alerts (behavior preserved, not re-wired).
4. `blackwall.protocol` still has zero imports from `blackwall.enterprise` (static import-boundary test passes).
5. Detaching the adapter restores the Core fallback with no gateway code changes.
**Verification:** `pytest tests/unit/test_enterprise_protocol_bridge.py -v`

#### TASK-G03: Evaluation-Containment Reaction Suppression & Prompt-Submit Routing
**Status:** ⏳ Not Started
**Dependencies:** TASK-G01, TASK-G02
**Requirements Satisfied:** FR-09, US-05

**Description:**
Ensure that when protocol-sourced evidence is flagged via `is_evaluation_mode(payload.trigger_evidence_id)`, the `ActiveReactionEngine` suppresses production reactions (eBPF socket drops, fleet mesh broadcast, Vault JIT revocation), consistent with the ATD containment invariant. Additionally, route intercepted `prompt/submit` traffic (`InboundMethodType.PROMPT_SUBMIT`) through the existing `PromptInjectionScanner` (ATD Task 26) rather than the tool-evaluation pipeline.
**Acceptance Criteria:**
1. Failing test: contained (evaluation) evidence does NOT trigger socket drop, mesh broadcast, or credential revocation (TDD).
2. Non-contained CRITICAL evidence DOES trigger the appropriate pillar reactions.
3. Mesh broadcast uses the existing optional, duck-typed hook (no hard dependency on a `blackwall.enterprise.mesh` module, which does not exist).
4. A `prompt/submit` frame is forwarded to `PromptInjectionScanner` and never reaches `SyncResolver` tool evaluation.
**Verification:** `pytest tests/unit/test_enterprise_protocol_bridge.py::test_evaluation_containment -v`

---

## 🛤️ Linear Execution: Phase 4 (BDD E2E & Spec Alignment)

> [!IMPORTANT]
> **LINEAR EXECUTION**
> Phase 4 requires Phases 1–3. BDD scenarios are the authoritative acceptance gate.

### Track H: Behavior-Driven End-to-End Verification

#### TASK-H01: BDD Feature — Malicious Hermes Agent MCP Tool Call (BLOCK)
**Status:** ⏳ Not Started
**Dependencies:** TASK-F01
**Requirements Satisfied:** FR-05, US-01, US-02, NFR-05

**Description:**
Behavior-driven integration test: a simulated Hermes Agent emits a malicious `tools/call` over MCP; the proxy returns `-32603` and logs the redacted payload to the SQLite Threat Graph. The proxy MUST be launched in a new process group with guaranteed cleanup.
**Acceptance Criteria:**
1. Add Gherkin scenarios to a new `tests/features/protocol_proxy_interception.feature` and implement step bindings in `tests/step_defs/test_protocol_proxy_bdd.py` (do not overload `blackwall_guardrails.feature`).
2. Spin up the Protocol Proxy in a subprocess with process-group isolation (e.g., `preexec_fn=os.setsid`).
3. Emit a malicious `tools/call` JSON-RPC payload imitating Hermes Agent.
4. Assert Blackwall returns a `-32603` error.
5. Assert the SQLite Threat Graph logs the BLOCKED (redacted) payload.
6. The entire subprocess group is terminated in a `finally` handler, including on test failure.
7. `pytest-bdd` executes the feature and passes.
**Verification:** `pytest tests/step_defs/test_protocol_proxy_bdd.py -v`

#### TASK-H02: BDD Feature — QUARANTINE Containment Path
**Status:** ⏳ Not Started
**Dependencies:** TASK-H01
**Requirements Satisfied:** FR-05, US-02, NFR-05

**Description:**
BDD scenario for a `QUARANTINE` verdict: the agent receives a sandboxed mock result, the real tool is NOT invoked, and the agent loop continues. Cover the fail-closed triggers (rate-limit exhaustion and verdict timeout).
**Acceptance Criteria:**
1. Gherkin scenario asserts a QUARANTINE verdict returns a successful sandboxed result, not an error crash.
2. Assert the real tool execution target was never invoked.
3. Cover rate-limit-exhaustion → fail-closed QUARANTINE.
4. Cover verdict-timeout → fail-closed QUARANTINE.
5. No scoring/signature/redaction details leak into the quarantined result.
**Verification:** `pytest tests/step_defs/test_protocol_proxy_bdd.py -v`

#### TASK-H03: Proxy-Path Property Tests & No-Duplication Assertion
**Status:** ⏳ Not Started
**Dependencies:** TASK-D01, TASK-D02, TASK-G02, TASK-H01
**Requirements Satisfied:** FR-07, NFR-04

**Description:**
ATD Properties 93–96 (header/Origin enforcement, rate-limit boundary, JSON-RPC sanitization, malformed rejection) are already covered on `main` by `tests/property/test_inbound_filter_properties.py` against `InboundProtocolFilter` directly. This task adds the **proxy-path** layer: property tests proving the same invariants hold when traffic flows through the `blackwall.protocol` gateway and admission port, in both Core-fallback and Enterprise-injected modes. No ATD spec re-point or documentation change is needed — Task 25 is already complete on `main`.
**Acceptance Criteria:**
1. `hypothesis` property tests assert header/Origin enforcement, per-sender rate boundary, sanitization, and malformed-payload rejection end-to-end through the gateway with `--hypothesis-seed=0`, in both admission modes.
2. A static/AST assertion verifies no `InboundProtocolFilter` policy logic (allow-list matching, sliding-window accounting, two-pass sanitization patterns) is duplicated inside `blackwall.protocol`.
3. The existing `tests/property/test_inbound_filter_properties.py` suite still passes unmodified.
**Verification:** `pytest tests/property/test_protocol_proxy_properties.py tests/property/test_inbound_filter_properties.py --hypothesis-seed=0 -v`

---

## Traceability Summary

| Requirement | Delivering Tasks |
|---|---|
| FR-01, FR-02 | TASK-A01 |
| FR-03 | TASK-A02 |
| FR-04 | TASK-B01, TASK-F01 |
| FR-05 | TASK-C01, TASK-F01, TASK-H01, TASK-H02 |
| FR-06 | TASK-E01 |
| FR-07 (ATD 23.x) | TASK-D01, TASK-D02, TASK-F01, TASK-G02, TASK-H03 |
| FR-08 | TASK-B01, TASK-F01, TASK-H01 |
| FR-09 | TASK-G01, TASK-G02, TASK-G03 |
| NFR-01, NFR-03 | TASK-A01, TASK-A02, TASK-C01 |
| NFR-02 | TASK-F01 |
| NFR-04, NFR-05 | All tracks (TDD/BDD), TASK-H01–H03 |
| NFR-06 | TASK-D01, TASK-G01, TASK-G02 |
| NFR-07 | TASK-F01 |
| NFR-08 | TASK-B01 |
| US-01 | TASK-H01 |
| US-02 | TASK-C01, TASK-H01, TASK-H02 |
| US-03 | TASK-A01 |
| US-04 | TASK-D02, TASK-G01 |
| US-05 | TASK-G01, TASK-G03 |

## Implementation Parity Guardrail (Zero-Drift Invariant)

No subtask may be marked `[STATUS: COMPLETE]` unless the corresponding repository artifact (source under `src/blackwall/protocol/` or `src/blackwall/enterprise/protocol_bridge.py`, unit/property/BDD tests, and any dependency-manifest changes) exists and passes. This plan was authored from a codebase audit confirming none of these artifacts exist yet; statuses must only advance as real code lands.
