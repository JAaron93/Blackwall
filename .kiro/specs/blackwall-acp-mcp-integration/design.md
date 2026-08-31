# Design Document: Blackwall Protocol Integration (ACP/MCP) — Dual-Tier Revision

## Overview

As the AI agent ecosystem evolves, hardcoded framework-specific hooks (like `sys.addaudithook` or ADK's `before_tool_callback`) become difficult to maintain at scale across disparate agent implementations. To achieve universal portability while retaining its Python-exclusive core, Blackwall is evolving into a **Protocol-Level Interceptor**.

This design document outlines the architecture for integrating Blackwall as a secure middleware proxy over standard agent communication protocols, specifically **Zed's Agent Client Protocol (ACP)** and the **Model Context Protocol (MCP)**. This shift guarantees day-zero compatibility with Python-based agents like **Hermes Agent** and establishes Blackwall as an Agentic Firewall capable of governing any protocol-compliant agent.

> [!IMPORTANT]
> **REVISION CONTEXT (2026-08-30)**
> This spec was originally authored on 2026-07-10, before Blackwall Enterprise, Advanced Threat Detection (ATD), and Attacker Attribution were implemented. This revision re-baselines the design against **`origin/main` (`b6cb9b5`)** — 155 commits ahead of the worktree HEAD where drafting began, so all claims below are anchored to main, not the stale checkout:
> - The canonical Core evaluation path is `SyncResolver` (Rate → ContextHygiene → Threat Signature Graph → Codebase Memory → conditional GTI → Score Aggregation → Threshold Verdict → Inline Signature → non-blocking Attacker Attribution), not `HybridPolicyServer`.
> - Verdicts are **tri-state**: `ALLOW`, `BLOCK`, and `QUARANTINE` (fail-closed). The protocol layer must synthesize a distinct response for each.
> - Blackwall Enterprise pillars (kernel probes, identity sidecar, pipeline wrappers, forensics, ATD incl. Tasks 25–28) are implemented and must receive protocol-layer events.
> - ATD Task 25 **is implemented on main** as `InboundProtocolFilter` (`blackwall.enterprise.advanced_threat_detection.inbound_filter`, wired into the ATD orchestrator via `inspect_and_sanitize_inbound_rpc`). This design **delegates** ingress admission to it via an injected hook; it does NOT re-implement it (see Spec Alignment).
> - The model referenced as `Callback_Token` in the original spec is `CallbackToken` in the codebase.

## Core Architectural Shift

Currently, Blackwall injects itself into the execution context (via ADK callbacks and audit hooks). In the new architecture, Blackwall additionally runs as an independent daemon acting as a **Reverse Proxy / Middleware Server** for JSON-RPC messages (used by MCP/ACP).

1.  **The OS/Environment** (e.g., Zed editor or a local terminal) sends context or tool execution requests to the **Agent** (e.g., Hermes).
2.  **Blackwall** intercepts the stdio/HTTP/SSE traffic.
3.  **Blackwall's Engine** parses the MCP `tools/call` payload.
4.  If the action is benign, Blackwall forwards the payload to the actual Agent/Tool.
5.  If the action is malicious, Blackwall blocks the payload and returns an MCP-compliant JSON-RPC response to the Agent, simulating a tool failure without crashing the agent.

## Dual-Tier Integration Model

The protocol gateway is a **Blackwall Core** capability; Enterprise telemetry and reaction coupling live strictly under `src/blackwall/enterprise/` per the dual-tier packaging invariant. Core MUST NOT import from `blackwall.enterprise`; the Enterprise bridge attaches to the gateway via an explicitly injected hook interface.

```
                     ┌────────────────────────────────────────────────────┐
                     │                BLACKWALL CORE                      │
 Zed / Hermes /      │  ┌──────────────────────────────────────────────┐  │
 any MCP client      │  │ Protocol Gateway  (blackwall.protocol)       │  │
      │   stdio /    │  │  Transport (stdio | Streamable HTTP+SSE)     │  │
      ▼   HTTP+SSE   │  │  └─ loopback bind, bearer auth (Core-native);│  │
 ┌─────────────┐     │  │     policy admission delegated to injected   │  │
 │ Protocol    │     │  │     ProtocolAdmissionHook                    │  │
 │ Gateway     │─────┼──┤  Method Interception Registry                │  │
 │ (proxy)     │     │  │  └─ tools/call intercepted; all other        │  │
 └──────┬──────┘     │  │     methods pass through unchanged           │  │
        │            │  │  Flow Control (in-flight tracker by RPC id)  │  │
        ▼            │  └──────────────┬───────────────────────────────┘  │
 ┌─────────────┐     │                 │ ToolCallContext (+ metadata)     │
 │ Payload     │     │                 ▼                                  │
 │ Adapter     │     │  ┌──────────────────────────────────────────────┐  │
 └──────┬──────┘     │  │ SyncResolver (canonical gating chain)        │  │
        │            │  │ Rate → Hygiene → TSG → CBM → GTI → Score →   │  │
        ▼            │  │ Verdict → Inline Sig → Attribution (async)   │  │
 ┌─────────────┐     │  └──────────────┬───────────────────────────────┘  │
 │ Response    │◄────┼─────────────────┘ Verdict (ALLOW|BLOCK|QUARANTINE) │
 │ Synthesizer │     │                                                    │
 └─────────────┘     └─────────────────────────┬──────────────────────────┘
                                               │ optional enterprise hook (injected)
                     ┌─────────────────────────▼──────────────────────────┐
                     │            BLACKWALL ENTERPRISE                    │
                     │  protocol_bridge (blackwall.enterprise.*)          │
                     │  └─ Injects InboundProtocolFilter (ATD Task 25)    │
                     │     as the gateway's ProtocolAdmissionHook         │
                     │  └─ Emits NormalizedEvents on EventSource.TOOL_CALL│
                     │     → EventStreamCollector → Correlators           │
                     │     (swarm / exploit-chain / AILM / C2)            │
                     │     → ActiveReactionEngine (eBPF socket drop,      │
                     │       fleet broadcast hook, Vault JIT revocation)  │
                     │  └─ Routes prompt/submit via PromptInjectionScanner│
                     │  Evaluation containment (is_evaluation_mode) is    │
                     │  honored end-to-end.                               │
                     └────────────────────────────────────────────────────┘
```

## Components

### 1. Protocol Gateway (The Proxy Layer) — `blackwall.protocol`
A high-performance `asyncio` server handling bidirectional JSON-RPC streams.

*   **Transports Supported:** `stdio` (standard input/output redirection) and **MCP Streamable HTTP** (POST endpoint with SSE responses), targeting the current MCP Streamable HTTP contract (revision 2025-06-18; the POST + SSE message shape is stable across 2024-11-05 and later). Legacy HTTP+SSE (pre-streamable) compatibility is **not** intentional. The endpoint establishes per-session isolation, validates Origin and Host headers for local deployments, binds to loopback by default, and requires authentication for network-bound requests.
*   **Admission Control (Delegated):** Transport-level security — loopback bind and bearer-token authentication — is Core-native and always enforced by the transport. Policy-level admission (Origin/Host allow-lists, per-sender sliding-window rate limiting with AlertBus escalation, JSON-RPC schema validation, two-pass secret sanitization, MCP-compliant error synthesis) is delegated to an injected **`ProtocolAdmissionHook`** (Component 2). Exactly one admission authority is active at a time.
*   **Role:** Replaces the direct connection between the Agent and the Tool Server.

### 2. Admission Port (`ProtocolAdmissionHook`)
Core defines the admission interface; it never imports Enterprise. The hook contract mirrors the capabilities of the already-implemented `InboundProtocolFilter` (ATD Task 25): header/origin validation, sender rate-limit check, RPC parse + schema validation, payload sanitization, and bounded error synthesis.

*   **Core default (always present):** a conservative transport-security admission — loopback enforcement, bearer-auth gate, minimal JSON-RPC parse rejection, bounded generic errors. It keeps Core-only deployments fail-safe (US-04) without duplicating Enterprise policy logic.
*   **Enterprise replacement:** when the Enterprise bridge attaches, it injects `InboundProtocolFilter` as the hook and the Core default is bypassed — the filter becomes the single admission authority, preserving ATD Requirements 23.1–23.4 and Properties 93–96 with zero duplicated implementation.

### 3. Method Interception Registry
Not every JSON-RPC method is a security-relevant execution. The gateway maintains a registry of intercepted methods:

*   **Intercepted (mandatory):** MCP `tools/call`.
*   **Pass-through (never evaluated):** `initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`, notifications, and responses. Pass-through preserves byte-level fidelity.
*   **Extensible:** ACP session/prompt-level methods can register interceptors later without transport changes. Until an ACP method interceptor is registered, ACP traffic rides the same stdio carriage but is pass-through. `prompt/submit` maps to the existing `InboundMethodType.PROMPT_SUBMIT` and is routed through the Prompt Injection Scanner when the Enterprise bridge is attached (Component 8).

### 4. Payload Adapter (Interceptor)
Extracts the semantic intent from the protocol payload.

*   **MCP Tool Calls:** Intercepts `tools/call` requests; extracts `name` and `arguments` from the JSON-RPC packet.
*   **Admission-First Ordering:** When an admission hook is attached, raw frames pass through its parse/validate/sanitize stages first (constructing an `InboundProtocolMessage` in Enterprise mode) before the adapter builds evaluation inputs; `ContextHygiene` inside `SyncResolver` remains the authoritative redaction during evaluation.
*   **Mapping:** Builds a `ToolCallContext` (what `SyncResolver` consumes) and wraps it in a `CallbackToken` for hold-and-resume flow control, mirroring the existing ADK/InterceptionQueue semantics.
*   **Metadata Enrichment:** Attaches transport provenance to `ToolCallContext.metadata`: `protocol` (mcp/acp), `transport` (stdio/http), `session_id`, `peer` (loopback or authenticated remote identity), and `jsonrpc_id`. This preserves Attacker Attribution continuity: `AttackerIdentityExtractor` maps HTTP peers to `IdentitySource.NETWORK_IP` and stdio peers to process metadata, with no `IdentitySource` enum changes required.

### 5. Engine Routing (Canonical Gating Chain)
The adapter routes the extracted payload through **`SyncResolver.evaluate()`**, which enforces the mandated sequence:

1.  **Rate Check** (token bucket, fail-closed `QUARANTINE`).
2.  **ContextHygiene Sanitization** (regex redaction to `[[PLACEHOLDER]]` form).
3.  **Threat Signature Graph (TSG)** similarity check in SQLite.
4.  **Codebase Memory MCP** AST / blast-radius query.
5.  **Conditional GTI Validation** — VirusTotal queries only for high-risk events, capped by `GTIQueryBudgetTracker` (4 queries / 60s sliding window; 1 token per 15s).
6.  **Score Aggregation → Threshold Verdict → Optional Inline Signature Generation**, followed by non-blocking Attacker Attribution for BLOCK/QUARANTINE outcomes.

`HybridPolicyServer` remains in the codebase but is **not** the gateway's evaluation path.

### 6. Response Synthesizer (Tri-State Verdict Enforcement)
Verdict mapping at the protocol boundary:

*   **ALLOW:** The proxy forwards the exact byte-stream to the destination and pipes the response back. The synthesizer is never invoked.
*   **BLOCK:** The proxy drops the request and synthesizes a valid JSON-RPC error. It explicitly extracts and reuses the incoming JSON-RPC request `id`. The message is bounded and generic — internal threat reasoning and redaction context MUST NOT leak.
    ```json
    {
      "jsonrpc": "2.0",
      "id": "<extracted_request_id>",
      "error": {
        "code": -32603,
        "message": "Blackwall Firewall: Execution blocked."
      }
    }
    ```
*   **QUARANTINE:** The proxy does **not** forward the request. It synthesizes a successful MCP tool result carrying a sandboxed mock payload — mirroring the ADK `_execute_quarantined` semantics — so the agent loop continues without real execution. The result content is generic (e.g., a quarantined-execution notice) and MUST NOT reveal scoring, signatures, or redaction details.

### 7. Flow Control
The stream layer tracks all in-flight intercepted requests by JSON-RPC `id` so concurrent calls cannot be mismatched when responses are held, blocked, quarantined, or resumed. Enforced limits: configurable maximum in-memory hold queue (overflow → fail-closed QUARANTINE synthesis), per-request verdict timeout (timeout → fail-closed QUARANTINE), cancellation propagation, and deterministic cleanup of abandoned requests.

### 8. Enterprise Protocol Bridge — `blackwall.enterprise.protocol_bridge`
An optional, injected hook (Core never imports Enterprise) that:

1.  **Injects `InboundProtocolFilter`** (the implemented ATD Task 25) as the gateway's `ProtocolAdmissionHook`, bypassing the Core default so ATD 23.1–23.4 ingress protections apply on the proxy path with zero duplicated logic.
2.  Emits each intercepted event as a `NormalizedEvent` on the existing **`EventSource.TOOL_CALL`** stream consumed by `EventStreamCollector.collect_from_tool_intercepts()`, feeding the ATD correlators (agent swarm, exploit chain, AILM, C2 detection).
3.  Allows `ActiveReactionEngine` CRITICAL verdicts to react through the existing pillars: eBPF/audit-driver socket drops (Pillar 1), fleet signature broadcast via the **optional, duck-typed mesh hook** (Pillar 2 — see Constraints), Vault JIT credential revocation (Pillar 3).
4.  Routes registered `prompt/submit` payloads through the **Prompt Injection Scanner** (implemented ATD Task 26) before host-agent context ingestion.
5.  Honors **evaluation containment**: events flagged via `is_evaluation_mode(payload.trigger_evidence_id)` suppress production reactions (socket drops, mesh broadcasts, credential revocation) per the ATD invariant.

## Spec Alignment & Boundary Decisions

*   **ATD Task 25 delegation (not duplication):** `InboundProtocolFilter` is already implemented and tested on `main` (unit, property tests for Properties 93–96, BDD feature `inbound_protocol_filter.feature`, and orchestrator wiring via `inspect_and_sanitize_inbound_rpc`). ATD Requirements 23.1–23.4 remain delivered by it. The gateway MUST delegate admission to it through the `ProtocolAdmissionHook` port and MUST NOT re-implement header validation, rate limiting, sanitization, or error synthesis. The ATD spec's Task 25 status stays as-is; this spec only adds proxy-path integration coverage.
*   **Mesh pillar status:** No `blackwall.enterprise.mesh` module exists on `origin/main` either (verified; Enterprise spec Tracks M01/M02 are marked complete, a zero-drift violation outside this spec's scope). The gateway and bridge MUST NOT hard-depend on the mesh; fleet broadcast remains an optional duck-typed hook, exactly as `ActiveReactionEngine.mesh_broadcaster` already handles it.
*   **Naming corrections:** `Callback_Token` → `CallbackToken`; "Agent Context Protocol" → "Agent Client Protocol (ACP)" (Zed's protocol for editor↔agent-CLI interfacing).

## Quality Assurance (TDD & BDD)
All protocol interception logic must be developed using a **Test-Driven Development (TDD)** approach. End-to-end integration flows (rogue agent payloads, quarantine behavior, enterprise event emission) must be governed by **Behavior-Driven Development (BDD)** using Gherkin syntax and `pytest-bdd`. Property tests cover the ingress invariants (header enforcement, rate boundaries, sanitization, malformed rejection) corresponding to ATD Properties 93–96. No new middleware proxy features can be merged without corresponding `.feature` specifications.

## Python Exclusivity & Hermes Compatibility
This implementation is 100% Python-based (`asyncio`, `pydantic`, `aiohttp` — already a dependency via `WebhookListener`). Hermes Agent, being a Python-based Agent OS, routes its tool requests through Blackwall's local MCP port (or via stdio piping); Blackwall protects the host OS without Node.js gateways or custom forks of the Hermes codebase.

## Constraints & Assumptions
*   **No Node.js:** The entire proxy stack uses Python's `asyncio`/`pydantic`/`aiohttp`.
*   **Performance:** The proxy adds network/serialization overhead. `asyncio` streaming must ensure <10ms overhead on top of Blackwall's core evaluation latency. The BLOCK-path inline signature generation (~200–500ms) is evaluator time, not proxy overhead, and runs after the verdict is committed to the response path.
*   **Dual-Tier Import Boundary:** `blackwall.protocol` (Core) must not import from `blackwall.enterprise`; the bridge injects itself via a hook protocol/interface.
*   **Provider Lock:** Runtime evaluation is 100% GCP Vertex AI Mode (paid tier), consistent with `blackwall.config`; no AI Studio key paths are reintroduced by the gateway.
*   **State Persistence:** Agent Behavioral Analytics and Threat Signatures continue to use the embedded SQLite database under the following constraints:
    - **Threat Signature Graph Schema:** Node types include `AttackerIntent`, `PayloadStructure`, and `TargetTool`. Edge types include `SIMILAR_TO` and `MITIGATED_BY` to support semantic relational queries.
    - **Database Configuration:** Must be initialized in WAL (Write-Ahead Logging) mode with strict connection pooling to minimize lock contention.
    - **Pruning Policy:** TTL or LFU pruning must autonomously evict stale signatures, keeping SQLite query latencies under 10ms and preventing write locks.
*   **Telemetry:** Interception events export OpenTelemetry spans via the existing `blackwall.telemetry` surface and are compatible with the GCP Cloud Trace exporter and GCP Vertex AI evaluation dataset pipeline (Weave is permanently purged).
