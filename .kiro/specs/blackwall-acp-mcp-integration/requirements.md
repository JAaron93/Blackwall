# Requirements Document: Protocol Integration (ACP/MCP) — Dual-Tier Revision

## Introduction

As part of Blackwall's long-term maintenance and portability strategy, the firewall must decouple from framework-specific execution hooks (such as `sys.addaudithook` and ADK 2.0 callbacks) and additionally operate as an independent middleware proxy. This document outlines the requirements for implementing a Model Context Protocol (MCP) and Agent Client Protocol (ACP) interception layer.

> [!IMPORTANT]
> **REVISION CONTEXT (2026-08-30)**
> This revision re-baselines the requirements against **`origin/main` (`b6cb9b5`)** — 155 commits ahead of the worktree HEAD where drafting began. The original (2026-07-10) requirements assumed a two-state verdict model (`ALLOW`/`BLOCK`) and routed through `HybridPolicyServer`. Both assumptions are superseded: the verdict model is **tri-state** (`ALLOW`/`BLOCK`/`QUARANTINE`), the canonical evaluation path is **`SyncResolver`**, and the proxy must integrate with the now-implemented Blackwall Enterprise pillars and Advanced Threat Detection (ATD) subsystem. Crucially, ATD Task 25 (`InboundProtocolFilter`) **is implemented on main**; this spec **delegates** ingress admission to it rather than re-implementing it.

The goal is to allow Python-based OS-level agents, specifically **Hermes Agent**, to route their tool executions through Blackwall securely and transparently. Blackwall will intercept JSON-RPC protocol payloads, evaluate them using the canonical `SyncResolver` gating chain (structural and semantic gating, threat-signature matching, GTI, and attribution), and return synthesized protocol responses for blocked or quarantined actions — all while remaining entirely Python-exclusive and respecting the Core/Enterprise import boundary.

## Glossary

*   **MCP (Model Context Protocol):** An open standard JSON-RPC protocol standardizing how AI models and agents communicate with external tools and data sources.
*   **ACP (Agent Client Protocol):** The protocol used primarily by Zed and similar environments to interface with standalone AI Agent CLIs over stdio.
*   **Protocol Proxy / Gateway:** The middleware layer in Blackwall that sits between the Agent and the execution environment, intercepting stdio/HTTP traffic.
*   **Hermes Agent:** An open-source, Python-based Agent OS that runs persistent background loops and manages local execution.
*   **JSON-RPC Synthesizer:** The Blackwall component responsible for translating firewall verdicts (`BLOCK`, `QUARANTINE`) into protocol-compliant JSON-RPC responses.
*   **SyncResolver:** The canonical single-request evaluation engine of Blackwall Core, enforcing the mandated gating chain: Rate → ContextHygiene → Threat Signature Graph → Codebase Memory → conditional GTI → Score Aggregation → Threshold Verdict → Inline Signature → non-blocking Attribution.
*   **CallbackToken:** The internal Pydantic model (in `blackwall.models`) that carries a `ToolCallContext` plus a resume callback. (The original spec's `Callback_Token` refers to this model.)
*   **Tri-State Verdict:** The `VerdictDecision` enum: `ALLOW`, `BLOCK`, and `QUARANTINE` (fail-closed sandboxed execution).
*   **Method Interception Registry:** The mapping that decides which JSON-RPC methods are security-evaluated (`tools/call`) and which pass through byte-for-byte.
*   **Enterprise Protocol Bridge:** The optional, injected hook under `blackwall.enterprise` that forwards intercepted events to ATD on the `EventSource.TOOL_CALL` stream.
*   **InboundProtocolFilter:** The already-implemented (ATD Task 25) ingress filter in `blackwall.enterprise.advanced_threat_detection.inbound_filter`, providing Origin/Host validation, per-sender sliding-window rate limiting, JSON-RPC schema validation, two-pass sanitization, and MCP-compliant error synthesis.
*   **ProtocolAdmissionHook:** The Core-defined interface the gateway delegates ingress admission to. Enterprise injects the `InboundProtocolFilter`; Core-only deployments use a conservative built-in fallback.
*   **Evaluation Containment:** The ATD invariant (`is_evaluation_mode`) that suppresses production reactions for contained test traffic.

## Functional Requirements

### FR-01: MCP/ACP Protocol Server (Python)
Blackwall MUST implement a standalone `asyncio`-based server capable of receiving, parsing, and routing JSON-RPC 2.0 messages conforming to the MCP/ACP specifications. No Node.js components are permitted.

### FR-02: Transport Layer Support
The proxy MUST support two primary transport methods for agent communication:
1.  **stdio:** Intercepting standard input/output streams for local CLI agents and for ACP carriage.
2.  **MCP Streamable HTTP (POST + SSE):** Intercepting network-bound tool requests. The proxy MUST define a POST endpoint (e.g., `/message`) for the agent to submit `tools/call` requests as bidirectional Streamable HTTP contracts, targeting the current MCP Streamable HTTP contract (revision 2025-06-18 and later; legacy pre-streamable HTTP+SSE is out of scope). Responses and events MUST return asynchronously over the established SSE channel. This explicit HTTP/SSE transport contract connects directly to the interception requirements in FR-03.
    *   **Transport Security (Mandatory):** The HTTP/SSE endpoint MUST validate `Origin` and `Host` headers to prevent DNS rebinding attacks. Local deployments MUST bind to loopback interfaces only (127.0.0.1/::1) by default. Network-bound requests MUST require authentication (e.g., bearer tokens, mutual TLS). Unauthenticated network access MUST be rejected to prevent unauthorized agent control.

### FR-03: Method Interception Registry
The gateway MUST maintain a registry distinguishing intercepted methods from pass-through methods.
*   **WHEN** a `tools/call` JSON-RPC request arrives, the gateway SHALL route it through the interception and evaluation pipeline (FR-04).
*   **WHEN** any non-intercepted method arrives (`initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`, notifications, responses), the gateway SHALL forward it byte-for-byte without evaluation, preserving protocol handshake fidelity.
*   The registry MUST be extensible so future ACP session/prompt methods can be registered without transport changes.

### FR-04: Message Interception & Payload Extraction
When an agent attempts a `tools/call` request, Blackwall MUST pause the stream, extract the tool `name` and `arguments`, and reconstruct them into a `ToolCallContext` wrapped in a `CallbackToken` compatible with the canonical `SyncResolver` evaluation path.
*   The gateway MUST enrich `ToolCallContext.metadata` with transport provenance: `protocol` (mcp/acp), `transport` (stdio/http), `session_id`, `peer`, and `jsonrpc_id`.
*   The original sensitive payload MUST NOT be forwarded to the destination during policy evaluation. Forwarding occurs only on an `ALLOW` verdict (FR-05).
*   Sensitive values are redacted by the `ContextHygiene` stage inside `SyncResolver`; the gateway MUST NOT independently log the unredacted payload.

### FR-05: Tri-State Verdict Enforcement via Protocol Synthesis
*   **ALLOW:** If the evaluator returns an `ALLOW` verdict, the original JSON-RPC payload MUST be passed cleanly to the destination tool execution context. The synthesizer MUST NOT be invoked for `ALLOW`.
*   **BLOCK:** If a `BLOCK` verdict is reached, Blackwall MUST NOT forward the request. It MUST synthesize an MCP-compliant JSON-RPC Error object (e.g., Error Code `-32603`), reusing the incoming JSON-RPC `id`. To prevent leaking redaction information, the error MUST be bounded and generic (e.g., "Blackwall Firewall: Execution blocked."), without exposing internal threat reasoning or redacted context.
*   **QUARANTINE:** If a `QUARANTINE` verdict is reached, Blackwall MUST NOT forward the request to the real tool. It MUST synthesize a successful MCP tool result carrying a sandboxed mock payload (mirroring the ADK `_execute_quarantined` semantics), allowing the agent loop to continue without real execution. The quarantined result content MUST be generic and MUST NOT reveal scoring, signatures, or redaction details.

### FR-06: Flow Control & Concurrency Integrity
The stream layer MUST track all in-flight intercepted requests by JSON-RPC `id` to ensure concurrent calls cannot be mismatched when responses are held, blocked, quarantined, or resumed. The gateway MUST enforce a configurable maximum in-memory hold queue (overflow → fail-closed `QUARANTINE` synthesis), per-request verdict timeout (timeout → fail-closed `QUARANTINE`), cancellation propagation, and deterministic cleanup of abandoned requests.

### FR-07: Ingress Admission Control (Delegates to ATD Task 25 `InboundProtocolFilter`)
Ingress admission MUST be delegated, not duplicated. ATD Task 25 is already implemented and tested on `main` as `InboundProtocolFilter` (fulfilling ATD Requirements 23.1–23.4 and Properties 93–96). The gateway MUST define a `ProtocolAdmissionHook` port in Core and delegate admission to the injected implementation; it MUST NOT re-implement header validation, rate limiting, sanitization, or error synthesis.
*   The gateway MUST ship a conservative **Core-only fallback** admission (loopback enforcement, bearer-auth gate, minimal JSON-RPC parse rejection) so Core-only deployments (US-04) remain fail-safe without importing Enterprise.
*   **WHEN** the Enterprise bridge is attached, the gateway SHALL use the injected `InboundProtocolFilter` as the sole admission authority, bypassing the Core fallback.
*   **WHEN** an HTTP/SSE request arrives, the admission authority SHALL validate `Origin` and `Host` headers and reject unauthenticated or non-loopback network requests (ATD 23.1).
*   **WHEN** a sender exceeds the per-sender sliding-window inbound rate limit, the admission authority SHALL drop additional messages (ATD 23.2).
*   **WHEN** an incoming `tools/call` payload is extracted, the admission authority SHALL sanitize arguments before evaluation (ATD 23.3).
*   **WHEN** an incoming message fails JSON-RPC schema validation, the admission authority SHALL synthesize an MCP-compliant error response without leaking internal threat context (ATD 23.4).

### FR-08: Threat Signature Logging & Attribution Continuity
All blocked protocol payloads MUST be redacted (credentials, secrets, PII removed) before being logged into the embedded SQLite Threat Signature Graph, ensuring Blackwall's self-learning loop continues to function without persisting sensitive data. Non-blocking Attacker Attribution (`AttackerIdentityExtractor` → `AttackerProfile` → `IncidentReport`) MUST continue to fire on `BLOCK`/`QUARANTINE` outcomes using the enriched transport metadata, mapping HTTP peers to `IdentitySource.NETWORK_IP` and stdio peers to process metadata without requiring `IdentitySource` enum changes. Detailed threat reasoning MUST be restricted to protected local diagnostics and MUST NOT be included in the persistence layer or the error response returned to the agent.

### FR-09: Enterprise Protocol Bridge (Optional, Injected)
An optional Enterprise bridge under `blackwall.enterprise` MUST be able to attach to the gateway without the Core importing Enterprise code.
*   **WHEN** the bridge is attached, it SHALL inject the `InboundProtocolFilter` as the gateway's `ProtocolAdmissionHook` (FR-07) and SHALL route registered `prompt/submit` payloads through the implemented Prompt Injection Scanner (ATD Task 26).
*   **WHEN** the bridge is attached and an event is intercepted, the bridge SHALL emit a `NormalizedEvent` on the existing `EventSource.TOOL_CALL` stream consumed by `EventStreamCollector.collect_from_tool_intercepts()`, feeding the ATD correlators (agent swarm, exploit chain, AILM, C2).
*   **WHEN** the ATD `ActiveReactionEngine` reaches a CRITICAL verdict from protocol-sourced evidence, it SHALL react through existing pillars (eBPF/audit-driver socket drops, optional duck-typed fleet broadcast, Vault JIT credential revocation).
*   **WHEN** the triggering evidence is flagged via `is_evaluation_mode(payload.trigger_evidence_id)`, all production reactions (socket drops, mesh broadcasts, credential revocation) MUST be suppressed per the ATD containment invariant.

## Non-Functional Requirements

### NFR-01: Zero Python Overhead Dependency
Blackwall MUST remain 100% Python-based. Integration with frameworks like OpenClaw (Node.js) is explicitly out of scope to prevent language fragmentation and maintenance burden.

### NFR-02: Latency Constraints
The serialization, parsing, and proxying of JSON-RPC messages MUST add no more than 10ms of overhead to the baseline Blackwall evaluation latency (which is <10ms for structural evaluation). The BLOCK-path inline signature generation (~200–500ms) is evaluator time, not proxy overhead, and runs after the verdict is committed to the response path.

### NFR-03: Agent Agnosticism
The protocol proxy MUST NOT contain hardcoded rules specific to Hermes Agent. It must adhere strictly to the MCP/ACP specification, ensuring compatibility with any future Python-based agent that adopts these protocols.

### NFR-04: Test-Driven Development (TDD)
All implementation tasks MUST follow strict TDD. Developers MUST write failing unit tests or reproduction commands before generating the minimum code required to pass the test.

### NFR-05: Behavior-Driven Development (BDD)
End-to-end security and interception workflows MUST be defined authoritatively using Gherkin syntax in a `.feature` file. The execution MUST be validated using `pytest-bdd` to ensure human-readable contracts for firewall behavior.

### NFR-06: Dual-Tier Import Boundary
`blackwall.protocol` (Core) MUST NOT import from `blackwall.enterprise`. The Enterprise bridge MUST attach via an explicitly injected hook interface. This preserves the Core/Enterprise packaging invariant and keeps Core deployable standalone.

### NFR-07: Provider & Telemetry Lock
Runtime evaluation MUST remain 100% GCP Vertex AI Mode (paid tier), consistent with `blackwall.config`; no Google AI Studio API-key paths are reintroduced by the gateway. Interception events MUST export OpenTelemetry spans via the existing `blackwall.telemetry` surface and remain compatible with the GCP Cloud Trace exporter and the GCP Vertex AI evaluation pipeline (Weights & Biases / Weave is permanently purged).

### NFR-08: State Persistence & Pruning
Threat signatures and behavioral analytics MUST continue to use the embedded SQLite database in WAL mode with connection pooling. Node types (`AttackerIntent`, `PayloadStructure`, `TargetTool`) and edge types (`SIMILAR_TO`, `MITIGATED_BY`) MUST be preserved. TTL/LFU pruning MUST keep SQLite query latencies under 10ms and prevent write locks.

## User Stories

### US-01: Seamless Integration for Hermes Admin
**As a system administrator running Hermes Agent,**
I want to configure Hermes to point its tool execution endpoint at Blackwall's local MCP port,
**So that** Blackwall can protect my OS from rogue agent actions without requiring me to maintain a custom, forked version of the Hermes repository.

### US-02: Graceful Agent Failure
**As an autonomous agent (like Hermes),**
I want to receive standard JSON-RPC error messages (for `BLOCK`) or sandboxed mock results (for `QUARANTINE`) when my tool call is denied or contained by the firewall,
**So that** my execution loop does not crash, and I can prompt the LLM to reflect on the failure and try a different, safer approach.

### US-03: Python Exclusivity for Maintainers
**As the lead maintainer of Blackwall,**
I want the entire proxy and integration layer to be built in Python (`asyncio`, `pydantic`, `aiohttp`),
**So that** I don't have to manage multiple runtime environments (like Node.js or npm) when deploying the firewall to my VPS infrastructure for years to come.

### US-04: Standalone Core Deployment
**As an operator of Blackwall Core (Individual Edition),**
I want the protocol proxy to function fully without any Enterprise modules installed,
**So that** I get protocol-level interception, tri-state verdict enforcement, and self-learning signatures on a single host without the enterprise mesh, kernel eBPF, or forensics dependencies.

### US-05: Enterprise Threat Correlation
**As an enterprise security operator,**
I want protocol-intercepted tool calls to flow into the Advanced Threat Detection correlators on the `TOOL_CALL` event stream,
**So that** cross-pillar swarm, exploit-chain, AILM, and C2 detection can react to protocol-borne attacks (socket drops, credential revocation) while contained evaluation traffic never triggers production reactions.
