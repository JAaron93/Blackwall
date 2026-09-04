# ADR 0004: Model Selection Rationale for Inline Security Interception

## Status
Approved

## Context
Blackwall is an autonomous agentic security firewall designed to intercept tool execution flows at machine speed before rogue, compromised, or prompt-injected AI agents can execute unauthorized OS/network actions, chain exploits, or exfiltrate sensitive credentials.

Interception occurs at runtime through three critical choke points:
1. **Application Layer**: Google ADK `before_tool_callback` hooks.
2. **Runtime Layer**: Synchronous Python audit hooks (`sys.addaudithook`).
3. **Kernel Layer**: Enterprise eBPF tracepoints (`LinuxeBPFDriver` / `ebpf-falco-mcp`).

In this real-time inline proxy topology, every millisecond of evaluation overhead directly degrades the host agent's execution loop. The core architectural constraints governing model selection are:
- **Strict Latency SLA**: Inline tool validation must complete with a deterministic P99 latency budget of `<250ms`. Delays exceeding 300ms introduce perceptible execution stutter, lock contention, or upstream agent timeouts.
- **Firewall Unit Economics**: Inline security inspection evaluates every intercepted tool invocation (up to tens of thousands of calls daily per agent cluster). Using standard frontier reasoning models on routine bash, file, or network calls produces unsustainable token inference costs.
- **Stateful Session Continuation**: Multi-turn tool execution produces repetitive context schemas, environment snapshots, and policy rules. Without server-side context caching, redundant token re-ingestion dramatically inflates both latency and cost.
- **Asynchronous Out-of-Band Deep Triage**: Complex, quarantined events flagged with high threat scores require deep forensic analysis and inline signature synthesis without blocking the calling agent.

With Claude models (including the Claude 3.5, 3.7, and 5 series) offered on Google Cloud Vertex AI Model Garden alongside Gemini, we evaluated whether to integrate Claude into Blackwall's resolution pipeline or maintain strict platform specialization.

---

## Decision

We decided to **standardize Blackwall's inline and background resolution pipeline exclusively on GCP Gemini Enterprise Agent Platform models via the Gemini Interactions API**, deliberately **excluding Claude models** from the core interception paths.

### 1. Inline Fast-Path Engine: Gemini 3.5 Flash-Lite
For synchronous inline resolution (`submit_to_gemini_sync` in `BatchResolver`), Blackwall standardizes on **Gemini 3.5 Flash-Lite**:
- **Sub-150ms TTFT**: Delivers deterministic sub-150ms Time-to-First-Token, fitting comfortably within the 250ms end-to-end P99 latency budget alongside local AST and SQLite threat graph checks.
- **Micro-Cent Unit Economics**: Enables continuous, non-sampled inspection across high-frequency tool invocations without cost exhaustion.
- **Server-Side Context Caching (`previous_interaction_id`)**: Natively persists policy snapshots and tool context server-side across interaction turns, guaranteeing a `>=50%` token reduction on cache hits and eliminating redundant payload serialization.

### 2. Asynchronous Out-of-Band Engine: Gemini 3.8 Flash
For quarantined events requiring deep threat correlation (`submit_to_gemini_background`), Blackwall standardizes on **Gemini 3.8 Flash**:
- **Native Background Webhooks (`background=True`)**: Employs the Gemini Interactions API's built-in background execution primitive. The model endpoint processes deep threat chains out-of-band and notifies Blackwall's `/webhook/analysis_complete` endpoint via asynchronous server-side webhooks.
- **Queue-Free Task Offloading & Ingress Topology**: Eliminates the operational overhead and failure modes of deploying separate distributed task brokers (e.g., Celery, Temporal, or RabbitMQ) to manage asynchronous forensic triage. In production deployments where `WebhookListener` binds locally (`127.0.0.1`), delivering completed cloud callbacks requires an external ingress relay, reverse proxy, or Cloud Run service URL to route traffic to the listener.

### 3. Deliberate Exclusion of Claude 5 Series Models
Claude models were evaluated and rejected for the following technical and economic reasons:

1. **Inline Latency SLA Infeasibility**:
   - Claude models (e.g., Sonnet / Opus tiers) exhibit TTFT between 400ms and 1,500ms+. Placing Claude in the synchronous inline execution path (`submit_to_gemini_sync`) violates the `<250ms` SLA by a factor of 2x–6x, starving calling agents and introducing unacceptable runtime latency.
2. **Economic Misalignment for Security Interception**:
   - Claude pricing per million tokens is 10x to 50x higher than Gemini Flash-Lite. Using Claude to inspect routine, high-volume tool parameters (e.g., benign `ls`, `cat`, or directory scans) breaks the operational economics of an always-on security firewall.
3. **Protocol and Architectural Impedance Mismatch**:
   - Claude on Vertex AI uses Anthropic's synchronous Messages API (`/v1/messages`). It lacks a native asynchronous background execution primitive with built-in server-side webhook callbacks (`background=True`, `webhook_config`), which would force Blackwall to introduce external queue daemons.
   - Claude's prompt caching relies on explicit ephemeral cache breakpoint markers with strict token thresholds and cache lifetimes, rather than seamless `previous_interaction_id` session chaining.
4. **Rejection of "Resume-Driven" Multi-Model Superficiality**:
   - Bolting on Claude simply to advertise multi-model support would create dead or divergent codepaths, degrade test suite reliability, and dilute Blackwall's core design. Real-world systems engineering favors deep exploitation of platform primitives over shallow multi-vendor abstractions.

### 4. Pluggable Enterprise Boundary
While Claude is excluded from core inline firewalling, Blackwall's modular `BatchResolver` and `SyncResolver` interfaces maintain clean separation of concerns. Enterprise deployments requiring external model arbitration (e.g., out-of-band compliance audits or cross-provider forensic second opinions) can implement custom adapter plugins without compromising the inline fast path.

---

## Consequences

### Positive
- **Deterministic SLA Performance**: Inline tool interception overhead remains consistently below 250ms (P99), preserving normal agent execution speed.
- **Optimal Cost Efficiency**: Keeps security inspection costs at fractional cents per 1,000 tool calls.
- **Lean Architecture**: Asynchronous deep triage leverages native webhook callbacks without requiring auxiliary task queue infrastructure.
- **High Cache Utilization**: Server-side context caching via `previous_interaction_id` cuts payload overhead by over 50% across multi-turn sessions.
- **Architectural Integrity**: Avoids artificial multi-model abstractions that add maintenance burden without tangible security benefits.

### Negative & Trade-offs
- **Platform Coupling**: Core resolution remains tightly coupled to GCP Vertex AI and the Gemini Interactions API wire specifications.
- **Air-Gapped & Offline Fail-Closed Policy**: Environments without GCP connectivity must rely exclusively on deterministic AST policies and local SQLite threat signatures. If an event requires cloud LLM arbitration, the resolvers enforce a strict fail-closed policy (`QUARANTINE`) rather than attempting an inline local model fallback. (The local Ollama engine remains strictly isolated to Enterprise Pillar 5 for out-of-band telemetry log triage, not inline tool-call resolution).
