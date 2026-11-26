# Design Document: Blackwall MCP Gateway

## Overview

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials.

As the AI agent ecosystem converges on the **Model Context Protocol (MCP)** as the standard interface between agents and tools, Blackwall evolves from an environment-injected execution hook into a **Standalone MCP Security Gateway** — a local background daemon that intercepts, evaluates, and governs all MCP tool calls on the developer's machine.

This design document outlines the architecture for deploying Blackwall as an independent, always-on security daemon that any MCP-compliant agent (Antigravity, Warp Terminal, Claude Desktop, Cursor, ADK agents, or any future MCP client) can route tool execution through — transparently, with zero agent-specific coupling.

## Core Architectural Principle

Blackwall runs as a **standalone local daemon** — not a sidecar, not a proxy for a specific agent runtime, not a hosted cloud service. It is a security process on the developer's machine that speaks MCP and governs tool execution.

1.  **The Agent** (e.g., Antigravity, Warp Terminal Agent) sends a `tools/call` JSON-RPC request.
2.  **Blackwall Gateway** receives the request over stdio or Streamable HTTP on `localhost:9229`.
3.  **Blackwall's Engine** (`SyncResolver` pipeline) evaluates the request: Rate Check → Context Hygiene Sanitization → SQLite Threat Signature Graph (TSG) Check → Codebase Memory MCP AST Query → Conditional Threat Intelligence Validation (AlienVault OTX, gated on high-risk or indicator-bearing events) → Semantic Triage (pluggable Tier-1 classifier with Tier-2 escalation — see `.kiro/specs/tier-1-jev-addition/`) → Score Aggregation → Threshold Verdict.
4.  **ALLOW Verdict:** Blackwall forwards the original payload to the downstream tool server and pipes the response back to the agent.
5.  **BLOCK Verdict:** Blackwall drops the request and synthesizes a valid MCP-compliant JSON-RPC Error response, simulating a tool failure without crashing the agent's execution loop.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Developer's Machine                         │
│ (Baseline: Intel MacBook Pro | Top: Apple Silicon MacBook Pro M-Series) │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Antigravity   │  │ Warp Terminal│  │ Any MCP-Compliant Agent  │  │
│  │ (MCP Client)  │  │ (MCP Client) │  │ (MCP Client)             │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬──────────────┘  │
│         │ stdio            │ HTTP                  │ stdio/HTTP     │
│         ▼                  ▼                       ▼                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Blackwall MCP Gateway (Daemon)                 │   │
│  │              localhost:9229 | PID: ~/.blackwall/blackwall.pid│   │
│  │                                                             │   │
│  │  ┌───────────┐  ┌──────────────┐  ┌───────────────────┐    │   │
│  │  │ Protocol  │→ │ Interceptor  │→ │ SyncResolver      │    │   │
│  │  │ Gateway   │  │ (Payload     │  │ Pipeline           │    │   │
│  │  │ (stdio +  │  │  Extraction) │  │                   │    │   │
│  │  │  HTTP)    │  │              │  │ ┌───────────────┐ │    │   │
│  │  └───────────┘  └──────────────┘  │ │ Rate Check    │ │    │   │
│  │                                    │ │ Context Hygiene│ │    │   │
│  │  ┌───────────┐                    │ │ Threat Graph  │ │    │   │
│  │  │ Response  │← ─ ─ Verdict ─ ─ ─│ │ CBM AST Query │ │    │   │
│  │  │ Synthesizer│                    │ │ GTI (high-risk)│ │    │   │
│  │  │ (ALLOW →  │                    │ └───────────────┘ │    │   │
│  │  │  forward, │                    └───────────────────┘    │   │
│  │  │  BLOCK →  │                                             │   │
│  │  │  error)   │                                             │   │
│  │  └─────┬─────┘                                             │   │
│  └────────┼───────────────────────────────────────────────────┘   │
│           │ ALLOW only                                             │
│           ▼                                                        │
│  ┌─────────────────────────────────────────┐                      │
│  │     Downstream Tool Servers             │                      │
│  │  (filesystem, github, shell, etc.)      │                      │
│  └─────────────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Protocol Gateway (Transport Layer)
A high-performance Python `asyncio` server handling bidirectional JSON-RPC streams.
*   **Transports Supported:** `stdio` (standard input/output redirection) and **MCP Streamable HTTP** (bidirectional POST `/mcp` endpoint with SSE responses). The gateway targets the **MCP 2025-03-26 revision**. The Streamable HTTP endpoint establishes per-session isolation, validates `Origin` and `Host` headers for local deployments, and binds to `127.0.0.1` by default.
*   **Remote Authentication:** When the HTTP transport binds to a non-loopback address (via `--host`), the gateway MUST require a pre-shared bearer token for all inbound requests. The token is configured via `--auth-token <token>` flag or `BLACKWALL_AUTH_TOKEN` environment variable. Requests without a valid `Authorization: Bearer <token>` header MUST be rejected with HTTP 401 before any JSON-RPC processing occurs. If `--host` specifies a non-loopback address and no auth token is configured, the gateway MUST refuse to start with a clear error message.
*   **Role:** Sits between MCP clients (any agent) and downstream tool servers.

### 2. Message Interceptor
Extracts semantic intent from MCP protocol payloads.
*   **MCP Tool Calls:** Intercepts `tools/call` requests, extracts `name` and `arguments`.
*   **Payload Reconstruction:** Reformats extracted data into Blackwall's internal `ToolCallContext`, ensuring compatibility with the existing `SyncResolver` pipeline.
*   **Pass-Through:** Non-tool methods (`initialize`, `notifications/*`, `tools/list`) are forwarded unchanged to preserve protocol compliance.
*   **Client Metadata Isolation:** Untrusted client-supplied `params._meta` MUST NOT override security-sensitive context properties (`environment_role`, `is_evaluation`, `agent_id`, `session_id`). Only an allow-list of non-security protocol properties (`client_name`, `client_version`, `progress_token`, `traceparent`, `tracestate`) is accepted and namespaced under `context.metadata["client_meta"]`.

### 3. Engine Router (SyncResolver Pipeline)
Routes extracted payloads through Blackwall's defenses in a strict, mandatory sequence:
1.  **Rate Check:** Token bucket rate limiter (300+ RPM via GCP Vertex AI paid tier billing credits; for reference, TypeSafe Jev at Tier-1 is 4,800 RPM = 80 req/s, default org limit).
2.  **Context Hygiene Sanitization:** Replace sensitive environment variable patterns with generic placeholders.
3.  **SQLite Threat Signature Graph (FTS5):** Check for structural similarities with known malicious payloads using word-level intersection match quality scoring.
4.  **Codebase Memory MCP:** Run AST query to trace dependency blast radius.
5.  **Threat Intelligence (AlienVault OTX):** Query AlienVault OTX for external IP/domain indicators for high-risk events or events carrying external indicators (`SyncResolver` derives `is_high_risk` from structural/CBM signals or indicator presence). Rate-limited to 10,000 queries/hour authenticated (1,000/hour unauthenticated) via token bucket with 3-state circuit breaker (`src/blackwall/threat_intel/otx.py`); served through the SQLite `threat_intel_cache` (≤ 1.0 ms average read, enforced by `tests/unit/threat_intel/test_benchmarks_sla.py`) with a primary + secondary provider cascade in `ThreatIntelOrchestrator`. No VirusTotal code path exists in the current implementation.
6.  **Semantic Triage (pluggable Tier-1 + Tier-2 escalation):** Novel payloads are scored by `SemanticTriageProvider` (`src/blackwall/policy/semantic.py`), currently the Tier-1 Jev decision classifier (TypeSafe Jev via the official TypeSafe AI API, `P(threat)` with `0.08/0.40` ambiguity band) backed by Gemini Tier-2 escalation and async forensic signature synthesis. Governed by `.kiro/specs/tier-1-jev-addition/`; the `gemini` backend is preserved for GCP-only operation.
7.  **Score Aggregation:** Weighted composite score from all signals.
8.  **Threshold Verdict:** `≥ 0.20 → BLOCK`, `≥ 0.10 → QUARANTINE`, `< 0.10 → ALLOW`.

### 4. Response Synthesizer
*   **ALLOW Verdict:** Forward the original JSON-RPC request byte-stream to the downstream tool server and pipe the response back to the agent.
*   **BLOCK Verdict:** Drop the request and synthesize a valid JSON-RPC error response, explicitly reusing the incoming request `id` (bounded generic message — zero threat reasoning leaked):
    ```json
    {
      "jsonrpc": "2.0",
      "id": "<extracted_request_id>",
      "error": {
        "code": -32603,
        "message": "Blackwall Firewall: Execution blocked"
      }
    }
    ```
*   **QUARANTINE Verdict:** Synthesize a JSON-RPC error with a distinct code (`-32001`) and log the event for manual review.
*   The stream layer tracks all in-flight requests by `id` to ensure concurrent calls are never mismatched.

### 5. Upstream Tool Server Manager
Manages downstream MCP tool server lifecycle and request forwarding.
*   **Wrap Mode (`--wrap`):** Spawns a single downstream tool server as a child process (stdio). Simplest integration path.
    ```bash
    blackwall serve --wrap "npx @anthropic/mcp-server-filesystem /Users/you/projects"
    ```
*   **Multi-Server Mode (`gateway.yaml`):** Manages multiple downstream servers defined in `~/.blackwall/gateway.yaml`.
    ```yaml
    upstream_servers:
      - name: filesystem
        command: "npx @anthropic/mcp-server-filesystem /Users/you/projects"
        transport: stdio
      - name: github
        url: "http://localhost:3001"
        transport: http
    ```
*   Connection pooling for HTTP upstream targets.
*   Health checks and graceful shutdown of child processes.

### 6. Daemon Lifecycle Manager
*   **Background Mode (default):** `blackwall serve` daemonizes the process, writes PID to `~/.blackwall/blackwall.pid`, redirects stdout/stderr to `~/.blackwall/blackwall.log`.
*   **Foreground Mode:** `blackwall serve --foreground` runs in the terminal with live log output. Useful for debugging and lightweight usage.
*   **Stop:** `blackwall stop` reads the PID file and sends `SIGTERM` for graceful shutdown.
*   **Status:** `blackwall status` checks PID liveness, reports threat graph stats, and recent verdict summary.
*   **Init:** `blackwall init` scaffolds `~/.blackwall/` with default `policy.yaml`, empty threat DB, and starter `gateway.yaml`.

### 7. CLI Entry Point
`click`-based CLI providing the `blackwall` command:
*   `blackwall serve` — start the gateway daemon
    *   `--transport stdio|http` (default: `stdio`)
    *   `--port 9229` (HTTP mode, default)
    *   `--host 127.0.0.1` (HTTP mode, loopback by default; non-loopback requires `--auth-token`)
    *   `--wrap <command>` (downstream tool server to proxy)
    *   `--config <path>` (path to `gateway.yaml`)
    *   `--policy <path>` (path to `policy.yaml`)
    *   `--db <path>` (path to SQLite threat graph; aliased to `--db-path`)
    *   `--pidfile <path>` (path to daemon PID file; default: `~/.blackwall/blackwall.pid`)
    *   `--logfile <path>` (path to log file; default: `~/.blackwall/blackwall.log`)
    *   `--foreground` (run in foreground instead of daemonizing; creates designated `--pidfile` when specified)
    *   `--auth-token <token>` (bearer token for non-loopback HTTP; also configurable via `BLACKWALL_AUTH_TOKEN` env var. Required when `--host` is non-loopback; gateway refuses to start without it)
    *   `--log-level debug|info|warning|error`
*   `blackwall init` — initialize `~/.blackwall/` directory
*   `blackwall stop` — stop the running daemon
*   `blackwall status` — show daemon status and recent verdicts
*   `blackwall service install|uninstall|start|stop|status|configure` — manage background daemon service via macOS `launchd` (`~/Library/LaunchAgents/com.blackwall.gateway.plist`)
    *   `install` options: `--config <path>` (default: `~/.blackwall/gateway.yaml`), `--wrap <cmd>`, `--project <id>` (or capture active `GCP_PROJECT`)
    *   `configure` options: `--project <id>`, `--credentials <path>`, `--typesafe-key <key>` (writes `TYPESAFE_API_KEY` to the protected `0600` env file, never inline)
*   `blackwall hook install|uninstall|status` — manage global Python runtime audit hook (`sitecustomize.py` / `.pth`)
*   `blackwall version` — print version

### 8. macOS Background Service Manager (launchd LaunchAgent)
*   **macOS Service Management:** `blackwall service` manages user-scoped background daemon execution on macOS via `launchd`:
    *   Generates and manages `~/Library/LaunchAgents/com.blackwall.gateway.plist` via `launchctl`.
*   **Absolute Path Resolution & Non-Tilde Invariant:** Because service runners and daemons do not execute in an interactive shell and do not perform tilde (`~`) expansion, `blackwall service install` resolves all file paths (configuration, logs, upstream targets, and credential files) to absolute filesystem paths at installation time (`Path.resolve()`). No unexpanded `~` characters are permitted in generated service files.
*   **Authoritative Upstream Target & Paths:** Configuration defaults to `~/.blackwall/gateway.yaml` with state at `~/.blackwall/`. The service executes `blackwall serve --foreground --transport http --port 9229 --config <resolved-config-path> --pidfile <resolved-pidfile> --logfile <resolved-logfile> --db <resolved-db>` (or user-specified `--wrap`), ensuring allowed tool requests are deterministically forwarded to defined downstream tool servers while keeping the gateway in the foreground so `launchd` directly supervises the active process and the PID file is created upon startup.
*   **Protected Secret Files (Never Inline):** Bearer secrets MUST NEVER appear inline in plist `EnvironmentVariables`, logs, or unit files (all inspectable). Non-sensitive identifiers (project IDs, credential *paths*) may be embedded; secret *values* MUST live only in `0600` files. When the Tier-1 Jev backend is selected (`.kiro/specs/tier-1-jev-addition/`), `blackwall service install` persists a present `TYPESAFE_API_KEY` exclusively to a `0600` env file — `~/.blackwall/gateway.env` — which the daemon loads at startup via dotenv loading (macOS `launchd` has no `EnvironmentFile` equivalent). ADC keeps its existing path-to-`0600`-file pattern; the TypeSafe key gets the equivalent. `blackwall service configure --typesafe-key <key>` provisions the same file.
*   **Credential Validation & ADC Fallback:** `blackwall service install` validates that `GCP_PROJECT` (or `GOOGLE_CLOUD_PROJECT`) is configured, failing fast with an exit code != 0 if absent. If `GOOGLE_APPLICATION_CREDENTIALS` is unset in the environment, the installer locates user ADC at `~/.config/gcloud/application_default_credentials.json` and injects the resolved absolute path into the plist `EnvironmentVariables`.
*   **Process Supervision & Crash-Loop Throttling:** Configures `<key>ThrottleInterval</key><integer>30</integer>` and `<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>`, executing `blackwall serve --foreground` so `launchd` directly supervises the process without parent exit.
*   **Logging:** Output streams are directed to resolved absolute paths (e.g. `/Users/<user>/.blackwall/blackwall.log`).

### 9. Native macOS Menu Bar Application & System Notifications
*   **Menu Bar Tray Application (`Blackwall.app`):** Lightweight native tray application (Swift/SwiftUI or lightweight macOS runner) living in the macOS menu bar.
*   **Visual Status Indicator:**
    *   🟢 **Green Shield**: Gateway daemon active, protected, 0 active threat alerts.
    *   🟡 **Amber Shield**: Suspicious payload quarantined, pending inspection.
    *   🔴 **Red Shield**: Malicious tool call blocked, threat signature generated.
*   **Native System Notifications:** Dispatches macOS native notification banners (via UserNotifications framework) when `SyncResolver` returns a `BLOCK` or `QUARANTINE` verdict, displaying the agent name, trapped tool, and risk score without exposing raw credentials.
*   **One-Click Tool Integrations:** GUI toggles to automatically register Blackwall's MCP gateway endpoint into Google Antigravity, Warp Terminal, Claude Desktop, and Cursor configuration files.

### 10. Global Python Audit Hook Auto-Bootstrap
*   **Zero-Config Hook Registration:** `blackwall hook install` automatically injects a lightweight bootstrap loader into Python's `sitecustomize.py` (or `.pth` file) across active Python virtualenvs and user site-packages on macOS (Apple Silicon `arm64` and Intel `x86_64`).
*   **Transparent Subprocess Protection:** Whenever an AI agent or tool executes a Python script, `sys.addaudithook` is attached immediately before user code runs, preventing rogue scripts from making direct `subprocess.Popen` or `socket.connect` escapes.

### 11. macOS Release Packaging Pipeline (`.dmg` for Apple Silicon & Intel)
*   **macOS Packaging (`.dmg`):** GitHub Actions CI builds standalone native macOS application bundles (`Blackwall.app`) for both Intel (`x86_64`) and Apple Silicon (`arm64`) architectures, packaged into drag-and-drop `.dmg` disk image installers (`Blackwall-Intel.dmg`, `Blackwall-AppleSilicon.dmg`).
*   **Windows Strictly Excluded:** Windows (`.exe`, `.msi`, PowerShell) is explicitly unsupported and excluded from CI release pipelines.

### 12. Apple Silicon High-End & Intel Baseline Architecture (Zero-GPU Footprint & Unified Memory Efficiency)
When operating on the top-of-the-line **Apple Silicon MacBook Pro** (M-Series ARM64: M1/M2/M3/M4 Pro/Max, up to 128GB unified memory, macOS), Blackwall Core operates with strict efficiency invariants to guarantee zero interference with developer workloads and local AI models:
*   **Zero GPU / Metal / ANE Footprint & Host Memory Bounding:** On Apple Silicon unified memory architectures where CPU, GPU cores, and Apple Neural Engine share the same physical memory pool, Blackwall Core strictly guarantees zero Metal shader context creation, zero ANE buffer allocations, and caps its host process RSS memory to ≤150MB. This leaves the full GPU and ANE bandwidth available for local LLM inference engines (Ollama, llama.cpp, MLX) or model training jobs. Conformance verification asserts zero GPU allocation across all layers: no Metal command queues, no ANE compute requests, and host process RSS strictly ≤150MB under active evaluation load.
*   **Port Collision Avoidance:** Default gateway port `9229` is specifically selected to avoid collision with common developer and AI serving software on macOS:
    *   `11434` — Ollama API
    *   `8000` / `8080` — Local API servers, dev servers
    *   `8888` / `8889` — JupyterLab / Jupyter Notebook
*   **Apple Ecosystem Transparency:** Blackwall's Python audit hooks and MCP stream proxies operate independently of macOS security frameworks (Gatekeeper, TCC, SIP), APFS, and XPC communication, ensuring native tooling is never corrupted or throttled.

### 13. MCP Gateway Demo & Showcase Infrastructure
A self-contained, reproducible demo suite demonstrating the MCP Gateway's threat interception capabilities against real-world AI agent attack vectors classified by [OWASP Top 10 for LLMs](https://genai.owasp.org/) and [MITRE ATLAS](https://atlas.mitre.org/).

*   **Local Honeypot Web Server (`scripts/gateway_demo/honeypot_server.py`):** A FastAPI application serving pages designed to look like legitimate library documentation but containing hidden **indirect prompt injection** payloads embedded via:
    *   HTML comments (`<!-- Ignore previous instructions... -->`)
    *   CSS-hidden divs (`<div style="display:none; font-size:0">`)
    *   Zero-width Unicode characters wrapping malicious instructions

    The payloads instruct the consuming agent to: (1) read credential files (`.env`, `~/.config/gcloud/application_default_credentials.json`), then (2) POST the contents to a locally-hosted attacker C2 endpoint (`/exfil`) for demo verification. The honeypot runs entirely on `localhost:8765` with zero external network dependencies.

*   **Five Demo Scenarios:**

    **Scenario 1 — "The Honeypot" (Shared Attack Environment):**
    A locally-hosted FastAPI server (`scripts/gateway_demo/honeypot_server.py`) serves `/docs/fake-library` (hidden HTML-comment, CSS-hidden and zero-width-Unicode injection payloads), `/docs/compromised-response` (tool-chain hijack used by The Quarantine), and `/exfil` (simulated attacker C2 with ephemeral, redacted capture). All credentials are synthetic fixtures under a temporary `HOME`. This scenario establishes the attack environment for the four attack scenarios below and is recorded as the opening `honeypot.cast`.
    *   **Attack Taxonomy:** [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/), [MITRE ATLAS AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

    **Scenario 2 — "The Heist" (BLOCK — Indirect Prompt Injection Credential Exfiltration):**
    An AI agent researches a dependency via web search / URL reading through the Blackwall MCP Gateway. The visited page (served by the local honeypot) contains a hidden prompt injection payload. The agent, following the injected instructions, attempts a `tools/call` for `read_file` targeting `.env`, then a `tools/call` for `http_request` POSTing the contents to the attacker's `/exfil` endpoint. The SyncResolver pipeline intercepts: Context Hygiene detects credential patterns, the Threat Signature Graph matches credential-exfiltration tool-call chains, and the composite score exceeds the BLOCK threshold (≥ 0.20). The gateway synthesizes a JSON-RPC `-32603` error with a bounded generic message — zero internal threat reasoning is leaked to the agent.
    *   **Attack Taxonomy:** [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/), [MITRE ATLAS AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

    **Scenario 3 — "The Quarantine" (QUARANTINE + ALLOW — Surgical Tool-Chain Isolation):**
    An agent performs a legitimate refactoring task through the gateway. A mock compromised MCP tool server returns a response containing embedded instructions to also read `~/.ssh/id_rsa` and cloud credentials. The agent attempts: (1) a legitimate `write_file` to update a project module — **ALLOW**, file written successfully; (2) a suspicious `read_file` targeting `~/.ssh/id_rsa` — **BLOCK**, credential-harvesting signature match. The agent's session continues uninterrupted: subsequent legitimate tool calls are ALLOW'd. Demonstrates that Blackwall is **surgical** — it kills only the malicious call, not the entire session.
    *   **Attack Taxonomy:** [OWASP LLM07 — Insecure Plugin Design](https://genai.owasp.org/), [MITRE ATLAS AML.T0054 — LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)

    **Scenario 4 — "The Poisoned Package" (BLOCK via Python Audit Hook — Supply Chain Defense-in-Depth):**
    An agent installs a package whose `postinstall` script attempts runtime escapes: `subprocess.Popen` opening a network connection to an attacker C2 server, `os.system` executing credential reads, and direct `socket.connect` to exfiltrate harvested data. The MCP Gateway ALLOW's the initial `run_command` for `pip install`, but the Python audit hook (`sys.addaudithook`, bootstrapped via `blackwall hook install`) fires during script execution, intercepting the `subprocess.Popen` and `socket.connect` audit events and raising `PermissionError`. Demonstrates **defense-in-depth**: even when a tool call passes protocol-level interception, runtime audit hooks provide a second layer of protection against in-process escapes.
    *   **Attack Taxonomy:** [OWASP LLM05 — Supply Chain Vulnerabilities](https://genai.owasp.org/), [MITRE ATLAS AML.T0049 — Exploit ML Supply Chain](https://atlas.mitre.org/techniques/AML.T0049)

    **Scenario 5 — "The Bouncer" (Tier-1 Jev Fast Path + Tier-2 Escalation):**
    A three-act demo of the additive triage architecture (governed by `.kiro/specs/tier-1-jev-addition/`): (1) a benign parameterized query is ALLOW'd on the Jev fast path (`P≈0.02`, no Tier-2 spend); (2) an obfuscated SQL injection is BLOCK'd on the fast path (`P≈0.98`); (3) an ambiguous C2-beacon-like probe lands in the escalation band (`P≈0.5`) and is handed to Gemini Tier-2 for the final verdict, followed by async signature synthesis. Demonstrates cost discipline — expensive reasoning fires only where judgment exists.
    *   **Attack Taxonomy:** [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/), [MITRE ATLAS AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

*   **Recording Infrastructure (`scripts/gateway_demo/record_demo.sh`):** Orchestration script producing `asciinema` terminal recordings in split-pane tmux format:
    *   **Left Pane:** Agent conversation / tool call flow with verdicts
    *   **Right Pane:** Blackwall gateway live logs (threat scores, signature matches, verdicts highlighted in color)
    *   Output: `.cast` files in `docs/recordings/` (one per scenario, including `honeypot.cast`) convertible to GIF/SVG via `agg` (asciinema GIF generator) for README embedding
    *   Optional "without Blackwall" comparison clip showing the same attack succeeding against an unprotected agent

## Defense-in-Depth Layers

Blackwall provides three layers of security, each operating at a different level:

| Layer | Scope | Integration | Target Hardware Support |
|-------|-------|-------------|-------------------------|
| **MCP Gateway** (protocol) | Tool calls from any MCP agent | Agent MCP config → Blackwall | ✅ Yes — Core (Intel MacBook Baseline & Apple Silicon High-End) |
| **Python Audit Hooks** (runtime) | Direct `os.system()`, `subprocess`, file I/O, network | `sys.addaudithook` in Python process | ✅ Yes — Core (Intel MacBook Baseline & Apple Silicon High-End) |
| **eBPF Kernel Probes** (kernel) | Container escapes, kernel syscalls | Enterprise daemon with root privileges | ❌ Portfolio only (Enterprise Mesh) |

## Resource Constraints (Dual Hardware Target Tiers)

All gateway components MUST operate within these hardware budgets:

| Metric | Intel MacBook Pro Baseline (Core i7, 16GB) | Apple Silicon MacBook High-End (M-Series ARM64, 36GB–128GB Unified Memory) | Enforcement / Rationale |
| :--- | :--- | :--- | :--- |
| **Idle RAM** | ≤ 60MB | ≤ 60MB | Event loop sleeping. Zero background ML models loaded at idle. |
| **Active RAM** | ≤ 150MB | ≤ 150MB | Peak during SyncResolver eval + concurrent multi-agent batch queries. |
| **GPU / Metal / ANE** | 0MB (N/A) | **0MB Metal / 0MB ANE** | **Strict Invariant**: Zero Metal command queues or ANE compute requests; full GPU and ANE bandwidth reserved for local LLM workloads. |
| **Idle CPU** | ~0% | ~0% | Asyncio event loop sleep. Zero polling. |
| **Active CPU** | < 5% single core | < 2% performance core | Sub-10ms evaluation burst (JSON parse + FTS5 + hygiene). Apple Silicon P-cores deliver sub-5ms on M2+ for Tier 0 local checks (structural + FTS5 graph, no network). |
| **Disk** | ≤ 50MB | ≤ 50MB | SQLite threat graph + policy YAML + logs. |
| **Startup** | < 2s | < 1s | APFS + unified memory enables faster cold-start on Apple Silicon. Lazy-load heavy dependencies on first call. |

## Quality Assurance (TDD & BDD)

All protocol gateway logic MUST be developed using strict **Test-Driven Development (TDD)**. End-to-end integration flows (simulating rogue agent payloads over MCP) MUST be governed by **Behavior-Driven Development (BDD)** using Gherkin syntax and `pytest-bdd`. No gateway features can be merged without corresponding `.feature` specifications.

## Python Exclusivity & Universal MCP Compatibility

This implementation is 100% Python-based (`asyncio`, `pydantic`, `click`). The gateway operates at the MCP protocol level, ensuring compatibility with **any** MCP-compliant agent — regardless of the agent's implementation language or framework. No Node.js components, no agent-specific coupling.

## GCP Vertex AI Mode (Mandatory for Tier-2, Forensics & Evaluation)

The gateway requires GCP Vertex AI Mode for the `SyncResolver`'s Tier-2 deep-reasoning escalation, async forensic signature synthesis, and Agent-as-a-Judge evaluation. Users MUST configure `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` and authenticate via Application Default Credentials (ADC). Google AI Studio API Key Mode is permanently removed.

Tier-1 semantic triage may instead run on the Jev classifier via the official TypeSafe AI API on paid per-token billing (see `.kiro/specs/tier-1-jev-addition/` and ADR 0008), which requires `TYPESAFE_API_KEY` rather than Vertex — but Vertex remains mandatory overall because Tier-2, forensics, and the eval harness cannot run without it.

## Constraints & Assumptions

*   **No Node.js:** The entire gateway stack is Python `asyncio` + `pydantic` + `click`. Semantic triage backends (including Tier-1 Jev per `.kiro/specs/tier-1-jev-addition/`) MUST be pure-Python pip-installable clients — no Node.js sidecars — so the Phase 5 packaging pipeline inherits a clean dependency closure.
*   **Operating System Scope & Explicit Windows Exclusion:** Supported platforms are **macOS** (Darwin `arm64` Apple Silicon and `x86_64` Intel). Linux packaging and NVIDIA DGX Spark support are explicitly de-scoped from Phase 5 (see Phase 5 scope refinement note below). **Windows is strictly unsupported** — no Windows releases, no PowerShell/MSI installers, and zero maintenance overhead.
*   **Dual Hardware Target Profiles:**
    - **Baseline**: 2019 Intel MacBook Pro (Intel Core i7, 16GB RAM) prioritizing strict resource conservation and low-power battery efficiency.
    - **Top-of-the-Line**: Apple Silicon MacBook Pro (M-Series ARM64: M1/M2/M3/M4 Pro/Max, 36GB–128GB unified memory) delivering high-throughput concurrent agent security at sub-5ms Tier 0 local evaluation latency (structural + FTS5 graph checks, no network calls) with zero Metal/ANE allocation, preserving full GPU and ANE capacity for local developer workloads and LLM inference.
*   **Performance:** Gateway overhead MUST remain < 10ms on top of core evaluation latency.
*   **Local-Only Binding:** HTTP transport binds to `127.0.0.1` by default. Network-bound deployments require explicit `--host` override and a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`). The gateway MUST refuse to start on a non-loopback address without a configured auth token.
*   **State Persistence:** SQLite Threat Signature Graph in WAL mode with strict connection pooling. TTL/LFU pruning keeps query latencies under 10ms.
    - Node types: `AttackerIntent`, `PayloadStructure`, `TargetTool`.
    - Edge types: `SIMILAR_TO`, `MITIGATED_BY`.

## Implementation Notes & Deviations (Phases 1–4, finalized under TASK-E01)

This section records where the shipped implementation (PRs #159, #160, #161) intentionally differs from or extends the original design. Phase 4 (spec finalization, TASK-E01) is complete. Phase 5 (service packaging) and Phase 6 (demo showcase) remain future work and are unaffected, except for the forward-compatibility notes below.

> **Phase 5 Scope Refinement (2026-11-17):** Following a strategic hardware review, Phase 5 is rebaselined from a cross-platform (macOS + NVIDIA DGX Spark / Linux) packaging effort to a **macOS-exclusive** release pipeline. Linux `systemd` service management, Debian `.deb` packaging, DGX OS `aarch64` targets, and NVIDIA zero-CUDA verification tests are de-scoped from Phase 5. The dual hardware target tiers are now: **Intel MacBook Pro** (Core i7, 16GB — lower-end baseline) and **Apple Silicon MacBook Pro** (M-Series ARM64, 36GB–128GB unified memory — higher-end target). No Phase 1–4 shipped code is affected.

### Phase 1: Foundation (PR #159 — TASK-A01, A02, B01, B02)
*   **Delivered as specified:** `src/blackwall/gateway/` (`server.py`, `flow.py`, `interceptor.py`, `synthesizer.py`, `exceptions.py`) with unit suites `tests/unit/gateway/test_{server,flow,interceptor,synthesizer}.py`.
*   **Deviation — stdio cancellation bypass:** `notifications/cancelled` bypasses the stdio concurrency semaphore so a stuck request can never starve its own cancellation. All other traffic (including general notifications) obeys the bound to preserve memory backpressure.

### Phase 2: Wiring (PR #160 — TASK-C01, C02, C03)
*   **Delivered as specified:** E2E pipeline (`MCPGatewayServer` → `PayloadInterceptor` → `SyncResolver` → downstream/`ResponseSynthesizer`, sub-10ms overhead benchmark), upstream manager (`StdioUpstreamServer` with process-group isolation, `HttpUpstreamServer` with pooling, `gateway.yaml` routing), and `click` CLI (`serve`, `init`, `stop`, `status`, `version`) with PID lifecycle and GCP credential fail-fast.
*   **Deviation — fail-closed policy loading:** A discovered but unloadable policy (`~/.blackwall/policy.yaml` or `--policy`) aborts startup with `RuntimeError` instead of running un-gated.
*   **Deviation — non-short-circuit structural evaluation:** Structural `BLOCK` records `structural_blocked = True` and flows through CBM, Threat Intelligence, and Semantic Triage; the verdict is enforced at Score Aggregation / Threshold stage.

### Phase 3: Integration & Validation (PR #161 — TASK-D01, D02, D03, D04)
*   **Delivered as specified:** 6 `pytest-bdd` scenarios (`tests/features/blackwall_gateway.feature` + `tests/step_defs/test_gateway.py`) covering stdio BLOCK (`-32603` + redacted SQLite logging), HTTP BLOCK via `POST /mcp` SSE, the non-loopback auth matrix (valid `Bearer` accepted, missing/invalid → 401, startup guard), and ALLOW forwarding to a mock echo downstream. Resource profiling (`tests/unit/gateway/test_resource_profile.py`, results: `docs/gateway_resource_profile.md`) enforces the MacBook baseline (idle ≤ 60MB, active ≤ 150MB including a real-`SyncResolver`-evaluation measurement, startup < 2s, per-call < 10ms, event-driven idle CPU).
*   **Deviation — deterministic GCP-free BDD harness:** Subprocess E2E tests run `tests/gateway_harness.py` (deterministic BLOCK/ALLOW resolver with redacted SQLite persistence) instead of the full `blackwall serve` stack so CI needs no Vertex AI credentials. Auth scenarios bind alternate ports (9230/9231) to avoid colliding with the specified 9229.
*   **Deviation — `--skip-gcp-check`:** `blackwall serve` accepts a testing/offline escape hatch bypassing GCP credential validation. Production deployments MUST NOT use it; the default remains fail-fast.
*   **Deviation — lazy-load enforcement (NFR-06):** Top-level `blackwall/__init__.py` resolves heavy exports lazily (PEP 562) and `resolver.py` imports `blackwall.config` at the triage call site. Measured cold start improved from 3.04s to 0.89s (budget < 2s).
*   **Addition — pool failure-path hardening:** `AsyncConnectionPool` now closes partially-created connections when `initialize()` fails and drains on `close()` even when uninitialized, fixing a leaked non-daemon `aiosqlite` worker thread that hung process exit on corrupt databases (regression: `tests/db/test_pool_init_failure.py`).

### Phase 4: Documentation & Spec Finalization (TASK-E01)
*   **Delivered as specified:** Canonical `design.md` / `requirements.md` / `tasks.md` with phase-accurate implementation notes; superseded-spec archival verified.
*   **Amendment — Tier-1 Jev harmonization:** The interception sequence, Engine Router stages, Vertex-mode scope, service env capture, and dependency constraints now account for the additive Tier-1 Jev classifier governed by `.kiro/specs/tier-1-jev-addition/` (A/B validated 2026-09-19: 100% parity, AUROC 1.0). Forward-compat notes for unbuilt work: TASK-F04 MUST verify the Jev backend's pure-Python dependency closure packages cleanly, and Phase 6 gains a fifth demo scenario ("The Bouncer") exercising the Jev fast path + Tier-2 escalation.

### Superseded `blackwall-acp-mcp-integration` spec (TASK-E01 AC3)
*   The old spec directory was already removed during the gateway rebaseline (commit `53ad25f`) and is absent from the repository. A repo-wide search confirms the only remaining references are this task's own acceptance text. No further archival action required.

### Phase 6: Demo Scenario Implementation Notes (TASK-G04)
*   **Audit hook execution ahead of TASK-F02:** `scenario_poisoned_package.py` was implemented prior to `TASK-F02` (`blackwall hook install`) and activates `AuditHookManager` (`sys.addaudithook`) directly inside an isolated child Python subprocess (Rule 4), seeding `localhost:8765` and `127.0.0.1:8765` in the ephemeral `blocked_iocs` table so `socket.connect` triggers `PermissionError` alongside `subprocess.Popen` and `os.system`.
*   **Note for future TASK-F02 / TASK-G06:** Because `pip` itself is a Python process that invokes `subprocess.Popen` during package builds, a global `sitecustomize.py` hook that unconditionally blocks `subprocess.Popen` will intercept `pip` before `setup.py` runs unless build subprocesses are scoped or `TASK-G06` invokes the postinstall script directly.

### Phase 6: Demo Scenario Implementation Notes (TASK-G05)
*   **`BW_SEMANTIC_BACKEND` removed (ADR 0009):** The env var `BW_SEMANTIC_BACKEND=jev` referenced in the original TASK-G05 description does not exist in the implemented codebase. Semantic triage is activated via `SyncResolver(..., enable_semantic_triage=True)`. The Jev backend is injected as `resolver._semantic_provider = JevTriageBackend(api_key=..., http_client=httpx.AsyncClient(transport=httpx.MockTransport(...)))`.
*   **P≈0.25 for Act 3 (not P≈0.51):** `P=0.51` is above the ambiguity band ceiling of 0.40 and would trigger the ADR 0009 Clear-High QUARANTINE floor without invoking Tier-2. Act 3 uses `P=0.25` (inside the 0.08–0.40 band), setting `escalate=True` and causing `_maybe_escalate_tier2` to call `GeminiTier2Backend.escalate()`.
*   **Act 1 tool selection:** `get_weather` is used for the benign act (not `database_query`). `database_query` is in `_MEDIUM_RISK_TOOLS` (demo `tool_score=0.6`), and `SELECT` is in `_SUSPICIOUS_KEYWORDS`, causing the aggregate demo-mode score to exceed the 0.10 QUARANTINE threshold even at P=0.02. `get_weather` is unrecognised (demo `tool_score=0.15`) with no suspicious keywords in its args, keeping the aggregate score ≈0.026 (ALLOW).
*   **Tier-2 backend injection:** `resolver._tier2_backend = GeminiTier2Backend(gemini_client)` is set directly to bypass the lazy property constructor (`tier2_backend` builds from `self.client`). The mock `gemini_client` suppresses its `aio.models` attribute to force `asyncio.to_thread` through the synchronous `client.models.generate_content` path.
*   **TSG persistence:** Uses a real `SQLiteThreatRepository` initialised in `tmp_path/bouncer.db`; checked via `resolver._inline_signatures_generated` after `await resolver.flush_background_tasks()` within the same `asyncio.run()` event loop.

### Phase 6: Recording Infrastructure Notes (TASK-G06)
*   **Two recording paths:** `record_demo.sh` prefers `asciinema rec` wrapping a split-pane `tmux` session (left pane = scenario/tool flow, right pane = filtered gateway verdict stream) and falls back to a portable asciinema-v2 `.cast` writer in `scripts/gateway_demo/recording.py` when the terminal tools are absent (headless CI). Both paths emit one `.cast` and one self-contained, XML-escaped SVG thumbnail per scenario into `docs/recordings/`. Every captured line passes through `redact_output()` before serialization so a recording can never leak an operator's real home path or credential-shaped values.
*   **Committed preview assets:** `docs/recordings/*.cast` / `*.svg` are clearly labelled `[PREVIEW]` narrations generated by `python -m scripts.gateway_demo.recording preview --output-dir docs/recordings`; maintainers regenerate live recordings with `record_demo.sh`. They exist so the README thumbnails resolve on GitHub without requiring a recording run at doc-build time.
*   **Honeypot lifecycle deviation:** the master script starts, verifies and stops the honeypot server as its own showcase step *before* the four attack scenarios rather than holding a listener open for the whole run. Every live scenario calls `_ensure_honeypot_port_free()` and deliberately refuses to start if `127.0.0.1:8765` is already served, so a persistent master-owned honeypot would break the suite. Each scenario still owns its own honeypot/gateway subprocesses; the script's session-isolated children and `EXIT`/`INT`/`TERM` traps provide a second cleanup layer.
*   **Test seams:** `BW_DEMO_SCENARIO_RUNNER` substitutes a runner executable for hermetic shell tests; `BW_DEMO_RECORDINGS_DIR` redirects assets to a temp dir; `BW_DEMO_LIVE_RECORD=0|1|auto` forces the portable or live path. Hermetic tests live in `tests/unit/test_gateway_demo_recording.py` and `tests/integration/test_gateway_demo_recording_scripts.py`.
