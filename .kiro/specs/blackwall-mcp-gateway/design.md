# Design Document: Blackwall MCP Gateway

## Overview

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials.

As the AI agent ecosystem converges on the **Model Context Protocol (MCP)** as the standard interface between agents and tools, Blackwall evolves from an environment-injected execution hook into a **Standalone MCP Security Gateway** — a local background daemon that intercepts, evaluates, and governs all MCP tool calls on the developer's machine.

This design document outlines the architecture for deploying Blackwall as an independent, always-on security daemon that any MCP-compliant agent (Antigravity, Warp Terminal, Claude Desktop, Cursor, ADK agents, or any future MCP client) can route tool execution through — transparently, with zero agent-specific coupling.

## Core Architectural Principle

Blackwall runs as a **standalone local daemon** — not a sidecar, not a proxy for a specific agent runtime, not a hosted cloud service. It is a security process on the developer's machine that speaks MCP and governs tool execution.

1.  **The Agent** (e.g., Antigravity, Warp Terminal Agent) sends a `tools/call` JSON-RPC request.
2.  **Blackwall Gateway** receives the request over stdio or Streamable HTTP on `localhost:9229`.
3.  **Blackwall's Engine** (`SyncResolver` pipeline) evaluates the request: Rate Check → Context Hygiene Sanitization → SQLite Threat Signature Graph (TSG) Check → Codebase Memory MCP AST Query → Conditional GTI/VirusTotal Validation (high-risk only) → Score Aggregation → Threshold Verdict.
4.  **ALLOW Verdict:** Blackwall forwards the original payload to the downstream tool server and pipes the response back to the agent.
5.  **BLOCK Verdict:** Blackwall drops the request and synthesizes a valid MCP-compliant JSON-RPC Error response, simulating a tool failure without crashing the agent's execution loop.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Developer's Machine                         │
│                    (2019 MacBook Pro / Intel i7)                    │
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

### 3. Engine Router (SyncResolver Pipeline)
Routes extracted payloads through Blackwall's defenses in a strict, mandatory sequence:
1.  **Rate Check:** Token bucket rate limiter (300+ RPM via GCP Vertex AI paid tier billing credits).
2.  **Context Hygiene Sanitization:** Replace sensitive environment variable patterns with generic placeholders.
3.  **SQLite Threat Signature Graph (FTS5):** Check for structural similarities with known malicious payloads using word-level intersection match quality scoring.
4.  **Codebase Memory MCP:** Run AST query to trace dependency blast radius.
5.  **Google Threat Intelligence (GTI):** Query VirusTotal for external IP/domain indicators — **ONLY** for high-risk events, rate-limited to 4 queries/60s via `GTIQueryBudgetTracker`.
6.  **Score Aggregation:** Weighted composite score from all signals.
7.  **Threshold Verdict:** `≥ 0.20 → BLOCK`, `≥ 0.10 → QUARANTINE`, `< 0.10 → ALLOW`.

### 4. Response Synthesizer
*   **ALLOW Verdict:** Forward the original JSON-RPC request byte-stream to the downstream tool server and pipe the response back to the agent.
*   **BLOCK Verdict:** Drop the request and synthesize a valid JSON-RPC error response, explicitly reusing the incoming request `id`:
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
    *   `--db <path>` (path to SQLite threat graph)
    *   `--foreground` (run in foreground instead of daemonizing)
    *   `--auth-token <token>` (bearer token for non-loopback HTTP; also configurable via `BLACKWALL_AUTH_TOKEN` env var. Required when `--host` is non-loopback; gateway refuses to start without it)
    *   `--log-level debug|info|warning|error`
*   `blackwall init` — initialize `~/.blackwall/` directory
*   `blackwall stop` — stop the running daemon
*   `blackwall status` — show daemon status and recent verdicts
*   `blackwall service install|uninstall|start|stop|status` — manage macOS `launchd` background service (`~/Library/LaunchAgents/com.blackwall.gateway.plist`)
*   `blackwall hook install|uninstall|status` — manage global Python runtime audit hook (`sitecustomize.py` / `.pth`)
*   `blackwall version` — print version

### 8. macOS Background Service Manager (`launchd`)
*   **LaunchAgent Plist Generation:** Automatically installs and manages `~/Library/LaunchAgents/com.blackwall.gateway.plist` for seamless user-session background startup.
*   **Process Supervision:** `launchd` keeps the `blackwall serve --transport http --port 9229` gateway alive continuously across system reboots and user logins, restarting the daemon automatically if terminated unexpectedly.
*   **Logging:** Output streams are directed to `~/.blackwall/blackwall.log` and `~/.blackwall/blackwall.err`.

### 9. Native macOS Menu Bar Application & System Notifications
*   **Menu Bar Tray Application (`Blackwall.app`):** Lightweight native tray application (Swift/SwiftUI or lightweight macOS runner) living in the macOS menu bar.
*   **Visual Status Indicator:**
    *   🟢 **Green Shield**: Gateway daemon active, protected, 0 active threat alerts.
    *   🟡 **Amber Shield**: Suspicious payload quarantined, pending inspection.
    *   🔴 **Red Shield**: Malicious tool call blocked, threat signature generated.
*   **Native System Notifications:** Dispatches macOS native notification banners (via UserNotifications framework) when `SyncResolver` returns a `BLOCK` or `QUARANTINE` verdict, displaying the agent name, trapped tool, and risk score without exposing raw credentials.
*   **One-Click Tool Integrations:** GUI toggles to automatically register Blackwall's MCP gateway endpoint into Google Antigravity, Warp Terminal, Claude Desktop, and Cursor configuration files.

### 10. Global Python Audit Hook Auto-Bootstrap
*   **Zero-Config Hook Registration:** `blackwall hook install` automatically injects a lightweight bootstrap loader into Python's `sitecustomize.py` (or `.pth` file) across active Python virtualenvs and user site-packages.
*   **Transparent Subprocess Protection:** Whenever an AI agent or tool executes a Python script, `sys.addaudithook` is attached immediately before user code runs, preventing rogue scripts from making direct `subprocess.Popen` or `socket.connect` escapes.

### 11. GitHub Release Distribution & `.dmg` Packaging Pipeline
*   **Standalone Bundle:** GitHub Actions CI builds standalone native macOS application bundles (`Blackwall.app`) for both Intel (`x86_64`) and Apple Silicon (`arm64`) architectures.
*   **Installer Packaging:** Packaged into a drag-and-drop `.dmg` disk image installer attached automatically to GitHub Releases for one-click download.

## Defense-in-Depth Layers

Blackwall provides three layers of security, each operating at a different level:

| Layer | Scope | Integration | Day-to-Day on 2019 MacBook? |
|-------|-------|-------------|----------------------------|
| **MCP Gateway** (protocol) | Tool calls from any MCP agent | Agent MCP config → Blackwall | ✅ Yes — Core |
| **Python Audit Hooks** (runtime) | Direct `os.system()`, `subprocess`, file I/O, network | `sys.addaudithook` in Python process | ✅ Yes — Core |
| **eBPF Kernel Probes** (kernel) | Container escapes, kernel syscalls | Enterprise daemon with root privileges | ❌ Portfolio only |

## Resource Constraints (2019 Intel MacBook Pro Baseline)

All gateway components MUST operate within these budgets:

| Resource | Budget | Rationale |
|----------|--------|-----------|
| Idle RAM | ≤ 60MB | Python asyncio daemon + SQLite mmap. No ML models at idle. |
| Active RAM | ≤ 150MB | Peak during SyncResolver eval with GTI query + threat graph scan. |
| Idle CPU | ~0% | Event loop sleeping. Zero polling, zero background threads. |
| Active CPU | < 5% single core | Per-tool-call burst: JSON parse + SQLite FTS5 + context hygiene. Sub-10ms. |
| Disk | ≤ 50MB | SQLite threat graph + policy YAML + PID/log files. |
| Startup | < 2s | Lazy-load heavy modules (GTI client, policy engine) on first call. |

## Quality Assurance (TDD & BDD)

All protocol gateway logic MUST be developed using strict **Test-Driven Development (TDD)**. End-to-end integration flows (simulating rogue agent payloads over MCP) MUST be governed by **Behavior-Driven Development (BDD)** using Gherkin syntax and `pytest-bdd`. No gateway features can be merged without corresponding `.feature` specifications.

## Python Exclusivity & Universal MCP Compatibility

This implementation is 100% Python-based (`asyncio`, `pydantic`, `click`). The gateway operates at the MCP protocol level, ensuring compatibility with **any** MCP-compliant agent — regardless of the agent's implementation language or framework. No Node.js components, no agent-specific coupling.

## GCP Vertex AI Mode (Mandatory)

The gateway requires GCP Vertex AI Mode for the `SyncResolver`'s LLM-based semantic evaluation. Users MUST configure `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` and authenticate via Application Default Credentials (ADC). Google AI Studio API Key Mode is permanently removed.

## Constraints & Assumptions

*   **No Node.js:** The entire gateway stack is Python `asyncio` + `pydantic` + `click`.
*   **Performance:** Gateway overhead MUST remain < 10ms on top of core evaluation latency.
*   **Local-Only Binding:** HTTP transport binds to `127.0.0.1` by default. Network-bound deployments require explicit `--host` override and a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`). The gateway MUST refuse to start on a non-loopback address without a configured auth token.
*   **State Persistence:** SQLite Threat Signature Graph in WAL mode with strict connection pooling. TTL/LFU pruning keeps query latencies under 10ms.
    - Node types: `AttackerIntent`, `PayloadStructure`, `TargetTool`.
    - Edge types: `SIMILAR_TO`, `MITIGATED_BY`.
*   **Hardware Baseline:** All resource budgets target a 2019 MacBook Pro (Intel i7, 16GB RAM). Enterprise features (eBPF, ZeroMQ mesh) are excluded from the resource budget.
