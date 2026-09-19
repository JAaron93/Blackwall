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
│      (Baseline: 2019 MacBook Pro | Top: NVIDIA DGX Spark ARM64)     │
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
1.  **Rate Check:** Token bucket rate limiter (300+ RPM via GCP Vertex AI paid tier billing credits).
2.  **Context Hygiene Sanitization:** Replace sensitive environment variable patterns with generic placeholders.
3.  **SQLite Threat Signature Graph (FTS5):** Check for structural similarities with known malicious payloads using word-level intersection match quality scoring.
4.  **Codebase Memory MCP:** Run AST query to trace dependency blast radius.
5.  **Threat Intelligence (AlienVault OTX):** Query AlienVault OTX for external IP/domain indicators for high-risk events or events carrying external indicators (`SyncResolver` derives `is_high_risk` from structural/CBM signals or indicator presence). Rate-limited to 10,000 queries/hour authenticated (1,000/hour unauthenticated) via token bucket with 3-state circuit breaker (`src/blackwall/threat_intel/otx.py`); served through the SQLite `threat_intel_cache` (≤ 1.0 ms average read, enforced by `tests/unit/threat_intel/test_benchmarks_sla.py`) with a primary + secondary provider cascade in `ThreatIntelOrchestrator`. No VirusTotal code path exists in the current implementation.
6.  **Semantic Triage (pluggable Tier-1 + Tier-2 escalation):** Novel payloads are scored by `SemanticTriageProvider` (`src/blackwall/policy/semantic.py`), currently the Tier-1 Jev decision classifier (`typesafe-ai/jev`, `P(threat)` with `0.35/0.75` ambiguity band) backed by Gemini Tier-2 escalation and async forensic signature synthesis. Governed by `.kiro/specs/tier-1-jev-addition/`; the `gemini` backend is preserved for GCP-only operation.
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
*   `blackwall service install|uninstall|start|stop|status|configure` — manage background daemon service: auto-detects macOS `launchd` (`~/Library/LaunchAgents/com.blackwall.gateway.plist`) or GNU/Linux `systemd` (`~/.config/systemd/user/blackwall.service` or `/etc/systemd/system/blackwall.service` on DGX OS / Ubuntu)
    *   `install` options: `--config <path>` (default: `~/.blackwall/gateway.yaml`), `--wrap <cmd>`, `--project <id>` (or capture active `GCP_PROJECT`), `--system` (Linux system-level unit vs user unit), `--user <name>` (system-service identity), `--credentials <path>` (credentials for direct-root installation)
    *   `configure` options: `--project <id>`, `--credentials <path>`, `--system` (updates `/etc/default/blackwall` and `/etc/blackwall/credentials.json` with permissions `0600` owned by `blackwall:blackwall` on system units, or updates user service environment)
*   `blackwall hook install|uninstall|status` — manage global Python runtime audit hook (`sitecustomize.py` / `.pth`)
*   `blackwall version` — print version

### 8. Cross-Platform Background Service Manager (`launchd` on macOS & `systemd` on Linux/DGX OS)
*   **Platform Auto-Detection:** `blackwall service` detects the host OS at runtime:
    *   **macOS:** Generates and manages `~/Library/LaunchAgents/com.blackwall.gateway.plist` via `launchctl`.
    *   **GNU/Linux (DGX OS / Ubuntu):** Generates and manages `systemd` unit file `blackwall.service` (`~/.config/systemd/user/blackwall.service` or `/etc/systemd/system/blackwall.service` when `--system` is specified) via `systemctl`.
*   **Absolute Path Resolution & Non-Tilde Invariant:** Because systemd `ExecStart` does not execute in a shell and does not perform tilde (`~`) expansion, `blackwall service install` resolves all file paths (configuration, logs, upstream targets, and credential files) to absolute paths at installation time (`Path.resolve()`). No unexpanded `~` characters are permitted in generated service files.
*   **Authoritative Upstream Target & System Paths:** For user services, configuration defaults to `~/.blackwall/gateway.yaml` with state at `~/.blackwall/`. For system services (`--system`), Blackwall uses standard FHS system locations: `/etc/blackwall/gateway.yaml` for configuration, `/run/blackwall/blackwall.pid` for PID management, `/var/log/blackwall/blackwall.log` for logs, and `/var/lib/blackwall/threat_signatures.db` for threat signatures, provisioned via systemd `RuntimeDirectory=blackwall`, `StateDirectory=blackwall`, and `LogsDirectory=blackwall`. The installer explicitly binds these paths in `/etc/blackwall/gateway.yaml` and passes them as explicit arguments in `ExecStart` (`--pidfile /run/blackwall/blackwall.pid --logfile /var/log/blackwall/blackwall.log --db-path /var/lib/blackwall/threat_signatures.db`) along with `Environment="BLACKWALL_DB_PATH=/var/lib/blackwall/threat_signatures.db"`, ensuring that the daemon never attempts to fall back to user home directory paths. On both platforms, the service executes `blackwall serve --foreground --transport http --port 9229 --config <resolved-config-path> --pidfile <resolved-pidfile> --logfile <resolved-logfile> --db <resolved-db>` (or user-specified `--wrap`), ensuring allowed tool requests are deterministically forwarded to defined downstream tool servers while keeping the gateway in the foreground so the service manager directly supervises the active process and the PID file is created upon startup.
*   **Environment Inheritance, Service User & Startup Validation:** Both `launchd` and `systemd` execute outside interactive terminal sessions. `blackwall service install` captures the active `GCP_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_TIER="paid"`, `AI_GATEWAY_API_KEY` (optional; required only when the Tier-1 Jev backend is selected per `.kiro/specs/tier-1-jev-addition/`), and `PATH`, embedding them in the plist `<key>EnvironmentVariables</key>` block on macOS, or the systemd `[Service]` `Environment=` directives on Linux. When installing a system unit (`--system`), the installer derives the non-root execution identity in order: (1) explicit `--user <name>`, (2) `SUDO_USER` if invoked via `sudo`, or (3) dedicated system user `blackwall` (group `blackwall`, created via `useradd --system --home-dir /var/lib/blackwall --create-home blackwall` if absent) when executed directly as root. Running systemd units as root (`User=root`) is strictly barred. If `GOOGLE_APPLICATION_CREDENTIALS` is unset in the environment, the installer inspects the standard user ADC file (`~/.config/gcloud/application_default_credentials.json`), resolving against the derived non-root service user's home directory. In direct root mode with the dedicated `blackwall` user, the installer accepts `--credentials <path>`, copying credentials to `/etc/blackwall/credentials.json` with permissions `0600` owned by `blackwall:blackwall`. For Linux system units (`/etc/systemd/system/blackwall.service`), the unit explicitly defines `User=<derived_user>` and `Group=<derived_group>`, sets `Environment="GOOGLE_APPLICATION_CREDENTIALS=<resolved-path>"`, verifies the designated user has read access, and enforces non-root execution.
*   **Process Supervision & Crash-Loop Throttling:**
    *   **macOS (`launchd`):** Configures `<key>ThrottleInterval</key><integer>30</integer>` and `<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>`, executing `blackwall serve --foreground` so `launchd` directly supervises the process without parent exit.
    *   **Linux (`systemd`):** Configures `StartLimitBurst=5` and `StartLimitIntervalSec=60s` under the `[Unit]` section (where systemd rate limits are defined), and `Type=exec`, `PIDFile=<resolved-pid-file>`, `Restart=on-failure`, `RestartSec=5s`, `MemoryHigh=320M`, and `MemoryMax=350M` under the `[Service]` section (strictly bounding memory to the DGX Spark 350MB host ceiling, while `--foreground` prevents parent-exit tracking issues).
*   **Logging:** Output streams are directed to resolved absolute paths (e.g. `/home/<user>/.blackwall/blackwall.log` for user units or `/var/log/blackwall/blackwall.log` for system units) and the systemd journal on Linux via `journalctl --user -u blackwall` or `journalctl -u blackwall`.

### 9. Native macOS Menu Bar Application & System Notifications
*   **Menu Bar Tray Application (`Blackwall.app`):** Lightweight native tray application (Swift/SwiftUI or lightweight macOS runner) living in the macOS menu bar.
*   **Visual Status Indicator:**
    *   🟢 **Green Shield**: Gateway daemon active, protected, 0 active threat alerts.
    *   🟡 **Amber Shield**: Suspicious payload quarantined, pending inspection.
    *   🔴 **Red Shield**: Malicious tool call blocked, threat signature generated.
*   **Native System Notifications:** Dispatches macOS native notification banners (via UserNotifications framework) when `SyncResolver` returns a `BLOCK` or `QUARANTINE` verdict, displaying the agent name, trapped tool, and risk score without exposing raw credentials.
*   **One-Click Tool Integrations:** GUI toggles to automatically register Blackwall's MCP gateway endpoint into Google Antigravity, Warp Terminal, Claude Desktop, and Cursor configuration files.

### 10. Global Python Audit Hook Auto-Bootstrap
*   **Zero-Config Hook Registration:** `blackwall hook install` automatically injects a lightweight bootstrap loader into Python's `sitecustomize.py` (or `.pth` file) across active Python virtualenvs and user site-packages on both macOS and Linux.
*   **Transparent Subprocess Protection:** Whenever an AI agent or tool executes a Python script, `sys.addaudithook` is attached immediately before user code runs, preventing rogue scripts from making direct `subprocess.Popen` or `socket.connect` escapes.

### 11. Cross-Platform Release Packaging Pipeline (macOS `.dmg` & Linux `.deb` / Tarball)
*   **macOS Packaging (`.dmg`):** GitHub Actions CI builds standalone native macOS application bundles (`Blackwall.app`) for both Intel (`x86_64`) and Apple Silicon (`arm64`) architectures, packaged into drag-and-drop `.dmg` disk image installers.
*   **GNU/Linux Packaging (`.deb` & Standalone Tarball):**
    *   **Debian/Ubuntu Package (`.deb`):** Pre-compiled `.deb` package targeting **DGX OS / Ubuntu 24.04 LTS `aarch64`** (NVIDIA DGX Spark) and **Ubuntu `x86_64`**, bundling the binary (`/usr/bin/blackwall`), default configuration (`/etc/blackwall/gateway.yaml`), environment template (`/etc/default/blackwall`), system-scope systemd service unit (`/lib/systemd/system/blackwall.service` configured with `EnvironmentFile=-/etc/default/blackwall`), optional user unit (`/usr/lib/systemd/user/blackwall.service`), post-install hooks (creating dedicated non-root system identity `blackwall:blackwall` via `useradd --system --home-dir /var/lib/blackwall --create-home --shell /usr/sbin/nologin --user-group blackwall` if absent, setting FHS directory ownership, auto-copying `$SUDO_USER` ADC credentials to `/etc/blackwall/credentials.json` with permissions `0600` when present, populating `/etc/default/blackwall`, and invoking `systemctl daemon-reload`), and man pages for one-command installation (`sudo dpkg -i blackwall-*.deb` or `apt install ./blackwall-*.deb`). On hosts without pre-existing credentials, administrators populate `/etc/default/blackwall` or execute `sudo blackwall service configure --project <id> --credentials <path>` before starting the service.
    *   **Standalone Linux Tarball (`.tar.gz`):** Pre-compiled standalone binary archive with automated `install.sh` script for non-Debian Linux environments.
*   **Windows Strictly Excluded:** Windows (`.exe`, `.msi`, PowerShell) is explicitly unsupported and excluded from CI release pipelines.

### 12. NVIDIA DGX Spark Co-Existence Architecture (Zero-VRAM & Port Isolation)
When operating on the top-of-the-line **NVIDIA DGX Spark** (Grace Blackwell GB10, 20 ARM cores, 128GB unified LPDDR5x memory, DGX OS / Ubuntu 24.04 LTS `aarch64`), Blackwall Core operates with strict co-existence invariants to guarantee zero interference with pre-installed AI workloads:
*   **Zero GPU VRAM Footprint & Host Memory Bounding:** On unified memory architectures where CPU and GPU share the same physical 128GB LPDDR5x memory pool, Blackwall Core strictly guarantees zero CUDA context creation, zero GPU device allocations, and caps its host process RSS memory to ≤350MB (<0.28% of the unified pool). This leaves >127.6GB (>99.7%) of the unified memory strictly available for local LLM inference engines (vLLM, Ollama, TensorRT-LLM) or model fine-tuning jobs. Conformance verification asserts zero CUDA initialization across all layers (no `/dev/nvidia*` file descriptors in `/proc/<daemon_pid>/fd/` resolving daemon PID via `~/.blackwall/blackwall.pid`, `/run/blackwall/blackwall.pid` for system services, or subprocess handle, daemon PID absent from NVML `nvmlDeviceGetComputeRunningProcesses`, `torch.cuda.is_initialized() is False`) and host process RSS ≤ 350MB.
*   **Port Collision Avoidance:** Default gateway port `9229` is specifically selected to avoid collision with standard AI serving and development software on DGX OS:
    *   `11434` — Ollama API / WebUI
    *   `8000` / `8001` / `8002` — vLLM OpenAI-compatible endpoint, Triton Inference Server HTTP/gRPC/Metrics
    *   `8888` / `8080` — JupyterLab, NGC Web Services
*   **Container & Runtime Transparency:** Blackwall's Python audit hooks and MCP stream proxies operate independently of the NVIDIA Container Toolkit (`nvidia-ctk`), Docker daemon, and NVIDIA GPU Operator, ensuring sandboxed agent containers and CUDA IPC communication are never corrupted or throttled.

### 13. MCP Gateway Demo & Showcase Infrastructure
A self-contained, reproducible demo suite demonstrating the MCP Gateway's threat interception capabilities against real-world AI agent attack vectors classified by [OWASP Top 10 for LLMs](https://genai.owasp.org/) and [MITRE ATLAS](https://atlas.mitre.org/).

*   **Local Honeypot Web Server (`scripts/gateway_demo/honeypot_server.py`):** A FastAPI application serving pages designed to look like legitimate library documentation but containing hidden **indirect prompt injection** payloads embedded via:
    *   HTML comments (`<!-- Ignore previous instructions... -->`)
    *   CSS-hidden divs (`<div style="display:none; font-size:0">`)
    *   Zero-width Unicode characters wrapping malicious instructions

    The payloads instruct the consuming agent to: (1) read credential files (`.env`, `~/.config/gcloud/application_default_credentials.json`), then (2) POST the contents to a locally-hosted attacker C2 endpoint (`/exfil`) for demo verification. The honeypot runs entirely on `localhost:8765` with zero external network dependencies.

*   **Four Demo Scenarios:**

    **Scenario 1 — "The Heist" (BLOCK — Indirect Prompt Injection Credential Exfiltration):**
    An AI agent researches a dependency via web search / URL reading through the Blackwall MCP Gateway. The visited page (served by the local honeypot) contains a hidden prompt injection payload. The agent, following the injected instructions, attempts a `tools/call` for `read_file` targeting `.env`, then a `tools/call` for `http_request` POSTing the contents to the attacker's `/exfil` endpoint. The SyncResolver pipeline intercepts: Context Hygiene detects credential patterns, the Threat Signature Graph matches credential-exfiltration tool-call chains, and the composite score exceeds the BLOCK threshold (≥ 0.20). The gateway synthesizes a JSON-RPC `-32603` error with a bounded generic message — zero internal threat reasoning is leaked to the agent.
    *   **Attack Taxonomy:** [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/), [MITRE ATLAS AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

    **Scenario 2 — "The Quarantine" (QUARANTINE + ALLOW — Surgical Tool-Chain Isolation):**
    An agent performs a legitimate refactoring task through the gateway. A mock compromised MCP tool server returns a response containing embedded instructions to also read `~/.ssh/id_rsa` and cloud credentials. The agent attempts: (1) a legitimate `write_file` to update a project module — **ALLOW**, file written successfully; (2) a suspicious `read_file` targeting `~/.ssh/id_rsa` — **BLOCK**, credential-harvesting signature match. The agent's session continues uninterrupted: subsequent legitimate tool calls are ALLOW'd. Demonstrates that Blackwall is **surgical** — it kills only the malicious call, not the entire session.
    *   **Attack Taxonomy:** [OWASP LLM07 — Insecure Plugin Design](https://genai.owasp.org/), [MITRE ATLAS AML.T0054 — LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)

    **Scenario 3 — "The Poisoned Package" (BLOCK via Python Audit Hook — Supply Chain Defense-in-Depth):**
    An agent installs a package whose `postinstall` script attempts runtime escapes: `subprocess.Popen` opening a network connection to an attacker C2 server, `os.system` executing credential reads, and direct `socket.connect` to exfiltrate harvested data. The MCP Gateway ALLOW's the initial `run_command` for `pip install`, but the Python audit hook (`sys.addaudithook`, bootstrapped via `blackwall hook install`) fires during script execution, intercepting the `subprocess.Popen` and `socket.connect` audit events and raising `PermissionError`. Demonstrates **defense-in-depth**: even when a tool call passes protocol-level interception, runtime audit hooks provide a second layer of protection against in-process escapes.
    *   **Attack Taxonomy:** [OWASP LLM05 — Supply Chain Vulnerabilities](https://genai.owasp.org/), [MITRE ATLAS AML.T0049 — Exploit ML Supply Chain](https://atlas.mitre.org/techniques/AML.T0049)

    **Scenario 4 — "The Bouncer" (Tier-1 Jev Fast Path + Tier-2 Escalation):**
    A three-act demo of the additive triage architecture (governed by `.kiro/specs/tier-1-jev-addition/`): (1) a benign parameterized query is ALLOW'd on the Jev fast path (`P≈0.02`, no Tier-2 spend); (2) an obfuscated SQL injection is BLOCK'd on the fast path (`P≈0.98`); (3) an ambiguous C2-beacon-like probe lands in the escalation band (`P≈0.5`) and is handed to Gemini Tier-2 for the final verdict, followed by async signature synthesis. Demonstrates cost discipline — expensive reasoning fires only where judgment exists.
    *   **Attack Taxonomy:** [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/), [MITRE ATLAS AML.T0051 — LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)

*   **Recording Infrastructure (`scripts/gateway_demo/record_demo.sh`):** Orchestration script producing `asciinema` terminal recordings in split-pane tmux format:
    *   **Left Pane:** Agent conversation / tool call flow with verdicts
    *   **Right Pane:** Blackwall gateway live logs (threat scores, signature matches, verdicts highlighted in color)
    *   Output: `.cast` files in `docs/recordings/` convertible to GIF/SVG via `agg` (asciinema GIF generator) for README embedding
    *   Optional "without Blackwall" comparison clip showing the same attack succeeding against an unprotected agent

## Defense-in-Depth Layers

Blackwall provides three layers of security, each operating at a different level:

| Layer | Scope | Integration | Target Hardware Support |
|-------|-------|-------------|-------------------------|
| **MCP Gateway** (protocol) | Tool calls from any MCP agent | Agent MCP config → Blackwall | ✅ Yes — Core (MacBook Baseline & DGX Spark) |
| **Python Audit Hooks** (runtime) | Direct `os.system()`, `subprocess`, file I/O, network | `sys.addaudithook` in Python process | ✅ Yes — Core (MacBook Baseline & DGX Spark) |
| **eBPF Kernel Probes** (kernel) | Container escapes, kernel syscalls | Enterprise daemon with root privileges | ❌ Portfolio only (Enterprise Mesh) |

## Resource Constraints (Dual Hardware Target Tiers)

All gateway components MUST operate within these hardware budgets:

| Metric | 2019 MacBook Pro Baseline (Intel i7, 16GB) | NVIDIA DGX Spark Top-of-the-Line (GB10 ARM64, 128GB) | Enforcement / Rationale |
| :--- | :--- | :--- | :--- |
| **Idle RAM** | ≤ 60MB | ≤ 100MB | Event loop sleeping. Zero background ML models loaded at idle. |
| **Active RAM** | ≤ 150MB | ≤ 350MB | Peak during SyncResolver eval + concurrent multi-agent batch queries. |
| **GPU VRAM** | 0MB (N/A) | **0MB CUDA / host RSS ≤ 350MB** | **Strict Invariant**: 0MB allocated in CUDA contexts; host RSS capped to ≤350MB (<0.28%), leaving >127.6GB (>99.7%) unified memory for local LLMs/training. |
| **Idle CPU** | ~0% | ~0% | Asyncio event loop sleep. Zero polling. |
| **Active CPU** | < 5% single core | < 2% across 20 ARM cores | Sub-10ms evaluation burst (JSON parse + FTS5 + hygiene). |
| **Disk** | ≤ 50MB | ≤ 50MB | SQLite threat graph + policy YAML + logs. |
| **Startup** | < 2s | < 1s | Lazy-load heavy dependencies (GTI client, policy engine) on first call. |

## Quality Assurance (TDD & BDD)

All protocol gateway logic MUST be developed using strict **Test-Driven Development (TDD)**. End-to-end integration flows (simulating rogue agent payloads over MCP) MUST be governed by **Behavior-Driven Development (BDD)** using Gherkin syntax and `pytest-bdd`. No gateway features can be merged without corresponding `.feature` specifications.

## Python Exclusivity & Universal MCP Compatibility

This implementation is 100% Python-based (`asyncio`, `pydantic`, `click`). The gateway operates at the MCP protocol level, ensuring compatibility with **any** MCP-compliant agent — regardless of the agent's implementation language or framework. No Node.js components, no agent-specific coupling.

## GCP Vertex AI Mode (Mandatory for Tier-2, Forensics & Evaluation)

The gateway requires GCP Vertex AI Mode for the `SyncResolver`'s Tier-2 deep-reasoning escalation, async forensic signature synthesis, and Agent-as-a-Judge evaluation. Users MUST configure `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` and authenticate via Application Default Credentials (ADC). Google AI Studio API Key Mode is permanently removed.

Tier-1 semantic triage may instead run on the Jev classifier via paid Vercel AI Gateway credits (see `.kiro/specs/tier-1-jev-addition/`), which requires `AI_GATEWAY_API_KEY` rather than Vertex — but Vertex remains mandatory overall because Tier-2, forensics, and the eval harness cannot run without it.

## Constraints & Assumptions

*   **No Node.js:** The entire gateway stack is Python `asyncio` + `pydantic` + `click`. Semantic triage backends (including Tier-1 Jev per `.kiro/specs/tier-1-jev-addition/`) MUST be pure-Python pip-installable clients — no Node.js sidecars — so the Phase 5 packaging pipeline inherits a clean dependency closure.
*   **Operating System Scope & Explicit Windows Exclusion:** Supported platforms are **macOS** (Darwin `x86_64`, `arm64`) and **GNU/Linux** (**DGX OS / Ubuntu 24.04 LTS `aarch64`** on NVIDIA DGX Spark, and Debian/Ubuntu `x86_64`). **Windows is strictly unsupported** — no Windows releases, no PowerShell/MSI installers, and zero maintenance overhead.
*   **Dual Hardware Target Profiles:**
    - **Baseline**: 2019 MacBook Pro (Intel i7, 16GB RAM) prioritizing strict resource conservation and low-power battery efficiency.
    - **Top-of-the-Line**: NVIDIA DGX Spark (NVIDIA GB10 Grace Blackwell, 20 ARM cores, 128GB unified memory) delivering high-throughput concurrent agent security with zero CUDA device allocation and strictly bounded host RSS (≤350MB), preserving >99.7% of unified memory for AI models.
*   **Performance:** Gateway overhead MUST remain < 10ms on top of core evaluation latency.
*   **Local-Only Binding:** HTTP transport binds to `127.0.0.1` by default. Network-bound deployments require explicit `--host` override and a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`). The gateway MUST refuse to start on a non-loopback address without a configured auth token.
*   **State Persistence:** SQLite Threat Signature Graph in WAL mode with strict connection pooling. TTL/LFU pruning keeps query latencies under 10ms.
    - Node types: `AttackerIntent`, `PayloadStructure`, `TargetTool`.
    - Edge types: `SIMILAR_TO`, `MITIGATED_BY`.

## Implementation Notes & Deviations (Phases 1–4, finalized under TASK-E01)

This section records where the shipped implementation (PRs #159, #160, #161) intentionally differs from or extends the original design. Phase 4 (spec finalization, TASK-E01) is complete. Phase 5 (service packaging) and Phase 6 (demo showcase) remain future work and are unaffected, except for the forward-compatibility notes below.

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
*   **Amendment — Tier-1 Jev harmonization:** The interception sequence, Engine Router stages, Vertex-mode scope, service env capture, and dependency constraints now account for the additive Tier-1 Jev classifier governed by `.kiro/specs/tier-1-jev-addition/` (A/B validated 2026-09-19: 100% parity, AUROC 1.0). Forward-compat notes for unbuilt work: TASK-F04 MUST verify the Jev backend's pure-Python dependency closure packages cleanly, and Phase 6 gains a fourth demo scenario ("The Bouncer") exercising the Jev fast path + Tier-2 escalation.

### Superseded `blackwall-acp-mcp-integration` spec (TASK-E01 AC3)
*   The old spec directory was already removed during the gateway rebaseline (commit `53ad25f`) and is absent from the repository. A repo-wide search confirms the only remaining references are this task's own acceptance text. No further archival action required.
