# Requirements Document: Blackwall MCP Gateway

## Introduction

Blackwall is an autonomous Agentic Security Firewall. To achieve universal portability across the AI agent ecosystem, Blackwall operates as a **standalone MCP Security Gateway** — a local background daemon that intercepts MCP protocol traffic, evaluates tool calls against its threat intelligence engine, and enforces security verdicts transparently.

The goal is to allow **any MCP-compliant agent** — Antigravity, Warp Terminal, Claude Desktop, Cursor, ADK agents, or any future MCP client — to route tool executions through Blackwall securely and transparently. Blackwall intercepts JSON-RPC protocol payloads, evaluates them using the `SyncResolver` pipeline (structural and semantic gating), and returns synthesized errors for blocked actions — all while remaining entirely Python-exclusive and operating within the resource constraints of a 2019 Intel MacBook Pro.

## Glossary

*   **MCP (Model Context Protocol):** An open standard JSON-RPC protocol standardizing how AI models and agents communicate with external tools and data sources.
*   **MCP Gateway:** The Blackwall daemon that sits between MCP clients (agents) and downstream tool servers, intercepting and governing tool execution traffic.
*   **Downstream Tool Server:** An MCP-compliant tool server (e.g., filesystem, GitHub, shell) that Blackwall protects by intercepting tool calls before they reach it.
*   **JSON-RPC Synthesizer:** The Blackwall component responsible for translating firewall BLOCK verdicts into protocol-compliant JSON-RPC error responses.
*   **SyncResolver Pipeline:** Blackwall's core evaluation engine that processes tool calls through threat graph matching, context hygiene, policy evaluation, and optional GTI validation.
*   **Wrap Mode:** A gateway deployment mode where Blackwall spawns and manages a single downstream tool server as a child process.

## Functional Requirements

### FR-01: MCP Protocol Gateway Server (Python)
Blackwall MUST implement a standalone `asyncio`-based server capable of receiving, parsing, and routing JSON-RPC 2.0 messages conforming to the MCP specification. No Node.js components are permitted.

### FR-02: Transport Layer Support
The gateway MUST support two primary transport methods for agent communication:
1.  **stdio:** Intercepting standard input/output streams for local CLI agents and IDE integrations (e.g., Antigravity MCP config).
2.  **MCP Streamable HTTP (POST + SSE):** Intercepting network-bound tool requests via a POST `/mcp` endpoint on `localhost:9229`. Responses and events return asynchronously over the established SSE channel.
    *   **Transport Security (Mandatory):** The HTTP endpoint MUST validate `Origin` and `Host` headers to prevent DNS rebinding attacks. Local deployments MUST bind to loopback interfaces only (`127.0.0.1`). When binding to a non-loopback address (via `--host`), the gateway MUST require a pre-shared bearer token configured via `--auth-token <token>` flag or `BLACKWALL_AUTH_TOKEN` environment variable. All inbound requests MUST include a valid `Authorization: Bearer <token>` header; requests without a valid token MUST be rejected with HTTP 401 before JSON-RPC processing. If `--host` specifies a non-loopback address and no auth token is configured, the gateway MUST refuse to start with a clear error message.

### FR-03: Message Interception & Payload Extraction
When an agent sends a `tools/call` request, Blackwall MUST pause the stream, extract the tool `name` and `arguments`, and pass them through the `ContextResolver` to replace sensitive values with generic placeholders before `SyncResolver` evaluation. The redacted payload MUST then be formatted into a `ToolCallContext` compatible with the existing `SyncResolver` pipeline. The original sensitive payload MUST NOT be forwarded during policy evaluation.

Non-tool methods (`initialize`, `notifications/*`, `tools/list`) MUST be passed through to the downstream tool server unchanged.

### FR-04: Verdict Enforcement via Protocol Synthesis
*   **ALLOW:** If the `SyncResolver` returns an ALLOW verdict, the original JSON-RPC payload MUST be passed cleanly to the downstream tool server, and its response piped back to the agent.
*   **BLOCK:** If a BLOCK verdict is reached, Blackwall MUST NOT forward the request. It MUST synthesize an MCP-compliant JSON-RPC Error object (Error Code `-32603`). The error MUST be bounded and generic (e.g., "Blackwall Firewall: Execution blocked"), without exposing internal threat reasoning or redacted context. The synthesizer MUST extract and reuse the incoming JSON-RPC request `id`.
*   **QUARANTINE:** If a QUARANTINE verdict is reached, Blackwall MUST synthesize a JSON-RPC Error with a distinct error code (`-32001`) and log the event for manual review.

The synthesizer MUST reject `ALLOW` inputs and raise an exception if incorrectly invoked for allowed verdicts.

### FR-05: Threat Signature Logging
All blocked protocol payloads MUST be redacted (credentials, secrets, PII removed) before being logged into the embedded SQLite Threat Signature Graph. Detailed threat reasoning MUST be restricted to protected local diagnostics (structured logs, audit trails) and MUST NOT be included in the error response returned to the agent.

### FR-06: CLI Entry Point
Blackwall MUST provide a `blackwall` CLI command (via `[project.scripts]` in `pyproject.toml`) with the following subcommands:
*   `blackwall serve` — Start the gateway daemon (background by default, `--foreground` for terminal mode).
*   `blackwall init` — Initialize `~/.blackwall/` directory with default policy, empty threat DB, and starter gateway config.
*   `blackwall stop` — Stop the running daemon via PID file.
*   `blackwall status` — Report daemon liveness, threat graph statistics, and recent verdict summary.
*   `blackwall version` — Print the installed version.

### FR-07: Upstream Tool Server Management
The gateway MUST support two modes for managing downstream tool servers:
1.  **Wrap Mode (`--wrap <command>`):** Spawn a single downstream MCP tool server as a stdio child process. Blackwall manages the process lifecycle (start, health check, graceful shutdown).
2.  **Multi-Server Mode (`--config <path>`):** Read a `gateway.yaml` configuration file listing multiple downstream tool servers (stdio or HTTP). Blackwall manages all listed servers and routes tool calls to the appropriate downstream target based on tool name registration.

### FR-08: Background Daemon with PID File Management
*   `blackwall serve` MUST daemonize the process by default, writing the PID to `~/.blackwall/blackwall.pid` and redirecting output to `~/.blackwall/blackwall.log`.
*   `blackwall serve --foreground` MUST run in the terminal with live log output to stdout/stderr.
*   `blackwall stop` MUST read the PID file, send `SIGTERM`, verify process termination, and clean up the PID file.
*   The daemon MUST handle `SIGTERM` and `SIGINT` gracefully, flushing pending evaluations and closing SQLite connections before exit.

### FR-09: GCP Vertex AI Mode (Mandatory)
The gateway MUST require GCP Vertex AI Mode for the `SyncResolver`'s LLM-based semantic evaluation. Configuration requires `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` and Application Default Credentials (ADC). Google AI Studio API Key Mode is permanently removed. The gateway MUST fail fast with a clear error message if GCP credentials are not configured.

### FR-10: Cross-Platform Background Service Management (`launchd` on macOS & `systemd` on Linux/DGX OS)
Blackwall MUST provide CLI and programmatic subcommands (`blackwall service install|uninstall|start|stop|status`) that auto-detect the operating system and manage native background daemon services:
*   **macOS (`launchd`):** Generates and manages `~/Library/LaunchAgents/com.blackwall.gateway.plist` via `launchctl`.
*   **GNU/Linux (`systemd`):** Generates and manages `blackwall.service` (`~/.config/systemd/user/blackwall.service` or `/etc/systemd/system/blackwall.service` when `--system` is provided) via `systemctl`.
*   **Absolute Path Resolution & Non-Tilde Invariant:** Because systemd `ExecStart` does not execute in a shell and does not perform tilde (`~`) expansion, `blackwall service install` MUST resolve all configuration paths, log file locations, upstream targets, and credential paths to absolute filesystem paths (`Path.resolve()`). Raw `~` characters MUST NOT appear in generated service definitions.
*   **Authoritative Upstream Target:** On both platforms, `install` MUST configure the service to supervise `blackwall serve --transport http --port 9229 --config <resolved-absolute-config-path>` (or user-specified `--wrap <cmd>`), ensuring allowed tool requests are deterministically forwarded to downstream tool servers.
*   **Install-Time Credential Validation:** `install` MUST validate that `GCP_PROJECT` (or `GOOGLE_CLOUD_PROJECT`) is configured, failing fast with an exit code != 0 and a clear error message if absent.
*   **Environment Variable Injection & Service User:** `install` MUST embed active GCP environment variables (`GCP_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_TIER="paid"`, `PATH`) into the plist's `EnvironmentVariables` dictionary on macOS, or the systemd `[Service]` `Environment=` directives on Linux. When `--system` is specified on Linux, the generated service MUST configure `User=` and `Group=` (defaulting to the invoking non-root user via `SUDO_USER` or explicit `--user <name>`), verify the user has read permissions to `GOOGLE_APPLICATION_CREDENTIALS`, and avoid running as root.
*   **Supervision & Throttling:**
    *   macOS plist MUST configure `RunAtLoad=true`, `KeepAlive` with `SuccessfulExit=false`, and `ThrottleInterval=30`.
    *   Linux systemd unit MUST configure `StartLimitBurst=5` and `StartLimitIntervalSec=60s` under the `[Unit]` section, and `Restart=on-failure`, `RestartSec=5s`, and `MemoryMax=500M` under the `[Service]` section.
*   `start`, `stop`, and `status` MUST invoke platform-native tools (`launchctl` or `systemctl`).
*   `uninstall` MUST unload the service and remove the service configuration file cleanly.

### FR-11: Native macOS Menu Bar GUI & System Notifications
Blackwall MUST support packaging as a native macOS Menu Bar application (`Blackwall.app`):
*   Display a menu bar status icon reflecting real-time protection state (Green = Protected, Amber = Quarantined, Red = Threat Blocked).
*   Dispatch native macOS UserNotifications banners upon `BLOCK` or `QUARANTINE` verdicts, presenting the triggering tool and severity while sanitizing credentials.
*   Provide a GUI menu showing daemon liveness, threat signature graph count, and one-click MCP registration for Antigravity, Warp Terminal, Claude Desktop, and Cursor.

### FR-12: Global Python Audit Hook Bootstrapping
Blackwall MUST provide subcommands (`blackwall hook install|uninstall|status`) to manage global Python runtime audit hook integration across macOS and Linux:
*   `install` MUST inject a non-destructive bootstrap snippet into `sitecustomize.py` (or a `.pth` file) in target Python environments.
*   The bootstrap snippet MUST attach Blackwall's `sys.addaudithook` before arbitrary user scripts execute.
*   `uninstall` MUST remove the bootstrap code cleanly without affecting existing `sitecustomize.py` customizations.

### FR-13: Cross-Platform Release Packaging Pipeline (macOS `.dmg` & Linux `.deb` / Tarball)
The build and CI pipeline MUST produce standalone release artifacts attached to GitHub Releases:
*   **macOS:** Standalone disk image installers (`.dmg`) containing `Blackwall.app` for both Intel (`x86_64`) and Apple Silicon (`arm64`).
*   **GNU/Linux:**
    *   Debian/Ubuntu packages (`.deb`) targeting **DGX OS / Ubuntu 24.04 LTS `aarch64`** (NVIDIA DGX Spark) and Ubuntu `x86_64`, bundling binary, default configuration, systemd unit, and man pages for single-command installation (`sudo dpkg -i blackwall-*.deb` or `apt install ./blackwall-*.deb`).
    *   Standalone Linux binary tarballs (`.tar.gz`) with automated `install.sh` scripts.
*   **Windows Strictly Excluded:** Windows formats (`.exe`, `.msi`, PowerShell) are explicitly excluded from all release workflows.

### FR-14: NVIDIA DGX Stack Co-Existence & Zero-VRAM Footprint
When deployed on the top-of-the-line **NVIDIA DGX Spark** (DGX OS / Ubuntu 24.04 LTS `aarch64`), Blackwall Core MUST guarantee complete non-interference with the pre-installed NVIDIA AI stack:
*   **Zero GPU VRAM Reservation & Host Memory Ceiling:** On unified memory architectures where CPU and GPU share the same 128GB LPDDR5x pool, Blackwall Core MUST run 100% in CPU user-space threads without initializing a CUDA runtime/driver context (`torch.cuda.is_initialized()` is False), and its host process RSS memory MUST NOT exceed 350MB (<0.28% of the unified pool). This strictly preserves >127.6GB (>99.7%) of unified memory for local LLM weights (vLLM, Ollama, TensorRT-LLM) and training workloads. Conformance testing MUST assert both zero CUDA context allocation and that host process RSS remains strictly capped under load.
*   **Port Collision Avoidance:** Default gateway port `9229` MUST NOT collide with standard DGX OS AI serving ports: `11434` (Ollama), `8000`/`8001`/`8002` (vLLM, Triton), or `8888` (JupyterLab).
*   **Container & Driver Transparency:** Blackwall's stream layer and Python audit hooks MUST operate transparently alongside Docker, `nvidia-container-toolkit` (`nvidia-ctk`), and CUDA IPC without intercepting or degrading GPU tensor operations.

## Non-Functional Requirements

### NFR-01: Zero Non-Python Dependencies
Blackwall Core MUST remain 100% Python-based (`asyncio`, `pydantic`, `click`). No Node.js, no Rust extensions required for Core functionality. The gateway MUST be installable via `pip install blackwall` or native `.deb` package.

### NFR-02: Latency Constraints
The serialization, parsing, and proxying of JSON-RPC messages MUST add no more than 10ms of overhead to the baseline `SyncResolver` evaluation latency (which is < 10ms for structural evaluation).

### NFR-03: Agent Agnosticism
The gateway MUST NOT contain hardcoded rules specific to any particular agent (Antigravity, Warp, Claude, Cursor, etc.). It MUST adhere strictly to the MCP specification, ensuring compatibility with any MCP-compliant client.

### NFR-04: Test-Driven Development (TDD)
All implementation tasks MUST follow strict TDD. Developers MUST write failing unit tests or reproduction commands before generating the minimum code required to pass the test.

### NFR-05: Behavior-Driven Development (BDD)
End-to-end security and interception workflows MUST be defined using Gherkin syntax in `.feature` files. Execution MUST be validated using `pytest-bdd`.

### NFR-06: Resource Constraints (Dual Hardware Target Tiers)
All gateway components MUST operate within these budgets across supported hardware profiles:

| Resource | 2019 MacBook Pro Baseline (Intel i7, 16GB) | NVIDIA DGX Spark Top-of-the-Line (GB10 ARM64, 128GB) | Enforcement |
| :--- | :--- | :--- | :--- |
| **Idle RAM** | ≤ 60MB | ≤ 100MB | Lazy-load heavy modules on first tool call |
| **Active RAM** | ≤ 150MB | ≤ 350MB | Peak during SyncResolver + GTI evaluation |
| **GPU VRAM** | 0MB (N/A) | **0MB CUDA / host RSS ≤ 350MB** | Zero CUDA context; host RSS capped to ≤350MB, leaving >127.6GB (>99.7%) unified memory free |
| **Idle CPU** | ~0% | ~0% | Event loop sleeping, no polling or background threads |
| **Active CPU** | < 5% single core | < 2% across 20 ARM cores | Sub-10ms burst per tool call |
| **Disk** | ≤ 50MB | ≤ 50MB | SQLite + policy + logs |
| **Startup** | < 2s | < 1s | Deferred initialization |

### NFR-07: Operating System Support & Windows Exclusion
Blackwall Core MUST support:
1. **macOS** (Darwin `x86_64` and `arm64`).
2. **GNU/Linux** (**DGX OS / Ubuntu 24.04 LTS `aarch64`** on NVIDIA DGX Spark, and Debian/Ubuntu `x86_64`).
**Windows is strictly and permanently unsupported.** No Windows installers, services, or documentation shall be produced or maintained.

## User Stories

### US-01: Transparent Security for AI-Powered Development
**As a developer using AI-powered tools (Antigravity, Warp Terminal, etc.),**
I want to route my tools through Blackwall's local gateway,
**So that** rogue agent actions are blocked before they reach my OS without requiring me to maintain complex whitelists or blacklists.

### US-02: Graceful Agent Failure on Block
**As an MCP-compliant AI agent,**
I want to receive standard JSON-RPC error messages when my tool call is denied by the firewall,
**So that** my execution loop does not crash, and I can prompt the LLM to reflect on the failure and try a different, safer approach.

### US-03: Python Exclusivity for Maintainers
**As the lead maintainer of Blackwall,**
I want the entire gateway to be built in Python (`asyncio`, `pydantic`, `click`),
**So that** I don't have to manage multiple runtime environments when deploying the firewall.

### US-04: Lightweight Local Daemon
**As a developer running a 2019 MacBook Pro,**
I want Blackwall to run as a background daemon that uses minimal CPU and memory when idle,
**So that** I can keep it always-on without impacting my development workflow or machine performance.

### US-05: Simple Initial Setup
**As a first-time Blackwall user,**
I want to run `blackwall init` and `blackwall serve --wrap <my-tool-server>` to get started,
**So that** I can protect my tools within minutes without reading extensive documentation.

### US-06: Frictionless Menu Bar Management
**As a macOS developer,**
I want Blackwall to run unobtrusively in my menu bar and start automatically on login via `launchd`,
**So that** I am protected continuously and notified immediately with native banners whenever rogue actions are intercepted.

### US-07: Downloadable GitHub Release App
**As a developer setting up a new Mac,**
I want to download a pre-built `Blackwall.dmg` directly from GitHub Releases,
**So that** I can install and run Blackwall with a single drag-and-drop without manually configuring Python environments.

### US-08: High-Throughput Protection on NVIDIA DGX Spark
**As an AI researcher running an NVIDIA DGX Spark AI supercomputer,**
I want Blackwall Core to run as a native `systemd` daemon on DGX OS (`aarch64`) with zero CUDA allocation and strictly bounded host RSS (≤350MB),
**So that** my multi-agent development workflows are secured at wire speed while preserving >99.7% (>127.6GB) of unified memory and all tensor cores for local LLM serving and model fine-tuning.

### US-09: Native Linux Package Installation (`.deb`)
**As a DGX OS / Ubuntu Linux user,**
I want to install Blackwall via `sudo dpkg -i blackwall-*.deb` or `apt install ./blackwall-*.deb`,
**So that** the executable, systemd unit, and default configuration are pre-installed and ready to run with zero manual configuration.
