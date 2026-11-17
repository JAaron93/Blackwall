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
*   `blackwall serve` MUST accept `--pidfile <path>`, `--logfile <path>`, and `--db <path>` (aliased to `--db-path`) to override default paths for systemd system services and multi-tenant environments.
*   Whenever `--pidfile <path>` is supplied (including in `--foreground` mode under system supervisors like systemd), `blackwall serve` MUST write its active process PID to the specified file upon startup and remove it upon process termination.
*   `blackwall serve --foreground` MUST run in the terminal or service supervisor without daemon forking, logging live output to stdout/stderr (or `--logfile` if specified) while honoring `--pidfile` when provided.
*   `blackwall stop` MUST read the PID file (supporting `--pidfile <path>`), send `SIGTERM`, verify process termination, and clean up the PID file.
*   The daemon MUST handle `SIGTERM` and `SIGINT` gracefully, flushing pending evaluations and closing SQLite connections before exit.

### FR-09: GCP Vertex AI Mode (Mandatory for Tier-2, Forensics & Evaluation)
The gateway MUST require GCP Vertex AI Mode for Tier-2 deep-reasoning escalation, async forensic signature synthesis, and Agent-as-a-Judge evaluation. Configuration requires `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` and Application Default Credentials (ADC). Google AI Studio API Key Mode is permanently removed. The gateway MUST fail fast with a clear error message if GCP credentials are not configured. Tier-1 semantic triage MAY run on the Jev classifier via the official TypeSafe AI API on paid per-token billing (`TYPESAFE_API_KEY`, governed by `.kiro/specs/tier-1-jev-addition/` and ADR 0008), but this never waives the Vertex requirement.

### FR-10: macOS Background Service Management (`launchd` LaunchAgent)
Blackwall MUST provide CLI and programmatic subcommands (`blackwall service install|uninstall|start|stop|status|configure`) that manage native macOS background daemon services via `launchd`:
*   **macOS (`launchd`):** Generates and manages `~/Library/LaunchAgents/com.blackwall.gateway.plist` via `launchctl`.
*   **Absolute Path Resolution & Non-Tilde Invariant:** `blackwall service install` MUST resolve all configuration paths, log file locations, upstream targets, and credential paths to absolute filesystem paths (`Path.resolve()`). Raw `~` characters MUST NOT appear in generated plist service definitions.
*   **Authoritative Upstream Target & Paths:** Configuration defaults to `~/.blackwall/gateway.yaml` with state at `~/.blackwall/`. The service MUST execute `blackwall serve --foreground --transport http --port 9229 --config <resolved-config-path> --pidfile <resolved-pidfile> --logfile <resolved-logfile> --db <resolved-db>` (or user-specified `--wrap <cmd>`), ensuring allowed tool requests are deterministically forwarded to downstream tool servers and the PID file is created upon startup in foreground mode so `launchd` directly supervises the active process.
*   **Install-Time Credential Validation & ADC Fallback:** `install` MUST validate that `GCP_PROJECT` (or `GOOGLE_CLOUD_PROJECT`) is configured, failing fast with an exit code != 0 if absent. If `GOOGLE_APPLICATION_CREDENTIALS` is unset in the environment, `install` MUST inspect the standard user Application Default Credentials path (`~/.config/gcloud/application_default_credentials.json`) and inject the resolved absolute path into the plist `EnvironmentVariables`. If credentials cannot be resolved, `install` MUST fail fast with an actionable error.
*   **Environment Variable Injection:** `install` MUST embed active GCP environment variables (`GCP_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_TIER="paid"`, `PATH`) into the plist's `EnvironmentVariables` dictionary. Bearer secret *values* (notably `TYPESAFE_API_KEY`) MUST NEVER appear inline in plist definitions or logs: when the Tier-1 Jev backend is selected (see `.kiro/specs/tier-1-jev-addition/`), `install` MUST persist a present `TYPESAFE_API_KEY` exclusively to a `0600` env file — `~/.blackwall/gateway.env` — loaded by the daemon at startup via dotenv loading. `configure --typesafe-key <key>` MUST provision the same file.
*   **Supervision & Throttling:** macOS plist MUST execute `blackwall serve --foreground` and configure `RunAtLoad=true`, `KeepAlive` with `SuccessfulExit=false`, and `ThrottleInterval=30`.
*   `start`, `stop`, and `status` MUST invoke `launchctl`.
*   `configure` MUST support setting cloud project identifiers and credential paths (`--project <id>`, `--credentials <path>`).
*   `uninstall` MUST unload the service via `launchctl` and remove `~/Library/LaunchAgents/com.blackwall.gateway.plist` cleanly.

### FR-11: Native macOS Menu Bar GUI & System Notifications
Blackwall MUST support packaging as a native macOS Menu Bar application (`Blackwall.app`):
*   Display a menu bar status icon reflecting real-time protection state (Green = Protected, Amber = Quarantined, Red = Threat Blocked).
*   Dispatch native macOS UserNotifications banners upon `BLOCK` or `QUARANTINE` verdicts, presenting the triggering tool and severity while sanitizing credentials.
*   Provide a GUI menu showing daemon liveness, threat signature graph count, and one-click MCP registration for Antigravity, Warp Terminal, Claude Desktop, and Cursor.

### FR-12: Global Python Audit Hook Bootstrapping
Blackwall MUST provide subcommands (`blackwall hook install|uninstall|status`) to manage global Python runtime audit hook integration across macOS (Apple Silicon `arm64` and Intel `x86_64`):
*   `install` MUST inject a non-destructive bootstrap snippet into `sitecustomize.py` (or a `.pth` file) in target Python environments.
*   The bootstrap snippet MUST attach Blackwall's `sys.addaudithook` before arbitrary user scripts execute.
*   `uninstall` MUST remove the bootstrap code cleanly without affecting existing `sitecustomize.py` customizations.

### FR-13: macOS Release Packaging Pipeline (`.dmg` for Apple Silicon & Intel)
The build and CI pipeline MUST produce standalone macOS release artifacts attached to GitHub Releases:
*   **macOS:** Standalone disk image installers (`.dmg`) containing `Blackwall.app` for both Intel (`x86_64`) and Apple Silicon (`arm64`), producing `Blackwall-Intel.dmg` and `Blackwall-AppleSilicon.dmg` respectively.
*   **Windows Strictly Excluded:** Windows formats (`.exe`, `.msi`, PowerShell) are explicitly excluded from all release workflows.

### FR-14: Apple Silicon High-End & Intel Baseline Architecture (Zero-GPU Footprint & Unified Memory Efficiency)
When deployed on the top-of-the-line **Apple Silicon MacBook Pro** (M-Series ARM64: M1/M2/M3/M4 Pro/Max, up to 128GB unified memory, macOS), Blackwall Core MUST guarantee complete non-interference with developer workloads and local AI models:
*   **Zero GPU / Metal / ANE Footprint & Host Memory Ceiling:** On Apple Silicon unified memory architectures where CPU, GPU cores, and Apple Neural Engine share the same physical memory pool, Blackwall Core MUST run 100% in CPU user-space threads without initializing a Metal command queue or ANE compute context, and its host process RSS memory MUST NOT exceed 150MB. This strictly preserves the full GPU and ANE bandwidth for local LLM inference engines (Ollama, llama.cpp, MLX) and developer workloads. Conformance testing MUST assert that no Metal or ANE contexts are allocated and host process RSS memory remains strictly ≤ 150MB under active evaluation load.
*   **Port Collision Avoidance:** Default gateway port `9229` MUST NOT collide with common macOS developer and AI serving ports: `11434` (Ollama), `8000`/`8080` (local dev servers), or `8888`/`8889` (JupyterLab / Jupyter Notebook).
*   **Apple Ecosystem Transparency:** Blackwall's stream layer and Python audit hooks MUST operate transparently alongside macOS security frameworks (Gatekeeper, TCC, SIP), APFS, and XPC communication without intercepting or degrading native macOS operations.

### FR-15: MCP Gateway Demo & Showcase Scenarios
Blackwall MUST provide a self-contained, reproducible demo suite demonstrating the MCP Gateway's threat interception capabilities against real-world AI agent attack vectors:
*   **Local Honeypot Server:** A locally-hosted FastAPI application (`scripts/gateway_demo/honeypot_server.py`) on `localhost:8765` serving pages with embedded indirect prompt injection payloads (hidden HTML comments, CSS-hidden divs, zero-width Unicode) that instruct consuming agents to exfiltrate credentials to a locally-captured C2 endpoint (`/exfil`). Zero external network dependencies.
*   **Four Demo Scenarios:**
    1.  **"The Heist" (BLOCK):** Demonstrates SyncResolver BLOCK verdict against indirect prompt injection credential exfiltration — agent reads a poisoned webpage, attempts `read_file` on `.env` + `http_request` POST to attacker C2, gateway blocks with JSON-RPC `-32603`. References [OWASP LLM01](https://genai.owasp.org/) and [MITRE ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051).
    2.  **"The Quarantine" (QUARANTINE + ALLOW):** Demonstrates surgical tool-chain isolation — legitimate `write_file` operations are ALLOW'd while a credential-harvesting `read_file` on `~/.ssh/id_rsa` is BLOCK'd, with session continuity verified. References [OWASP LLM07](https://genai.owasp.org/) and [MITRE ATLAS AML.T0054](https://atlas.mitre.org/techniques/AML.T0054).
    3.  **"The Poisoned Package" (BLOCK via Audit Hook):** Demonstrates defense-in-depth — MCP Gateway ALLOW's initial `run_command` for package install, but Python audit hook (`sys.addaudithook`) catches `subprocess.Popen` and `socket.connect` runtime escapes in the postinstall script. References [OWASP LLM05](https://genai.owasp.org/) and [MITRE ATLAS AML.T0049](https://atlas.mitre.org/techniques/AML.T0049).
    4.  **"The Bouncer" (Tier-1 Jev Fast Path + Tier-2 Escalation):** Demonstrates the additive triage architecture (governed by `.kiro/specs/tier-1-jev-addition/`) — benign query ALLOW'd on the Jev fast path, obfuscated injection BLOCK'd on the fast path, and an ambiguous C2-beacon-like probe escalated to Gemini Tier-2 with async signature synthesis. References [OWASP LLM01](https://genai.owasp.org/) and [MITRE ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051).
*   **Recording Infrastructure:** An orchestration script (`scripts/gateway_demo/record_demo.sh`) producing `asciinema` terminal recordings in split-pane tmux format (agent flow + gateway logs), with `.cast` output files in `docs/recordings/` convertible to GIF/SVG for README embedding.
*   **Single Entry Point:** All four scenarios MUST be executable via `scripts/gateway_demo/run_gateway_demo.sh` with zero manual intervention.
*   **OWASP & MITRE Attribution:** Each demo scenario MUST reference its corresponding [OWASP Top 10 for LLMs](https://genai.owasp.org/) and [MITRE ATLAS](https://atlas.mitre.org/) taxonomy entries in documentation and source comments.

## Non-Functional Requirements

### NFR-01: Zero Non-Python Dependencies
Blackwall Core MUST remain 100% Python-based (`asyncio`, `pydantic`, `click`). No Node.js, no Rust extensions required for Core functionality. The gateway MUST be installable via `pip install blackwall` or native macOS `.dmg` package. Semantic triage backends, including Tier-1 Jev (see `.kiro/specs/tier-1-jev-addition/`), MUST be pure-Python pip-installable clients so the Phase 5 packaging pipeline inherits a clean dependency closure.

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

| Resource | Intel MacBook Pro Baseline (Core i7, 16GB) | Apple Silicon MacBook High-End (M-Series ARM64, 36GB–128GB Unified Memory) | Enforcement |
| :--- | :--- | :--- | :--- |
| **Idle RAM** | ≤ 60MB | ≤ 60MB | Lazy-load heavy modules on first tool call |
| **Active RAM** | ≤ 150MB | ≤ 150MB | Peak during SyncResolver + GTI evaluation |
| **GPU / Metal / ANE** | 0MB (N/A) | **0MB Metal / 0MB ANE** | Zero Metal command queues or ANE compute requests; full GPU and ANE bandwidth reserved for local LLMs |
| **Idle CPU** | ~0% | ~0% | Event loop sleeping, no polling or background threads |
| **Active CPU** | < 5% single core | < 2% performance core | Sub-10ms burst per tool call; sub-5ms on M2+ P-cores |
| **Disk** | ≤ 50MB | ≤ 50MB | SQLite + policy + logs |
| **Startup** | < 2s | < 1s | APFS + unified memory enables faster cold-start on Apple Silicon; deferred initialization |

### NFR-07: Operating System Support & Windows Exclusion
Blackwall Core MUST support:
1. **macOS** (Darwin `arm64` Apple Silicon and `x86_64` Intel).
Linux packaging and NVIDIA DGX Spark support are explicitly de-scoped from Phase 5 (see Phase 5 scope refinement in `design.md`).
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

### US-08: High-Throughput Protection on Apple Silicon MacBook
**As an AI developer running a high-end Apple Silicon MacBook Pro (M-Series),**
I want Blackwall Core to run as a native `launchd` LaunchAgent on macOS (`arm64`) with zero Metal/ANE allocation and strictly bounded host RSS (≤150MB),
**So that** my multi-agent development workflows are secured at sub-5ms evaluation latency while preserving full GPU and ANE capacity for local LLM inference (Ollama, llama.cpp, MLX) and other developer workloads.

### US-09: One-Click macOS Installation (`.dmg` & LaunchAgent)
**As a macOS developer setting up Blackwall on an Apple Silicon or Intel Mac,**
I want to download a pre-built `Blackwall-AppleSilicon.dmg` or `Blackwall-Intel.dmg` directly from GitHub Releases and run `blackwall service install` for automatic login-time startup,
**So that** I am protected within minutes without manually configuring Python environments or reading extensive documentation.

### US-10: Witnessing Gateway BLOCK Against Indirect Prompt Injection
**As a potential Blackwall user evaluating the product,**
I want to watch a recorded demo showing an AI agent being tricked by a malicious website into stealing my API keys, only for Blackwall's MCP Gateway to block the exfiltration in real-time,
**So that** I can see concrete proof of Blackwall's protection before deciding to install it.

### US-11: Witnessing Surgical Quarantine Without Disrupting Legitimate Work
**As a developer evaluating whether Blackwall will slow down my workflow,**
I want to see a demo where Blackwall allows legitimate file operations to proceed while simultaneously blocking a credential theft attempt from the same agent session,
**So that** I know Blackwall is surgical rather than a blunt kill switch that would break my development flow.

### US-12: Witnessing Defense-in-Depth via Python Audit Hook
**As a security-conscious developer,**
I want to see a demo where even after a tool call passes the MCP Gateway, a malicious postinstall script's runtime escape attempt is caught by Blackwall's Python audit hook,
**So that** I understand Blackwall provides multiple layers of protection, not just protocol-level interception.

### US-13: Witnessing Tiered Triage (Jev Fast Path + Gemini Escalation)
**As a cost-conscious operator evaluating Blackwall,**
I want to see a demo where obvious tool calls are decided instantly by the Tier-1 Jev classifier while only an ambiguous probe triggers expensive Gemini reasoning,
**So that** I trust Blackwall spends deep-reasoning budget only where judgment exists.
