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
6. When `--host` specifies a non-loopback address, the server requires a pre-shared bearer token (`--auth-token` or `BLACKWALL_AUTH_TOKEN`). Requests without a valid `Authorization: Bearer <token>` header are rejected with HTTP 401.
7. Server refuses to start on a non-loopback address if no auth token is configured (startup guard test).
8. Zero Node.js dependencies are introduced.
9. All unit tests pass.

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
**Requirements Satisfied:** FR-02, FR-06, FR-08, FR-09, US-04, US-05

**Description:**
Build the `click`-based CLI (`src/blackwall/cli.py`) and daemon lifecycle manager:
- `blackwall serve` — daemonize by default, write PID to `~/.blackwall/blackwall.pid`, redirect logs to `~/.blackwall/blackwall.log`. Support `--foreground`, `--transport`, `--port`, `--host`, `--wrap`, `--config`, `--policy`, `--db`, `--auth-token`, `--log-level`.
- `--auth-token <token>` (or `BLACKWALL_AUTH_TOKEN` env var) MUST be accepted by the CLI and wired into the HTTP server's request validation middleware. When `--host` specifies a non-loopback address and no token is configured, `blackwall serve` MUST refuse to start with a clear error.
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
8. `--auth-token` value (or `BLACKWALL_AUTH_TOKEN` env var) is wired into the HTTP server; non-loopback requests without a valid `Authorization: Bearer <token>` header are rejected with HTTP 401.
9. `blackwall serve --host 0.0.0.0` without `--auth-token` or `BLACKWALL_AUTH_TOKEN` refuses to start with a clear error message (startup guard).
10. `blackwall serve --host 0.0.0.0 --transport http --auth-token <valid-token>` starts successfully; an HTTP request to `/mcp` with a valid `Authorization: Bearer <valid-token>` header is accepted and processed (valid-token happy path).
11. All unit tests pass (TDD).

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
5. Add Gherkin scenario for authenticated non-loopback HTTP: gateway starts with `--host 0.0.0.0 --auth-token <test-token>`, a request with valid `Authorization: Bearer <test-token>` is accepted and processed.
6. Add Gherkin scenario for unauthenticated non-loopback rejection: gateway starts with `--host 0.0.0.0 --auth-token <test-token>`, a request without a valid token is rejected with HTTP 401.
7. `pytest-bdd` passes.

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

---

## 🛤️ Phase 5: Cross-Platform Service, Linux Packaging & Release Pipeline

> [!TIP]
> **PARALLEL EXECUTION**
> `TASK-F01` (Cross-Platform Service Manager) and `TASK-F02` (Python Audit Hook Bootstrap) can be developed concurrently in Track E.

#### TASK-F01: Implement Cross-Platform Service Manager (macOS LaunchAgent + Linux systemd for DGX OS)
**Status:** ⏳ Not Started
**Dependencies:** TASK-C03
**Requirements Satisfied:** FR-10, US-06, US-08

**Description:**
Implement the cross-platform background service management module and CLI subcommands:
- Platform auto-detection (`platform.system()`): detects Darwin (macOS) vs Linux (DGX OS / Ubuntu).
- **macOS (`launchd`):**
  - `blackwall service install` — Generate and validate `~/Library/LaunchAgents/com.blackwall.gateway.plist` configured to supervise `blackwall serve --transport http --port 9229 --config ~/.blackwall/gateway.yaml` (or user-specified `--wrap <cmd>`), ensuring allowed tool calls are forwarded to downstream tool servers.
  - Embed `EnvironmentVariables` dictionary containing `GCP_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_TIER="paid"`, and `PATH`.
  - Set `RunAtLoad=true`, `KeepAlive` with `SuccessfulExit=false`, `ThrottleInterval=30`, and log redirection to `~/.blackwall/blackwall.log` and `~/.blackwall/blackwall.err`.
- **GNU/Linux (`systemd` on DGX OS / Ubuntu):**
  - `blackwall service install` — Generate and validate systemd unit `blackwall.service` (`~/.config/systemd/user/blackwall.service` or `/etc/systemd/system/blackwall.service` with `--system`).
  - Configure `[Unit]` with `Description=Blackwall MCP Gateway`, `After=network.target`.
  - Configure `[Service]` with `ExecStart=...`, `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=5`, `StartLimitIntervalSec=60s`, `MemoryMax=500M`, and active `Environment=` directives.
  - Enable and start via `systemctl --user enable --now blackwall` (or systemctl).
- Fail fast at install time if `GCP_PROJECT` / `GOOGLE_CLOUD_PROJECT` is absent.
- `blackwall service start|stop|status|uninstall` — Dispatch to `launchctl` or `systemctl`.

**Acceptance Criteria:**
1. Unit tests assert correct XML generation for macOS `com.blackwall.gateway.plist` and correct INI syntax for Linux `blackwall.service` unit file (TDD).
2. Service installer detects OS accurately and writes to correct platform paths (`~/Library/LaunchAgents/` on macOS, `~/.config/systemd/user/` on Linux).
3. Both service configurations embed upstream `--config` flag and GCP credentials.
4. `install` fails fast with an exit code != 0 when `GCP_PROJECT` is missing.
5. Crash throttling is configured on both platforms (`ThrottleInterval=30` on launchd, `RestartSec=5s` on systemd).
6. `uninstall` unloads the service and removes service definition files cleanly.
7. All unit tests pass.

#### TASK-F02: Implement Python Audit Hook Auto-Bootstrap
**Status:** ⏳ Not Started
**Dependencies:** TASK-C03
**Requirements Satisfied:** FR-12, US-01, US-06

**Description:**
Implement the global Python runtime audit hook bootstrap manager across macOS and Linux:
- `blackwall hook install` — Identify active Python virtualenv and user site-packages directories. Inject a safe, non-destructive bootstrap snippet into `sitecustomize.py` (or drop `blackwall_audit.pth`) that attaches `sys.addaudithook` before user code executes.
- `blackwall hook uninstall` — Remove the bootstrap snippet cleanly without corrupting pre-existing `sitecustomize.py` logic.
- `blackwall hook status` — Verify whether audit hooks are actively attached and functional in the current environment.

**Acceptance Criteria:**
1. Unit tests assert that `hook install` correctly injects hook bootstrap into mock site-packages (TDD).
2. Starting a clean Python subprocess in the bootstrapped environment automatically attaches `sys.addaudithook` without explicit imports.
3. Subprocess attempts to invoke blocked OS calls (`subprocess.Popen` with malicious payload) raise `PermissionError` immediately.
4. `hook uninstall` restores original `sitecustomize.py` state with byte-for-byte fidelity.
5. All unit tests pass.

#### TASK-F03: Implement macOS Menu Bar Tray Application & System Notifications
**Status:** ⏳ Not Started
**Dependencies:** TASK-F01, TASK-C01
**Requirements Satisfied:** FR-11, US-06

**Description:**
Build a lightweight native macOS Menu Bar application (`Blackwall.app`):
- Tray icon reflecting real-time state: Green (Protected), Amber (Quarantine), Red (Threat Blocked).
- Menu items: Service Status (Running/Stopped), Threat DB Stats (signature count), Recent Incidents list, Quick Links, and Exit.
- Native notification integration: Dispatch macOS UserNotifications banners when `SyncResolver` triggers `BLOCK` or `QUARANTINE` verdicts.
- One-click tool config registration for Google Antigravity, Warp Terminal, Claude Desktop, and Cursor.

**Acceptance Criteria:**
1. Menu bar app launches cleanly and displays current protection status.
2. Background poll or IPC socket updates icon state when threats are intercepted.
3. System notifications display sanitized threat telemetry (tool name, risk score) without leaking raw payloads or credentials.
4. Idle memory footprint remains < 25MB RAM and 0.0% CPU.
5. All unit and UI tests pass.

#### TASK-F04: Build GitHub Actions Release Packaging Pipeline (macOS .dmg & Linux .deb / Tarball)
**Status:** ⏳ Not Started
**Dependencies:** TASK-F03
**Requirements Satisfied:** FR-13, US-07, US-09, NFR-07

**Description:**
Create the GitHub Actions workflow (`.github/workflows/release_packages.yml`) to build, bundle, and package release artifacts:
- **macOS:** Matrix build for macOS `x86_64` (Intel baseline) and `arm64` (Apple Silicon), creating `.dmg` installers (`Blackwall-Intel.dmg`, `Blackwall-AppleSilicon.dmg`).
- **GNU/Linux (DGX OS / Ubuntu):**
  - Build Debian packages (`.deb`) targeting **DGX OS / Ubuntu 24.04 LTS `aarch64`** (NVIDIA DGX Spark) and Ubuntu `x86_64`, packaging `/usr/local/bin/blackwall`, `/usr/lib/systemd/user/blackwall.service`, default config, and post-install hooks.
  - Build standalone Linux binary tarballs (`blackwall-linux-aarch64.tar.gz`, `blackwall-linux-x86_64.tar.gz`) with `install.sh`.
- Windows artifacts (`.exe`, `.msi`) are explicitly excluded.
- Automatically attach release assets to tagged GitHub Releases.

**Acceptance Criteria:**
1. Workflow builds `.app` and `.dmg` on GitHub macOS runners without errors.
2. Workflow builds valid `.deb` packages using `dpkg-deb` on Linux runners for `aarch64` and `x86_64`.
3. Packaged `.deb` installs cleanly via `dpkg -i` on clean Ubuntu 24.04 LTS and DGX OS environments.
4. Release assets are attached automatically upon publishing a git tag.
5. All build verification checks pass.

#### TASK-F05: Implement NVIDIA DGX OS Co-Existence & Zero-VRAM Verification Tests
**Status:** ⏳ Not Started
**Dependencies:** TASK-F01, TASK-F04
**Requirements Satisfied:** FR-14, NFR-06, US-08

**Description:**
Implement verification tests ensuring complete non-interference and zero GPU VRAM consumption on NVIDIA DGX OS environments:
- Verify that running `blackwall serve` never invokes CUDA runtime functions or allocates GPU memory (`torch.cuda.is_initialized()` is False; GPU VRAM allocation is 0MB).
- Verify port non-collision: assert that Blackwall HTTP gateway runs and forwards traffic on port `9229` while mock local AI services run on port `11434` (Ollama), `8000` (vLLM), `8001` (Triton), and `8888` (JupyterLab).
- Verify that Python audit hooks and MCP stream filters do not intercept or disrupt NVIDIA Container Toolkit (`nvidia-ctk`) or GPU device nodes (`/dev/nvidia*`).
- Test Linux `systemd` user unit lifecycle (`blackwall service install`, `start`, `status`, `stop`, `uninstall`) inside an Ubuntu 24.04 / DGX OS container.

**Acceptance Criteria:**
1. Automated tests assert 0MB GPU VRAM allocation during gateway execution (TDD).
2. Gateway successfully handles concurrent requests while mock AI serving ports (11434, 8000) are occupied.
3. Systemd service lifecycle tests pass in an Ubuntu 24.04 container.
4. Active memory remains within the DGX Spark budget (≤ 350MB active RAM, zero VRAM).
5. All unit and integration tests pass.

