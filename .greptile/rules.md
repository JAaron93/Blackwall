# Blackwall Security Suite: Code Review Standards & Guidelines

This document outlines the repository policy, security invariants, and code review compliance requirements for the Blackwall Security Suite.

---

## 1. Product Tier Boundaries & Architecture Invariants

Blackwall is divided into two distinct product tiers, with the MCP Gateway serving as the primary entry point for Core:

### Blackwall Core (Developer Edition)
- **Single-Host Daemon**: Core components under `src/blackwall/` (outside `src/blackwall/enterprise/`) must remain a lightweight single-host daemon.
- **Core Attacker Attribution**: Single-host local attacker attribution (`AttackerIdentityExtractor`, `AttackerProfile`, `IncidentReportGenerator` in `src/blackwall/attribution/` & `SyncResolver`) is a shared baseline Core capability.
- **Zero Cluster-Mesh / eBPF Dependencies**: Core must contain zero imports or dependencies on ZeroMQ, NATS, or eBPF C headers.
- **Support**: Core fully supports 100% GCP Vertex AI Mode (`google-genai` with `vertexai=True`).

### Blackwall MCP Gateway (Core Entry Point)
- **Location**: `src/blackwall/gateway/` (server, interceptor, synthesizer, upstream manager) + `src/blackwall/cli.py`.
- **Standalone Daemon**: The gateway is the primary way Blackwall runs — a local background daemon on `localhost:9229` with PID file management (`~/.blackwall/blackwall.pid`). It is NOT a sidecar or proxy for any specific agent runtime.
- **Agent Agnosticism**: The gateway MUST NOT contain hardcoded rules or references specific to any particular agent (no Hermes, no Antigravity-specific, no Warp-specific logic). It operates purely at the MCP protocol level.
- **Transport Security**: HTTP transport MUST bind to `127.0.0.1` by default. `Origin` and `Host` header validation is mandatory. Network-bound requests require authentication.
- **JSON-RPC `id` Tracking**: The stream layer MUST track all in-flight requests by their JSON-RPC `id` to prevent concurrent call mismatching.
- **Upstream Management**: Supports `--wrap` (single downstream tool server as child process) and `gateway.yaml` (multi-server configuration). ALLOW'd requests are forwarded; BLOCK'd requests return synthesized JSON-RPC errors.
- **Resource Budget**: Gateway components MUST operate within the 2019 Intel MacBook Pro baseline: ≤60MB idle RAM, ~0% idle CPU, <2s startup, ≤150MB active RAM during evaluation.
- **Hardware Targets**: Blackwall Core targets the 2019 Intel MacBook Pro as its baseline (<=60MB idle RAM, <=150MB active RAM) and the NVIDIA DGX Spark (Grace Blackwell GB10 ARM64, 128GB unified memory) as top-of-the-line (0MB CUDA contexts, host RSS <= 350MB, preserving >127.6GB unified memory for AI models).
- **Spec Reference**: Architecture governed by `.kiro/specs/blackwall-mcp-gateway/` (design.md, requirements.md, tasks.md).

### Blackwall Enterprise Mesh (Enterprise Edition)
- **Isolated Location**: All enterprise capabilities must reside exclusively under `src/blackwall/enterprise/`.
- **Subsystem Breakdown**:
  - **Pillar 1 (Kernel Interception)**: `src/blackwall/enterprise/kernel/` (`LinuxeBPFDriver` with fallback to `UserSpaceAuditDriver`).
  - **Pillar 2 (Threat Mesh)**: `src/blackwall/enterprise/mesh/` (ZeroMQ/NATS pub/sub socket communication with <15ms persistence).
  - **Pillar 3 (Ephemeral Identity Sidecar)**: `src/blackwall/enterprise/identity/` (Honey-tokens `BW_SYNTHETIC_*` and Vault MCP JIT STS tokens).
  - **Pillar 4 (Pipeline Interception & Sandboxes)**: `src/blackwall/enterprise/pipeline/` (`@blackwall.guard_pipeline` and container sandboxes).
  - **Pillar 5 (Forensic Engine & OpenTelemetry)**: `src/blackwall/enterprise/forensics/` (Dual-mode LLM triage with regex/AST fallback, OpenTelemetry exporter).
  - **Pillar 6 (Advanced Threat Detection & Swarm Analysis)**: `src/blackwall/enterprise/advanced_threat_detection/` (`EventStreamCollector`, `AttackGraphStore`, `AgentSwarmDetector`, `ExploitChainAnalyzer`, `AILMTracker`, `C2InfrastructureDetector`, `K8sDefenseLayer`, `RegistryMonitor`, `ActiveReactionEngine`, `InboundProtocolFilter`, `PromptInjectionScanner`, `AgentQuotaEnforcer`).

---

## 2. Interception Resolver & Scoring Rules

- **Execution Flow**: In `SyncResolver`, execution flow MUST follow:
  `Rate Check` -> `ContextHygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Conditional GTI Validation (High-Risk Only)` -> `Score Aggregation` -> `Threshold Verdict` -> `Optional Inline Signature Generation`.
- **Context Hygiene**: Sensitivity maskers MUST replace credentials with generic placeholders (`[[VARIABLE_NAME]]`).
- **FTS5 Similarity Scoring**: SQLite Threat Signature Graph queries MUST use word-level intersection match quality calculation scaled by BM25 rank score: `fts_rank_scale = min(max(1.0 + abs(bm25_rank) / 10.0, 1.0), 1.5)`.

---

## 3. Data Model & Pydantic Validation

- **Pydantic v2**: All models in `src/blackwall/enterprise/advanced_threat_detection/models.py` (`NormalizedEvent`, `AttackPath`, `SwarmEvidence`, `ActiveReactionPayload`, `InboundProtocolMessage`, `PromptInjectionEvidence`, `AgentQuotaUsage`) and attacker attribution modules MUST enforce strict Pydantic v2 validation.
- **Constraints**:
  - `event_id`, `reaction_id`, `trigger_evidence_id`, `message_id`, `scan_id`: UUID v4 format.
  - `timestamps`: UTC timezone aware with zero offset (`AwareDatetime`, `v.utcoffset() == timedelta(0)`). Reject naive datetimes and non-UTC offsets.
  - Risk/Confidence/Threat scores: Bounded strictly in range `[0.0, 1.0]`.
  - Non-negative usage metrics: `tokens_consumed >= 0`, `api_call_count >= 0`, `token_burn_rate_per_sec >= 0.0`.
  - String Enums: Validate `ReactionActionType`, `InboundProtocolType`, `InboundMethodType`, `InjectionSourceType`.
  - Mandatory Evaluation Containment: `ActiveReactionEngine` methods MUST query `is_evaluation_mode(payload.trigger_evidence_id)` from the evidence graph and quash production actions in eval mode.
- **Fail-Closed Behavior**: Attacker attribution and security resolvers MUST fail closed cleanly without raising unhandled exceptions.

---

## 4. Rust Acceleration Subsystem & Native FFI Invariants

- **Non-Greedy Rewrite Philosophy (90/10 to 95/5 Rule)**:
  - Only compute-heavy, latency-critical hot paths (DFA regex context hygiene, SIMD vector cosine similarity, word intersection match quality, single-pass IOC extraction, graph DFS path traversal) reside in Rust (`crates/blackwall_core_rs/`).
  - High-level application frameworks (FastAPI/Uvicorn, aiosqlite, Google GenAI SDK, Pydantic models, OpenTelemetry) must remain 100% in Python.
- **Dual-Mode Sanitization Parity**:
  - **Middleware Mode** (`preserve_prefix = false`): Replaces full matched token (`api_key=SECRET` $\rightarrow$ `[[API_KEY]]`) and records `original_hash = sha256(matched_string)` in `RedactionRecord` logs.
  - **Resolver Mode** (`preserve_prefix = true`): Preserves credential prefixes/delimiters in prompts (`api_key=SECRET` $\rightarrow$ `api_key=[[API_KEY]]`, `password="x"` $\rightarrow$ `password="[[PASSWORD]]"`).
- **Resilient Batch Vector Similarity & Corrupted Candidate Isolation**:
  - Invalid *query* vector dimensions ($\ne 768$) MUST raise `ValueError`.
  - Corrupted, invalid-byte, or dimension-mismatched *candidate* vector rows during batch queries MUST be isolated and excluded with diagnostic logging, allowing all valid candidate rows to be scored without aborting the batch.
- **Zero-Panic FFI & Pure-Python Fallback Guarantee**:
  - All Rust FFI boundaries MUST return `PyResult<T>` and never panic across the C ABI.
  - Internal Rust errors MUST map cleanly to Python built-in exceptions (`PyValueError`, `PyRuntimeError`).
  - All Python wrappers (`context_hygiene.py`, `resolver.py`, `validators.py`, `repository.py`, `semantic.py`, `correlator.py`, `swarm.py`) MUST maintain seamless pure-Python fallbacks when `blackwall._core_rs` is missing or unbuilt.
- **Anti-Oscillation & Review Stability Directive**:
  - Reviewers must not reopen, oscillate between, or contradict previously accepted implementations across review iterations.
  - **IPv6 Token Parsing Semantics**: In IOC extraction, standard RFC 4291 token boundaries and Rust `std::net::Ipv6Addr` grammar govern valid addresses. Distinct valid hexadecimal characters within a token (e.g. `2001:db8::1abc`) parse as legitimate 16-bit hextets (`0x1abc`) according to standard IPv6 notation.
- **Portable Cross-Platform Toolchains**:
  - Rust crate configuration in `crates/blackwall_core_rs/Cargo.toml` and `pyproject.toml` MUST use standard toolchains discovered in `PATH` or `$CARGO_HOME/bin`, ensuring portable builds across macOS (x86_64, ARM64 Apple Silicon) and Linux containers without hardcoded developer-specific paths.

---

## 5. Active Threat Reaction, Kernel Semantics, & Evaluation Invariants

### Pillar 1 (Kernel Interception Scope & Semantics)
- **Tracepoint Enforcement**: `LinuxeBPFDriver` uses eBPF tracepoints (`sys_enter_connect`, `sys_enter_execve`) with BPF map lookup tables (`dropped_pids`, `dropped_ips`, `dropped_ip6s`). Enforcement operates via portable `bpf_send_signal(9)` (`SIGKILL`) upon intercepted syscall entry. Tracepoint probes do not perform synchronous inline packet rewriting or `bpf_override_return` (which requires error-injection kprobes).
- **Userspace Compatibility Fallback**: On non-Linux or development hosts without BCC/eBPF, `UserSpaceAuditDriver` enforces process/socket restrictions via Python runtime audit hooks (`sys.addaudithook`).
- **Atomic Drop Management**: Injections of PID, IPv4, or IPv6 socket drops must update BPF maps and roll back local userspace bookkeeping if driver insertion fails.

### Evaluation Containment & Provenance Invariants
- **Deterministic Evaluation Boundary**: Evaluation containment is envelope and namespace driven. An alert or reaction payload is classified as evaluation mode if:
  1. The payload/alert envelope carries explicit evaluation metadata (`evaluation_env_id`, `is_evaluation=True`, or `eval_mode=True`), OR
  2. The trigger evidence ID matches an active or historical evaluation identifier recorded in `EvaluationEnvironmentManager`, OR
  3. The trigger evidence ID matches the deterministic SHA-256 evaluation namespace derivation.
- **Production Resolution**: For standard production alerts where evaluation stores confirm no matching evaluation session, absence of evaluation provenance resolves cleanly to production execution.

### Pillar 3 Identity Revocation & Principal Anchoring
- **Principal Binding**: JIT STS credentials issued by `VaultMCPAdapter` and `SecretVaultSidecar` are bound to a verified `agent_id` / `principal_id` at issuance.
- **Revocation Scoping**: `ActiveReactionEngine` revokes active sessions belonging to the compromised target agent. If an alert provides a compromised `token_id` without an explicit `agent_id`, the engine discovers the owning principal from the active token registry before executing revocation.

### Dual-Tiered GCP Evaluation Architecture & Zero-SaaS Invariants
- **Dual-Tiered Red-Teaming & Evaluation Strategy**:
  - **Tier 1 (Core & Fast CI/CD)**: Google Cloud Agent Platform / ADK Adversarial Harness in 100% GCP Vertex AI Mode (`before_tool_callback`, Gemini in Vertex AI mode via Application Default Credentials).
  - **Tier 2 (Enterprise Kernel & Multi-Stage Attack Simulations)**: Cybench / CyberGym on GCP Cloud Run with gVisor container sandbox isolation for testing eBPF socket drops, ZeroMQ signature broadcast, and Vault token invalidation.
- **Weave Deprecation & Zero-SaaS Standard**: Weights & Biases (Weave) is deprecated and replaced by Google Cloud Vertex AI Gen AI Evaluation Service (`vertexai.preview.evaluation` / `EvalTask`) and Google Cloud Trace (`opentelemetry-exporter-gcp-trace`). Evaluation pipelines MUST NOT require third-party SaaS credentials (`WANDB_API_KEY`, AI Studio keys) and must authenticate exclusively via GCP Application Default Credentials (ADC).

---

## 6. Testing Hygiene & TDD Standards

- **TDD Requirement**: Source code modifications must include corresponding unit/integration tests under `tests/` and property-based tests under `tests/property/`.
- **BDD Verification**: End-to-end security scenarios must pass using `pytest-bdd` under `tests/features/`.
- **Audit Hook Isolation**: Registrations of `sys.addaudithook` in tests MUST be scoped inside isolated test functions (never module-level).
- **Process Group Cleanup**: Background test processes MUST clean up process groups using `os.killpg(os.getpgid(pid), signal.SIGTERM)`.
- **Secret Scanner Hygiene**: Synthetic test credentials MUST NOT match live cloud provider key formats (e.g. `AWS_KEY_<digits>`).

---

## 7. Cross-Platform Background Service Management (`launchd` & `systemd`) & Packaging Invariants

- **Foreground Execution Invariant**: Both macOS `launchd` and Linux `systemd` must supervise `blackwall serve --foreground` (with `Type=exec` and `PIDFile=` in systemd), ensuring supervisors directly track the active gateway child process rather than an exiting daemonized parent.
- **Foreground PID Creation**: In `--foreground` mode, whenever `--pidfile <path>` is supplied, `blackwall serve` MUST write its active process PID upon startup and delete it upon shutdown.
- **Absolute Path Resolution**: Because system service supervisors do not execute in a shell and do not expand tildes (`~`), `blackwall service install` MUST resolve all configuration paths, executable paths, log paths, and credential files to absolute filesystem paths (`Path.resolve()`). Zero unexpanded `~` characters may appear in generated service definitions.
- **systemd Syntax & Sectioning**: Start-rate limit throttling (`StartLimitBurst=5`, `StartLimitIntervalSec=60s`) belongs strictly under `[Unit]`. Placing rate limits under `[Service]` is invalid systemd syntax and disables throttling.
- **FHS Separation for System Services**: System units (`/etc/systemd/system/blackwall.service`) MUST NOT reference `~/.blackwall/`. System units MUST use standard FHS directories: `/etc/blackwall/gateway.yaml` (config), `/run/blackwall/blackwall.pid` (`RuntimeDirectory=blackwall`), `/var/log/blackwall/blackwall.log` (`LogsDirectory=blackwall`), and `/var/lib/blackwall/threat_signatures.db` (`StateDirectory=blackwall`).
- **Non-Root Execution Identity**: Running systemd units as root (`User=root`) is strictly disallowed. Identity is derived in order: (1) `--user <name>`, (2) `SUDO_USER`, or (3) dedicated system user `blackwall` (group `blackwall`) provisioned with `--home-dir /var/lib/blackwall --create-home`.
- **Debian Package (`.deb`) Structure**: Packaged `.deb` files deploy the system unit to `/lib/systemd/system/blackwall.service` configured with `EnvironmentFile=-/etc/default/blackwall`. In `postinst`, the package creates `blackwall:blackwall` if absent, assigns FHS directory ownership, auto-captures `$SUDO_USER` ADC credentials when present, and runs `systemctl daemon-reload`.
- **Credential Configuration Subcommand**: The CLI provides `blackwall service configure --project <id> --credentials <path> --system` to provision `/etc/default/blackwall` and `/etc/blackwall/credentials.json` (`0600 blackwall:blackwall`) on hosts without pre-existing credentials.

---

## 8. NVIDIA DGX Spark Co-Existence, Unified Memory Bounding & Hardware Invariants

- **Unified Memory Guarantee**: On unified memory systems (NVIDIA DGX Spark / Grace Blackwell GB10, 128GB LPDDR5x), CPU and GPU share the same physical pool. Blackwall Core MUST run 100% in CPU user-space threads with 0MB allocated in CUDA contexts/VRAM. Its host process RSS memory MUST NOT exceed 350MB (<0.28% of the unified pool), strictly preserving >127.6GB (>99.7%) of unified memory for colocated AI inference engines (vLLM, Ollama, TensorRT-LLM) or model fine-tuning.
- **Port Non-Collision**: Default gateway port `9229` MUST NOT collide with standard DGX OS AI serving ports: `11434` (Ollama), `8000`/`8001`/`8002` (vLLM, Triton), or `8888`/`8080` (JupyterLab).
- **Multi-Layer Zero-CUDA Verification**: Conformance tests asserting zero-CUDA usage must inspect `/proc/<daemon_pid>/fd/` for `/dev/nvidia*` character devices on the target daemon PID (resolved from `blackwall.pid` or subprocess handle, NOT `/proc/self/fd/`), confirm daemon PID absence from `nvmlDeviceGetComputeRunningProcesses`, and verify `torch.cuda.is_initialized() is False`.
- **Resource Budgets**:
  - **2019 MacBook Pro Baseline**: <=60MB idle RAM, <=150MB active RAM, ~0% idle CPU, <5% active CPU, <2s startup.
  - **NVIDIA DGX Spark Top-of-the-Line**: <=100MB idle RAM, <=350MB active RAM, 0MB CUDA, ~0% idle CPU, <2% active CPU across 20 cores, <1s startup.

---

## 9. Operating System Support Scope & Windows Exclusion

- **Supported Operating Systems**:
  1. **macOS**: Darwin `x86_64` (Intel baseline) and `arm64` (Apple Silicon).
  2. **GNU/Linux**: **DGX OS / Ubuntu 24.04 LTS `aarch64`** (NVIDIA DGX Spark) and Ubuntu `x86_64`.
- **Strict Windows Exclusion**: Windows OS packaging (`.exe`, `.msi`), PowerShell scripts, and Windows service wrappers are explicitly barred from all codebase development, CI workflows, and release pipelines.


