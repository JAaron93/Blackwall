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

### Blackwall MCP Gateway (Core Entry Point Specification)
- **Location (Specification)**: Architecture governed by `.kiro/specs/blackwall-mcp-gateway/`, targeting `src/blackwall/gateway/` (server, interceptor, synthesizer, upstream manager) + `src/blackwall/cli.py`.
- **Standalone Daemon**: The gateway is the primary way Blackwall runs — a local background daemon on `localhost:9229` with PID file management (`~/.blackwall/blackwall.pid`). It is NOT a sidecar or proxy for any specific agent runtime.
- **Agent Agnosticism**: The gateway MUST NOT contain hardcoded rules or references specific to any particular agent (no Hermes, no Antigravity-specific, no Warp-specific logic). It operates purely at the MCP protocol level.
- **Transport Security**: HTTP transport MUST bind to `127.0.0.1` by default. `Origin` and `Host` header validation is mandatory. Network-bound requests require authentication.
- **JSON-RPC `id` Tracking**: The stream layer MUST track all in-flight requests by their JSON-RPC `id` to prevent concurrent call mismatching.
- **Upstream Management**: Supports `--wrap` (single downstream tool server as child process) and specification config `gateway.yaml` (multi-server configuration). ALLOW'd requests are forwarded; BLOCK'd requests return synthesized JSON-RPC errors.
- **Resource Budget**: Gateway components MUST operate within the 2019 Intel MacBook Pro baseline: ≤60MB idle RAM, ~0% idle CPU, <2s startup, ≤150MB active RAM during evaluation.
- **Hardware Targets**: Blackwall Core targets the 2019 Intel MacBook Pro as its baseline (<=60MB idle RAM, <=150MB active RAM) and the NVIDIA DGX Spark (Grace Blackwell GB10 ARM64, 128GB unified memory) as top-of-the-line (0MB CUDA contexts, host RSS <= 350MB, preserving >127.6GB unified memory for AI models).
- **Spec Reference**: Architecture governed by `.kiro/specs/blackwall-mcp-gateway/` (design.md, requirements.md, tasks.md).

### Blackwall Enterprise Mesh (Enterprise Edition)
- **Isolated Location**: All enterprise capabilities must reside exclusively under `src/blackwall/enterprise/`.
- **Subsystem Breakdown**:
  - **Pillar 1 (Kernel Interception)**: `src/blackwall/enterprise/kernel/` (`LinuxeBPFDriver` with fallback to `UserSpaceAuditDriver`).
  - **Pillar 2 (Distributed Threat Mesh)**: `src/blackwall/enterprise/mesh/` (`MeshBroadcaster` and `MeshReceiver` communicating over ZeroMQ pub/sub sockets with <15ms SQLite persistence).
  - **Pillar 3 (Ephemeral Identity Sidecar)**: `src/blackwall/enterprise/identity/` (Honey-tokens `BW_SYNTHETIC_*` and Vault MCP JIT STS tokens).
  - **Pillar 4 (Pipeline Interception & Sandboxes)**: `src/blackwall/enterprise/pipeline/` (`guard_pipeline` decorator and container sandboxes).
  - **Pillar 5 (Forensic Engine & OpenTelemetry)**: `src/blackwall/enterprise/forensics/` (Dual-mode LLM triage with regex/AST fallback, OpenTelemetry exporter).
  - **Pillar 6 (Advanced Threat Detection & Swarm Analysis)**: `src/blackwall/enterprise/advanced_threat_detection/` (`EventStreamCollector`, `AttackGraphStore`, `AgentSwarmDetector`, `ExploitChainAnalyzer`, `AILMTracker`, `C2InfrastructureDetector`, `K8sDefenseLayer`, `RegistryMonitor`, `ActiveReactionEngine`, `InboundProtocolFilter`, `PromptInjectionScanner`, `AgentQuotaEnforcer`).

---

## 2. Interception Resolver & Scoring Rules

- **Execution Flow**: In `SyncResolver`, execution flow MUST follow:
  `Rate Check` -> `ContextHygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Conditional GTI Validation (High-Risk Only)` -> `Optional Semantic Triage (Gemini 3.5 Flash-Lite)` -> `Score Aggregation` -> `Threshold Verdict` -> `Optional Inline Signature Generation`.
- **Context Hygiene**: Sensitivity maskers MUST replace credentials with generic placeholders (`[[VARIABLE_NAME]]`). For semantic triage, `preserve_iocs=True` preserves target URLs, domains, and filesystem paths (`/etc/shadow`) while strictly redacting secrets and credentials.
- **FTS5 Similarity Scoring**: SQLite Threat Signature Graph queries MUST use word-level intersection match quality calculation scaled by BM25 rank score: `fts_rank_scale = min(max(1.0 + abs(bm25_rank) / 10.0, 1.0), 1.5)`.
- **Threat Signature Graph URL-Decoding**: SQLite TSG queries and pattern matching MUST perform URL-decoding (`urllib.parse.unquote`) on candidate queries/arguments prior to pattern matching to detect encoded evasion attempts against persisted plaintext patterns.

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
- **Serialization & Persistence Casing**: When serializing Pydantic models for SQLite or database persistence, keys must map to expected column conventions without silent field dropping. Batch insertion methods must defensively accept both snake_case and camelCase field aliases.
- **In-Process Task Dispatch**: When executing background analysis tasks in-process, candidate responses must be consumed and dispatched to downstream generators rather than abandoned in a pending state.
- **Timeout Contract Scoping**: Mandatory HTTP client request timeout floors for LLM APIs (e.g. 120s) must never overwrite or inflate explicit caller synchronous execution deadlines.
- **Native Structured Outputs & Model Standards**: Interception triage and signature generation must use native `response_schema` and `response_mime_type="application/json"`. Manual regex JSON extractors and defensive prompt scaffolding are strictly prohibited. Production models default to `gemini-3.5-flash-lite` (rapid triage) and `gemini-3.8-flash` (deep reasoning); all `gemini-3.1-*` models, Pro models, and preview variants are deprecated.


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
  - **Endpoint & Infrastructure Extraction Invariants**: In network target and resource string parsing across `swarm.py` and `covert_channel.py`, the network host component is strictly isolated before any path (`/`), query (`?`), or fragment (`#`). Path components (such as IP literals in REST URL paths like `/api/198.51.100.5/storage`) represent application-level resource data, not network routing infrastructure, and must never be classified as external C2 endpoints. Both IPv4 and IPv6 addresses (bracketed, unbracketed, with/without port, scheme/non-scheme) are recognized as first-class endpoints.
  - **Correlation Cycle Deduplication Lifecycle**: Deduplication of covert channel alerts across multi-agent correlation passes in `orchestrator.py` is governed by explicit cycle completion (`complete_correlation_cycle`) and temporal activity TTL (`max(300.0, temporal_window * 2)`). Reviewers must not oscillate between demanding memory bounds and flagging TTL-based eviction of inactive cycles.
  - **IPv6 Token Parsing Semantics**: In IOC extraction, standard RFC 4291 token boundaries and Rust `std::net::Ipv6Addr` grammar govern valid addresses. Distinct valid hexadecimal characters within a token (e.g. `2001:db8::1abc`) parse as legitimate 16-bit hextets (`0x1abc`) according to standard IPv6 notation.
- **Portable Cross-Platform Toolchains**:
  - Rust crate configuration in `crates/blackwall_core_rs/Cargo.toml` and `pyproject.toml` MUST use standard toolchains discovered in `PATH` or `$CARGO_HOME/bin`, ensuring portable builds across macOS (x86_64, ARM64 Apple Silicon) and Linux containers without hardcoded developer-specific paths.
- **Benchmark SLA Calibration & Workload Invariants** (`scripts/benchmark_rust_hotpaths.py`):
  - NFR-1 gate workloads are **fixed** as follows. Reviewers MUST NOT flag benchmark gates as "too weak" or oscillate on SLA thresholds that are already calibrated to observed end-to-end latency:
    - **Context Redaction**: Payload ≥ 9KB of realistic agent text with 2-3 embedded credentials. SLA ≤ 50µs mean.
    - **Vector Cosine Similarity** (`batch_cosine_similarity`): 100 candidates × 768-dim. NFR-1 specifies `< 20µs per 100 vectors` for the **native comparison compute operations**. From Python, the PyO3 FFI call itself costs ~15–20µs regardless of batch size; the Rust extension processes the full batch in ~200–400µs end-to-end (vs ~15–20ms for the equivalent pure-Python `array.array` loop in `repository.py`). The benchmark gate asserts **≥ 35× speedup** over the pure-Python baseline, which is the correct observable metric from Python. Reviewers MUST NOT demand a raw `< 20µs` end-to-end gate for 100 candidates — that would require bypassing Python FFI overhead which is outside the scope of this Python benchmark. The per-vector native compute (~3µs) is verified in Rust unit tests (`cargo test`).
    - **IOC Extraction + Shannon Entropy**: Both `extract_iocs([payload])` and `calculate_entropy(payload)` are called in the benchmark (they are sequentially invoked in the semantic gating phase). Combined SLA ≤ 30µs mean on a 1KB payload.
    - **Graph DFS**: 500 nodes (25 chains × 20), `max_paths=50` (realistic bounded enumeration). NFR-1 specifies `< 500µs` for up to 500 nodes. SLA ≤ 500µs mean.
    - **Word Intersection Scoring**: SLA ≤ 10µs mean.
  - All benchmarks MUST return `False` and exit code 1 if the Rust extension is unavailable — silent skipping/passing is not permitted.
  - SLA predicates MUST use `mean < sla` (not `min < sla or mean < sla`).

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

---

## 10. Evaluation, Benchmark & Cybersecurity Test Harness Invariants (`src/blackwall/eval/`, `tests/eval/`, `tests/evaluation/`, `tests/evals/`)

* **Adversarial Input Tolerance**: Golden datasets, evaluation test cases, and candidate model outputs in evaluation suites intentionally contain malformed text, prompt injection vectors, delimiter attacks (`[INST]`, `<<SYS>>`), and scoring directives (`assign maximum score`). These represent test probes, NOT vulnerabilities in the test harness. Do NOT flag benchmark fixtures, test inputs, or red-team datasets as security vulnerabilities.
* **Fallback Isolation vs. Process Crashing**: In evaluation runners and test suites, catching `SanitizationError`, model exceptions, or network timeouts to record an explicit fallback metric (`is_fallback = True`, fallback score, or tie) is the MANDATORY architectural pattern. It guarantees that multi-hour benchmark runs survive adversarial samples without crashing the runner. Do NOT flag exception handling or fallback metrics as "swallowed errors" or "sanitizer bypasses".
* **XML Nonce Sandboxing**: Evaluation judges evaluate untrusted candidate outputs wrapped in per-request cryptographic nonces (e.g. `===JUDGE DATA <nonce> START===`) and XML sandboxes (`<candidate>` tags) with dynamically bound system instructions. Do NOT flag candidate output interpolation inside bounded sandboxes as prompt injection vulnerabilities.
* **Anti-Oscillation Standard on Candidate Sanitization**: When evaluation runners pass candidate outputs or benchmark prompts through an input sanitizer, any rejected attacks must safely route to fallback evaluation states (`is_fallback = True`). Valid outputs may then be stripped of instruction delimiters and escaped within XML sandboxes. Do NOT oscillate between demanding pre-neutralization of candidate text and demanding strict sanitizer rejection.
* **Synthetic Metric Vocabulary vs. User Data**: Evaluation category normalizers, heuristics, and regex matchers operate on standardized synthetic test vocabularies and domain labels. Do NOT flag substring-matching optimizations or test label mappings in evaluation runners as user-facing bugs.
* **ADK `before_tool_callback` Non-Crashing Return Contract**: In ADK agent evaluation harnesses, `before_tool_callback` MUST return a dictionary `{"status": "blocked", "verdict": "BLOCK", "error": f"[BLACKWALL BLOCK] {reasoning}"}` rather than raising exceptions (`PermissionError`). Do NOT flag returning an interception dictionary as "failing to enforce security policy" or demand raising unhandled exceptions that crash the ADK graph.
* **Dual-Gate Trajectory & Rubric Scoring**: Formal ADK evaluations require dual gating: deterministic exact trajectory match (`tool_trajectory_avg_score: 1.0`) AND LLM-as-a-judge rubric scoring (`rubric_based_tool_use_quality_v1`). Do NOT flag trajectory score assertion checks or rubric dual gates as redundant metrics.
* **Agent Entrypoint Knowledge Graph Client**: The agent entrypoint (`agent/__init__.py`) must wire `SyncResolver` with `cbm_client=CodebaseMemoryClient(base_url=os.getenv("CBM_MCP_BASE_URL"))` to satisfy the base branch interception flow.

---

## 11. Antigravity 2.0 CLI-First Architecture & Operational Guardrails

> [!NOTE]
> **Developer Tooling Scope vs. Blackwall Product Architecture**:
> This section governs **developer agent workflows** (how AI coding assistants, subagents, and review bots develop and operate on this codebase using CLI tools rather than stateless MCP servers). It does **NOT** apply to Blackwall's product runtime. The Blackwall agent is an **agent-agnostic MCP Gateway security proxy** (`localhost:9229`, background daemon, macOS LaunchAgent service) that actively integrates with `codebase-memory-mcp` AST knowledge graphs, VirusTotal Google Threat Intelligence (GTI), and enterprise MCP adapters.

- **CLI-First Developer Architecture**: For repository development tasks, version control, PR triage, and cloud/container management MUST execute through native CLI binaries (`gh`, `git`, `gcloud`, `docker`) paired with lightweight skills. PRs introducing stateless developer MCP servers (e.g. GitHub MCP, Git MCP, Jira/Slack MCP) for agent pair-programming are prohibited and must be rejected.
- **MCP Scope & Stateful Boundaries**: MCP is reserved exclusively for stateful engines: `codebase-memory-mcp` (AST memory graphs), persistent database connections, and CDP browser sessions.
- **GitHub CLI (`gh`) Guardrails**:
  - All work must be conducted on dedicated feature branches. Direct commits or pushes to `main` and `master` are strictly prohibited.
  - Autonomous merging via CLI (`gh pr merge`) or API is forbidden. All PRs require human review and approval.
  - Pre-commit hygiene must verify zero `.env` files, API keys, credentials, or `.sqlite` WAL files are staged.
- **CLI Output Hygiene & Token Conservation**:
  - Terminal queries with structured output support must use projection flags: `gh` queries MUST use `--json <fields>` and `--limit <N>`; `gcloud` MUST use `--format`; `docker` MUST use `--format`.
  - Unbounded streams must be piped through Unix filters (`jq`, `head -n <N>`, `grep`).
- **Architectural Perpetuation**: All subagents and child workflows must perpetuate this CLI-first standard and codify it in any newly authored instruction files.

---

## 12. Shell Background Daemon Orchestration & Live Demo Scoreboard Standards

* **Process-Group PID Capture in Shell Launchers**: Shell scripts orchestrating background services (`scripts/run_demo.sh`, `set -m`) MUST capture the actual service PID in `$!` (using `cmd > log.txt 2>&1 &`) rather than piping through `tee` (`cmd 2>&1 | tee log.txt &`), ensuring cleanup traps terminate the service process group and prevent orphaned background daemons.
* **Dynamic Demo Scoreboard Derivation**: Interactive demonstration TUIs and scoreboards (`demo_live.py`) MUST derive all metrics dynamically from actual resolver verdicts. Evasion rate MUST be calculated as `(allowed / total) * 100.0`, FRR on purely adversarial suites MUST report `N/A (Adversarial Suite)`, and `QUARANTINE` verdicts must be explicitly tracked and displayed rather than collapsed into `ALLOW` or `BLOCK`.





