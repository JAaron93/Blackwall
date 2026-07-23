# Macroscope & Antigravity Agent Constitution: Blackwall Project Context & Architecture

## 1. Dual-Tier Project Context & Requirements

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials.

Blackwall is structured into **two distinct product tiers**:

1. **Blackwall Core (Individual Developer Edition)**:
   - Single-host Python daemon centered around ADK callbacks (`before_tool_callback`), Python runtime audit hooks (`sys.addaudithook`), and local SQLite threat graph.
   - Zero cluster-mesh/peer-to-peer networking (ZeroMQ/NATS) or C-kernel eBPF dependencies (exemption: standard outbound HTTPS API clients for Gemini API and VirusTotal GTI MCP are fully supported in Core).
2. **Blackwall Enterprise Mesh (Enterprise Edition)**:
   - Multi-host security mesh isolated under `src/blackwall/enterprise/`.
   - Features C/Python eBPF kernel probes, ZeroMQ pub/sub signature sync, Ephemeral Identity Sidecar, Data Pipeline Wrappers, Dual-Mode Local Forensic Triage Engine, and 4 Open-Source Local MCP adapters.

---

## 2. Macroscope Review Agent Directives & SDD Rules

All code submitted via pull requests or feature branches must be reviewed against these Macroscope agent guardrails:

* **No CodeRabbit Residuals**: Replace legacy CodeRabbit review directives with Macroscope agent review standards. Macroscope reviews must verify both Core and Enterprise architecture invariants.
* **Spec-Driven Consistency**: All edits must align with `.kiro/specs/blackwall-enterprise-security-mesh/` (`design.md`, `requirements.md`, `tasks.md`).
* **Behavior-Driven Specifications**: Verify all security behavior contracts using Gherkin syntax via `pytest-bdd` scenarios in `tests/features/`.
* **Strict Test-Driven Development (TDD)**: Every feature addition or bug fix must include a failing unit test or reproduction script before code changes are staged.

---

## 3. Core Architecture & Interception Flow (Base Branch Invariants)

Macroscope reviews must enforce the existing base branch architectural patterns:

1. **Async Interception Resolver (`SyncResolver`) Sequence**:
   - Execution flow MUST follow: `Rate Check` -> `ContextHygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Conditional GTI Validation (High-Risk Only)` -> `Score Aggregation` -> `Threshold Verdict` -> `Optional Inline Signature Generation`.
2. **FTS5 Similarity Scoring & Match Quality**:
   - SQLite Threat Signature Graph queries MUST use word-level intersection match quality calculation (`match_quality = len(intersection) / min_len`) scaled by FTS fallback score and capped by dynamic threshold limits to prevent false positives.
3. **Context Hygiene & Sanitization**:
   - `ContextResolver` middleware must replace sensitive environment variable patterns with generic placeholders (`[[VARIABLE_NAME]]`).
   - Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g., `wd-bouygues.com`) to prevent accidental sanitization matching.

---

## 4. Enterprise Security Mesh (5 Pillars & 4 Free Open-Source MCPs)

When reviewing or building Enterprise Mesh code under `src/blackwall/enterprise/`:

### Pillar 1: Kernel-Level Interception (`blackwall.enterprise.kernel`) & `ebpf-falco-mcp`
- Dual-driver kernel probe: `LinuxeBPFDriver` (Linux kernel >= 5.4) with automatic fallback to `UserSpaceAuditDriver` (`sys.addaudithook` on macOS).
- Integrated with open-source `ebpf-falco-mcp` for local kernel syscall telemetry.

### Pillar 2: Distributed Threat Mesh (`blackwall.enterprise.mesh`)
- `MeshBroadcaster` and `MeshReceiver` services communicating over ZeroMQ/NATS pub/sub sockets.
- Incoming signatures are written to local SQLite WAL graphs within `< 15 ms` with LFU/TTL eviction policies.

### Pillar 3: Ephemeral Identity Sidecar (`blackwall.enterprise.identity`) & `hashicorp-vault-mcp`
- Replaces static environment credentials (`AWS_SECRET_ACCESS_KEY`, `KUBECONFIG`) with synthetic honey-tokens (`BW_SYNTHETIC_*`).
- Exfiltrating synthetic tokens triggers an immediate `CRITICAL` threat verdict.
- Authorized tool calls obtain short-lived (15 min TTL) real STS tokens via `hashicorp-vault-mcp` (tested locally via `vault server -dev` or LocalStack).

### Pillar 4: Application Pipeline Interception Wrappers (`blackwall.enterprise.pipeline`) & `container-sandbox-mcp`
- `@blackwall.guard_pipeline` decorator and AST parser protecting dataset loaders, pickle parsers, and Jinja/SQL template renderers.
- `ASTPipelineFilter` MUST clean source indentation via `inspect.cleandoc` prior to `ast.parse` and track both import aliases (`ast.Import`/`ast.ImportFrom`) and variable assignment aliases (`ast.Assign`) to resolve indirect calls (e.g. `runner = os.system; runner(...)`).
- Interfaces with `container-sandbox-mcp` controlling local Docker or gVisor (`runsc`) microVM sandboxes.

### Pillar 5: Native Local Forensic Triage Engine (`blackwall.enterprise.forensics`) & `opentelemetry-mcp`
- Out-of-band telemetry log stream analyzer with **Dual-Mode execution**:
  - **Primary**: Local Ollama open-weight LLM endpoint (Qwen3 / GLM-5.2) without cloud safety refusals.
  - **Fallback**: `LightweightForensicParser` (regex/AST heuristic engine) automatically active when GPU/Ollama is offline.
- Exports telemetry via `opentelemetry-mcp` (OpenTelemetry Collector / Jaeger UI local runner).

---

## 5. Configured MCP Servers Overview

| MCP Server | Core / Enterprise | Open-Source Local Driver | Primary Function |
| :--- | :--- | :--- | :--- |
| **GTI MCP** | Core | VirusTotal API | Secondary validator for high-risk IPs/hashes |
| **`codebase-memory-mcp`** | Core | Embedded SQLite AST | Blast radius & call chain structural analysis |
| **`ebpf-falco-mcp`** | Enterprise | Falco OSS / eBPF | Real-time kernel syscall events & process lineage |
| **`hashicorp-vault-mcp`** | Enterprise | Vault Dev / LocalStack | JIT token exchange & honey-token rotation |
| **`container-sandbox-mcp`** | Enterprise | Docker API / gVisor | Ephemeral microVM sandbox container control |
| **`opentelemetry-mcp`** | Enterprise | OpenTelemetry / Jaeger | Telemetry log stream ingestion & SOC export |

---

## 6. Optimization Engineering & API Constraints

1. **Async Batching Bottleneck**:
   - Tool callbacks paused via `before_tool_callback` are held in an asynchronous queue, batched, dispatched to Gemini Interactions API (300 RPM limit), and mapped back to paused threads simultaneously.
2. **SQLite WAL Concurrency**:
   - SQLite database must operate in **WAL mode** with strict connection pooling and LFU/TTL signature pruning to guarantee fast-path queries under 8ms.

---

## 7. Mandatory Behavior-Driven Development (BDD) & TDD Verification

* **Framework**: Behavior-driven verification via `pytest-bdd`. Step implementations use `pytest-asyncio` (`async def`) ONLY when code under test is asynchronous; synchronous interception paths MUST use synchronous step definitions.
* **Verification Gate**: Run `pytest -v tests/` and confirm 100% pass rate before approving any PR or completing implementation tasks.

---

## 8. Testing SLA, Sanitization, and Teardown Guardrails

* **Warmup Latency Benchmarking**: Latency SLA tests MUST run at least one warmup query prior to starting timers to bypass FTS5 parser compilation and pool initialization overhead.
* **Audit Hook Isolation**: Tests evaluating `sys.addaudithook` MUST defer import to function scope or isolated subprocesses. Never import hook-registering code at global module scope in test files.
* **Subprocess Process Group Cleanup**: Background test servers MUST use `preexec_fn=os.setsid` and `os.killpg(os.getpgid(pid), signal.SIGTERM)` in `finally` blocks to guarantee zero zombie processes or port leaks.
* **SLA Default Validation**: SLA helper functions (`safe_sla_limit`) MUST validate that default parameters are finite, positive numbers (`math.isfinite(default) and default > 0.0`) before returning.
* **Mock Credential Hygiene for Secret Scanners**: When creating synthetic test inputs or honey-token strings in unit/integration tests, NEVER use strings containing cloud provider keyword patterns (e.g. `AWS_KEY`, `AKIA`, `SLACK_TOKEN`) or high-entropy literals with `secret_`/`key_`/`pass_` prefixes (e.g. `secret_abc123_xyz`). Always use generic prefixes such as `BW_SYNTHETIC_MOCK_SECRET_0192` to prevent automated secret scanners (GitGuardian) from triggering false-positive alerts.
* **Worktree Environment Path Alignment**: When executing test suites inside isolated git worktrees, ensure `pip install -e .` is run or pass `PYTHONPATH=src` so pytest imports modules from the current worktree rather than stale global site-packages.
