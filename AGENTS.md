# Qodo & Antigravity Agent Constitution: Blackwall Project Context & Architecture

## 1. Dual-Tier Project Context & Requirements

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials.

Blackwall is structured into **two distinct product tiers**:

1. **Blackwall Core (Individual Developer Edition)**:
   - Single-host Python daemon centered around ADK callbacks (`before_tool_callback`), Python runtime audit hooks (`sys.addaudithook`), and local SQLite threat graph.
   - Zero cluster-mesh/peer-to-peer networking (ZeroMQ/NATS) or C-kernel eBPF dependencies (exemption: 100% GCP Vertex AI Mode clients for Gemini Enterprise Agent Platform and VirusTotal GTI MCP are fully supported in Core; red-teamer attack agents in demo harness use Hyperbolic API).
2. **Blackwall Enterprise Mesh (Enterprise Edition)**:
   - Multi-host security mesh isolated under `src/blackwall/enterprise/`.
   - Features C/Python eBPF kernel probes, ZeroMQ pub/sub signature sync, Ephemeral Identity Sidecar, Data Pipeline Wrappers, Dual-Mode Local Forensic Triage Engine, and 4 Open-Source Local MCP adapters.

---

## 2. Qodo Review Agent Directives & SDD Rules

All code submitted via pull requests or feature branches must be reviewed against these Qodo agent guardrails:

* **Qodo Review Directives**: Enforce Qodo agent review standards configured in `.qodo.yaml` and `pr_compliance_checklist.yaml`. Qodo reviews must verify both Core and Enterprise architecture invariants.
* **Spec-Driven Consistency**: All edits must align with `.kiro/specs/blackwall-enterprise-security-mesh/` (`design.md`, `requirements.md`, `tasks.md`).
* **Behavior-Driven Specifications**: Verify all security behavior contracts using Gherkin syntax via `pytest-bdd` scenarios in `tests/features/`.
* **Strict Test-Driven Development (TDD)**: Every feature addition or bug fix must include a failing unit test or reproduction script before code changes are staged.

---

## 3. Core Architecture & Interception Flow (Base Branch Invariants)

Qodo reviews must enforce the existing base branch architectural patterns:

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
- `LightweightForensicParser` AST inspection MUST resolve fully qualified callee names (e.g. `os.system`, `subprocess.Popen`, `pickle.loads`) rather than bare attribute names to prevent false-positive threat classifications on benign modules like `json.loads` or `asyncio.run`.
- Exports telemetry via `opentelemetry-mcp` (OpenTelemetry Collector / Jaeger UI local runner).
- Local MCP server adapters storing event streams or trace logs in memory (e.g., `OpenTelemetryMCPAdapter`) MUST use bounded queues (`collections.deque(maxlen=max_buffer_size)`) with configurable maximum capacities (defaulting to 1000 items) and provide explicit `clear_buffers()` methods to prevent memory growth in long-running daemons.

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
3. **Unconditional Credential Purging**:
   - Provider configuration helpers (`configure_provider_env()`) MUST purge legacy API keys (`GEMINI_API_KEY`, `LLM_API_KEY`) and re-assert required mode variables (`GOOGLE_GENAI_USE_VERTEXAI="true"`, `GEMINI_TIER="paid"`) on *every* call, regardless of module-level caching flags.
4. **Production Import Error Enforcement**:
   - Module entrypoints (`agent/__init__.py`) MUST NOT swallow missing configuration `ValueError` exceptions in production. Exception suppression is permitted ONLY when `PYTEST_CURRENT_TEST` or `BLACKWALL_TEST_MODE` is present in `os.environ`.
5. **DSN & Credential Log Sanitization**:
   - Log messages MUST NEVER include raw DSN connection strings (`self.dsn`), URLs containing embedded credentials, or raw authentication keys. Omit DSN parameters or log sanitized host/port strings to prevent credential exposure in failure logs.
6. **Atomic Database Transactions & Cache Synchronization**:
   - Store modules persisting data across both a database backend and an in-memory cache MUST wrap database persistence statements in an explicit transaction (`async with conn.transaction():`), and mutate in-memory cache structures ONLY after successful DB commit. Re-ingesting duplicate items MUST preserve existing cached edge/relationship lists.
7. **Explicit Connection Error Escalation**:
   - Persistent store initialization methods MUST NOT silently degrade to in-memory mode when an explicit DSN is provided and `in_memory=False`. Connection exceptions MUST be raised to signal non-durable state to callers.

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
* **Async Coroutine Creation Safety**: When lazy-starting background tasks in classes or trackers (e.g. `_ensure_task_started()`), retrieve the running loop via `asyncio.get_running_loop()` before calling the coroutine function (e.g., `loop.create_task(self._loop())`) to prevent unawaited coroutine `RuntimeWarning` exceptions if no event loop is running.
* **Pytest Asyncio Marker Scoping**: In test modules containing both synchronous (`def`) and asynchronous (`async def`) tests, do NOT declare global module-level `pytestmark = pytest.mark.asyncio`. Decorate `async def` test functions individually with `@pytest.mark.asyncio` to prevent `PytestWarning` on synchronous test functions.
* **`aiohttp` Test Decorator Modernization**: Do not use the deprecated `@unittest_run_loop` decorator on `AioHTTPTestCase` subclasses; async test methods execute natively under modern `aiohttp` (>= 3.8).
* **Pytest Custom Marker Registration**: All custom markers used in BDD features or unit tests (e.g., `@pytest.mark.guardrails`, `@pytest.mark.zero_ambient_authority`) MUST be explicitly registered under `[tool.pytest.ini_options].markers` in `pyproject.toml` to prevent `PytestUnknownMarkWarning`.
* **Mocked Async Coroutine Teardown**: When mocking `asyncio.wait_for` or async wrapper functions with side-effects (e.g. raising `asyncio.TimeoutError`), the mock `side_effect` MUST invoke `if hasattr(fut, "close"): fut.close()` on the coroutine parameter before raising to prevent unawaited `RuntimeWarning` exceptions during garbage collection.
* **Async CLI Test Script Timeouts & Range Validation**: Async CLI test tools using `asyncio.gather` MUST validate numerical arguments (`concurrency_count > 0`) at function entry, wrap individual async network calls in per-request timeouts (e.g. `asyncio.wait_for(..., timeout=10.0)`), and wrap total batch gathers in overall timeouts with `return_exceptions=True` to report diagnostic summaries cleanly.
* **Absolute Imports in Test Modules**: In `tests/` subdirectories (e.g., `tests/integration/`, `tests/unit/`), always use absolute imports from the repository root (e.g., `from tests.integration.helpers import ...`) rather than relative imports (`from .helpers import ...`). Relative imports in test submodules cause `ImportError` during pytest collection.
* **Portable Documentation Links**: Markdown documentation files in `docs/` must use **repo-relative markdown paths** (e.g., `[helpers.py](../tests/integration/helpers.py)`), and must **never** hard-code local environment `file:///Users/...` or `file:///C:/...` URLs.
* **Mock Type Signature Alignment**: Test helper functions creating mock objects must ensure the return type annotation matches the actual mock class instantiated (`AsyncMock` vs `MagicMock`). Async side-effect handlers assigned to mock methods should be wrapped with `AsyncMock(side_effect=_fn)`.
* **Pydantic v2 Datetime Validation Hygiene**: Data models performing temporal comparisons in `@model_validator(mode="after")` (e.g. `end_time >= start_time`, `last_seen >= first_seen`) MUST enforce UTC timezone-awareness via `@field_validator` on all datetime fields to prevent unhandled `TypeError` exceptions on naive or non-UTC inputs.
* **Hypothesis Test Scope Isolation**: Property test modules MUST NOT call `settings.load_profile()` or `settings.register_profile()` at module import scope. Decorate individual test functions with `@settings(max_examples=100)` to prevent cross-test settings mutation.
* **Enterprise Mesh BDD Feature Alignment**: When implementing new enterprise security pillars or capabilities, add Gherkin scenarios to `tests/features/blackwall_enterprise_mesh.feature` and step definitions to `tests/step_defs/test_enterprise_mesh.py` in addition to any dedicated feature files.
* **Async BDD Step Execution Pattern**: In `pytest-bdd` step definitions executing asynchronous coroutines within synchronous step functions, steps MUST use the project's centralized `run_async(coro)` helper function rather than declaring nested `async def` functions with inline `asyncio.run(...)`.
* **Early Parameter Validation for Model Invariants**: Store query methods constructing Pydantic models with length or range invariants (e.g., `min_path_length >= 2` for `AttackPath`) MUST validate parameters at entry and raise `ValueError` before triggering downstream Pydantic validation exceptions.


