# Qodo & Antigravity Agent Constitution: Blackwall Core & Architecture

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
   - Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g. `wd-bouygues.com`) to prevent accidental sanitization matching.

---

## 4. Enterprise Security Mesh (5 Pillars & 4 Free Open-Source MCPs)

When reviewing or building Enterprise Mesh code under `src/blackwall/enterprise/`:

* **Pillar 1: Kernel-Level Interception (`blackwall.enterprise.kernel`) & `ebpf-falco-mcp`**
  - Dual-driver kernel probe: `LinuxeBPFDriver` (Linux kernel >= 5.4) with fallback to `UserSpaceAuditDriver` (`sys.addaudithook` on macOS).
* **Pillar 2: Distributed Threat Mesh (`blackwall.enterprise.mesh`)**
  - `MeshBroadcaster` and `MeshReceiver` communicating over ZeroMQ/NATS pub/sub sockets with <15ms signature persistence.
* **Pillar 3: Ephemeral Identity Sidecar (`blackwall.enterprise.identity`) & `hashicorp-vault-mcp`**
  - Honey-token interception (`BW_SYNTHETIC_*`) triggering instant `CRITICAL` verdicts, with short-lived STS tokens issued via Vault MCP.
* **Pillar 4: Application Pipeline Interception Wrappers (`blackwall.enterprise.pipeline`) & `container-sandbox-mcp`**
  - `@blackwall.guard_pipeline` decorator and AST parser protecting dataset loaders, pickle parsers, and microVM container sandboxes.
* **Pillar 5: Native Local Forensic Triage Engine (`blackwall.enterprise.forensics`) & `opentelemetry-mcp`**
  - Dual-mode out-of-band telemetry log analyzer (local Ollama LLM with AST/regex fallback) and OpenTelemetry exporter.

---

## 5. Modular Guardrails & Rule Directory

Detailed architectural, security, database persistence, and testing hygiene rules are modularized under `.agents/rules/`:

* [`architecture_and_security.md`](.agents/rules/architecture_and_security.md): DSN log privacy, atomic DB transactions, explicit connection error escalation, credential purging, and import handling.
* [`testing_and_hygiene.md`](.agents/rules/testing_and_hygiene.md): SLA warmup benchmarking, audit hook isolation, BDD `run_async` step execution, Pydantic model validation, Pytest asyncio scoping, and property test isolation.

---

## 6. Constitution & Rule Maintenance Protocol

Agents updating or expanding project rules (e.g. via `/learn` or code review resolutions) MUST adhere to the following governance:

1. **Root `AGENTS.md` Scope**:
   - Reserved exclusively for core product identity, dual-tier architecture invariants, Qodo review directives, high-level interception sequences, and pointers to `.agents/rules/`.
   - Do NOT add granular function-level or test-specific rules directly to `AGENTS.md`.

2. **`.agents/rules/` Scope**:
   - Detailed implementation guardrails, DB transaction guidelines, logging privacy, BDD execution patterns, and test hygiene MUST be added to (or updated within) modular rule files under `.agents/rules/` (e.g. `architecture_and_security.md`, `testing_and_hygiene.md`).

3. **Learning & Proposal Workflow**:
   - Before modifying project rules, agents MUST draft a proposal (`learning_proposal.md` or `implementation_plan.md`) outlining the classification, rationale, and exact diffs, and obtain explicit user approval before staging changes.
