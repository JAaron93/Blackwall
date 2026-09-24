# Greptile & Antigravity Agent Constitution: Blackwall Core & Architecture

## 1. Dual-Tier Project Context & Requirements

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials.

Blackwall is structured into **two distinct product tiers**:

1. **Blackwall Core (Individual Developer Edition)**:
   - Single-host Python daemon centered around ADK callbacks (`before_tool_callback`), Python runtime audit hooks (`sys.addaudithook`), local SQLite threat graph, native compiled Rust acceleration extension (`crates/blackwall_core_rs/` / `blackwall._core_rs` with pure-Python fallback), and baseline single-host Attacker Attribution (`src/blackwall/attribution/` & `SyncResolver`).
   - Primary local entry point: **Blackwall MCP Gateway** (specification governed by `.kiro/specs/blackwall-mcp-gateway/`, implemented via `src/blackwall/cli.py` with future specification target src/blackwall/gateway/), providing an agent-agnostic stdio/HTTP security proxy on `localhost:9229` with background PID daemon management (`~/.blackwall/blackwall.pid`) and macOS LaunchAgent service integration.
   - Zero cluster-mesh/peer-to-peer networking (ZeroMQ/NATS) or C-kernel eBPF dependencies (exemption: 100% GCP Vertex AI Mode clients for Gemini Enterprise Agent Platform and AlienVault OTX Threat Intelligence Engine are fully supported in Core; the approved Tier-1 Jev classifier `typesafe-ai/jev` egresses to Vercel AI Gateway on paid credits per ADR 0006 — sanitization-before-egress with mandatory `disallowPromptTraining: true`; red-teamer attack agents in demo harness use Hyperbolic API).
2. **Blackwall Enterprise Mesh (Enterprise Edition)**:
   - Multi-host security mesh isolated under `src/blackwall/enterprise/`.
   - Features C/Python eBPF kernel probes, Ephemeral Identity Sidecar, Data Pipeline Wrappers, Dual-Mode Local Forensic Triage Engine, 4 Open-Source Local MCP adapters, and Distributed Threat Mesh (`src/blackwall/enterprise/mesh/`).

---

## 2. Greptile Review Agent Directives & SDD Rules

All code submitted via pull requests or feature branches must be reviewed against these Greptile agent guardrails:

* **Greptile Review Directives**: Enforce Greptile agent review standards configured in `.greptile/config.json`, `.greptile/rules.md`, and `.greptile/files.json`. Greptile reviews must verify both Core and Enterprise architecture invariants.
* **Spec-Driven Consistency**: All edits must align with `.kiro/specs/` (`agent-swarm-attribution-logic`, `blackwall-advanced-threat-detection`, `blackwall-agentic-firewall`, `blackwall-attacker-attribution`, `blackwall-enterprise-security-mesh`, `blackwall-gcp-evaluation-coverage`, `blackwall-mcp-gateway`, `blackwall-rust-acceleration`, `blackwall-test-coverage-remediation`, `blackwall-threat-intel-cli` — `design.md`, `requirements.md`, `tasks.md`).

* **Behavior-Driven Specifications**: Verify all security behavior contracts using Gherkin syntax via `pytest-bdd` scenarios in `tests/features/`.
* **Strict Test-Driven Development (TDD)**: Every feature addition or bug fix must include a failing unit test or reproduction script before code changes are staged.

---

## 3. Core Architecture & Interception Flow (Base Branch Invariants)

Greptile reviews must enforce the existing base branch architectural patterns:

1. **Interception Resolver (`SyncResolver`) Sequence**:
   - Execution flow MUST follow: `Rate Check` -> `ContextHygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Threat Intelligence Validation (AlienVault OTX / Multi-Provider Orchestrator)` -> `Semantic Triage via pluggable jev|gemini backend (Tier-1 Jev P(threat) with 0.35/0.75 band, Gemini Tier-2 escalation; governed by .kiro/specs/tier-1-jev-addition/)` -> `Score Aggregation` -> `Threshold Verdict` -> `Optional Inline Signature Generation`.
2. **FTS5 Similarity Scoring & Match Quality**:
   - SQLite Threat Signature Graph queries MUST use word-level intersection match quality calculation (`match_quality = len(intersection) / min_len`) scaled by FTS fallback score and capped by dynamic threshold limits to prevent false positives.
3. **Context Hygiene & Sanitization**:
   - `ContextHygiene` middleware (production interception path uses the implementation in `src/blackwall/resolver.py`; the async variant in `src/blackwall/middleware/context_hygiene.py` is exercised by `tests/middleware/` only) must replace sensitive environment variable patterns with generic placeholders (`[[VARIABLE_NAME]]`).
   - Integration tests querying external hostnames (e.g. GTI / VirusTotal) must use un-redacted standalone hostnames (e.g. `wd-bouygues.com`) to prevent accidental sanitization matching.
4. **Threat Intelligence High-Capacity Invariant (AlienVault OTX & Legacy Fallback)**:
   - External threat intelligence is powered by in-process `AlienVaultOTXProvider` (10,000 queries/hour, ~166 RPM) with SQLite `threat_intel_cache` (<1ms SLA), replacing the restrictive 4 RPM VirusTotal GTI bottleneck. The only configured alternative primary provider is the Harpoon companion bridge, selected via `BW_THREAT_INTEL_PRIMARY=harpoon|harpoon-otx`; no VirusTotal client ships in `src/blackwall/threat_intel/` (see `docs/adr/0005-alienvault-otx-threat-intel-engine.md`).

---

## 4. Enterprise Security Mesh (5 Pillars & 4 Free Open-Source MCPs)

When reviewing or building Enterprise Mesh code under `src/blackwall/enterprise/`:

* **Pillar 1: Kernel-Level Interception (`blackwall.enterprise.kernel`) & `ebpf-falco-mcp`**
  - Dual-driver kernel probe: `LinuxeBPFDriver` (Linux kernel >= 5.4) with fallback to `UserSpaceAuditDriver` (`sys.addaudithook` on macOS).
* **Pillar 2: Distributed Threat Mesh (`blackwall.enterprise.mesh`)**
  - `MeshBroadcaster` and `MeshReceiver` communicating over ZeroMQ pub/sub sockets with <15ms SQLite signature persistence (integrated with `ActiveReactionEngine` reactions and `SQLiteThreatRepository` in WAL mode).
* **Pillar 3: Ephemeral Identity Sidecar (`blackwall.enterprise.identity`) & `hashicorp-vault-mcp`**
  - Honey-token interception (`BW_SYNTHETIC_*`) triggering instant `CRITICAL` verdicts, with short-lived STS tokens issued via Vault MCP.
* **Pillar 4: Application Pipeline Interception Wrappers (`blackwall.enterprise.pipeline`) & `container-sandbox-mcp`**
  - `guard_pipeline` decorator (`from blackwall.enterprise.pipeline import guard_pipeline`) and AST parser protecting dataset loaders, pickle parsers, and microVM container sandboxes.
* **Pillar 5: Native Local Forensic Triage Engine (`blackwall.enterprise.forensics`) & `opentelemetry-mcp`**
  - Dual-mode out-of-band telemetry log analyzer (local Ollama LLM with AST/regex fallback) and OpenTelemetry exporter.
* **Pillar 6: Advanced Threat Detection & Evaluation (`blackwall.enterprise.advanced_threat_detection`)**
  - Cross-pillar swarm, exploit chain, AILM, and C2 detection with `ActiveReactionEngine`.
  - **Dual-Tiered Evaluation Strategy**: Tier 1 (ADK Adversarial Harness in 100% GCP Vertex AI Mode) + Tier 2 (Cybench on Cloud Run with gVisor container isolation).
  - **100% Cloud-Native GCP Evaluation**: Zero-SaaS evaluation using GCP Vertex AI Gen AI Evaluation Service (`vertexai.preview.evaluation` / `EvalTask`), Google Cloud Trace, and ADK Trajectory Gating (`tool_trajectory_avg_score: 1.0` dual-gate protocol governed by `.agents/rules/testing_and_hygiene.md#51`), fully replacing legacy Weights & Biases (Weave).
  - **Agent-as-a-Judge Evaluation Pipeline**: 9 domain-specific autonomous Antigravity SDK judge agents (`google.antigravity.Agent`, `vertex=True`, `AgentBehavior.AUTONOMOUS`) producing structured Pydantic rubric scores under zero-trust XML prompt delimitation. Requires `GEMINI_TIER=paid` for 300+ RPM quota contract.
  - **Tier-1 CI Entry Point**: `scripts/run_gcp_eval.py` orchestrates domain judges, `SLAValidator` component latency measurement, the managed Vertex AI `EvalTask` gate (`COMPLETED` required), and `HistoricalRegressionTracker` baselines, exiting 0/1 as the CI gate.

---

## 5. Modular Guardrails & Rule Directory

Detailed architectural, security, database persistence, and testing hygiene rules are modularized under `.agents/rules/`:

* [`architecture_and_security.md`](.agents/rules/architecture_and_security.md): DSN log privacy, atomic DB transactions, explicit connection error escalation, credential purging, and import handling.
* [`testing_and_hygiene.md`](.agents/rules/testing_and_hygiene.md): SLA warmup benchmarking, audit hook isolation, BDD `run_async` step execution, Pydantic model validation, Pytest asyncio scoping, and property test isolation.

---

## 6. Constitution & Rule Maintenance Protocol

Agents updating or expanding project rules (e.g. via `/learn` or code review resolutions) MUST adhere to the following governance:

1. **Root `AGENTS.md` Scope**:
   - Reserved exclusively for core product identity, dual-tier architecture invariants, Greptile review directives, high-level interception sequences, and pointers to `.agents/rules/`.
   - Do NOT add granular function-level or test-specific rules directly to `AGENTS.md`.

2. **`.agents/rules/` Scope**:
   - Detailed implementation guardrails, DB transaction guidelines, logging privacy, BDD execution patterns, and test hygiene MUST be added to (or updated within) modular rule files under `.agents/rules/` (e.g. `architecture_and_security.md`, `testing_and_hygiene.md`).

3. **Learning & Proposal Workflow**:
   - Before modifying project rules, agents MUST draft a proposal artifact (`learning_proposal` or `implementation_plan`) outlining the classification, rationale, and exact diffs, and obtain explicit user approval before staging changes.


---

## 7. Antigravity 2.0 CLI-First Architecture & Tool Governance

> [!NOTE]
> **Developer Tooling Scope vs. Blackwall Product Architecture**:
> This CLI-first protocol strictly governs **agentic developer workflows** (how AI coding assistants, subagents, and review bots develop and operate on this codebase using CLI tools rather than stateless MCP servers). It does **NOT** restrict the runtime architecture of Blackwall itself. The Blackwall agent is an **agent-agnostic MCP Gateway security proxy** (`localhost:9229`, background daemon, macOS LaunchAgent service) that actively integrates with `codebase-memory-mcp` AST knowledge graphs, AlienVault OTX Threat Intelligence Engine, and enterprise MCP adapters (Falco, Vault, Container Sandbox, OpenTelemetry).

Antigravity operates on a **CLI-first, stateful-MCP-sparing architecture** for repository development:

### 1. GitHub CLI (`gh`) & Git Operational Guardrails
* **Feature Branches Only**: All code modifications must occur within an isolated git worktree and be pushed to a dedicated feature branch. Direct commits or pushes to `main` and `master` are strictly prohibited.
* **No Autonomous Merging**: Agents may create Pull Requests via `gh pr create` and inspect reviews via `gh pr view`, but are strictly forbidden from merging Pull Requests via the terminal (`gh pr merge` is prohibited) or any API. A human must review and merge all code.
* **Pre-Commit Hygiene**: Before staging files via `git add`, verify that no `.env` files, API keys, credentials, or `.sqlite` WAL files are included in the commit payload.
* **No Destructive API / CLI Actions**: Repository deletion, branch protection tampering, and visibility modifications are blocked at the token level and strictly prohibited by rule.

### 2. CLI Output Hygiene & Token Conservation Protocol
To maintain strict token economy across long-running sessions, agents must adhere to output-limiting practices:
* **Mandatory Projection Flags**: On tools with structured output support (`gh`, `gcloud`, `aws`, `docker`), always specify output projections:
  - `gh`: Use `--json <fields>` and `--limit <N>` (e.g. `gh pr list --limit 10 --json number,title,author,headRefName,state`).
  - `gcloud`: Use `--format="value(field)"` or `--format="table(field1,field2)"`.
  - `docker`: Use `--format "{{.ID}}: {{.Names}} ({{.Status}})"`.
* **Unix Pipeline Filtering**: Filter raw text streams before they reach model context. Pipe through `jq`, `head -n <N>`, `grep`, `awk`, or `cut` (e.g. `gh run view <id> --log-failed | head -n 50`).
* **Scratch File Buffering for Large Outputs**: If a diagnostic command or test run generates more than 100 lines of logs, redirect or tee it to the conversation scratch directory and inspect targeted segments with `grep` or `head` rather than dumping full traces into context.
* **Atomic Pipelines Over Chatty Turns**: Prefer chaining commands in a single shell invocation using `&&` or pipelines (`|`) rather than executing separate single-command tool calls across multiple turns.

### 3. MCP Scope & Stateful Boundaries
* **MCP Reserved Tier (Stateful & Daemon Integrations Only)**:
  - **AST Knowledge Graph**: `codebase-memory-mcp` maintains the persistent SQLite Abstract Syntax Tree graph for codebase navigation and call-graph tracing.
  - **External Library Documentation**: `context7` resolves third-party package syntax and API definitions.
  - **Live Browser Sessions**: `chrome-devtools` and `axe-core` manage interactive Chrome DevTools Protocol (CDP) sessions and accessibility validation.
  - **Automated Review Agent Gateways**: `greptile` triggers and manages PR code reviews.
* **CLI Tier (Stateless Operations)**:
  - All version control, pull requests, issues, cloud infrastructure, container management, and build tasks MUST execute through native CLI tools (`gh`, `git`, `gcloud`, `aws`, `docker`, `cargo`, `npm`, etc.) paired with lightweight companion skills rather than stateless MCP servers.

### 4. Architectural Perpetuation & Downstream Agent Invariant
This CLI-first, MCP-sparing doctrine is a permanent, indefinite architectural standard. All future agents, subagents, and automated workflows governed by this constitution must:
1. **Perpetuate the Pattern**: Prioritize CLI binaries paired with lightweight skills rather than introducing new MCP servers.
2. **Defend the Boundaries**: Strictly reject the addition of stateless MCP servers (e.g. for Jira, Slack, Linear, Stripe, or cloud providers) whenever a mature CLI tool or scriptable API exists. Reserve MCP exclusively for persistent stateful daemons, database connections, AST memory graphs, and the designated Reserved Tier.
3. **Propagate to Project Invariants**: When authoring repository-level `AGENTS.md`, `.cursor/rules/`, or subagent system prompts, agents must explicitly codify this CLI-first discipline to ensure child agents and subagents inherit identical token hygiene.

