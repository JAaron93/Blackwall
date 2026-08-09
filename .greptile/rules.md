# Blackwall Security Suite: Code Review Standards & Guidelines

This document outlines the repository policy, security invariants, and code review compliance requirements for the Blackwall Security Suite.

---

## 1. Product Tier Boundaries & Architecture Invariants

Blackwall is divided into two distinct product tiers:

### Blackwall Core (Developer Edition)
- **Single-Host Daemon**: Core components under `src/blackwall/` (outside `src/blackwall/enterprise/`) must remain a lightweight single-host daemon.
- **Zero Cluster-Mesh / eBPF Dependencies**: Core must contain zero imports or dependencies on ZeroMQ, NATS, or eBPF C headers.
- **Support**: Core fully supports 100% GCP Vertex AI Mode (`google-genai` with `vertexai=True`).

### Blackwall Enterprise Mesh (Enterprise Edition)
- **Isolated Location**: All enterprise capabilities must reside exclusively under `src/blackwall/enterprise/`.
- **Subsystem Breakdown**:
  - **Pillar 1 (Kernel Interception)**: `src/blackwall/enterprise/kernel/` (`LinuxeBPFDriver` with fallback to `UserSpaceAuditDriver`).
  - **Pillar 2 (Threat Mesh)**: `src/blackwall/enterprise/mesh/` (ZeroMQ/NATS pub/sub socket communication with <15ms persistence).
  - **Pillar 3 (Ephemeral Identity Sidecar)**: `src/blackwall/enterprise/identity/` (Honey-tokens `BW_SYNTHETIC_*` and Vault MCP JIT STS tokens).
  - **Pillar 4 (Pipeline Interception & Sandboxes)**: `src/blackwall/enterprise/pipeline/` (`@blackwall.guard_pipeline` and container sandboxes).
  - **Pillar 5 (Forensic Engine & OpenTelemetry)**: `src/blackwall/enterprise/forensics/` (Dual-mode LLM triage with regex/AST fallback, OpenTelemetry exporter).
  - **Pillar 6 (Advanced Threat Detection & Attacker Attribution)**: `src/blackwall/enterprise/advanced_threat_detection/` (`EventStreamCollector`, `AttackGraphStore`, `AgentSwarmDetector`, `ExploitChainAnalyzer`, `AILMTracker`, `C2InfrastructureDetector`, `K8sDefenseLayer`, `RegistryMonitor`, `AttackerIdentityExtractor`, `AttackerProfile`, `IncidentReportGenerator`).

---

## 2. Interception Resolver & Scoring Rules

- **Execution Flow**: In `SyncResolver`, execution flow MUST follow:
  `Rate Check` -> `ContextHygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Conditional GTI Validation (High-Risk Only)` -> `Score Aggregation` -> `Threshold Verdict` -> `Optional Inline Signature Generation`.
- **Context Hygiene**: Sensitivity maskers MUST replace credentials with generic placeholders (`[[VARIABLE_NAME]]`).
- **FTS5 Similarity Scoring**: SQLite Threat Signature Graph queries MUST use word-level intersection match quality calculation scaled by BM25 rank score: `fts_rank_scale = min(max(1.0 + abs(bm25_rank) / 10.0, 1.0), 1.5)`.

---

## 3. Data Model & Pydantic Validation

- **Pydantic v2**: All models in `src/blackwall/enterprise/advanced_threat_detection/models.py` and attacker attribution modules MUST enforce strict Pydantic v2 validation.
- **Constraints**:
  - `event_id`: UUID v4 format.
  - `timestamps`: UTC timezone aware (`datetime.now(timezone.utc)`).
  - Risk/Threat scores: Bounded strictly in range `[0.0, 1.0]`.
  - Sequence lengths: Enforce minimum length constraints.
  - Temporal ordering: `end_time >= start_time`.
- **Fail-Closed Behavior**: Attacker attribution and security resolvers MUST fail closed cleanly without raising unhandled exceptions.

---

## 4. Testing Hygiene & TDD Standards

- **TDD Requirement**: Source code modifications must include corresponding unit/integration tests under `tests/` and property-based tests under `tests/property/`.
- **BDD Verification**: End-to-end security scenarios must pass using `pytest-bdd` under `tests/features/`.
- **Audit Hook Isolation**: Registrations of `sys.addaudithook` in tests MUST be scoped inside isolated test functions (never module-level).
- **Process Group Cleanup**: Background test processes MUST clean up process groups using `os.killpg(os.getpgid(pid), signal.SIGTERM)`.
- **Secret Scanner Hygiene**: Synthetic test credentials MUST NOT match live cloud provider key formats (e.g. `AWS_KEY_<digits>`).
