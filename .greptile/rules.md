# Blackwall Security Suite: Code Review Standards & Guidelines

This document outlines the repository policy, security invariants, and code review compliance requirements for the Blackwall Security Suite.

---

## 1. Product Tier Boundaries & Architecture Invariants

Blackwall is divided into two distinct product tiers:

### Blackwall Core (Developer Edition)
- **Single-Host Daemon**: Core components under `src/blackwall/` (outside `src/blackwall/enterprise/`) must remain a lightweight single-host daemon.
- **Core Attacker Attribution**: Single-host local attacker attribution (`AttackerIdentityExtractor`, `AttackerProfile`, `IncidentReportGenerator` in `src/blackwall/attribution/` & `SyncResolver`) is a shared baseline Core capability.
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

---

## 6. Testing Hygiene & TDD Standards

- **TDD Requirement**: Source code modifications must include corresponding unit/integration tests under `tests/` and property-based tests under `tests/property/`.
- **BDD Verification**: End-to-end security scenarios must pass using `pytest-bdd` under `tests/features/`.
- **Audit Hook Isolation**: Registrations of `sys.addaudithook` in tests MUST be scoped inside isolated test functions (never module-level).
- **Process Group Cleanup**: Background test processes MUST clean up process groups using `os.killpg(os.getpgid(pid), signal.SIGTERM)`.
- **Secret Scanner Hygiene**: Synthetic test credentials MUST NOT match live cloud provider key formats (e.g. `AWS_KEY_<digits>`).
