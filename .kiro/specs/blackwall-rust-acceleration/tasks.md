# Task Implementation Plan: Blackwall Rust Acceleration (`blackwall-rust-acceleration`)

This task document defines the test-driven implementation plan for the Blackwall Rust Acceleration subsystem, breaking down requirements into modular execution tracks with explicit dependencies, parallelism highlights, and strict TDD/BDD validation gates.

---

## Task Matrix & Traceability

| Task ID | Component | Requirements Covered | Dependencies | Execution Mode | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TASK-1.1** | Rust Crate Scaffolding & Maturin Build | FR-5, FR-6, NFR-4 | None | Sequential | **`[x] COMPLETE`** |
| **TASK-1.2** | PyO3 Module Stub & Build Verification | FR-6, NFR-4 | TASK-1.1 | Sequential | **`[x] COMPLETE`** |
| **TASK-2.1** | Rust `ContextSanitizer` (Dual-Mode) & Hasher | FR-1, NFR-1, NFR-2, NFR-3 | TASK-1.2 | Sequential | **`[x] COMPLETE`** |
| **TASK-2.2** | Python `ContextHygiene` Wrappers & Fallbacks | FR-1, FR-5, NFR-2 | TASK-2.1 | Sequential | **`[x] COMPLETE`** |
| **TASK-2.3** | Context Hygiene BDD & Property Tests | FR-1, NFR-2, NFR-3 | TASK-2.2 | Sequential | **`[x] COMPLETE`** |
| **TASK-3A.1**| Rust SIMD Cosine & Malformed Isolation | FR-2, NFR-1, NFR-2 | TASK-1.2 | Parallel Track A | `[ ] PENDING` |
| **TASK-3A.2**| Python `validators.py` / `repository.py` Wrap | FR-2, FR-5, NFR-2 | TASK-3A.1 | Parallel Track A | `[ ] PENDING` |
| **TASK-3A.3**| Vector & Match Quality Verification Tests | FR-2, NFR-1, NFR-2 | TASK-3A.2 | Parallel Track A | `[ ] PENDING` |
| **TASK-3B.1**| Rust `RegexSet` IOC & Entropy Engine | FR-3, NFR-1, NFR-3 | TASK-1.2 | Parallel Track B | `[ ] PENDING` |
| **TASK-3B.2**| Python `semantic.py` Wrapper & Fallback | FR-3, FR-5, NFR-2 | TASK-3B.1 | Parallel Track B | `[ ] PENDING` |
| **TASK-3B.3**| IOC Extraction & Entropy Unit Tests | FR-3, NFR-1, NFR-2 | TASK-3B.2 | Parallel Track B | `[ ] PENDING` |
| **TASK-4.1** | Rust Graph DFS & Temporal Correlator | FR-4, NFR-1, US-3 | TASK-1.2 | Sequential | `[ ] PENDING` |
| **TASK-4.2** | Python `correlator.py` / `swarm.py` Wrap | FR-4, FR-5, US-3 | TASK-4.1 | Sequential | `[ ] PENDING` |
| **TASK-4.3** | Path & Swarm Correlation BDD Tests | FR-4, NFR-1, US-3 | TASK-4.2 | Sequential | `[ ] PENDING` |
| **TASK-5.1** | End-to-End SLA Benchmarking & Verification | NFR-1, US-1, US-2 | TASK-2.3, TASK-3A.3, TASK-3B.3, TASK-4.3 | Sequential | `[ ] PENDING` |
| **TASK-5.2** | Full Suite Regression & Fallback Invariant | All FRs, All NFRs | TASK-5.1 | Sequential | `[ ] PENDING` |

---

## Track 1: Rust Crate Foundation & Maturin Build Pipeline
 
### - [x] TASK-1.1: Scaffolding `crates/blackwall_core_rs` Cargo Crate & Portable Build Config
- **Description**: Create `crates/blackwall_core_rs/Cargo.toml` configuring `crate-type = ["cdylib"]`, `pyo3` with `extension-module` features, `regex`, `sha2`, and `serde`. Configure `pyproject.toml` to support Maturin builds using standard toolchains discovered in `PATH` or `$CARGO_HOME/bin`.
- **Dependencies**: None.
- **Traceability**: FR-5, FR-6, NFR-4.
- **Validation**: Verify `cargo check` passes across standard macOS and Linux environments.

### - [x] TASK-1.2: PyO3 Module Stub & Build Verification (TDD)
- **Description**: Create `crates/blackwall_core_rs/src/lib.rs` exporting basic module functions and version checks. Verify compilation with `maturin develop --release` into `.venv`.
- **Dependencies**: TASK-1.1.
- **Traceability**: FR-6, NFR-4.
- **TDD Requirement**: Write test in `tests/test_rust_bindings.py` asserting `import blackwall._core_rs` loads properly and reports version string.


---

## Track 2: Context Hygiene & Redaction Engine

### - [x] TASK-2.1: Implement Rust `ContextSanitizer` with Dual-Mode Support & Match Hashing
- **Description**: Implement `crates/blackwall_core_rs/src/sanitizer.rs` with compiled DFA regex replacement supporting both:
  1. Middleware mode (`preserve_prefix = false`): replaces full match (`api_key=SECRET` $\rightarrow$ `[[API_KEY]]`) and records `original_hash = sha256(match.group(0))`.
  2. Resolver mode (`preserve_prefix = true`): preserves prefixes for prompt templates (`api_key=SECRET` $\rightarrow$ `api_key=[[API_KEY]]`).
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-1, NFR-1, NFR-2, NFR-3.
- **TDD Requirement**: Write unit tests in Rust (`cargo test`) verifying:
  1. In Middleware mode (`preserve_prefix = false`): exact full-match substitution parity and SHA-256 `original_hash` digest parity with `blackwall.middleware.context_hygiene`.
  2. In Resolver mode (`preserve_prefix = true`): exact prefix-preserving prompt substitution parity with `blackwall.resolver.ContextHygiene` (without generating redaction records or hashes).

### - [x] TASK-2.2: Implement Python `ContextHygiene` Thin Wrappers & Pure-Python Fallbacks
- **Description**: Update `src/blackwall/middleware/context_hygiene.py` (middleware mode) and `src/blackwall/resolver.py` (resolver mode) to route sanitization directly to `_core_rs.ContextSanitizer`, completely eliminating the `KillableRegexWorker` multiprocessing spawn, while preserving pure-Python fallback logic.
- **Dependencies**: TASK-2.1.
- **Traceability**: FR-1, FR-5, NFR-2.
- **TDD Requirement**: Run `pytest tests/middleware/test_context_hygiene.py tests/test_sync_resolver.py` to verify both suites pass without IPC.

### - [x] TASK-2.3: Context Hygiene BDD & Property-Based Test Verification
- **Description**: Execute hypothesis property tests (`tests/middleware/test_context_hygiene_properties.py`) and Gherkin BDD scenarios to verify idempotency, structure preservation, and $<50\mu\text{s}$ latency.
- **Dependencies**: TASK-2.2.
- **Traceability**: FR-1, NFR-1, NFR-2, NFR-3.
- **BDD Requirement**: Verify all hypothesis test cases pass with zero failures.

---

## Track 3: Similarity Scoring & IOC Extraction (Parallel Tracks)

> [!TIP] PARALLEL EXECUTION
> Track 3A (Vector Similarity & Word Match) and Track 3B (IOC Extraction & Entropy) can be developed concurrently once Track 1 is complete.

### - [ ] TASK-3A.1: Implement Rust SIMD Vector Cosine, Malformed Candidate Isolation & Word Match (Track 3A)
- **Description**: Create `crates/blackwall_core_rs/src/similarity.rs` implementing SIMD-aligned cosine similarity over `&[f32]` byte slices, resilient malformed candidate isolation (excluding corrupted database rows while scoring valid candidates), and zero-allocation lowercase word-intersection matching. Raise `ValueError` on invalid query vector dimensions.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-2, NFR-1, NFR-2.
- **TDD Requirement**: Write Rust tests verifying:
  1. Cosine similarity mathematical accuracy against numpy/scipy.
  2. Exclusion of corrupted candidate rows in batch queries without aborting the batch.
  3. Word-intersection match quality parity.

### - [ ] TASK-3A.2: Integrate Vector & Match Quality into Python Wrappers (Track 3A)
- **Description**: Update `src/blackwall/validators.py` and `src/blackwall/db/repository.py` to use `_core_rs.batch_cosine_similarity` and `_core_rs.compute_word_intersection_match_quality` with pure-Python fallback, preserving diagnostic exclusion logs for corrupted database rows.
- **Dependencies**: TASK-3A.1.
- **Traceability**: FR-2, FR-5, NFR-2.
- **TDD Requirement**: Run `pytest tests/unit/test_validators.py tests/db/test_repository_similarity.py`.

### - [ ] TASK-3A.3: Vector & Match Quality Verification Suite (Track 3A)
- **Description**: Benchmark 768-dim vector searches over 1,000 candidate vectors to verify $<20\mu\text{s}$ latency and assert exact score parity.
- **Dependencies**: TASK-3A.2.
- **Traceability**: FR-2, NFR-1, NFR-2.

---

### - [ ] TASK-3B.1: Implement Rust Single-Pass `RegexSet` IOC Extractor & Shannon Entropy (Track 3B)
- **Description**: Create `crates/blackwall_core_rs/src/iocs.rs` implementing combined `RegexSet` matching for IPv4/IPv6, URLs, domains, hashes, and 256-bin Shannon entropy calculation.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-3, NFR-1, NFR-3.
- **TDD Requirement**: Write Rust unit tests verifying extraction and entropy matching Python reference implementations.

### - [ ] TASK-3B.2: Integrate IOC Extractor into `semantic.py` & Forensics (Track 3B)
- **Description**: Update `src/blackwall/policy/semantic.py` to route `extract_iocs` and `calculate_entropy` to `_core_rs` with pure-Python fallback.
- **Dependencies**: TASK-3B.1.
- **Traceability**: FR-3, FR-5, NFR-2.
- **TDD Requirement**: Run `pytest tests/unit/test_semantic_gating.py`.

### - [ ] TASK-3B.3: IOC & Entropy Test Verification (Track 3B)
- **Description**: Verify semantic gating test suite and edge-case inputs (IPv6 loopbacks, malformed URLs).
- **Dependencies**: TASK-3B.2.
- **Traceability**: FR-3, NFR-1, NFR-2.

---

## Track 4: Graph DFS Traversal & Swarm Correlator

### - [ ] TASK-4.1: Implement Rust Graph DFS Traversal & Temporal Pairwise Matrix
- **Description**: Create `crates/blackwall_core_rs/src/graph.rs` implementing native DFS path enumeration with cycle pruning, exponential decay edge weighting, and two-pointer temporal alignment.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-4, NFR-1, US-3.
- **TDD Requirement**: Write Rust tests verifying path discovery and score calculation on synthetic multi-stage attack graphs.

### - [ ] TASK-4.2: Integrate Graph Engine into Python `correlator.py` & `swarm.py`
- **Description**: Update `src/blackwall/enterprise/advanced_threat_detection/correlator.py` and `swarm.py` to route DFS traversal and pairwise correlation to `_core_rs` with pure-Python fallback.
- **Dependencies**: TASK-4.1.
- **Traceability**: FR-4, FR-5, US-3.
- **TDD Requirement**: Run `pytest tests/unit/test_path_correlator.py tests/unit/test_agent_swarm_detector.py`.

### - [ ] TASK-4.3: Path & Swarm Correlation BDD Scenarios
- **Description**: Run BDD feature tests in `tests/step_defs/test_path_correlation_bdd.py` and `tests/step_defs/test_agent_swarm_detector_bdd.py`.
- **Dependencies**: TASK-4.2.
- **Traceability**: FR-4, NFR-1, US-3.

---

## Track 5: System Integration, Benchmarks, & Verification

### - [ ] TASK-5.1: End-to-End SLA Benchmarking & Verification
- **Description**: Run automated latency comparison script across all 4 optimized hot paths against baseline Python metrics, asserting $<50\mu\text{s}$ context redaction and $<5\text{ms}$ total `SyncResolver` SLA.
- **Dependencies**: TASK-2.3, TASK-3A.3, TASK-3B.3, TASK-4.3.
- **Traceability**: NFR-1, US-1, US-2.

### - [ ] TASK-5.2: Full Suite Regression & Pure-Python Fallback Invariant
- **Description**: Execute the complete Blackwall test suite with compiled Rust extension active, then uninstall/rename extension and verify 100% test pass rate in pure-Python fallback mode.
- **Dependencies**: TASK-5.1.
- **Traceability**: All FRs, All NFRs.
