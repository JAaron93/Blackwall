# Requirements Document: Blackwall Rust Acceleration (`blackwall-rust-acceleration`)

## 1. Functional Requirements (FR)

- **FR-1: DFA-Based Regex Context Redaction & Hash Generation**
  - The Rust module MUST compile and execute regex redaction patterns using Deterministic Finite Automata (DFA) in guaranteed linear time $O(N)$.
  - The system MUST compute a SHA-256 hash for every redacted token match during the substitution pass.
  - The system MUST return structured redaction records containing `timestamp`, `original_hash`, `pattern_matched`, `placeholder_used`, and `context_size`.

- **FR-2: Vector Cosine Similarity & Word-Level Intersection Scoring**
  - The system MUST compute cosine similarity between 768-dimensional float query vectors and candidate vector buffers.
  - The system MUST compute word-level intersection match quality (`len(intersection) / min_len`) using zero-allocation tokenization.
  - Dimensionality mismatches or invalid vector bytes MUST raise standard `ValueError` exceptions with clear diagnostics.

- **FR-3: Multi-Pattern IOC Extraction & Shannon Entropy**
  - The system MUST extract IP addresses (IPv4/IPv6), URLs, domains, and cryptographic hashes in a single pass using `RegexSet`.
  - The system MUST validate IP octets and loopback addresses natively.
  - The system MUST compute Shannon entropy for input strings in a single $O(N)$ pass over byte frequencies.

- **FR-4: Fast Graph DFS Traversal & Temporal Pairwise Correlation**
  - The system MUST perform depth-first search (DFS) path enumeration across temporal adjacency graphs with cycle detection and depth limits.
  - The system MUST compute exponential decay temporal edge weights ($e^{-\Delta t / 300}$) and composite path risk scores.
  - The system MUST calculate pairwise temporal alignment scores across agent event streams using two-pointer algorithms.

- **FR-5: Transparent Python Wrapper & Pure-Python Fallback**
  - All Rust accelerators MUST be wrapped in Python modules (`context_hygiene.py`, `validators.py`, `semantic.py`, `correlator.py`).
  - If the compiled native extension `blackwall._core_rs` is not installed or importable, the Python wrappers MUST seamlessly fall back to pure-Python implementations with zero runtime errors.

- **FR-6: PyO3 Exception & Memory Safety**
  - All Rust FFI boundaries MUST return `PyResult<T>` and never panic (`panic = "abort"` in release builds).
  - Internal Rust errors MUST be mapped directly to appropriate Python built-in exception types (`PyValueError`, `PyRuntimeError`).

---

## 2. Non-Functional Requirements (NFR)

- **NFR-1: Latency Budget & Performance Multiplier**
  - Context redaction on payloads up to 10KB MUST complete in **< 50 microseconds** (a $>100\times$ speedup over Python multiprocessing).
  - 768-dimensional vector cosine similarity comparisons MUST complete in **< 20 microseconds** per 100 vectors.
  - Graph DFS traversal for up to 500 nodes MUST execute in **< 500 microseconds**.

- **NFR-2: Strict Output & Behavior Parity**
  - Redacted string outputs, placeholder positions, and original hash values MUST match character-for-character with legacy Python behavior.
  - Word intersection and cosine similarity scores MUST maintain numerical parity within float precision tolerance ($\epsilon \le 10^{-5}$).

- **NFR-3: ReDoS & Memory Safety Guarantee**
  - Regular expression evaluation MUST be mathematically guaranteed immune to catastrophic backtracking (zero ReDoS vulnerability).
  - Memory safety, buffer access bounds, and pointer conversions MUST be guaranteed by the Rust compiler.

- **NFR-4: Clean Build & Virtual Environment Integration**
  - The native extension MUST build cleanly via `maturin develop --release` or `pip install -e .` without requiring manual C toolchain modifications.

---

## 3. User Stories (US)

- **US-1: Real-Time Machine-Speed Tool Call Interception**
  - *As an* AI agent runtime orchestrator,
  - *I want* tool call arguments sanitized and checked against threat signatures in under 1 millisecond,
  - *So that* user tool execution experiences zero perceived latency lag.

- **US-2: High-Throughput Threat Graph Vector Search**
  - *As a* Blackwall security engine,
  - *I want* high-dimensional vector similarity scored across thousands of signatures in microseconds,
  - *So that* threat pattern matching does not delay the critical interception path.

- **US-3: Scalable Multi-Agent Swarm Detection**
  - *As an* Enterprise Security Mesh node,
  - *I want* pairwise correlation matrices and multi-stage graph paths computed in native machine code,
  - *So that* complex swarm attacks are detected across hundreds of concurrent agents in real time.

---

## 4. Behavior-Driven Development (BDD) Scenarios

```gherkin
Feature: Native Rust Acceleration for Blackwall Interception Hot Paths

  Scenario: High-Speed Context Hygiene Redaction with SHA-256 Hashes
    Given a tool call payload containing sensitive API keys and IP addresses
    When the context is sanitized using the native Rust ContextSanitizer
    Then all API keys MUST be replaced with [[API_KEY]]
    And all IP addresses MUST be replaced with [[IP_ADDRESS]]
    And a redaction log MUST be generated containing SHA-256 hashes of original matches
    And the sanitization elapsed time MUST be less than 100 microseconds

  Scenario: SIMD Vector Cosine Similarity and Word Intersection
    Given a 768-dimensional float query vector and raw candidate byte vector
    When cosine similarity is computed via the native similarity engine
    Then the calculated similarity score MUST match the expected mathematical cosine distance within 1e-5 tolerance
    And invalid vector dimensions MUST raise a Python ValueError

  Scenario: Seamless Pure-Python Fallback on Missing Extension
    Given an environment where the native Rust extension is not compiled
    When ContextHygiene or similarity scoring is invoked
    Then the system MUST automatically execute the pure-Python fallback implementation
    And the output results MUST remain identical with zero runtime exceptions
```
