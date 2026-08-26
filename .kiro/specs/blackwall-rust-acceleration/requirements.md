# Requirements Document: Blackwall Rust Acceleration (`blackwall-rust-acceleration`)

## 1. Functional Requirements (FR)

- **FR-1: DFA-Based Regex Context Redaction & Hash Generation**
  - The Rust module MUST compile and execute regex redaction patterns using Deterministic Finite Automata (DFA) in guaranteed linear time $O(N)$.
  - The system MUST support two distinct sanitization modes matching the architecture:
    - **Middleware Redaction Mode** (`blackwall.middleware.context_hygiene`): Replaces the full matched pattern (e.g. `api_key=SECRET123` $\rightarrow$ `[[API_KEY]]`, `10.0.0.1` $\rightarrow$ `[[IP_ADDRESS]]`) and returns structured `RedactionRecord` logs.
    - **Resolver Redaction Mode** (`blackwall.resolver.ContextHygiene`): Preserves key and delimiter prefixes in prompts (e.g. `api_key=SECRET123` $\rightarrow$ `api_key=[[API_KEY]]`, `password="secret"` $\rightarrow$ `password="[[PASSWORD]]"`), while performing full-token substitution for standalone indicators.
  - The system MUST compute the authoritative `original_hash` for every match in Middleware mode as the SHA-256 digest of the entire matched substring (`match.group(0)`).
  - The system MUST return structured redaction records containing `timestamp`, `original_hash`, `pattern_matched`, `placeholder_used`, and `context_size`.

- **FR-2: Vector Cosine Similarity & Word-Level Intersection Scoring**
  - The system MUST compute cosine similarity between 768-dimensional float query vectors and candidate vector buffers.
  - If a **query vector** has an invalid dimension ($\ne 768$) or invalid type, the system MUST raise a `ValueError`.
  - If an individual **stored candidate vector** contains malformed bytes or a dimension mismatch during batch similarity evaluation, the system MUST isolate and exclude that candidate from the similarity results with a diagnostic warning, while continuing to score all remaining valid candidates without aborting the batch query.
  - The system MUST compute word-level intersection match quality (`len(intersection) / min_len`) using zero-allocation tokenization.

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
  - In Middleware Mode, redacted string outputs, placeholder positions, and original hash values MUST match character-for-character with `blackwall.middleware.context_hygiene.ContextHygiene`.
  - In Resolver Mode, prompt string replacements MUST match character-for-character with `blackwall.resolver.ContextHygiene`.
  - Word intersection and cosine similarity scores MUST maintain numerical parity within float precision tolerance ($\epsilon \le 10^{-5}$).

- **NFR-3: ReDoS & Memory Safety Guarantee**
  - Regular expression evaluation MUST be mathematically guaranteed immune to catastrophic backtracking (zero ReDoS vulnerability).
  - Memory safety, buffer access bounds, and pointer conversions MUST be guaranteed by the Rust compiler.

- **NFR-4: Portable Build & Cross-Platform Toolchain Integration**
  - The native extension MUST build cleanly via `maturin develop --release` or `pip install -e .` using standard `cargo`/`rustc` toolchains in `PATH` or `$CARGO_HOME/bin` across macOS (x86_64, ARM64 Apple Silicon) and Linux container environments.

---

## 3. User Stories (US)

- **US-1: Real-Time Machine-Speed Tool Call Interception**
  - *As an* AI agent runtime orchestrator,
  - *I want* tool call arguments sanitized and checked against threat signatures in under 1 millisecond,
  - *So that* user tool execution experiences zero perceived latency lag.

- **US-2: High-Throughput Threat Graph Vector Search**
  - *As a* Blackwall security engine,
  - *I want* high-dimensional vector similarity scored across thousands of signatures in microseconds with resilient isolation of corrupted database rows,
  - *So that* threat pattern matching remains robust and fast.

- **US-3: Scalable Multi-Agent Swarm Detection**
  - *As an* Enterprise Security Mesh node,
  - *I want* pairwise correlation matrices and multi-stage graph paths computed in native machine code,
  - *So that* complex swarm attacks are detected across hundreds of concurrent agents in real time.

---

## 4. Behavior-Driven Development (BDD) Scenarios

```gherkin
Feature: Native Rust Acceleration for Blackwall Interception Hot Paths

  Scenario: High-Speed Middleware Context Hygiene Redaction with Original Hashes
    Given a tool call payload containing "api_key=SECRET_TOKEN_XYZ_12345" and "host=192.168.1.100"
    When the context is sanitized in Middleware Mode using native Rust ContextSanitizer
    Then the entire API key match MUST be replaced with "[[API_KEY]]"
    And the IP address MUST be replaced with "[[IP_ADDRESS]]"
    And the redaction log MUST contain the SHA-256 hash of "api_key=SECRET_TOKEN_XYZ_12345"
    And the sanitization elapsed time MUST be less than 100 microseconds

  Scenario: High-Speed Resolver Prompt Redaction with Prefix Preservation
    Given a prompt payload containing "api_key=SECRET_TOKEN_XYZ_12345"
    When the context is sanitized in Resolver Mode using native Rust ContextSanitizer
    Then the output string MUST preserve the prefix as "api_key=[[API_KEY]]"

  Scenario: Resilient Vector Cosine Similarity and Corrupted Candidate Isolation
    Given a valid 768-dimensional float query vector
    And a batch containing 10 valid 768-dim candidates and 1 malformed candidate vector
    When batch cosine similarity is computed via the native similarity engine
    Then all 10 valid candidates MUST be accurately scored within 1e-5 mathematical tolerance
    And the 1 malformed candidate MUST be isolated and reported without aborting the query batch

  Scenario: Invalid Query Vector Dimensionality Error
    Given an invalid 512-dimensional float query vector
    When cosine similarity is invoked
    Then a Python ValueError MUST be raised indicating incorrect query dimensionality

  Scenario: Seamless Pure-Python Fallback on Missing Extension
    Given an environment where the native Rust extension is not compiled
    When ContextHygiene or similarity scoring is invoked
    Then the system MUST automatically execute the pure-Python fallback implementation
    And the output results MUST remain identical with zero runtime exceptions
```
