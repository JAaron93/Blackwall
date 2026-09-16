# ADR 0005: Non-Greedy Rust Native Acceleration for Latency-Critical Interception Hot Paths

## Status
Approved

## Context
Blackwall enforces a strict `<5ms` latency SLA on synchronous interception pipelines (`SyncResolver`). As attack payloads scale, adversarial agent velocities increase (up to 600 RPM), and threat graph sizes expand, pure-Python execution encounters severe CPU bottlenecks:

1. **Character-by-Character String Scanning & Regex Backtracking**: Python's `re` module performs NFA backtracking and incurs multi-process IPC serialization overhead, taking hundreds of microseconds to milliseconds on large argument payloads.
2. **Interpreted High-Dimensional Vector Math**: Evaluating cosine similarity across hundreds of 768-dimensional float vectors in Python requires deserializing binary blobs via `array.array("f")` and iterating through Python float loops, consuming 15–20ms per batch. Word-level intersection scoring (`compute_word_intersection_match_quality`) repeatedly allocates sets and regex tokens per FTS fallback row.
3. **Sequential Regex Passes & Entropy Calculation**: IOC extraction in Python runs multiple sequential regular expressions, splits IP octets manually, and calculates Shannon entropy with `collections.Counter` and `math.log2`.
4. **Deep Graph DFS & Temporal Alignment**: Recursive depth-first search (DFS) path traversal up to depth 10 over dense attack graphs and pairwise temporal correlation across agent pairs in Python loops introduce significant latency overhead.

Rewriting the entire application in a compiled systems language would destroy development agility and forfeit rich Python ecosystem integrations (FastAPI, Google GenAI SDK, Pydantic, aiosqlite, OpenTelemetry).

## Decision
We implemented a **Non-Greedy Rust Acceleration Subsystem (the 95/5 Rule)** using **PyO3** and **Maturin**:

```
+---------------------------------------------------------------------------------------------------+
|                        BLACKWALL HYBRID RUNTIME TOPOLOGY (95% Python / 5% Rust)                   |
+---------------------------------------------------+-----------------------------------------------+
|         HIGH-LEVEL PYTHON ORCHESTRATION LAYER     |        NATIVE RUST EXTENSION (_core_rs)       |
+---------------------------------------------------+-----------------------------------------------+
| - Async Interception Resolvers (Sync / Batch)     | - DFA Regex Sanitization (O(N), No IPC)       |
| - SQLite Async Connection Pool & WAL persistence  | - SIMD 768-dim Vector Cosine Similarity       |
| - Google GenAI SDK (Vertex AI Mode) & GTI MCP     | - Word-Level Intersection Scoring (<5µs)      |
| - Pydantic Data Models & Semantic Routing Policy  | - Single-Pass RegexSet IOC & Entropy Engine   |
| - Cloud-Native Vertex AI Eval & OpenTelemetry     | - Graph DFS Path Traversal & Swarm Correlator |
+---------------------------------------------------+-----------------------------------------------+
```

### 1. Non-Greedy Scope Demarcation
- 90–95% of the codebase remains in pure Python. Web routers, database drivers, Pydantic models, Gemini API clients, and telemetry exporters remain untouched.
- Only compute-heavy, latency-critical hot paths reside in Rust (`crates/blackwall_core_rs/`).
- Rust functions are called once per large payload with contiguous memory buffers (`&str` or byte slices `&[u8]`), returning structured outputs in a single FFI crossing to eliminate serialization chattiness.

### 2. The 4 Accelerated Hot-Path Subsystems
1. **Context Sanitization Engine (`src/sanitizer.rs` / `ContextSanitizer`)**:
   - Uses linear-time DFA regexes (guaranteed mathematically immune to ReDoS).
   - Supports dual modes:
     - *Middleware Mode* (`preserve_prefix=false`): Replaces full matched token (`api_key=SECRET` $\to$ `[[API_KEY]]`) and records `original_hash = sha256(matched_string)`.
     - *Resolver Mode* (`preserve_prefix=true`): Preserves credential prefixes in prompts (`api_key=SECRET` $\to$ `api_key=[[API_KEY]]`).
   - Latency SLA: $< 50\mu\text{s}$ on $\ge 9\text{KB}$ realistic payloads (measured $\approx 45\mu\text{s}$).
2. **Vector Math & Similarity Scoring Engine (`src/similarity.rs`)**:
   - Zero-copy byte buffer casting to `&[f32]` with auto-vectorized SIMD dot-product computation.
   - `batch_cosine_similarity`: Evaluates query vectors against an array of candidate vectors in a single FFI call.
   - *Resilient Candidate Isolation*: If an individual candidate vector row in the database contains corrupted bytes or dimensionality mismatches, the native accelerator excludes that candidate row with diagnostic warnings and continues scoring all valid rows without aborting the batch.
   - Word intersection match quality: Zero-allocation lowercase tokenization returning $\frac{|\text{query} \cap \text{cand}|}{\min(|\text{query}|, |\text{cand}|)}$ in $< 10\mu\text{s}$ (measured $\approx 5\mu\text{s}$).
3. **Single-Pass IOC Extraction & Shannon Entropy Engine (`src/iocs.rs`)**:
   - Single combined DFA pass via `RegexSet` detecting IPv4, IPv6, URLs, domains, and hashes.
   - Direct IP address validation via Rust `std::net::IpAddr`.
   - Single-pass 256-element byte frequency array computing Shannon entropy: $H(X) = -\sum p_i \log_2(p_i)$.
   - Latency SLA: $< 35\mu\text{s}$ combined on 1KB payloads (measured $\approx 20\mu\text{s}$).
4. **Graph DFS Traversal & Temporal Correlation Engine (`src/graph.rs`)**:
   - Native recursive DFS path enumeration with cycle prevention and depth pruning ($\le 10,000$ limit).
   - Exponential decay edge weighting and pairwise two-pointer timestamp alignment (`avg_min_time_diff`).
   - Latency SLA: $< 500\mu\text{s}$ for 500 nodes with `max_paths=50` (measured $\approx 340\mu\text{s}$).

### 3. Zero-Panic FFI & Seamless Pure-Python Fallback
- All Rust PyO3 functions return `PyResult<T>` and never panic across the C ABI. Internal errors map directly to standard Python exceptions (`ValueError`, `RuntimeError`).
- All 7 Python wrappers (`context_hygiene.py`, `resolver.py`, `validators.py`, `repository.py`, `semantic.py`, `correlator.py`, `swarm.py`) provide seamless pure-Python fallbacks when the compiled binary is unbuilt.

### 4. Dual-Tier Benchmark Calibration
- Pure native compute throughput (e.g. $<20\mu\text{s}$ per 100 vector comparisons) is verified natively via `cargo test`.
- Python integration benchmarks (`scripts/benchmark_rust_hotpaths.py`) gate vector similarity via an empirical **speedup ratio** ($\ge 35\times$, measured $\approx 50\text{--}70\times$ faster than pure-Python `array.array` loops), properly accounting for PyO3 FFI marshaling overhead.

## Consequences
- **Pros:**
  - Microsecond-level execution across all 4 hot paths, keeping total `SyncResolver` evaluation well under the $<5\text{ms}$ SLA (measured $\approx 460\mu\text{s}$).
  - $>50\times$ speedup on batch vector searches and $>100\times$ speedup on context sanitization.
  - Zero ReDoS vulnerability via DFA regex execution.
  - Full backward compatibility and zero platform lock-in through automated pure-Python fallbacks.
  - Clean build integration via Maturin (`pyproject.toml` and `Cargo.toml`).
- **Cons:**
  - Requires Rust 1.70+ (`cargo` / `rustc`) when building from source with native acceleration.
  - C ABI boundaries require careful memory layout management and type conversion boundaries.
