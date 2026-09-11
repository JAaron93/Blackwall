# System Architecture Design: Blackwall Rust Acceleration (`blackwall-rust-acceleration`)

## 1. Executive Summary & Architectural Vision

Blackwall enforces a strict `<5ms` latency SLA on synchronous interception pipelines (`SyncResolver`). As attack payloads scale and context sizes increase, pure-Python execution encounters severe bottlenecks in character-by-character string scanning, regular expression backtracking, multi-process serialization overhead, and interpreted high-dimensional vector math.

The **Blackwall Rust Acceleration Subsystem** (`blackwall-rust-acceleration`) optimizes latency-critical, CPU-bound hot paths by rewriting them as high-performance, compiled Rust extensions using **PyO3** and **Maturin**, while adhering strictly to the **Non-Greedy Rewrite Philosophy (90/10 to 95/5 Rule)**:

```
+---------------------------------------------------------------------------------------------------+
|                        BLACKWALL HYBRID RUNTIME TOPOLOGY (95% Python / 5% Rust)                   |
+---------------------------------------------------+-----------------------------------------------+
|         HIGH-LEVEL PYTHON ORCHESTRATION LAYER     |        NATIVE RUST EXTENSION (_core_rs)       |
+---------------------------------------------------+-----------------------------------------------+
| - Async Interception Resolvers (Sync / Batch)     | - DFA Regex Sanitization (O(N), No IPC)       |
| - SQLite Async Connection Pool & WAL persistence  | - SIMD 768-dim Vector Cosine Similarity       |
| - Google GenAI SDK (Vertex AI Mode) & GTI MCP     | - Word-Level Intersection Scoring (<2µs)      |
| - Pydantic Data Models & Semantic Routing Policy  | - Single-Pass RegexSet IOC & Entropy Engine   |
| - Cloud-Native Vertex AI Eval & OpenTelemetry     | - Graph DFS Path Traversal & Swarm Correlator |
+---------------------------------------------------+-----------------------------------------------+
```

### 1.1 Non-Greedy Design Principles
- **Keep High-Level Frameworks in Python**: Web routers, database drivers (`aiosqlite`), Pydantic models, Gemini API clients, and telemetry exporters remain 100% in Python.
- **Eliminate FFI Serialization Chattiness**: Rust functions are called once per large payload with contiguous memory buffers (e.g. raw string references `&str` or float slices `&[f32]`), doing heavy computation and returning structured outputs in a single FFI crossing.
- **Zero-Panic & Fail-Safe Fallbacks**: The Rust crate exposes robust `PyResult<T>` error handling that maps internal errors directly to standard Python exceptions (`ValueError`, `RuntimeError`). If the compiled native extension is absent, thin wrappers automatically fall back to pure-Python implementations.

---

## 2. Core Architecture & Interception Flow Integration

The native Rust extension is compiled into a shared library module (`blackwall._core_rs`) and interfaced via Python thin wrappers:

```mermaid
flowchart TD
    subgraph Python Application Layer
        TR[Tool Call Request]
        SR[SyncResolver / BatchResolver]
        REPO[SQLiteThreatRepository]
        SG[SemanticGatingEngine]
        PC[PathCorrelator / SwarmDetector]
    end

    subgraph Python Thin Wrappers with Pure-Python Fallbacks
        W_CH[Middleware ContextHygiene Wrapper]
        W_RES[Resolver ContextHygiene Wrapper]
        W_VAL[validators.py Wrapper]
        W_SEM[semantic.py Wrapper]
        W_GR[correlator.py Wrapper]
    end

    subgraph Rust Native PyO3 Module (_core_rs)
        RS_CH[ContextSanitizer & Regex DFA Engine]
        RS_SIM[SIMD Vector Cosine & Word Match]
        RS_IOC[Single-Pass IOC & Shannon Entropy]
        RS_GR[Graph DFS & Pairwise Correlation]
    end

    TR --> SR
    SR -->|1. Sanitize| W_RES
    SR -->|Middleware Sanitize| W_CH
    SR -->|2. TSG Match| REPO
    REPO -->|Cosine Similarity| W_VAL
    SR -->|3. Gate & IOCs| SG
    SG -->|Extract IOCs & Entropy| W_SEM
    PC -->|4. Correlate Graph| W_GR

    W_CH -->|PyO3 <50µs (Full Match)| RS_CH
    W_RES -->|PyO3 <50µs (Preserve Prefix)| RS_CH
    W_VAL -->|PyO3 <2µs| RS_SIM
    W_SEM -->|PyO3 <20µs| RS_IOC
    W_GR -->|PyO3 <500µs| RS_GR
```

---

## 3. Subsystem Components & Data Interfaces

### 3.1 Subsystem 1: Context Hygiene & Redaction Engine (`blackwall.middleware.context_hygiene` & `blackwall.resolver`)
- **Problem**: The legacy Python implementation in `context_hygiene.py` uses a spawned multiprocessing worker (`KillableRegexWorker`) over IPC queues with an `asyncio.Lock` barrier to avoid ReDoS from Python's backtracking `re` engine. This introduces 10–25ms of IPC overhead and lock contention.
- **Dual-Mode Sanitization Semantics**:
  The Rust `ContextSanitizer` supports two explicit substitution modes matching the existing architecture:
  1. **Middleware Redaction Mode** (`preserve_prefix = false`):
     - Used by `blackwall.middleware.context_hygiene.ContextHygiene`.
     - Replaces the entire matched pattern (e.g. `api_key=SECRET123` $\rightarrow$ `[[API_KEY]]`).
     - Computes the authoritative `original_hash` as `SHA-256(matched_string)` for each `RedactionRecord`.
  2. **Resolver Prompt Redaction Mode** (`preserve_prefix = true`):
     - Used by `blackwall.resolver.ContextHygiene` in `SyncResolver` and `BatchResolver`.
     - Preserves credential prefixes/delimiters in prompts (e.g. `api_key=SECRET123` $\rightarrow$ `api_key=[[API_KEY]]`, `password="secret"` $\rightarrow$ `password="[[PASSWORD]]"`).
     - Standalone patterns (IPs, URLs, emails, file paths) undergo full-token substitution.
- **Rust Architecture**:
  - Utilizes the Rust `regex` crate which guarantees linear time $O(N)$ execution via Deterministic Finite Automata (DFA), making catastrophic backtracking mathematically impossible.
  - Eliminates multiprocessing IPC and lock contention with direct, in-process multithreaded DFA replacement.
  - Implements in-memory SHA-256 calculation (`sha2` crate) over the full matched token for metadata logging.
  - Returns `(sanitized_text: String, redactions: Vec<RedactionRecord>)`.

```rust
#[pyclass]
pub struct ContextSanitizer {
    patterns: Vec<CompiledPattern>,
}

#[derive(Serialize, Deserialize)]
pub struct RedactionRecord {
    pub timestamp: String,
    pub original_hash: String,
    pub pattern_matched: String,
    pub placeholder_used: String,
    pub context_size: usize,
}
```

### 3.2 Subsystem 2: Vector Math & Similarity Scoring Engine (`blackwall.validators` & `blackwall.db.repository`)
- **Problem**: Computing cosine similarities across hundreds of 768-dimensional float vectors in Python requires deserializing blobs via `array.array("f")` and running slow Python float loops. Word-level intersection scoring (`compute_word_intersection_match_quality`) repeatedly allocates sets and regex tokens per FTS fallback row.
- **Malformed Candidate Isolation**:
  - If a **query vector** has an invalid dimension ($\ne 768$) or type, the system raises a `ValueError`.
  - If an individual **stored candidate vector** in the database contains malformed bytes or dimension mismatches during batch evaluation, the native batch accelerator isolates and excludes that candidate row with an error/warning indicator, continuing evaluation of all remaining valid candidate rows without aborting the batch.
- **Rust Architecture**:
  - **Vector Cosine Similarity**: Directly casts byte buffers to `&[f32]` slices with zero-copy decoding. Calculates dot product and Euclidean norms using auto-vectorized SIMD instructions.
  - **Batch Cosine Similarity**: Evaluates query vectors against an array of candidate vectors in a single FFI call: `batch_cosine_similarity(query: &[f32], candidates: &[&[u8]], dim: usize, threshold: f32) -> (Vec<MatchResult>, Vec<InvalidCandidateError>)`.
  - **Word Intersection**: Zero-allocation ASCII/UTF-8 lowercase tokenization into pre-allocated hash sets or bitsets, returning `intersection_len as f64 / min(query_len, cand_len) as f64`.

### 3.3 Subsystem 3: Single-Pass IOC Extraction & Entropy Engine (`blackwall.policy.semantic`)
- **Problem**: `extract_iocs` executes 4 sequential regexes on every argument string, manually splits IP octets, and computes Shannon entropy using Python's `Counter` and `math.log2`.
- **Rust Architecture**:
  - Uses `RegexSet` to test for IPv4, IPv6, URL, domain, and hash patterns in a single combined DFA pass.
  - Validates IP addresses natively using `std::net::IpAddr`.
  - Calculates Shannon entropy in a single byte scan using a 256-element byte frequency array:
    $$H(X) = -\sum_{i=0}^{255} p_i \log_2(p_i)$$

### 3.4 Subsystem 4: Graph DFS & Temporal Correlation Engine (`blackwall.enterprise.advanced_threat_detection`)
- **Problem**: Deep path correlation (`PathCorrelator`) performs recursive DFS up to depth 10 to find attack paths, computing exponential decay weights per edge and pairwise correlation matrix computations across all agent pairs in interpreted Python loops.
- **Rust Architecture**:
  - Encodes the temporal adjacency graph into contiguous Rust structs `AttackNodeRust` and `AdjacencyList`.
  - Executes DFS path enumeration with cycle prevention and depth pruning in native machine code.
  - Evaluates pairwise two-pointer timestamp alignments (`_avg_min_time_diff`) and Jaccard action similarities over pre-sorted timestamp vectors.

---

## 4. Memory Layout, FFI Safety, & Thread Safety

### 4.1 FFI Memory Management & GIL Release
- For operations exceeding 1ms (e.g. large batch vector searches or deep graph traversals), Rust releases the Python Global Interpreter Lock (GIL) via `py.allow_threads(|| ...)` to allow concurrent Python async tasks to progress uninterrupted.

### 4.2 Error Handling & Exception Mapping
- No panics across the FFI boundary: all Rust functions return `PyResult<T>`.
- Internal validation failures map cleanly to Python standard exceptions:
  - Invalid query vector dimension $\rightarrow$ `PyValueError::new_err(...)`
  - Regex syntax errors $\rightarrow$ `PyValueError::new_err(...)`
  - Empty or invalid string arguments $\rightarrow$ `PyValueError::new_err(...)`

---

## 5. Build, Packaging, & Portable Toolchain Configuration

- **Cargo Workspace**: The Rust source resides in `crates/blackwall_core_rs/`.
- **Build Backend**: `pyproject.toml` integrates `maturin` (v1.7+) as the build tool, enabling standard `pip install -e .` and `maturin develop --release`.
- **Portable Toolchain Discovery**: The build configuration relies on standard `cargo` and `rustc` binaries discovered via the system `PATH` or standard `$CARGO_HOME/bin`, ensuring seamless compilation across macOS (Apple Silicon and x86_64), Linux containers, and CI/CD environments.
