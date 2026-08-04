# Blackwall Codebase — Centralized Helper Functions Reference

This document serves as the central documentation for all reusable helper functions, factory utilities, and test helpers across the Blackwall codebase. Developers and test authors should consult this reference to maintain the **DRY (Don't Repeat Yourself)** principle across all modules.

---

## 1. Integration Test Helpers

Located in [`tests/integration/helpers.py`](../tests/integration/helpers.py).

### `POLICY_YAML` (Constant)
* **Purpose:** Canonical policy configuration YAML string containing default environment roles (`sandbox`, `production`), structural rules, MCP server configs, and threat signature graph parameters.
* **Usage:** Use as the single source of truth for integration test policy definitions to avoid inline policy duplication.

### `make_policy_file(tmp_path: Path, db_name: str = "test_policy.db") -> str`
* **Purpose:** Writes `POLICY_YAML` to a temporary directory with an isolated SQLite database filename.
* **Location:** [`tests/integration/helpers.py`](../tests/integration/helpers.py)
* **Use Case:** Used in integration pytest fixtures (e.g. `policy_yaml_path`) to set up isolated policy files for pipeline testing without database lock conflicts.

### `make_structural_engine(policy_yaml_path: str) -> StructuralGatingEngine`
* **Purpose:** Instantiates a `StructuralGatingEngine` and loads the policy from the provided YAML file path.
* **Location:** [`tests/integration/helpers.py`](../tests/integration/helpers.py)
* **Use Case:** Replaces boilerplate engine creation across pipeline integration tests (`test_pipeline_checkpoint.py`, `test_checkpoint_18.py`).

### `make_mock_semantic_engine(verdict: VerdictDecision = VerdictDecision.ALLOW, latency_ms: float = 0.0, cpu_spin_ms: float = 0.0) -> AsyncMock`
* **Purpose:** Creates a mocked `SemanticGatingEngine` that returns a fixed verdict with optional simulated network latency (`latency_ms`) or CPU spin load (`cpu_spin_ms`).
* **Location:** [`tests/integration/helpers.py`](../tests/integration/helpers.py)
* **Use Case:** Used in pipeline latency tests, fast-path verification, and system resource load tests (`test_system_resource_consumption_load`).

---

## 2. Unit Test YAML Helpers

Located in [`tests/unit/policy_yaml_helpers.py`](../tests/unit/policy_yaml_helpers.py).

### `BASE_YAML_TEMPLATE` (Constant)
* **Purpose:** Base template string for structural gating unit tests supporting rule block string interpolation and SemVer header configuration.

### `make_yaml(rules_yaml: str, version: str = "1.0.0") -> str`
* **Purpose:** Indents a raw YAML rules fragment and interpolates it into `BASE_YAML_TEMPLATE`.
* **Location:** [`tests/unit/policy_yaml_helpers.py`](../tests/unit/policy_yaml_helpers.py)
* **Use Case:** Used across `tests/unit/test_structural_gating.py` to construct custom policy variants for priority, AST validation, and hot-reload tests.

### `write_temp_yaml(content: str) -> str`
* **Purpose:** Writes a string to a temporary `.yaml` file on disk and returns the absolute file path.
* **Location:** [`tests/unit/policy_yaml_helpers.py`](../tests/unit/policy_yaml_helpers.py)
* **Use Case:** Used in unit tests requiring physical file paths for `load_policy` or `PolicyWatcher`.

---

## 3. Core Architectural Helpers & Factories

Located across [`src/blackwall/`](../src/blackwall/).

### `create_resolver(...) -> Union[SyncResolver, BatchResolver]`
* **Purpose:** Factory function that instantiates either `SyncResolver` (free tier, serial evaluation) or `BatchResolver` (paid tier, asynchronous batching) based on the `BLACKWALL_TIER` environment variable.
* **Location:** [`src/blackwall/resolver.py`](../src/blackwall/resolver.py)
* **Use Case:** Interception layer initialization when booting Blackwall via ADK CLI or live demo scripts.

### `normalize_operators(expression: str) -> str`
* **Purpose:** Normalizes uppercase logical operators (`AND`, `OR`, `NOT`) in structural rule condition strings to Python-compatible lowercase operators while preserving text within string literals.
* **Location:** [`src/blackwall/policy/engine.py`](../src/blackwall/policy/engine.py)
* **Use Case:** Pre-processing YAML rule condition expressions before AST evaluation.

### `calculateMetrics(results: List[TestResult], ground_truth: List[GroundTruthLabel]) -> SecurityMetrics`
* **Purpose:** Computes security performance metrics including False Refusal Rate (FRR), Evasion Rate (FNR), Accuracy, and Confusion Matrix.
* **Location:** [`src/blackwall/eval/metrics.py`](../src/blackwall/eval/metrics.py)
* **Use Case:** Automated benchmark evaluation and Kaggle competition metric reporting.

---

## 4. Script & Dataset Generation Helpers

Located in [`scripts/build_evalset.py`](../scripts/build_evalset.py).

### `_build_cases(cases: list[dict], default_verdict: str, prompt_fn: Callable, metadata_fn: Callable) -> list[dict]`
* **Purpose:** Generic eval-case builder that constructs ADK `EvalCase` dictionary payloads with trajectory definitions, references, and metadata.
* **Location:** [`scripts/build_evalset.py`](../scripts/build_evalset.py)
* **Use Case:** Powers `build_benign_cases`, `build_malicious_cases`, and `build_evasion_cases` to build Kaggle benchmark datasets from ground-truth test data.

---

## Maintenance Guidelines
1. **Never copy-paste YAML templates:** Always use `POLICY_YAML` or `BASE_YAML_TEMPLATE` from test helper modules.
2. **Reuse `make_mock_semantic_engine`:** Use parameterised options (`latency_ms`, `cpu_spin_ms`) rather than writing local mock classes.
3. **Module Placement:** Test helpers belong in `tests/integration/helpers.py` or `tests/unit/policy_yaml_helpers.py`; domain logic helpers belong in `src/blackwall/`.
