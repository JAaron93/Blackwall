# Design: Blackwall Test Coverage Remediation

## 1. Overview

This spec defines the systematic remediation of structural test coverage gaps across the Blackwall codebase. The analysis identified that only ~34% of source symbols (functions, methods, classes) in `src/blackwall/` have inbound TESTS edges in the knowledge graph, meaning ~66% of production code lacks any form of dedicated test verification.

After the initial remediation pass (PR #89), structural coverage improved to ~52%. This spec targets the remaining ~48% gap through granular task decomposition across unit tests, property-based tests (hypothesis), and BDD Gherkin feature scenarios (pytest-bdd).

## 2. Motivation

### Security Criticality
Blackwall is an **Agentic Security Firewall** — its correctness is a security invariant. Untested code in the interception pipeline, scoring algorithms, or evaluation environment creates blind spots where:
- False negatives allow malicious tool calls to pass undetected
- False positives block legitimate agent operations
- Regression bugs in scoring silently degrade threat detection rates
- Evaluation environment isolation failures leak into production

### Spec-Driven Governance
Per `AGENTS.md` §2, all code submitted via PRs must align with `.kiro/specs/`. This spec provides the reference document for Greptile review validation of future test-coverage PRs.

## 3. Analysis Methodology

### Structural Graph Analysis
Coverage was measured using `codebase-memory-mcp` Cypher queries against the project knowledge graph:

1. **Total source symbols**: Count all `Function`, `Method`, and `Class` nodes with `file_path STARTS WITH 'src/'` and `is_test = false`
2. **Tested symbols**: Count source symbols that have at least one inbound `TESTS` edge from any test node
3. **Coverage ratio**: `tested_symbols / total_symbols` per file and globally
4. **Priority weighting**: Fan-in (hotspot rank), cyclomatic complexity, and security criticality

### Priority Classification

| Tier | Criteria | Target Coverage |
|------|----------|----------------|
| **P0** | Security-critical, zero coverage, high fan-in | ≥ 90% symbol coverage |
| **P1** | Core pipeline, ≤30% coverage, complexity ≥ 15 | ≥ 80% symbol coverage |
| **P2** | Enterprise subsystems, partial coverage | ≥ 70% symbol coverage |
| **P3** | Utility/config modules, low complexity | ≥ 60% symbol coverage |

## 4. Current State (Post-PR #89)

### Modules with Complete Coverage (done)
| Module | Tests Added | Test Type |
|--------|------------|-----------|
| `adk_integration.py` | 40 | Unit + BDD |
| `audit/manager.py` | 70 | Unit |
| `security/privilege.py` | 25 | Unit |
| `telemetry.py` | 31 | Unit |
| `api/webhook_listener.py` | 18 | Unit + BDD |
| `policy/engine.py` (_eval_ast) | 86 + 21 | Unit + Property |
| `interception.py` (queue) | 12 | Property |
| `sync_resolver.py` (scoring) | 52 | Property |

### Modules with Remaining Gaps

#### Core (P0/P1)
| Module | Total Symbols | Tested | Gap % |
|--------|:---:|:---:|:---:|
| `mcp/codebase_memory.py` | 21 | 0 | 100% |
| `sync_resolver.py` (non-scoring methods) | 20 | 6 | 70% |
| `resolver.py` (BatchResolver) | 20 | 6 | 70% |
| `models.py` | 36 | 2 | 94% |
| `mcp/gti_client.py` (private methods) | 36 | 16 | 55% |

#### Enterprise Advanced Threat Detection (P2)
| Module | Total Symbols | Tested | Gap % |
|--------|:---:|:---:|:---:|
| `evaluation.py` | 53 | 3 | 94% |
| `models.py` (validators) | 33 | 2 | 94% |
| `gcp_vertex_eval.py` | 24 | 8 | 67% |
| `gcp_trace_exporter.py` | 14 | 4 | 71% |
| `gcp_eval_datasets.py` | 4 | 2 | 50% |
| `reaction.py` | 8 | 0 (BDD covers some) | ~60% |
| `orchestrator.py` | 17 | 8 | 53% |
| `correlator.py` | 8 | 4 | 50% |

#### Enterprise Other Pillars (P2/P3)
| Module | Total Symbols | Tested | Gap % |
|--------|:---:|:---:|:---:|
| `forensics/ollama_engine.py` | 5 | 0 | 100% |
| `mcp/opentelemetry_mcp.py` | 10 | 2 | 80% |
| `mcp/sandbox_mcp.py` | 7 | 0 (unit test exists) | ~50% |
| `pipeline/wrapper.py` | 8 | 2 | 75% |
| `kernel/probe.py` (untested methods) | 22 | 9 | 59% |

#### Core Utilities (P3)
| Module | Total Symbols | Tested | Gap % |
|--------|:---:|:---:|:---:|
| `config.py` | 5 | 1 | 80% |
| `logging.py` | 2 | 1 | 50% |
| `exceptions.py` | 2 | 0 | 100% |
| `eval/metrics.py` | 1 | 0 | 100% |
| `analytics/__init__.py` | 15 | 5 | 67% |

## 5. Test Type Strategy

### Unit Tests
- Target: individual functions/methods in isolation
- Mock external dependencies (DB, network, MCP clients)
- Cover happy path, edge cases, error handling, boundary values
- Naming: `tests/unit/test_<module_name>.py`

### Property Tests (Hypothesis)
- Target: mathematical invariants and contracts
- Score bounds ∈ [0,1], monotonicity, idempotency, ordering guarantees
- Use `@given` with custom strategies, `settings(max_examples=200)`
- Naming: `tests/property/test_<invariant_domain>_properties.py`

### BDD Feature Files (pytest-bdd)
- Target: security behavior contracts visible to stakeholders
- Gherkin scenarios in `tests/features/<feature_name>.feature`
- Step definitions in `tests/step_defs/test_<feature_name>_bdd.py`
- Use `run_async` helper from `tests/step_defs/async_utils.py`

## 6. Acceptance Criteria (Global)

1. All P0 modules achieve ≥90% symbol coverage
2. All P1 modules achieve ≥80% symbol coverage
3. All functions with cyclomatic complexity ≥15 have ≥3 dedicated test cases
4. Every property test uses `hypothesis` `@given` with ≥100 examples
5. Every new `.feature` file has a corresponding step definition file
6. `pytest --tb=short` passes with 0 new failures after each task
7. Overall structural TESTS-edge coverage reaches ≥75%

## 7. Constraints

- No changes to production source code (`src/`) in this spec
- Tests must be isolated (no shared mutable state between test functions)
- Audit hook tests must use `tmp_path` fixtures to avoid process-level hook pollution
- BDD step definitions must use `run_async` for async operations
- Property tests must not depend on external services (GTI, Ollama, etc.)
- All hypothesis strategies must produce valid Pydantic models (no `ValidationError` in generation)
