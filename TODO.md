# Blackwall: Weights & Biases (Weave) Complete Deprecation & Purge TODO

This document tracks all remaining tasks required to completely purge Weights & Biases (Weave) from the Blackwall codebase, test suites, dependencies, environment configurations, and historical/completed specifications in the upcoming evaluation PR.

---

## 1. Source Code Purge (`src/blackwall/enterprise/advanced_threat_detection/`)

- [ ] **Delete legacy Weave modules**:
  - `src/blackwall/enterprise/advanced_threat_detection/weave_config.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_datasets.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_harness.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_metrics.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_serializer.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_traced.py`
- [ ] **Clean up module exports**:
  - Remove all `Weave*` class imports and exports from `src/blackwall/enterprise/advanced_threat_detection/__init__.py`.

---

## 2. Test Suite Purge (`tests/`)

- [ ] **Delete legacy Weave unit tests**:
  - `tests/unit/test_weave_config.py`
  - `tests/unit/test_weave_datasets.py`
  - `tests/unit/test_weave_harness.py`
  - `tests/unit/test_weave_metrics_collector.py`
  - `tests/unit/test_weave_serializer.py`
  - `tests/unit/test_weave_traced_detectors.py`
- [ ] **Delete legacy Weave property & integration tests**:
  - `tests/property/test_weave_properties.py`
  - `tests/integration/test_weave_trace_sanitization.py`
- [ ] **Delete legacy Weave BDD scenarios**:
  - `tests/step_defs/test_weave_evaluation_bdd.py`
  - `tests/features/weave_evaluation_tracking.feature`
- [ ] **Delete legacy enterprise evaluation tests**:
  - `tests/evals/test_enterprise_weave_evals.py`
- [ ] **Clean up test runner configuration (`tests/conftest.py`)**:
  - Remove `_weave_available()` probing helper.
  - Remove `@pytest.mark.weave` collection-time auto-skipping hook.

---

## 3. Dependencies & Build Configuration (`pyproject.toml`, `.env.example`)

- [ ] **Update `pyproject.toml`**:
  - Remove `weave = ["weave>=0.50.0"]` under `[project.optional-dependencies]`.
  - Remove `weave` marker registration under `[tool.pytest.ini_options].markers`.
- [ ] **Update `.env.example`**:
  - Verify zero `WANDB_*` or `WEAVE_*` environment variables remain.

---

## 4. Governance & Modular Agent Rules (`.agents/rules/`)

- [ ] **Update `.agents/rules/testing_and_hygiene.md`**:
  - Remove or rewrite **Rule 15 (Weave Marker Collection-Time Skip)** to focus on Google Cloud Trace and GCP Vertex AI evaluation testing.
- [ ] **Update `.agents/rules/architecture_and_security.md`**:
  - Clean up any legacy passing mentions of "Weave evals" in Rule 38.

---

## 5. Specification Cleanup (Historical & Completed Specs)

- [ ] **`blackwall-enterprise-security-mesh`**:
  - `.kiro/specs/blackwall-enterprise-security-mesh/tasks.md`: Refactor Track 7 (`TASK-V01` through `TASK-V05`) from W&B Weave to GCP Vertex AI Gen AI Evaluation & Cybench.
  - `.kiro/specs/blackwall-enterprise-security-mesh/design.md`: Clean up any lingering references to W&B Weave in Track 7 architecture diagrams.
- [ ] **`blackwall-advanced-threat-detection`**:
  - `.kiro/specs/blackwall-advanced-threat-detection/requirements.md`: Remove definitions for `Weave_Trace_Serializer` and `Weave_Traced_Detectors`.

---

## 6. Implementation of 100% GCP Vertex AI Evaluation (Tasks 22 & 23)

- [ ] **Task 22: Google Cloud Vertex AI Gen AI Evaluation Service**:
  - Implement `gcp_vertex_eval.py` wrapping `vertexai.preview.evaluation.EvalTask`, `PointwiseMetric`, and `PairwiseMetric`.
  - Implement `gcp_trace_exporter.py` exporting GenAI traces to **Google Cloud Trace** via OpenTelemetry.
- [ ] **Task 23: Dual-Tiered Adversarial Red Team Evaluation Scenarios**:
  - **Tier 1**: In-process Google Cloud Agent Platform / ADK Adversarial Harness (`before_tool_callback` integration).
  - **Tier 2**: Cybench adversarial evaluation on GCP Cloud Run with gVisor container microVM isolation.
