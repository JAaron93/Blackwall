# Blackwall: Weave Purge & GCP Vertex AI Gen AI Evaluation Engine Migration TODO

This document tracks the complete deprecation and purge of Weights & Biases (Weave) and the end-to-end implementation of the **Google Cloud Vertex AI Gen AI Evaluation Engine** (`vertexai.preview.evaluation` / `EvalTask`) across Blackwall.

---

## 1. 100% GCP Vertex AI Evaluation Engine Implementation (Tasks 22 & 23)

### A. Core Evaluation Modules (`src/blackwall/enterprise/advanced_threat_detection/`)
- [x] **Implement `gcp_vertex_eval.py` (Vertex AI `EvalTask` Engine)**:
  - Wrap `vertexai.preview.evaluation.EvalTask` for offline and online threat evaluation.
  - Define `PointwiseMetric` autoraters for:
    - Threat Interception Accuracy (verdict correctness against ground-truth attacks)
    - Latency SLA Compliance (<10ms TSG, <100ms rapid triage, <50ms eBPF drop)
    - Context Hygiene & Sanitization (preventing credential leakage in traces)
    - Prompt Injection Resistance & Evasion Robustness
  - Define `PairwiseMetric` autoraters for baseline vs. adversarial model comparison.
  - Integrate ADC (Application Default Credentials) with 100% Zero-SaaS authentication (zero external API keys).
- [x] **Implement `gcp_trace_exporter.py` (Google Cloud Trace Exporter)**:
  - OpenTelemetry GenAI semantic conventions (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.finish_reasons`).
  - Stream telemetry spans and evaluation results directly to **Google Cloud Trace** (`opentelemetry-exporter-gcp-trace`).
- [x] **Implement `EvaluationEnvironmentManager` GCP Binding**:
  - Route synthetic adversarial evaluation telemetry to isolated GCP datasets, maintaining production containment.

### B. Dual-Tiered Adversarial Evaluation Sandboxes
- [x] **Tier 1 (In-Process ADK Adversarial Harness)**:
  - Adversarial agent harness testing `before_tool_callback` tool calls with `gemini-3.5-flash-lite` (main) and `gemini-3.7-flash` (reasoner).
  - Fast CI/CD validation of single-turn and multi-turn prompt injection and tool evasion scenarios.
- [x] **Tier 2 (Cybench MicroVM Container Evaluation on Cloud Run / GKE Sandbox)**:
  - Cybench CTF benchmark scenarios running inside gVisor container microVMs.
  - Validate live multi-pillar mitigations: `<50ms` eBPF socket drops, ZeroMQ threat mesh broadcast, and Vault STS token revocations.

### C. GCP Evaluation Test Suites (`tests/`)
- [x] **Unit Tests**: `tests/unit/test_gcp_vertex_eval.py`, `tests/unit/test_gcp_trace_exporter.py`, `tests/unit/test_gcp_eval_datasets.py`
- [x] **Property-Based Tests**: `tests/property/test_vertex_eval_properties.py` (testing invariant coverage across metric thresholds)
- [x] **BDD Security Contracts**: `tests/step_defs/test_vertex_evaluation_bdd.py` & `tests/features/vertex_evaluation.feature`
- [x] **Adversarial Scenarios**: `tests/evaluation/test_tier1_adk_harness.py`, `tests/evaluation/test_tier2_gvisor_scenarios.py`, `tests/evaluation/test_swarm_scenario.py`, `tests/evaluation/test_exploit_chain_scenario.py`, `tests/evaluation/test_c2_scenario.py`, `tests/evaluation/test_k8s_scenario.py`

---

## 2. Legacy Source Code Purge (`src/blackwall/enterprise/advanced_threat_detection/`)

- [x] **Delete legacy Weave modules**:
  - `src/blackwall/enterprise/advanced_threat_detection/weave_config.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_datasets.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_harness.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_metrics.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_serializer.py`
  - `src/blackwall/enterprise/advanced_threat_detection/weave_traced.py`
- [x] **Clean up module exports**:
  - Replace `Weave*` exports with `GCPVertexAIEvaluationHarness`, `GCPCloudTraceExporter`, and `GCPVertexEvalMetrics` in `src/blackwall/enterprise/advanced_threat_detection/__init__.py`.

---

## 3. Legacy Test Suite Purge (`tests/`)

- [x] **Delete legacy Weave unit tests**:
  - `tests/unit/test_weave_config.py`, `tests/unit/test_weave_datasets.py`, `tests/unit/test_weave_harness.py`, `tests/unit/test_weave_metrics_collector.py`, `tests/unit/test_weave_serializer.py`, `tests/unit/test_weave_traced_detectors.py`
- [x] **Delete legacy Weave property & integration tests**:
  - `tests/property/test_weave_properties.py`, `tests/integration/test_weave_trace_sanitization.py`
- [x] **Delete legacy Weave BDD scenarios & evals**:
  - `tests/step_defs/test_weave_evaluation_bdd.py`, `tests/features/weave_evaluation_tracking.feature`, `tests/evals/test_enterprise_weave_evals.py`
- [x] **Clean up test runner configuration (`tests/conftest.py`)**:
  - Remove `_weave_available()` probing helper and `@pytest.mark.weave` collection-time auto-skipping hook.

---

## 4. Dependencies, Build & Rule Configuration

- [x] **Update `pyproject.toml`**:
  - Remove `weave = ["weave>=0.50.0"]` from `[project.optional-dependencies]`.
  - Ensure `google-cloud-trace` / `opentelemetry-exporter-gcp-trace` dependencies are declared.
  - Remove `@pytest.mark.weave` marker from `[tool.pytest.ini_options].markers`.
- [x] **Update Governance & Rules**:
  - `.agents/rules/testing_and_hygiene.md`: Replace Rule 15 with **Rule 15: Google Cloud Trace & GCP Vertex AI Evaluation Testing Standards**.
  - `.agents/rules/architecture_and_security.md`: Verify Rule 40 (GCP-Native Evaluation Service & Dual-Tiered Sandbox Architecture).

---

## 5. Completed Spec Purge & Alignment

- [x] **`blackwall-enterprise-security-mesh`**:
  - `.kiro/specs/blackwall-enterprise-security-mesh/tasks.md`: Refactor Track 7 (`TASK-V01`..`TASK-V05`) to GCP Vertex AI Eval & Cybench.
  - `.kiro/specs/blackwall-enterprise-security-mesh/design.md`: Update Track 7 architecture diagrams to GCP Vertex AI & Cloud Trace.
- [x] **`blackwall-advanced-threat-detection`**:
  - `.kiro/specs/blackwall-advanced-threat-detection/requirements.md`: Remove definitions for `Weave_Trace_Serializer` and `Weave_Traced_Detectors`.
