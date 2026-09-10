# Implementation Plan: Blackwall GCP Evaluation Coverage (Agent-as-a-Judge)

## Overview

This implementation plan closes 12 identified evaluation gaps by building an Agent-as-a-Judge evaluation pipeline using Google Antigravity SDK. The work is organized into 5 parallel execution tracks (A–E) with explicit dependencies and TDD/BDD verification at every step.

## Execution Tracks & Parallelism

> [!TIP] PARALLEL EXECUTION
> **Tracks A and B** have zero mutual dependencies and can execute concurrently.
> **Track C** depends on Track A (datasets).
> **Track D** depends on Track B (judge agents).
> **Track E** depends on both C and D (integration).

```
  ┌─────────┐     ┌─────────┐
  │ Track A │     │ Track B │
  │ Datasets│     │ Judges  │
  └────┬────┘     └────┬────┘
       │               │
       ▼               ▼
  ┌─────────┐     ┌─────────┐
  │ Track C │     │ Track D │
  │Scenarios│     │Pipeline │
  └────┬────┘     └────┬────┘
       │               │
       └───────┬───────┘
               ▼
          ┌─────────┐
          │ Track E │
          │  CI/CD  │
          └─────────┘
```

## Tasks

### Track A: Dataset Foundation

- [x] A.1 Create ADK-to-EvalTask dataset bridge
  - [x] A.1.1 Implement `scripts/bridge_adk_to_eval.py` transformer
    - Parse ADK evalset JSON (`tests/eval/evalsets/blackwall_security.evalset.json`)
    - Transform `eval_case_id` → `scenario_id`, `reference` → `ground_truth_verdict`, `metadata.ground_truth` → `ground_truth_label`
    - Extract `tool_name` from `expected_tool_use` into `reference_trajectory`
    - Output judge-consumable JSON to `tests/eval/judge_scenarios/`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_
    - _Verification: `pytest tests/unit/test_adk_bridge.py -v`_

  - [x] A.1.2 Write property tests for ADK bridge
    - **Property E-1: Bridge output schema compliance** (all fields present, types correct)
    - **Property E-2: Bridge bijection** (no cases dropped, no duplicates)
    - **Property E-3: Verdict mapping correctness** (ALLOW/BLOCK/QUARANTINE preserved)
    - _Verification: `pytest tests/property/test_adk_bridge_properties.py --hypothesis-seed=0 -v`_

  - [x] A.1.3 Write BDD feature tests for ADK bridge
    - Scenario: benign ADK case transforms to judge scenario with `ground_truth_verdict=ALLOW`
    - Scenario: malicious ADK case transforms with `ground_truth_label=MALICIOUS` and `reference_trajectory=["before_tool_callback"]`
    - Scenario: evasion ADK case preserves `evasion_type` and `parent_case_id` in metadata
    - _Verification: `pytest tests/step_defs/test_adk_bridge_bdd.py -v`_

- [x] A.2 Expand GCP evaluation datasets for missing domains
  - [x] A.2.1 Create AILM evaluation scenarios
    - 10+ scenarios covering permission accumulation across trust boundaries
    - Include single-boundary, multi-boundary, and CRITICAL risk_level cases
    - Schema: `{scenario_id, domain: "ailm", permission_grants: [...], ground_truth_crossings: [...], expected_risk_level}`
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
    - _Verification: `pytest tests/unit/test_ailm_eval_dataset.py -v`_

  - [x] A.2.2 Create Prompt Injection evaluation scenarios
    - 15+ scenarios covering structural jailbreaks, role-play overrides, and benign content
    - Include both true positives and true negatives for false positive testing
    - Schema: `{scenario_id, domain: "prompt_injection", payload, ground_truth_is_injection: bool, expected_severity}`
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
    - _Verification: `pytest tests/unit/test_injection_eval_dataset.py -v`_

  - [x] A.2.3 Create Inbound Protocol Filter evaluation scenarios
    - 10+ scenarios covering valid/invalid headers, rate limit bursts, malformed RPC
    - Include loopback (allowed) vs remote (rejected) origin tests
    - Schema: `{scenario_id, domain: "inbound_filter", request_headers, rpc_payload, ground_truth_allowed: bool}`
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
    - _Verification: `pytest tests/unit/test_inbound_eval_dataset.py -v`_

  - [x] A.2.4 Create Agent Quota Enforcer evaluation scenarios
    - 10+ scenarios covering normal usage, velocity spikes, and sustained burn
    - Include threshold boundary cases (499 vs 501 tokens/sec)
    - Schema: `{scenario_id, domain: "quota_enforcement", activity_stream: [...], ground_truth_throttled: bool, expected_alert_type}`
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
    - _Verification: `pytest tests/unit/test_quota_eval_dataset.py -v`_

  - [x] A.2.5 Create Context Hygiene evaluation scenarios
    - 12+ scenarios covering API keys, JWT tokens, AWS secrets, GCP credentials, and benign metadata
    - Include partial redaction edge cases
    - Schema: `{scenario_id, domain: "context_hygiene", raw_payload, expected_sanitized, sensitive_patterns: [...]}`
    - _Requirements: 9.1, 9.2, 9.3, 9.4_
    - _Verification: `pytest tests/unit/test_hygiene_eval_dataset.py -v`_

  - [x] A.2.6 Create SyncResolver evaluation scenarios (Core)
    - 20+ scenarios from bridged ADK data + novel multi-stage attack patterns
    - Include scoring boundary cases (high-confidence benign, ambiguous, clear malicious)
    - Schema: `{scenario_id, domain: "threat_interception", tool_call, ground_truth_verdict, ground_truth_label, expected_score_range}`
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
    - _Verification: `pytest tests/unit/test_resolver_eval_dataset.py -v`_

- [x] A.3 Implement scenario JSON schema validation
  - [x] A.3.1 Create Pydantic models for eval scenario schema
    - Define `EvalScenarioBase`, domain-specific scenario models
    - Validate required fields, enum values, and type constraints
    - _Verification: `pytest tests/unit/test_eval_scenario_schema.py -v`_

---

### Track B: Judge Agent Registry

- [x] B.1 Create base judge agent infrastructure
  - [x] B.1.1 Implement judge agent factory (`src/blackwall/eval/judge_factory.py`)
    - Create `create_judge_agent(domain, rubric_schema)` factory function
    - Configure `LocalAgentConfig(vertex=True, project=GCP_PROJECT, location=GCP_LOCATION, model="gemini-3.8-flash", response_schema=rubric_schema, capabilities=CapabilitiesConfig(agent_behavior=AgentBehavior.AUTONOMOUS))`
    - Support configurable model override via `BLACKWALL_JUDGE_MODEL` env var
    - _Requirements: 1.4, 2.4, 3.4, 4.4, 5.4, 6.4, 7.4, 8.4, 9.4, NFR-1_
    - _Verification: `pytest tests/unit/test_judge_factory.py -v`_

  - [x] B.1.2 Implement prompt sanitization utility (`src/blackwall/eval/prompt_sanitizer.py`)
    - Regex patterns to neutralize: `[INST]`, `[/INST]`, `<<SYS>>`, `<|im_start|>`, `<|im_end|>`
    - Regex patterns to neutralize instruction overrides: `\b(ignore|disregard|forget|bypass|override)\b.*\binstructions?\b`
    - Regex patterns to neutralize scoring manipulation: multi-verb + nonnumeric directives
    - XML escape utility for `<untrusted_input>` tag content
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_
    - _Verification: `pytest tests/unit/test_prompt_sanitizer.py -v`_

  - [x] B.1.3 Implement zero-trust prompt template builder (`src/blackwall/eval/prompt_template.py`)
    - Generate structured prompts with XML boundaries
    - Place static system instruction and rubric at the beginning (prefix) for Gemini implicit context caching (>32k prefix → 90% input cost discount)
    - Place per-scenario evaluation context (untrusted inputs, ground truth) at the end (dynamic tail)
    - Enforce `<untrusted_input type="...">` wrappers on all dynamic content
    - Ordering: `<system_instruction>` → `<rubric>` → `<evaluation_context>` (scenario data)
    - _Requirements: 16.1, 16.5, NFR-3, NFR-5_
    - _Verification: `pytest tests/unit/test_prompt_template.py -v`_

  - [x] B.1.4 Implement heuristic fallback scorer base class (`src/blackwall/eval/fallback_scorer.py`)
    - Define `HeuristicFallbackScorer` ABC with `score(scenario, result) -> Rubric`
    - Always set `is_fallback=True` on returned rubrics
    - Implement basic confusion-matrix comparison (predicted vs ground truth)
    - _Requirements: 17.1, 17.2, 17.3, 17.4_
    - _Verification: `pytest tests/unit/test_fallback_scorer.py -v`_

  - [x] B.1.5 Write property tests for judge infrastructure
    - **Property E-4: Sanitizer neutralizes all known injection patterns** (fuzzing with injection corpus)
    - **Property E-5: Prompt template always wraps dynamic content in XML tags** (never raw insertion)
    - **Property E-6: Fallback scorer always sets `is_fallback=True`**
    - **Property E-7: Factory always produces `vertex=True` config**
    - _Verification: `pytest tests/property/test_judge_infra_properties.py --hypothesis-seed=0 -v`_

- [x] B.2 Implement domain-specific Pydantic rubric models
  - [x] B.2.1 Create all 9 rubric models (`src/blackwall/eval/rubrics.py`)
    - `ThreatInterceptionRubric`, `SwarmDetectionRubric`, `ExploitChainRubric`, `C2DetectionRubric`, `AILMDetectionRubric`, `PromptInjectionRubric`, `InboundFilterRubric`, `QuotaEnforcementRubric`, `ContextHygieneRubric`
    - All: `ConfigDict(extra="forbid")`, scores `Field(ge=1, le=5)`, `justification: str = Field(min_length=10)`, `is_fallback: bool = Field(default=False)`
    - `RegressionComparisonRubric`: `overall_quality_delta: int = Field(ge=-5, le=5)`, `regression_detected: bool`, `justification`
    - _Requirements: 1.2, 2.2, 3.2, 4.2, 5.2, 6.2, 7.2, 8.2, 9.2, 13.2_
    - _Verification: `pytest tests/unit/test_rubric_models.py -v`_

  - [x] B.2.2 Write property tests for rubric models
    - **Property E-8: All score fields reject values outside [1, 5]**
    - **Property E-9: Justification rejects strings shorter than 10 characters**
    - **Property E-10: `extra="forbid"` rejects unknown fields**
    - **Property E-11: `is_fallback` defaults to False**
    - _Verification: `pytest tests/property/test_rubric_properties.py --hypothesis-seed=0 -v`_

- [x] B.3 Implement domain-specific judge agents
  - [x] B.3.1 Implement `ThreatInterceptionJudge` with system instruction and rubric
    - System instruction: "You are an expert AI cybersecurity judge evaluating firewall verdict accuracy..."
    - Rubric criteria: detection accuracy, false positive control, reasoning quality, trajectory soundness
    - Heuristic fallback: compare predicted verdict to ground truth, score 5 if match, 1 if miss
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
    - _Verification: `pytest tests/unit/test_threat_interception_judge.py -v`_

  - [x] B.3.2 Implement `SwarmDetectionJudge`
    - Criteria: coordination detection, temporal precision, shared infrastructure identification, fingerprint quality
    - Fallback: score based on whether swarm was detected at all (binary)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
    - _Verification: `pytest tests/unit/test_swarm_judge.py -v`_

  - [x] B.3.3 Implement `ExploitChainJudge`
    - Criteria: chain completeness, novelty calibration, MITRE mapping accuracy, chaining confidence
    - Fallback: compare detected stages against ground truth stage list
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
    - _Verification: `pytest tests/unit/test_exploit_chain_judge.py -v`_

  - [x] B.3.4 Implement `C2DetectionJudge`
    - Criteria: endpoint classification, beaconing detection, persistence identification, cross-pillar correlation
    - Fallback: check if C2 endpoints appear in detection output
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
    - _Verification: `pytest tests/unit/test_c2_judge.py -v`_

  - [x] B.3.5 Implement `AILMDetectionJudge`
    - Criteria: boundary crossing detection, permission composition accuracy, risk classification, evidence completeness
    - Fallback: compare detected boundary crossings count against ground truth
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
    - _Verification: `pytest tests/unit/test_ailm_judge.py -v`_

  - [x] B.3.6 Implement `PromptInjectionJudge`
    - Criteria: injection detection rate, redaction completeness, false positive control, alert severity accuracy
    - Fallback: binary detected/not-detected comparison
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
    - _Verification: `pytest tests/unit/test_injection_judge.py -v`_

  - [x] B.3.7 Implement `InboundFilterJudge`
    - Criteria: header validation accuracy, rate limit precision, sanitization quality, error response safety
    - Fallback: compare allow/deny decision against ground truth
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
    - _Verification: `pytest tests/unit/test_inbound_judge.py -v`_

  - [x] B.3.8 Implement `QuotaEnforcementJudge`
    - Criteria: burn rate detection, throttling precision, alert timeliness, quarantine accuracy
    - Fallback: binary throttle/no-throttle comparison
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
    - _Verification: `pytest tests/unit/test_quota_judge.py -v`_

  - [x] B.3.9 Implement `ContextHygieneJudge`
    - Criteria: redaction completeness, placeholder format compliance, metadata preservation, non-sensitive passthrough
    - Fallback: regex check for leaked secrets in output
    - _Requirements: 9.1, 9.2, 9.3, 9.4_
    - _Verification: `pytest tests/unit/test_hygiene_judge.py -v`_

  - [x] B.3.10 Implement `RegressionComparisonJudge` (pairwise)
    - Uses PairwiseMetric pattern with response flipping and 4x multi-sampling
    - Compares baseline vs candidate evaluation summaries
    - Returns `RegressionComparisonRubric` with quality deltas
    - _Requirements: 13.1, 13.2, 13.3, 13.4_
    - _Verification: `pytest tests/unit/test_regression_judge.py -v`_

  - [x] B.3.11 Write BDD feature tests for judge agents
    - Create `tests/features/judge_agents.feature` with Gherkin scenarios
    - Scenario: `threat_interception_judge` correctly awards maximum score when predicted BLOCK matches ground truth MALICIOUS
    - Scenario: `swarm_detection_judge` penalizes missed coordination when ground truth shows 6 agents coordinating
    - Scenario: judge agent returns valid Pydantic rubric with all scores in [1, 5] range
    - Scenario: Vertex AI unavailable triggers heuristic fallback with `is_fallback=True`
    - Scenario: untrusted input containing `[INST]` tokens is sanitized before judge ingestion
    - _Requirements: 1–9, 16, 17_
    - _Verification: `pytest tests/step_defs/test_judge_agents_bdd.py -v`_

---

### Track C: Missing Evaluation Scenarios (Depends on Track A)

- [x] C.1 Implement AILM evaluation scenario
  - [x] C.1.1 Create `tests/evaluation/test_ailm_scenario.py`
    - Simulate cross-boundary permission accumulation (3+ boundaries → CRITICAL)
    - Execute `AILMTracker.detect_permission_composition()` and `identify_boundary_crossing()`
    - Route results to `ailm_detection_judge` agent
    - Assert structured rubric scores ≥ 3 on all dimensions
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
    - _Verification: `pytest tests/evaluation/test_ailm_scenario.py -v`_

- [x] C.2 Implement Prompt Injection evaluation scenario
  - [x] C.2.1 Create `tests/evaluation/test_prompt_injection_scenario.py`
    - Simulate structural jailbreaks, role-play overrides, and benign content
    - Execute `PromptInjectionScanner.scan()` against each payload
    - Route results to `prompt_injection_judge` agent
    - Assert detection rate ≥ 0.9 and false positive rate ≤ 0.05
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
    - _Verification: `pytest tests/evaluation/test_prompt_injection_scenario.py -v`_

- [x] C.3 Implement Inbound Protocol Filter evaluation scenario
  - [x] C.3.1 Create `tests/evaluation/test_inbound_filter_scenario.py`
    - Simulate valid/invalid Origin headers, rate limit bursts, malformed RPC
    - Execute `InboundProtocolFilter.inspect()` against each request
    - Route results to `inbound_filter_judge` agent
    - Assert header validation accuracy and sanitization quality ≥ 4/5
    - _Requirements: 7.1, 7.2, 7.3, 7.4_
    - _Verification: `pytest tests/evaluation/test_inbound_filter_scenario.py -v`_

- [x] C.4 Implement Quota Enforcer evaluation scenario
  - [x] C.4.1 Create `tests/evaluation/test_quota_enforcer_scenario.py`
    - Simulate normal usage, velocity spike (>500 tokens/sec), sustained burn
    - Execute `AgentQuotaEnforcer.track()` and `enforce()` against activity streams
    - Route results to `quota_enforcement_judge` agent
    - Assert quarantine triggers on velocity spikes
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
    - _Verification: `pytest tests/evaluation/test_quota_enforcer_scenario.py -v`_

- [x] C.5 Implement SyncResolver evaluation scenario (Core)
  - [x] C.5.1 Create `tests/evaluation/test_sync_resolver_scenario.py`
    - Load bridged ADK scenarios (benign + malicious + evasion)
    - Execute `SyncResolver.resolve()` against each tool call payload
    - Compute confusion matrix (TP, FP, FN, TN)
    - Route results to `threat_interception_judge` agent
    - Assert overall F1 ≥ 0.85
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 15.1, 15.2, 15.3, 15.4, 15.5_
    - _Verification: `pytest tests/evaluation/test_sync_resolver_scenario.py -v`_

- [x] C.6 Implement Context Hygiene evaluation scenario
  - [x] C.6.1 Create `tests/evaluation/test_context_hygiene_scenario.py`
    - Load hygiene eval scenarios with API keys, JWT tokens, AWS secrets
    - Execute `ContextHygiene.sanitize()` against each payload
    - Verify `[[VARIABLE_NAME]]` format compliance and non-sensitive passthrough
    - Route results to `context_hygiene_judge` agent
    - Assert redaction completeness ≥ 4/5
    - _Requirements: 9.1, 9.2, 9.3, 9.4_
    - _Verification: `pytest tests/evaluation/test_context_hygiene_scenario.py -v`_

- [x] C.7 Implement full callback chain trajectory evaluation
  - [x] C.7.1 Create `tests/evaluation/test_callback_trajectory_scenario.py`
    - Define reference trajectories for ALLOW and BLOCK paths
    - Execute full interception pipeline (before_tool_callback → verdict → execute/block)
    - Compute `trajectory_precision`, `trajectory_recall`, `trajectory_exact_match`
    - Feed trajectory results to `threat_interception_judge` for qualitative assessment
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_
    - _Verification: `pytest tests/evaluation/test_callback_trajectory_scenario.py -v`_

---

### Track D: Pipeline Infrastructure (Depends on Track B)

- [x] D.1 Implement Evaluation Pipeline Runner
  - [x] D.1.1 Create `scripts/run_gcp_eval.py` orchestrator
    - Authenticate via ADC (zero API keys); exit with error if ADC unavailable
    - Validate `GEMINI_TIER=paid` and `BLACKWALL_TIER=paid` at startup; exit with descriptive error if the 300+ RPM paid-tier quota contract is not configured
    - Load scenarios from `tests/eval/judge_scenarios/` and GCP native datasets
    - Route each scenario to the correct judge agent based on `domain` field
    - Collect structured rubric results per domain
    - Support `--domains` CLI flag for selective execution
    - Support `--eval-threshold` CLI flag (default 3.5)
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, NFR-2_
    - _Verification: `pytest tests/unit/test_eval_pipeline_runner.py -v`_

  - [x] D.1.2 Implement results aggregator with fallback isolation
    - Filter `is_fallback=True` rows before computing domain means
    - Report `None` for domains with 100% fallback
    - Include `fallback_count` and `fallback_rate` in summary
    - Emit CI pass (exit 0) if all domain means ≥ threshold; fail (exit 1) otherwise
    - _Requirements: 17.1, 17.2, 17.3, 17.4_
    - _Verification: `pytest tests/unit/test_results_aggregator.py -v`_

- [x] D.2 Implement SLA Validation Engine
  - [x] D.2.1 Create `src/blackwall/eval/sla_validator.py`
    - Define SLA thresholds: TSG < 10ms, structural gating < 5ms, reaction < 50ms, eBPF < 50ms, Mesh < 15ms
    - Measure execution time via `time.perf_counter_ns()`
    - Record Cloud Trace span attributes: `blackwall.sla.component`, `blackwall.sla.threshold_ms`, `blackwall.sla.measured_ms`, `blackwall.sla.violated`
    - Factor SLA compliance into `trajectory_soundness_score` via judge prompt context
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_
    - _Verification: `pytest tests/unit/test_sla_validator.py -v`_

  - [x] D.2.2 Write property tests for SLA validator
    - **Property E-12: Measured time always ≥ 0**
    - **Property E-13: Violation correctly flagged when measured > threshold**
    - **Property E-14: Non-violation correctly flagged when measured ≤ threshold**
    - _Verification: `pytest tests/property/test_sla_validator_properties.py --hypothesis-seed=0 -v`_

- [x] D.3 Implement Historical Regression Tracker
  - [x] D.3.1 Create `src/blackwall/eval/regression_tracker.py`
    - Persist evaluation results to `tests/eval/regression/history.jsonl` (JSON Lines)
    - Load most recent entry as comparison baseline on new run
    - Flag regression when any domain mean drops > 0.5 from baseline
    - Support `get_history(n)` for last N runs
    - _Requirements: 14.1, 14.2, 14.3, 14.4_
    - _Verification: `pytest tests/unit/test_regression_tracker.py -v`_

  - [x] D.3.2 Write BDD feature tests for regression tracker
    - Scenario: first evaluation run stores baseline with no comparison
    - Scenario: second run with improved scores reports no regression
    - Scenario: third run with domain mean drop > 0.5 flags regression
    - Scenario: `get_history(3)` returns the 3 most recent entries
    - _Verification: `pytest tests/step_defs/test_regression_tracker_bdd.py -v`_

- [x] D.4 Implement Cloud Trace integration for evaluation spans
  - [x] D.4.1 Extend `GCPCloudTraceExporter` with evaluation-specific attributes
    - Add `gen_ai.evaluation.domain`, `gen_ai.evaluation.judge_model`, `gen_ai.evaluation.rubric_scores`
    - Add `gen_ai.evaluation.is_fallback`, `gen_ai.evaluation.mean_score`
    - Reuse existing `start_span()` / `record_evaluation_result()` / `flush()` API
    - _Requirements: 10.6, NFR-6_
    - _Verification: `pytest tests/unit/test_eval_trace_export.py -v`_

---

### Track E: Integration & CI (Depends on Tracks C + D)

- [ ] E.1 End-to-end integration testing
  - [ ] E.1.1 Create `tests/integration/test_eval_pipeline_e2e.py`
    - Execute full pipeline: load scenarios → run Blackwall detection → judge → aggregate → gate
    - Verify Cloud Trace spans emitted (mock exporter)
    - Verify regression tracker persistence
    - Verify CI exit code reflects threshold pass/fail
    - _Requirements: 10.1–10.6, 14.1–14.4, 18.1–18.4_
    - _Verification: `pytest tests/integration/test_eval_pipeline_e2e.py -v`_

  - [ ] E.1.2 Write BDD feature tests for full pipeline
    - Create `tests/features/eval_pipeline.feature` with Gherkin scenarios
    - Scenario: full pipeline with all domains above threshold exits with code 0
    - Scenario: pipeline with one domain below threshold exits with code 1
    - Scenario: pipeline under Vertex AI outage produces fallback verdicts and reports fallback_rate
    - Scenario: Cloud Trace receives spans with `gen_ai.evaluation.domain` attributes
    - Scenario: second pipeline run compares against stored baseline and reports no regression
    - _Requirements: 10.1–10.6, 14.1–14.4, 17.1–17.4, 18.1–18.4_
    - _Verification: `pytest tests/step_defs/test_eval_pipeline_bdd.py -v`_

- [ ] E.2 CI/CD configuration and pytest markers
  - [ ] E.2.1 Register `gcp_eval` pytest marker in `pyproject.toml`
    - Add `[tool.pytest.ini_options] markers = ["gcp_eval: GCP evaluation pipeline tests (require ADC)"]`
    - Decorate all `tests/evaluation/` files with `@pytest.mark.gcp_eval`
    - _Requirements: 18.1, 18.2_
    - _Verification: `pytest --markers | grep gcp_eval`_

  - [ ] E.2.2 Create evaluation CI stage configuration template
    - Document recommended CI workflow: `pytest -m gcp_eval --eval-threshold=3.5`
    - Include ADC credential provisioning steps
    - Include `BLACKWALL_DISABLE_CLOUD_TRACE=true` flag for non-GCP CI runners
    - _Requirements: 18.3, 18.4_
    - _Verification: Manual review of CI template documentation_

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["A.1.1", "A.1.2", "B.1.1", "B.1.2", "B.1.3", "B.1.4"], "label": "Foundation (parallel)" },
    { "id": 1, "tasks": ["A.1.3", "A.2.1", "A.2.2", "A.2.3", "A.2.4", "A.2.5", "A.2.6", "A.3.1", "B.1.5", "B.2.1", "B.2.2"], "label": "Datasets + Rubrics (parallel)" },
    { "id": 2, "tasks": ["B.3.1", "B.3.2", "B.3.3", "B.3.4", "B.3.5", "B.3.6", "B.3.7", "B.3.8", "B.3.9", "B.3.10"], "label": "Judge Agents (parallel)" },
    { "id": 3, "tasks": ["B.3.11", "C.1.1", "C.2.1", "C.3.1", "C.4.1", "C.5.1", "C.6.1", "C.7.1"], "label": "Scenarios (parallel, depends A)" },
    { "id": 4, "tasks": ["D.1.1", "D.1.2", "D.2.1", "D.2.2", "D.3.1", "D.3.2", "D.4.1"], "label": "Pipeline infra (depends B)" },
    { "id": 5, "tasks": ["E.1.1", "E.1.2", "E.2.1", "E.2.2"], "label": "Integration (depends C+D)" }
  ]
}
```

## Traceability Matrix

| Requirement | Tasks |
|---|---|
| FR-1 (Threat Interception Judge) | B.3.1, C.5.1, C.7.1 |
| FR-2 (Swarm Detection Judge) | B.3.2 |
| FR-3 (Exploit Chain Judge) | B.3.3 |
| FR-4 (C2 Detection Judge) | B.3.4 |
| FR-5 (AILM Detection Judge) | B.3.5, C.1.1 |
| FR-6 (Prompt Injection Judge) | B.3.6, C.2.1 |
| FR-7 (Inbound Filter Judge) | B.3.7, C.3.1 |
| FR-8 (Quota Enforcement Judge) | B.3.8, C.4.1 |
| FR-9 (Context Hygiene Judge) | B.3.9, C.6.1 |
| FR-10 (Pipeline Runner) | D.1.1, D.1.2 |
| FR-11 (ADK Bridge) | A.1.1, A.1.2, A.1.3 |
| FR-12 (SLA Validation) | D.2.1, D.2.2 |
| FR-13 (Pairwise Regression Judge) | B.3.10 |
| FR-14 (Regression Tracker) | D.3.1, D.3.2 |
| FR-15 (Callback Chain Trajectory) | C.7.1 |
| FR-16 (Zero-Trust Prompts) | B.1.2, B.1.3 |
| FR-17 (Fallback Isolation) | B.1.4, D.1.2 |
| FR-18 (CI/CD) | E.2.1, E.2.2 |
| NFR-1 (Structured Output) | B.1.1, B.2.1 |
| NFR-2 (Zero SaaS) | D.1.1 |
| NFR-3 (Prompt Safety) | B.1.2, B.1.3 |
| NFR-4 (Eval Containment) | C.1–C.7 |
| NFR-5 (Token Efficiency) | B.1.3 |
| NFR-6 (Observability) | D.4.1 |
