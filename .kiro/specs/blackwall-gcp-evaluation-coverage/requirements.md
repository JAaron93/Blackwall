# Requirements: Blackwall GCP Evaluation Coverage (Agent-as-a-Judge)

## Introduction

This document defines the functional and non-functional requirements for closing evaluation gaps in Blackwall's use of GCP's Gen AI Evaluation Engine. All evaluation judges are implemented as autonomous Google Antigravity SDK agents in Vertex AI Standard Mode, producing structured Pydantic rubric scores under zero-trust prompt delimitation.

## Glossary

- **Agent-as-a-Judge**: An autonomous Antigravity SDK agent configured to evaluate model/system outputs against a structured rubric, returning deterministic JSON scores via `response_schema`
- **Judge Agent**: A domain-specific Antigravity SDK `Agent` instance with `vertex=True`, `AgentBehavior.AUTONOMOUS`, and a Pydantic `BaseModel` response schema
- **Rubric**: A Pydantic model defining multi-dimensional scoring (1–5 per dimension) with mandatory justification
- **Zero-Trust Delimitation**: XML boundary tags around untrusted evaluation inputs with regex sanitization of injection patterns
- **Fallback Isolation**: Explicit `is_fallback: bool` flag on heuristic verdicts, excluded from aggregate quality metrics
- **Evaluation Pipeline Runner**: The end-to-end orchestration script loading datasets, executing scenarios, routing to judges, and gating CI
- **ADK Bridge**: Transformer converting ADK evalset format (from `build_evalset.py`) to judge-consumable scenario format

## Requirements

### Requirement 1: Threat Interception Judge Agent (Core SyncResolver)

**User Story:** As a detection engineer, I want an autonomous Antigravity SDK judge agent to evaluate the SyncResolver's verdict accuracy and reasoning quality, so that I can detect precision/recall regressions in the core interception pipeline.

#### Acceptance Criteria

1. WHEN a SyncResolver evaluation scenario completes, THE `threat_interception_judge` SHALL receive the tool call payload, predicted verdict, ground truth label, and reasoning text within XML-delimited `<untrusted_input>` boundaries
2. WHEN judging, THE agent SHALL return a `ThreatInterceptionRubric` Pydantic model with `detection_accuracy_score`, `false_positive_control_score`, `reasoning_quality_score`, `trajectory_soundness_score` (each 1–5), `justification` (≥10 chars), and `is_fallback` (bool)
3. WHEN Vertex AI is unavailable, THE judge SHALL fall back to a heuristic scorer that compares predicted verdict against ground truth and sets `is_fallback=True`
4. THE judge agent SHALL run with `vertex=True`, `AgentBehavior.AUTONOMOUS`, and `response_schema=ThreatInterceptionRubric`

### Requirement 2: Swarm Detection Judge Agent

**User Story:** As a security analyst, I want an autonomous judge agent to evaluate swarm detection accuracy, so that I can validate coordination detection and temporal correlation quality.

#### Acceptance Criteria

1. WHEN a swarm detection scenario completes, THE `swarm_detection_judge` SHALL receive agent events, detected swarm evidence, and ground truth coordination data within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `SwarmDetectionRubric` with `coordination_detection_score`, `temporal_precision_score`, `shared_infra_identification_score`, `fingerprint_quality_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN evaluating, THE judge SHALL assess whether swarms with `coordination_score >= 0.75` were correctly classified as high-confidence
4. THE scenario SHALL include at least 6 coordinated agents sharing infrastructure to test positive detection

### Requirement 3: Exploit Chain Judge Agent

**User Story:** As a vulnerability researcher, I want an autonomous judge agent to evaluate exploit chain detection quality, so that I can validate novelty scoring calibration and MITRE ATT&CK mapping accuracy.

#### Acceptance Criteria

1. WHEN an exploit chain scenario completes, THE `exploit_chain_judge` SHALL receive the detected chain, novelty score, MITRE mappings, and reference ground truth within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return an `ExploitChainRubric` with `chain_completeness_score`, `novelty_calibration_score`, `mitre_mapping_accuracy_score`, `chaining_confidence_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN a chain with novelty_score ≥ 0.8 is presented as known in ground truth, THE judge SHALL penalize `novelty_calibration_score`
4. WHEN a chain's MITRE technique IDs are all valid, THE judge SHALL award maximum `mitre_mapping_accuracy_score`

### Requirement 4: C2 Detection Judge Agent

**User Story:** As a threat intelligence analyst, I want an autonomous judge agent to evaluate C2 infrastructure detection, so that I can validate endpoint classification, beaconing detection, and cross-pillar correlation.

#### Acceptance Criteria

1. WHEN a C2 detection scenario completes, THE `c2_detection_judge` SHALL receive network events, detected C2 evidence, and ground truth C2 indicators within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `C2DetectionRubric` with `endpoint_classification_score`, `beaconing_detection_score`, `persistence_identification_score`, `cross_pillar_correlation_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN RequestBin/Pastebin URLs are present in ground truth, THE judge SHALL verify they appear in detected `c2_endpoints`
4. WHEN periodic connections at regular intervals are present, THE judge SHALL verify beaconing pattern classification

### Requirement 5: AILM Detection Judge Agent

**User Story:** As a security architect, I want an autonomous judge agent to evaluate AI-Induced Lateral Movement detection, so that I can validate boundary crossing detection and permission composition accuracy.

#### Acceptance Criteria

1. WHEN an AILM scenario completes, THE `ailm_detection_judge` SHALL receive permission grant sequences, detected AILM evidence, and ground truth boundary crossings within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return an `AILMDetectionRubric` with `boundary_crossing_detection_score`, `permission_composition_accuracy_score`, `risk_classification_score`, `evidence_completeness_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN 3+ boundary crossings exist in ground truth, THE judge SHALL verify CRITICAL risk_level classification
4. THE scenario SHALL test cross-trust-boundary permission accumulation over multiple time windows

### Requirement 6: Prompt Injection Judge Agent

**User Story:** As an AI safety engineer, I want an autonomous judge agent to evaluate indirect prompt injection detection, so that I can validate injection pattern recognition, redaction completeness, and false positive control.

#### Acceptance Criteria

1. WHEN a prompt injection scenario completes, THE `prompt_injection_judge` SHALL receive the input payload, detected injection evidence, applied redactions, and ground truth labels within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `PromptInjectionRubric` with `injection_detection_rate_score`, `redaction_completeness_score`, `false_positive_control_score`, `alert_severity_accuracy_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN a structural jailbreak is present in ground truth, THE judge SHALL verify it was detected and redacted
4. WHEN benign content is scanned, THE judge SHALL verify no false injection alerts were raised

### Requirement 7: Inbound Protocol Filter Judge Agent

**User Story:** As a platform security engineer, I want an autonomous judge agent to evaluate inbound protocol interception accuracy, so that I can validate header validation, rate limiting, and sanitization quality.

#### Acceptance Criteria

1. WHEN an inbound filter scenario completes, THE `inbound_filter_judge` SHALL receive RPC requests, filter decisions, and ground truth access policies within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return an `InboundFilterRubric` with `header_validation_accuracy_score`, `rate_limit_precision_score`, `sanitization_quality_score`, `error_response_safety_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN an unauthenticated non-loopback request is presented, THE judge SHALL verify it was rejected
4. WHEN rate limits are exceeded, THE judge SHALL verify excess requests were dropped without internal context leakage

### Requirement 8: Quota Enforcement Judge Agent

**User Story:** As a cloud infrastructure lead, I want an autonomous judge agent to evaluate Denial-of-Wallet defense accuracy, so that I can validate token burn rate detection, throttling precision, and alert timeliness.

#### Acceptance Criteria

1. WHEN a quota enforcement scenario completes, THE `quota_enforcement_judge` SHALL receive agent activity streams, quota decisions, and ground truth velocity data within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `QuotaEnforcementRubric` with `burn_rate_detection_score`, `throttling_precision_score`, `alert_timeliness_score`, `quarantine_accuracy_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN token burn rate exceeds 500 tokens/sec, THE judge SHALL verify quarantine was triggered
4. WHEN API velocity surges occur, THE judge SHALL verify Denial of Wallet alerts were emitted

### Requirement 9: Context Hygiene Judge Agent

**User Story:** As a compliance engineer, I want an autonomous judge agent to evaluate secret sanitization quality, so that I can validate redaction completeness and placeholder format compliance.

#### Acceptance Criteria

1. WHEN a context hygiene scenario completes, THE `context_hygiene_judge` SHALL receive raw payloads, sanitized outputs, and expected redaction patterns within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `ContextHygieneRubric` with `redaction_completeness_score`, `placeholder_format_compliance_score`, `metadata_preservation_score`, `non_sensitive_passthrough_score` (each 1–5), `justification`, and `is_fallback`
3. WHEN API keys, JWT tokens, or AWS/GCP secrets are present in the raw input, THE judge SHALL verify complete replacement with `[[VARIABLE_NAME]]` format
4. WHEN non-sensitive data is present, THE judge SHALL verify it passes through unmodified

### Requirement 10: Evaluation Pipeline Runner

**User Story:** As a CI/CD engineer, I want an automated evaluation pipeline that loads datasets, executes scenarios, routes results to judge agents, and produces a pass/fail CI gate, so that regressions are caught before merge.

#### Acceptance Criteria

1. WHEN invoked, THE pipeline runner SHALL authenticate via Application Default Credentials (ADC) with zero API keys
2. WHEN invoked, THE pipeline runner SHALL validate that `GEMINI_TIER=paid` and `BLACKWALL_TIER=paid` are set, exiting with a descriptive error if the paid-tier quota contract (300+ RPM) is not configured
3. WHEN loading datasets, THE pipeline runner SHALL consume both ADK-bridged scenarios and GCP-native eval datasets
4. WHEN scenarios execute, THE pipeline runner SHALL route results to the correct domain judge agent based on scenario metadata
5. WHEN all judges return, THE pipeline runner SHALL aggregate scores with fallback isolation (exclude `is_fallback=True` from means)
6. WHEN aggregated, THE pipeline runner SHALL emit a CI pass/fail verdict based on configurable threshold (default: all domains ≥ 3.5/5.0 mean)
7. WHEN complete, THE pipeline runner SHALL export all evaluation spans to Google Cloud Trace with `gen_ai.evaluation.*` attributes

### Requirement 11: ADK-to-EvalTask Dataset Bridge

**User Story:** As a test data engineer, I want the existing 127+ ADK evalset cases automatically bridged to judge-consumable format, so that the comprehensive test data is reusable across the evaluation pipeline.

#### Acceptance Criteria

1. WHEN ADK evalset cases are loaded, THE bridge SHALL transform `eval_case_id`, `conversation`, `expected_tool_use`, `reference`, and `metadata` into judge-consumable scenario format
2. WHEN transforming, THE bridge SHALL map `metadata.ground_truth` to `ground_truth_label` and `reference` to `ground_truth_verdict`
3. WHEN transforming, THE bridge SHALL extract `tool_name` from `expected_tool_use` into `reference_trajectory`
4. THE bridge SHALL support all three ADK case types: benign, malicious, and evasion
5. THE bridge SHALL validate output schema compliance before writing

### Requirement 12: SLA Validation Engine

**User Story:** As a performance engineer, I want evaluation runs to measure and record latency compliance against SLA thresholds, so that performance regressions are detected as part of the evaluation pipeline.

#### Acceptance Criteria

1. WHEN a scenario involves TSG signature matching, THE SLA validator SHALL measure execution time and assert < 10ms
2. WHEN a scenario involves structural gating, THE SLA validator SHALL measure execution time and assert < 5ms
3. WHEN a scenario involves active reaction containment, THE SLA validator SHALL measure execution time and assert < 50ms
4. WHEN SLA violations are detected, THE validator SHALL record them as Cloud Trace span attributes (`blackwall.sla.violated=true`, `blackwall.sla.measured_ms=N`)
5. WHEN SLA results are available, THE validator SHALL factor latency compliance into the relevant judge's `trajectory_soundness_score`

### Requirement 13: Pairwise Regression Judge Agent

**User Story:** As a detection engineer, I want a pairwise comparison judge that evaluates whether a candidate model/algorithm is better or worse than the baseline, so that I can detect quality regressions before deployment.

#### Acceptance Criteria

1. WHEN baseline and candidate evaluation results are available, THE `regression_judge` SHALL receive both result sets within XML-delimited boundaries
2. WHEN judging, THE agent SHALL return a `RegressionComparisonRubric` with `overall_quality_delta` (-5 to +5), `precision_delta`, `recall_delta`, `trajectory_quality_delta`, `regression_detected` (bool), and `justification`
3. WHEN `regression_detected=True`, THE pipeline SHALL emit a CI failure with the justification
4. THE regression judge SHALL use `PairwiseMetric` pattern with response flipping and 4x multi-sampling to eliminate position bias

### Requirement 14: Historical Regression Tracker

**User Story:** As a team lead, I want evaluation metrics stored historically so that I can track quality trends and compare against baselines over time.

#### Acceptance Criteria

1. WHEN an evaluation run completes, THE tracker SHALL persist domain-level mean scores, timestamps, and run metadata to `tests/eval/regression/history.jsonl`
2. WHEN a new run starts, THE tracker SHALL load the most recent historical entry as the comparison baseline
3. WHEN any domain mean score drops > 0.5 points from baseline, THE tracker SHALL flag a potential regression
4. THE tracker SHALL support querying the last N runs for trend visualization

### Requirement 15: Full ADK Callback Chain Trajectory Evaluation

**User Story:** As a quality engineer, I want the complete before_tool_callback → verdict → execution chain evaluated as an agent trajectory, so that I can verify the callback always fires first and verdicts are enforced.

#### Acceptance Criteria

1. WHEN evaluating callback chain trajectories, THE evaluation SHALL define reference trajectories: `["before_tool_callback", "verdict_decision", "execution_or_block"]`
2. WHEN a BLOCK verdict occurs, THE reference trajectory SHALL NOT include tool execution
3. WHEN an ALLOW verdict occurs, THE reference trajectory SHALL include the target tool execution
4. THE trajectory evaluation SHALL compute `trajectory_precision`, `trajectory_recall`, `trajectory_exact_match`, and `trajectory_in_order_match`
5. THE trajectory results SHALL be fed to the `threat_interception_judge` for qualitative assessment

### Requirement 16: Zero-Trust Prompt Delimitation

**User Story:** As a security engineer, I want all judge agent prompts to implement prompt defense against indirect injection from evaluated content, so that malicious payloads in test data cannot manipulate judge scoring.

#### Acceptance Criteria

1. WHEN constructing judge prompts, ALL untrusted inputs (trajectories, verdicts, evidence, payloads) SHALL be enclosed in `<untrusted_input type="...">` XML tags
2. WHEN sanitizing inputs, THE system SHALL regex-neutralize special LLM tokens (`[INST]`, `<<SYS>>`, `<|im_start|>`, etc.)
3. WHEN sanitizing inputs, THE system SHALL regex-neutralize instruction override attempts (`ignore.*instructions`, `disregard.*rules`, etc.)
4. WHEN sanitizing inputs, THE system SHALL regex-neutralize scoring manipulation directives (e.g., `assign maximum score`, `give 5/5`, `rate as perfect`)
5. THE system instruction SHALL explicitly state that `<untrusted_input>` content is evaluation data, never instructions

### Requirement 17: Fallback Isolation and Clean Aggregation

**User Story:** As a data scientist, I want heuristic fallback verdicts explicitly tracked and excluded from aggregate quality metrics, so that offline testing does not contaminate CI quality gates.

#### Acceptance Criteria

1. WHEN a judge agent fails (Vertex AI unavailable, timeout, API error), THE system SHALL invoke the heuristic fallback scorer with `is_fallback=True`
2. WHEN aggregating summary metrics per domain, THE system SHALL filter out `is_fallback=True` rows before computing mean scores
3. WHEN an entire domain consists of fallback rows, THE system SHALL report `None`/`NaN` for judge quality metrics (not heuristic values)
4. THE aggregation report SHALL include `fallback_count` and `fallback_rate` per domain for pipeline monitoring

### Requirement 18: CI/CD Integration and Pytest Markers

**User Story:** As a DevOps engineer, I want evaluation tests selectable via pytest markers so that they can run in appropriate CI stages without blocking fast unit test feedback.

#### Acceptance Criteria

1. ALL evaluation tests SHALL be decorated with `@pytest.mark.gcp_eval`
2. WHEN running in CI/CD, THE pipeline SHALL support `pytest -m gcp_eval` for isolated evaluation execution
3. WHEN evaluation pass/fail is determined, THE pipeline SHALL exit with code 0 (pass) or 1 (fail) for CI gating
4. THE evaluation pipeline SHALL support `--eval-threshold` CLI argument to configure minimum domain mean score

## Non-Functional Requirements

### NFR-1: Structured Output Determinism
All judge agents MUST use `response_schema` (Pydantic model) for structured output. Freeform text responses from judges are forbidden. Schema validation failures SHALL trigger retry (up to 3 attempts) before fallback.

### NFR-2: Zero Third-Party SaaS Dependencies and Paid-Tier Quota Contract
All evaluation operations MUST authenticate exclusively via GCP Application Default Credentials (ADC). The system SHALL NOT require `WANDB_API_KEY`, `GEMINI_API_KEY`, or any third-party SaaS tokens. The pipeline MUST validate `GEMINI_TIER=paid` and `BLACKWALL_TIER=paid` at startup to guarantee the 300+ RPM quota contract required for multi-agent judge workloads; if unset or not `paid`, the pipeline SHALL exit with a clear error rather than degrading to free-tier rate limits.

### NFR-3: Prompt Safety
All untrusted evaluation inputs MUST be XML-delimited and regex-sanitized before judge agent ingestion. No raw user content or model output may appear outside `<untrusted_input>` boundaries in judge prompts.

### NFR-4: Evaluation Containment
All evaluation scenarios MUST execute within `EvaluationEnvironmentManager` isolation. Judge evaluations SHALL NOT trigger production side effects (eBPF drops, Mesh broadcasts, Vault revocations).

### NFR-5: Token Efficiency
Judge prompts MUST place large static instructions and rubrics at the prompt beginning (system instruction) for implicit Gemini context caching (>32k prefix → 90% input cost discount). Per-scenario instance data MUST appear at the prompt end.

### NFR-6: Observability
All judge agent invocations MUST export OpenTelemetry spans to Google Cloud Trace with standard GenAI semantic convention attributes (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.*`, `gen_ai.evaluation.*`).
