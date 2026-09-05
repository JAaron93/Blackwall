# Task Implementation Plan: Blackwall Agent Swarm Attribution Logic (`agent-swarm-attribution-logic`)

This task implementation plan structures the development of Blackwall's Agent Swarm Attribution subsystem into test-driven, modular execution tracks. Every task enforces strict Test-Driven Development (TDD) and Behavior-Driven Development (BDD) using Gherkin syntax.

---

## Task Matrix & Traceability

| Task ID | Component | Requirements Covered | Dependencies | Execution Mode | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TASK-1.1** | Swarm Attribution Models (Core & Enterprise) | FR-1, FR-2, FR-4 | None | Sequential | [ ] PENDING |
| **TASK-1.2** | Model Property & Validation Tests (TDD) | FR-1, FR-2, FR-4 | TASK-1.1 | Sequential | [ ] PENDING |
| **TASK-1.3** | Data Models BDD Gherkin Scenarios | FR-1, FR-2, FR-4, BDD | TASK-1.2 | Sequential | [ ] PENDING |
| **TASK-2A.1**| Implement `LinguisticSwarmClassifier` (TDD) | FR-1, FR-2, NFR-1 | TASK-1.3 | Parallel Track 2A | [ ] PENDING |
| **TASK-2A.2**| Linguistic Classifier Unit Tests | FR-1, FR-2, NFR-1 | TASK-2A.1 | Parallel Track 2A | [ ] PENDING |
| **TASK-2A.3**| Integrate Classifier into `AttackerIdentityExtractor` | FR-1, FR-2, NFR-2 | TASK-2A.2 | Parallel Track 2A | [ ] PENDING |
| **TASK-2A.4**| Linguistic Attribution BDD Scenarios | FR-1, FR-2, US-1 | TASK-2A.3 | Parallel Track 2A | [ ] PENDING |
| **TASK-2B.1**| Implement `CovertChannelDetector` (TDD) | FR-3, FR-4, NFR-4 | TASK-1.3 | Parallel Track 2B | [ ] PENDING |
| **TASK-2B.2**| Covert Channel Inference Unit Tests | FR-3, FR-4, NFR-4 | TASK-2B.1 | Parallel Track 2B | [ ] PENDING |
| **TASK-2B.3**| Integrate Detector with `AgentSwarmDetector` & `AlertBus` | FR-3, FR-4, NFR-2 | TASK-2B.2 | Parallel Track 2B | [ ] PENDING |
| **TASK-2B.4**| Covert Channel BDD Gherkin Scenarios | FR-3, FR-4, US-2 | TASK-2B.3 | Parallel Track 2B | [ ] PENDING |
| **TASK-3.1** | SQLite Swarm Lineage Schema Migration | FR-5, NFR-3 | TASK-1.3 | Sequential | [ ] PENDING |
| **TASK-3.2** | Implement `SwarmContextProvider` Protocol (TDD) | FR-5, NFR-3, NFR-4 | TASK-2A.4, TASK-2B.4, TASK-3.1 | Sequential | [ ] PENDING |
| **TASK-3.3** | Swarm Attribution Provider Unit & BDD Tests | FR-5, NFR-4 | TASK-3.2 | Sequential | [ ] PENDING |
| **TASK-4.1** | Wire `SwarmContextProvider` into `SyncResolver` | FR-5, FR-6, NFR-1 | TASK-3.3 | Sequential | [ ] PENDING |
| **TASK-4.2** | Enriched Incident Reporting Formatters (MD/JSON) | FR-6, FR-7, US-1 | TASK-4.1 | Sequential | [ ] PENDING |
| **TASK-4.3** | End-to-End Multi-Agent Swarm BDD Scenarios | US-1, US-2, US-3 | TASK-4.2 | Sequential | [ ] PENDING |
| **TASK-4.4** | GCP Cloud Evaluation Dataset & Benchmark Audit | US-3, Constitution §4 | TASK-4.3 | Sequential | [ ] PENDING |

---

## Track 1: Foundation Data Models & Validation

### [ ] TASK-1.1: Implement Swarm Attribution Models & Extensions (TDD)
- **Description**: Add `LinguisticSwarmMarkers` and `SwarmContextSummary` directly to Core models (`src/blackwall/models.py`) to prevent Core-to-Enterprise coupling and provide a unified provider return contract. Add `CovertChannelEvidence` to Enterprise models (`src/blackwall/enterprise/advanced_threat_detection/models.py`). Extend `AttackerIdentity`, `AttackerProfile`, and `IncidentReport` in `src/blackwall/models.py` with collective fields (`is_collective`, `collective_name`, `swarm_id`, `suspected_covert_channels`, and bounded `collective_confidence: float = Field(default=0.0, ge=0.0, le=1.0)`).
- **Dependencies**: None.
- **Traceability**: FR-1, FR-2, FR-4, FR-5.
- **TDD Requirement**: Write failing unit tests in `tests/unit/test_swarm_attribution_models.py` asserting field presence, UTC timezone validation, score bounds (`[0.0, 1.0]`), and default empty list factories before implementing models.

### [ ] TASK-1.2: Implement Model Property & Validation Tests
- **Description**: Add Hypothesis property tests verifying score boundary validation (`[0.0, 1.0]`), minimal agent set lengths ($N \ge 2$), timezone-aware UTC datetime validation via `validate_utc_datetime` (for `CovertChannelEvidence` and `SwarmContextSummary`), and temporal sequence ordering (`last_detected >= first_detected`).
- **Dependencies**: TASK-1.1.
- **Traceability**: FR-1, FR-2, FR-4, FR-5.
- **TDD Requirement**: Verify all property checks pass via `pytest tests/property/test_swarm_attribution_properties.py`.

### [ ] TASK-1.3: Implement Data Models BDD Gherkin Scenarios
- **Description**: Create `tests/features/agent_swarm_attribution_models.feature` and step definitions in `tests/step_defs/test_agent_swarm_attribution_models_bdd.py` validating data models under Gherkin scenarios.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-1, FR-2, FR-4, BDD Scenarios.
- **BDD Requirement**: Verify scenarios pass with `pytest tests/step_defs/test_agent_swarm_attribution_models_bdd.py`.

---

## Track 2: Core Attribution & Inference Engines

> [!TIP] PARALLEL EXECUTION
> Track 2A (`LinguisticSwarmClassifier`) and Track 2B (`CovertChannelDetector`) address distinct architectural pillars and can be developed concurrently once Track 1 is verified.

### Track 2A: Linguistic Swarm Classifier (Pillar 1)

#### [ ] TASK-2A.1: Implement `LinguisticSwarmClassifier` (TDD)
- **Description**: Create `src/blackwall/attribution/linguistic.py`. Implement regex-based pronoun scanning, consensus phrase weighting, and `collective_confidence_score` calculation with fail-safe error isolation.
- **Dependencies**: TASK-1.3.
- **Traceability**: FR-1, FR-2, NFR-1.
- **TDD Requirement**: Write failing tests in `tests/unit/test_linguistic_swarm_classifier.py` covering single "we" vs. multi-pronoun consensus phrases before implementing classifier.

#### [ ] TASK-2A.2: Linguistic Classifier Unit Tests & Edge Case Hardening
- **Description**: Test edge cases including false monoliths (`agent_id="we"`), natural language ambiguity (casual "we" in benign prompts), empty strings, and adversarial unicode substitutions.
- **Dependencies**: TASK-2A.1.
- **Traceability**: FR-1, FR-2, NFR-1.
- **TDD Requirement**: Ensure execution time per evaluation is benchmarked under <2ms.

#### [ ] TASK-2A.3: Integrate Classifier into `AttackerIdentityExtractor`
- **Description**: Update `src/blackwall/attribution/extractor.py` to call `LinguisticSwarmClassifier.classify(context)` and embed `LinguisticSwarmMarkers` inside the returned `AttackerIdentity`. Implement session-salted fingerprinting for false-monolith prevention.
- **Dependencies**: TASK-2A.2.
- **Traceability**: FR-1, FR-2, NFR-2.
- **TDD Requirement**: Update `tests/test_identity_extractor.py` with tests verifying `is_collective` assignment.

#### [ ] TASK-2A.4: Linguistic Attribution BDD Scenarios
- **Description**: Add Gherkin scenarios in `tests/features/agent_swarm_linguistic_attribution.feature` and step definitions in `tests/step_defs/test_agent_swarm_linguistic_bdd.py` testing pronoun extraction and collective identity tagging.
- **Dependencies**: TASK-2A.3.
- **Traceability**: FR-1, FR-2, US-1, BDD Scenarios.
- **BDD Requirement**: Execute `pytest tests/step_defs/test_agent_swarm_linguistic_bdd.py`.

---

### Track 2B: Covert Channel & Latent Coordination Detector (Pillar 2)

#### [ ] TASK-2B.1: Implement `CovertChannelDetector` (TDD)
- **Description**: Create `src/blackwall/enterprise/advanced_threat_detection/covert_channel.py`. Implement the Latent Coordination Divergence heuristic to infer `UNLOCATED_MESSAGE_BOARD` when high correlation occurs without visible external C2.
- **Dependencies**: TASK-1.3.
- **Traceability**: FR-3, FR-4, NFR-4.
- **TDD Requirement**: Write failing tests in `tests/unit/test_covert_channel_detector.py` checking unlocated board deduction when external IPs are absent.

#### [ ] TASK-2B.2: Steganographic Registry & Storage Channel Detection
- **Description**: Implement heuristics recognizing Artifactory package name steganography, unusual metadata querying spikes, and local file dead-drop sequences (`/tmp`, `/dev/shm`).
- **Dependencies**: TASK-2B.1.
- **Traceability**: FR-4, US-2.
- **TDD Requirement**: Add unit tests simulating multi-agent Artifactory directory polling.

#### [ ] TASK-2B.3: Integrate Detector with `AgentSwarmDetector` & `AlertBus`
- **Description**: Wire `CovertChannelDetector` into `AgentSwarmDetector.detect_swarms()`. Add `publish_covert_channel_alert()` to `src/blackwall/enterprise/advanced_threat_detection/alert_bus.py` with `CRITICAL` severity mapping.
- **Dependencies**: TASK-2B.2.
- **Traceability**: FR-3, FR-4, NFR-2.
- **TDD Requirement**: Update alert bus tests in `tests/unit/test_alert_generation.py` ensuring covert channel alerts are published.

#### [ ] TASK-2B.4: Covert Channel BDD Gherkin Scenarios
- **Description**: Add Gherkin scenarios in `tests/features/covert_channel_detection.feature` and step definitions in `tests/step_defs/test_covert_channel_bdd.py` testing unlocated board inference and Artifactory steganography detection.
- **Dependencies**: TASK-2B.3.
- **Traceability**: FR-3, FR-4, US-2, BDD Scenarios.
- **BDD Requirement**: Execute `pytest tests/step_defs/test_covert_channel_bdd.py`.

---

## Track 3: Swarm-to-Attribution Bridge & Persistence (Pillar 3)

### [ ] TASK-3.1: SQLite Swarm Lineage Schema Migration (TDD)
- **Description**: Update `src/blackwall/db/database.py` to add `swarm_memberships` and `suspected_covert_channels` columns to `attacker_profiles` table, supporting JSON array serialization.
- **Dependencies**: TASK-1.3.
- **Traceability**: FR-5, NFR-3.
- **TDD Requirement**: Write migration tests in `tests/test_attacker_profile_db.py` ensuring backward compatibility with existing profiles.

### [ ] TASK-3.2: Implement `SwarmContextProvider` Protocol & Providers (TDD)
- **Description**: Create `src/blackwall/attribution/provider.py` defining the abstract `SwarmContextProvider` protocol returning `Optional[SwarmContextSummary]`, and `SQLiteSwarmContextProvider` in Core with zero Enterprise dependencies. In Enterprise, create `src/blackwall/enterprise/advanced_threat_detection/bridge.py` implementing `EnterpriseSwarmContextProvider` adapting `AttackGraphStore` without Core ever importing from `blackwall.enterprise`.
- **Dependencies**: TASK-2A.4, TASK-2B.4, TASK-3.1.
- **Traceability**: FR-5, NFR-3, NFR-4.
- **TDD Requirement**: Write unit tests in `tests/unit/test_swarm_attribution_provider.py` verifying lookup latency (<15ms) across both SQLite and mock Enterprise providers.

### [ ] TASK-3.3: Swarm Attribution Provider Unit & BDD Tests
- **Description**: Add BDD scenarios in `tests/features/swarm_attribution_provider.feature` testing provider resolution, bi-directional profile updates, and strict tier isolation (verifying no Enterprise imports inside Core).
- **Dependencies**: TASK-3.2.
- **Traceability**: FR-5, NFR-3, NFR-4, BDD Scenarios.
- **BDD Requirement**: Execute `pytest tests/step_defs/test_swarm_attribution_provider_bdd.py`.

---

## Track 4: Interception Pipeline & End-to-End Verification

### [ ] TASK-4.1: Wire `SwarmContextProvider` into `SyncResolver`
- **Description**: Add optional constructor dependency injection `swarm_provider: Optional[SwarmContextProvider] = None` to `SyncResolver.__init__()` in `src/blackwall/sync_resolver.py` (defaulting to `SQLiteSwarmContextProvider`). Update `_process_attribution()` to call `swarm_provider.resolve_swarm_context()` asynchronously upon `BLOCK` or `QUARANTINE` verdicts.
- **Dependencies**: TASK-3.3.
- **Traceability**: FR-5, FR-6, NFR-1, NFR-3.
- **TDD Requirement**: Verify in `tests/test_attribution_integration.py` that resolver background tasks enrich profiles without exceeding 5ms total latency and without importing any enterprise modules.

### [ ] TASK-4.2: Enriched Incident Reporting Formatters (MD/JSON)
- **Description**: Update `IncidentReportGenerator` in `src/blackwall/attribution/reporter.py` and `to_markdown()` / `to_json()` in `src/blackwall/models.py` to format swarm IDs, collective markers, and suspected covert channels.
- **Dependencies**: TASK-4.1.
- **Traceability**: FR-6, FR-7, US-1.
- **TDD Requirement**: Update `tests/test_report_generator.py` asserting Markdown and JSON representations contain the new collective headers.

### [ ] TASK-4.3: End-to-End Multi-Agent Swarm BDD Scenarios
- **Description**: Implement full end-to-end simulation in `tests/features/e2e_swarm_attribution.feature` simulating an ExploitGym breakout: 5 agents using collective "we" framing and Artifactory directory manipulation -> Blackwall blocks execution -> infers unlocated message board -> attributes attack to collective swarm.
- **Dependencies**: TASK-4.2.
- **Traceability**: US-1, US-2, US-3, BDD Scenarios.
- **BDD Requirement**: Execute full suite via `pytest -m "not slow"`.

### [ ] TASK-4.4: Cloud Evaluation Dataset & Benchmark Audit
- **Description**: Extend `src/blackwall/enterprise/advanced_threat_detection/gcp_eval_datasets.py` with multi-agent collective swarm and covert message board benchmarks. Verify compatibility with Vertex AI Gen AI Evaluation Service.
- **Dependencies**: TASK-4.3.
- **Traceability**: US-3, Constitution §4.
- **Verification**: Run evaluation smoke test in `tests/evaluation/test_swarm_scenario.py`.
