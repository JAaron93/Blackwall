# Task Implementation Plan: Blackwall Attacker Identification & Reporting (`blackwall-attacker-attribution`)

This task document breaks down the implementation of attacker attribution into modular, test-driven execution tracks, mandating both unit tests and Gherkin BDD scenarios for every task.

---

## Task Matrix & Traceability

| Task ID | Component | Requirements Covered | Dependencies | Execution Mode | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TASK-1.1** | Pydantic Models & Fingerprinting | FR-1, FR-2, FR-4 | None | Sequential | **[x] COMPLETE** |
| **TASK-1.2** | Pydantic Models BDD Scenarios | FR-1, FR-2, FR-4 | TASK-1.1 | Sequential | **[x] COMPLETE** |
| **TASK-2A.1**| Identity Extractor | FR-1, FR-2, NFR-2 | TASK-1.2 | Parallel Track A | **[x] COMPLETE** |
| **TASK-2A.2**| Identity Extractor BDD Scenarios | FR-1, FR-2, NFR-2 | TASK-2A.1 | Parallel Track A | **[x] COMPLETE** |
| **TASK-2B.1**| Incident Report Builder | FR-4, FR-6 | TASK-1.2 | Parallel Track B | **[x] COMPLETE** |
| **TASK-2B.2**| Incident Report Builder BDD Scenarios | FR-4, FR-6 | TASK-2B.1 | Parallel Track B | **[x] COMPLETE** |
| **TASK-3.1** | SQLite Attacker Profile DB | FR-3, NFR-1 | TASK-1.2 | Sequential | Pending |
| **TASK-3.2** | Attacker Profile DB BDD Scenarios | FR-3, NFR-1 | TASK-3.1 | Sequential | Pending |
| **TASK-4.1** | Resolver & ADK Integration | FR-5, NFR-1, US-1 | TASK-2A.2, TASK-2B.2, TASK-3.2 | Sequential | Pending |
| **TASK-4.2** | End-to-End Interception BDD Scenarios| FR-5, US-1, US-2 | TASK-4.1 | Sequential | Pending |
| **TASK-5**   | Full System Verification | US-1, US-2, BDD Scenarios | TASK-4.2 | Sequential | Pending |

---

## Track 1: Foundation Data Models & Validation

### - [x] TASK-1.1: Implement Attribution Pydantic Models & Fingerprinting (TDD)
- **Description**: Add `AttackerIdentity`, `AttackerProfile`, and `IncidentReport` models to `src/blackwall/models.py`. Implement identity SHA-256 fingerprinting logic.
- **Dependencies**: None.
- **Traceability**: FR-1, FR-2, FR-4.
- **TDD Requirement**: Write unit tests in `tests/test_attribution_models.py` verifying fingerprint determinism and model validation before writing model code.

### - [x] TASK-1.2: Implement Data Model BDD Gherkin Scenarios
- **Description**: Add Gherkin BDD feature scenarios to `tests/features/attacker_attribution.feature` and step definitions in `tests/step_defs/test_attacker_attribution_steps.py` for model validation, UTC timestamp enforcement, score bounds, and format serialization.
- **Dependencies**: TASK-1.1.
- **Traceability**: FR-1, FR-2, FR-4, BDD Scenarios.
- **BDD Requirement**: Verify scenarios pass with `pytest tests/step_defs/test_attacker_attribution_steps.py`.


---

## Track 2: Core Attribution Engines

> [!TIP] PARALLEL EXECUTION
> Track 2A (TASK-2A.1 & TASK-2A.2) and Track 2B (TASK-2B.1 & TASK-2B.2) can be developed concurrently once Track 1 is complete.

### - [x] TASK-2A.1: Implement `AttackerIdentityExtractor` (TDD)
- **Description**: Create `src/blackwall/attribution/extractor.py` to parse identity attributes from ADK metadata, process IDs, and environment variables.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-1, FR-2, NFR-2.
- **TDD Requirement**: Write failing tests in `tests/test_identity_extractor.py` covering ADK metadata parsing, process fallback, and fail-closed error handling.

### - [x] TASK-2A.2: Implement Identity Extractor BDD Gherkin Scenarios
- **Description**: Add Gherkin BDD feature scenarios to `tests/features/attacker_attribution.feature` and step definitions in `tests/step_defs/test_attacker_attribution_steps.py` testing identity extraction from ADK context metadata and fallback process inspection.
- **Dependencies**: TASK-2A.1.
- **Traceability**: FR-1, FR-2, NFR-2, BDD Scenarios.
- **BDD Requirement**: Execute `pytest -k "extractor"` to verify BDD scenarios pass.

### - [x] TASK-2B.1: Implement `IncidentReportGenerator` & Formatter (TDD)
- **Description**: Create `src/blackwall/attribution/reporter.py` to build `IncidentReport` instances and provide `to_markdown()` and `to_json()` formatting functions.
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-4, FR-6, US-1.
- **TDD Requirement**: Write failing tests in `tests/test_report_generator.py` testing secret redaction and Markdown formatting.

### - [x] TASK-2B.2: Implement Incident Report Builder BDD Gherkin Scenarios
- **Description**: Add Gherkin BDD feature scenarios to `tests/features/attacker_attribution.feature` and step definitions in `tests/step_defs/test_attacker_attribution_steps.py` testing report builder formatting and secret sanitization.
- **Dependencies**: TASK-2B.1.
- **Traceability**: FR-4, FR-6, US-1, BDD Scenarios.
- **BDD Requirement**: Execute `pytest -k "reporter"` to verify BDD scenarios pass.


---

## Track 3: Persistence & Resolver Integration

### TASK-3.1: SQLite Attacker Profile Store & Threat Graph Updates (TDD)
- **Description**: Extend `src/blackwall/db/database.py` with `attacker_profiles` table schema and update methods (`upsert_attacker_profile`, `get_attacker_profile`).
- **Dependencies**: TASK-1.2.
- **Traceability**: FR-3, NFR-1.
- **TDD Requirement**: Write failing tests in `tests/test_attacker_profile_db.py` verifying SQLite CRUD operations and SLA execution times (<5ms).

### TASK-3.2: Implement Attacker Profile DB BDD Gherkin Scenarios
- **Description**: Add Gherkin BDD feature scenarios to `tests/features/attacker_attribution.feature` and step definitions in `tests/step_defs/test_attacker_attribution_steps.py` testing persistent profile updates and total attack counter increments.
- **Dependencies**: TASK-3.1.
- **Traceability**: FR-3, NFR-1, BDD Scenarios.
- **BDD Requirement**: Execute `pytest -k "profile_db"` to verify BDD scenarios pass.

### TASK-4.1: Integrate Attribution into `SyncResolver` & `ADKIntegration`
- **Description**: Wire `AttackerIdentityExtractor`, `AttackerProfile` DB updates, and `IncidentReportGenerator` into `SyncResolver.evaluate()` when a `BLOCK` or `QUARANTINE` verdict is issued.
- **Dependencies**: TASK-2A.2, TASK-2B.2, TASK-3.2.
- **Traceability**: FR-5, NFR-1, US-1.
- **TDD Requirement**: Add integration tests in `tests/test_attribution_integration.py` ensuring blocked callbacks automatically emit reports and log alerts.

### TASK-4.2: Implement End-to-End Interception BDD Gherkin Scenarios
- **Description**: Add end-to-end Gherkin BDD feature scenarios to `tests/features/attacker_attribution.feature` and step definitions in `tests/step_defs/test_attacker_attribution_steps.py` testing full interception flow: tool call -> BLOCK verdict -> attacker identity extraction -> profile score update -> CLI alert.
- **Dependencies**: TASK-4.1.
- **Traceability**: FR-5, US-1, US-2, BDD Scenarios.
- **BDD Requirement**: Execute `pytest -k "e2e_attribution"` to verify BDD scenarios pass.

---

## Track 4: Full System Verification

### TASK-5: Full System Regression & Verification
- **Description**: Execute complete test suite and BDD feature validation across Blackwall Core and Enterprise Mesh modules.
- **Dependencies**: TASK-4.2.
- **Traceability**: US-1, US-2, BDD Scenarios.
- **Verification**: Run `pytest tests/` and `pytest tests/features/` to confirm 100% pass rate.
