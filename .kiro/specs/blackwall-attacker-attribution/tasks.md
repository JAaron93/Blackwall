# Task Implementation Plan: Blackwall Attacker Identification & Reporting (`blackwall-attacker-attribution`)

This task document breaks down the implementation of attacker attribution into modular, test-driven execution tracks.

---

## Task Matrix & Traceability

| Task ID | Component | Requirements Covered | Dependencies | Execution Mode |
| :--- | :--- | :--- | :--- | :--- |
| **TASK-1** | Pydantic Models | FR-1, FR-2, FR-4 | None | Sequential |
| **TASK-2A**| Identity Extractor | FR-1, FR-2, NFR-2 | TASK-1 | Parallel Track A |
| **TASK-2B**| Incident Report Builder | FR-4, FR-6 | TASK-1 | Parallel Track B |
| **TASK-3** | SQLite Attacker Profile DB | FR-3, NFR-1 | TASK-1 | Sequential |
| **TASK-4** | Resolver & ADK Integration | FR-5, NFR-1, US-1 | TASK-2A, TASK-2B, TASK-3 | Sequential |
| **TASK-5** | BDD Test Suite & E2E Validation | US-1, US-2, BDD Scenarios | TASK-4 | Sequential |

---

## Track 1: Foundation Data Models (TDD)

### TASK-1: Implement Attribution Pydantic Models & Fingerprinting
- **Description**: Add `AttackerIdentity`, `AttackerProfile`, and `IncidentReport` models to `src/blackwall/models.py`. Implement identity SHA-256 fingerprinting logic.
- **Dependencies**: None.
- **Traceability**: FR-1, FR-2, FR-4.
- **TDD Requirement**: Write unit tests in `tests/test_attribution_models.py` verifying fingerprint determinism and model validation before writing model code.

---

## Track 2: Core Attribution Engines

> [!TIP] PARALLEL EXECUTION
> TASK-2A and TASK-2B can be developed concurrently once TASK-1 is complete.

### TASK-2A: Implement `AttackerIdentityExtractor`
- **Description**: Create `src/blackwall/attribution/extractor.py` to parse identity attributes from ADK metadata, process IDs, and environment variables.
- **Dependencies**: TASK-1.
- **Traceability**: FR-1, FR-2, NFR-2.
- **TDD Requirement**: Write failing tests in `tests/test_identity_extractor.py` covering ADK metadata parsing, process fallback, and fail-closed error handling.

### TASK-2B: Implement `IncidentReportGenerator` & Formatter
- **Description**: Create `src/blackwall/attribution/reporter.py` to build `IncidentReport` instances and provide `to_markdown()` and `to_json()` formatting functions.
- **Dependencies**: TASK-1.
- **Traceability**: FR-4, FR-6, US-1.
- **TDD Requirement**: Write failing tests in `tests/test_report_generator.py` testing secret redaction and Markdown formatting.

---

## Track 3: Persistence & Resolver Integration

### TASK-3: SQLite Attacker Profile Store & Threat Graph Updates
- **Description**: Extend `src/blackwall/db/database.py` with `attacker_profiles` table schema and update methods (`upsert_attacker_profile`, `get_attacker_profile`).
- **Dependencies**: TASK-1.
- **Traceability**: FR-3, NFR-1.
- **TDD Requirement**: Write failing tests in `tests/test_attacker_profile_db.py` verifying SQLite CRUD operations and SLA execution times (<5ms).

### TASK-4: Integrate Attribution into `SyncResolver` & `ADKIntegration`
- **Description**: Wire `AttackerIdentityExtractor`, `AttackerProfile` DB updates, and `IncidentReportGenerator` into `SyncResolver.evaluate()` when a `BLOCK` or `QUARANTINE` verdict is issued.
- **Dependencies**: TASK-2A, TASK-2B, TASK-3.
- **Traceability**: FR-5, NFR-1, US-1.
- **TDD Requirement**: Add integration tests in `tests/test_attribution_integration.py` ensuring blocked callbacks automatically emit reports and log alerts.

---

## Track 4: Acceptance Testing & BDD Verification

### TASK-5: BDD Feature Scenarios & E2E Validation
- **Description**: Implement `pytest-bdd` step definitions in `tests/features/steps/test_attacker_attribution_steps.py` for `tests/features/attacker_attribution.feature`.
- **Dependencies**: TASK-4.
- **Traceability**: US-1, US-2, BDD Scenarios.
- **Verification**: Run `pytest tests/` and `pytest tests/features/` to confirm 100% pass rate.
