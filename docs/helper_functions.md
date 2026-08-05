# Centralized Helper Functions & Utility Modules

This document serves as the centralized reference for reusable helper functions and utility modules across the Blackwall codebase to enforce the DRY (Don't Repeat Yourself) principle.

---

## 1. Validation & Utility Helpers (`src/blackwall/validators.py`)

Module Location: [`src/blackwall/validators.py`](../src/blackwall/validators.py)

| Function | Signature | Description / Purpose | Use Cases & Applied Locations |
| :--- | :--- | :--- | :--- |
| `validate_semver_format` | `(v: str) -> str` | Validates that a version string strictly follows the `MAJOR.MINOR.PATCH` semantic versioning format via regex `^\d+\.\d+\.\d+$`. Raises `ValueError` on mismatch. | `PolicyServerState.validate_semver` ([models.py](../src/blackwall/models.py)), `PolicyConfig.validate_semver` ([policy/models.py](../src/blackwall/policy/models.py)). |
| `validate_utc_datetime` | `(v: datetime) -> datetime` | Validates that a `datetime` object is timezone-aware and set to UTC (`v.tzinfo` is not None and UTC offset matches UTC). Raises `ValueError` if naive or non-UTC. | `NormalizedEvent`, `AttackPath`, `SwarmEvidence` field validators ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)). |
| `utc_now` | `() -> datetime` | Returns the current timezone-aware UTC `datetime` (`datetime.now(timezone.utc)`). | Default factories in Pydantic models, telemetry spans, audit timestamps. |

---

## 2. Test Step Async Helper (`tests/step_defs/async_utils.py`)

Module Location: [`tests/step_defs/async_utils.py`](../tests/step_defs/async_utils.py)

| Function | Signature | Description / Purpose | Use Cases & Applied Locations |
| :--- | :--- | :--- | :--- |
| `run_async` | `(coro: Coroutine) -> Any` | Safely executes an asynchronous coroutine synchronously inside `pytest-bdd` step definitions using an isolated event loop. | `test_advanced_threat_detection_bdd.py`, `test_batch_resolver_bdd.py`, `test_enterprise_mesh.py`. |

---

## 3. BDD Security Contract Helpers (`tests/step_defs/test_security_contract_validators_steps.py`)

Module Location: [`tests/step_defs/test_security_contract_validators_steps.py`](../tests/step_defs/test_security_contract_validators_steps.py)
Feature Location: [`tests/features/security_contract_validators.feature`](../tests/features/security_contract_validators.feature)

| Step Definition | Gherkin Pattern | Description / Purpose |
| :--- | :--- | :--- |
| `set_version_string` | `Given a version string "{version_str}"` | Sets test version input on `ValidatorState`. |
| `execute_semver_validation` | `When the semver validation helper is executed` | Executes `validate_semver_format` and captures exceptions into state. |
| `execute_utc_datetime_validation` | `When the UTC datetime validation helper is executed` | Executes `validate_utc_datetime` and captures exceptions into state. |
| `set_naive_datetime` | `Given a naive datetime without timezone info` | Generates a naive datetime without timezone info (`tzinfo=None`). |
| `set_non_utc_datetime` | `Given a non-UTC timezone-aware datetime` | Generates a non-UTC timezone-aware datetime object. |

---

## Guidelines for Adding New Helpers
1. Place general domain/validation helpers in `src/blackwall/validators.py` or dedicated sub-package utility modules.
2. Ensure all helper functions follow the **Single Responsibility Principle**.
3. Always add unit tests for new helper functions in `tests/unit/test_validators.py`.
4. Add corresponding BDD security contract scenarios under `tests/features/` and executable steps under `tests/step_defs/`.
5. Update this document whenever new shared helper functions are added or modified.
