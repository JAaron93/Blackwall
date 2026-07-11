# Blackwall Deprecations & Test Warnings

This document outlines the 54 test warnings and deprecations discovered during test execution. As this project is intended for long-term maintenance, addressing these issues will prevent future breakages when upgrading dependencies (e.g., Python 3.14, aiohttp 4.0, pytest 10.0).

## 1. Third-Party Library Deprecations

These warnings originate from upstream dependencies. Upgrading the underlying packages (or waiting for upstream maintainers to release patches) is usually the solution.

*   **Google Protobuf (`google._upb._message`)**:
    *   **Warning:** `DeprecationWarning: Type google._upb._message.MessageMapContainer uses PyType_Spec with a metaclass that has custom tp_new. This is deprecated and will no longer be allowed in Python 3.14.`
    *   **Impact:** This is a core incompatibility with upcoming Python 3.14 C-extension rules in the protobuf library.
    *   **Fix:** Upgrade `protobuf` / `grpcio` packages to their latest versions once they support Python 3.13/3.14 correctly.
*   **Gherkin Official (`gherkin_line.py`)**:
    *   **Warning:** `DeprecationWarning: 'maxsplit' is passed as positional argument`
    *   **Impact:** Minor syntax deprecation in Python 3.13's `re.split()`.
    *   **Fix:** Check if a newer version of `gherkin-official` (used by `pytest-bdd`) has resolved this.
*   **ADK Core (`<frozen abc>:106`)**:
    *   **Warning:** `DeprecationWarning: BaseAgentConfig is deprecated and will be removed in future versions. Config is now loaded via reflection so the separate config class is no longer needed.`
    *   **Fix:** Refactor ADK initialization in `tests/integration/test_demo_harness.py` to remove `BaseAgentConfig` usage.

## 2. Test Framework Warnings (`pytest` & `pytest-bdd`)

These warnings require minor configuration updates or test file modifications within the Blackwall repository.

*   **`aiohttp` Legacy Test Decorator**:
    *   **Warning:** `DeprecationWarning: Decorator @unittest_run_loop is no longer needed in aiohttp 3.8+`
    *   **Location:** Occurs roughly 8 times in `tests/unit/test_webhook.py`.
    *   **Fix:** Remove the `@unittest_run_loop` decorator from test functions in `test_webhook.py` as it is now natively handled by newer `aiohttp` versions.
*   **Missing Pytest Marks Registration**:
    *   **Warning:** `PytestUnknownMarkWarning: Unknown pytest.mark.guardrails - is this a typo?` (Also applies to `zero_ambient_authority`).
    *   **Fix:** Register the custom marks in `pyproject.toml` under the `[tool.pytest.ini_options]` section:
        ```toml
        [tool.pytest.ini_options]
        markers = [
            "guardrails: Marks BDD guardrail scenarios",
            "zero_ambient_authority: Marks unprivileged execution tests"
        ]
        ```
*   **`pytest-bdd` Scoping Deprecations**:
    *   **Warning:** `PytestRemovedIn10Warning: Passing nodeid to _register_fixture is deprecated. Pass node instead for fixture scoping.` and `Passing baseid to FixtureDef is deprecated.`
    *   **Fix:** Upgrade the `pytest-bdd` dependency in `pyproject.toml` to a version compatible with the declared `pytest>=8.0.0` and `pytest-bdd>=8.0.0` requirements. The tested compatible range is `pytest-bdd>=8.0.0,<9.0.0` paired with `pytest>=8.0.0,<9.0.0`. Versions beyond this range may introduce breaking changes in fixture scoping internals and should be validated before upgrading.
*   **Incorrect `pytest.mark.asyncio` Usage**:
    *   **Warning:** `PytestWarning: The test <Function test_generateSignature_no_sleep> is marked with '@pytest.mark.asyncio' but it is not an async function.` (Also applies to `test_WebhookListener_no_sleep`).
    *   **Location:** `tests/unit/test_event_driven_invariant.py`.
    *   **Fix:** Remove the `@pytest.mark.asyncio` decorator from these strictly synchronous test functions.

## 3. Coroutine Teardown Warnings

These occur when a test runner exits before an internally scheduled asyncio task has a chance to execute or be awaited properly. They don't typically fail a test but generate console spam.

*   **Un-awaited Coroutines**:
    *   **Warning:** `RuntimeWarning: coroutine 'BatchResolver.submit_to_gemini_sync' was never awaited`
    *   **Warning:** `RuntimeWarning: coroutine 'GTIQueryBudgetTracker._replenish_loop' was never awaited`
    *   **Warning:** `RuntimeWarning: coroutine 'HybridPolicyServer.evaluate' was never awaited`
    *   **Fix:** Ensure that mock objects return valid awaited futures if they are mocked out, or ensure that background tasks (like `_replenish_loop` or background submissions) are properly cancelled and awaited during `teardown`/`pytest_fixture` cleanup steps.
