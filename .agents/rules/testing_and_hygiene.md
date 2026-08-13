# Testing SLA, BDD, & Code Hygiene Rules

## 1. Warmup Latency Benchmarking
* **Rule:** Latency SLA tests MUST run at least one untimed warmup query prior to starting timers to bypass FTS5 parser compilation, database pool initialization, and JIT compilation overhead.

## 2. Async BDD Step Execution Pattern
* **Rule:** In `pytest-bdd` step definitions executing asynchronous coroutines within synchronous step functions, steps MUST import and use the centralized `run_async(coro)` helper from `tests.step_defs.async_utils` (`from tests.step_defs.async_utils import run_async`) rather than declaring local `run_async` functions or nested `async def` coroutines with inline `asyncio.run(...)`.

## 3. Early Parameter Validation for Model Invariants
* **Rule:** Store query methods and API functions constructing Pydantic models with length or range invariants (e.g. `min_path_length >= 2` for `AttackPath`) MUST validate parameters at entry and raise `ValueError` before triggering downstream Pydantic validation exceptions.

## 4. Audit Hook Isolation in Test Suites
* **Rule:** Tests evaluating `sys.addaudithook` MUST defer import to function scope or isolated subprocesses. Never import hook-registering code at global module scope in test files to avoid polluting global runtime state across unrelated test modules.

## 5. Mock Credential Hygiene for Secret Scanners
* **Rule:** When creating synthetic test inputs or honey-token strings in unit/integration tests, NEVER use strings containing cloud provider keyword patterns (e.g. `AWS_KEY`, `AKIA`, `SLACK_TOKEN`) or high-entropy literals with `secret_`/`key_`/`pass_` prefixes. Always use generic prefixes such as `BW_SYNTHETIC_MOCK_SECRET_0192` to prevent secret scanners (GitGuardian) from triggering false-positive alerts.

## 6. Absolute Imports in Test Modules
* **Rule:** In `tests/` subdirectories (e.g. `tests/integration/`, `tests/unit/`), always use absolute imports from the repository root (e.g. `from tests.integration.helpers import ...`) rather than relative imports (`from .helpers import ...`). Relative imports in test submodules cause `ImportError` during pytest collection.

## 7. Portable Documentation Links
* **Rule:** Markdown documentation files in `docs/` must use **repo-relative markdown paths** (e.g. `[helpers.py](../tests/integration/helpers.py)`), and must **never** hard-code local environment `file:///Users/...` or `file:///C:/...` URLs.

## 8. Mock Type Signature Alignment
* **Rule:** Test helper functions creating mock objects must ensure the return type annotation matches the actual mock class instantiated (e.g. `AsyncMock` vs `MagicMock`). Async side-effect handlers assigned to mock methods should be wrapped with `AsyncMock(side_effect=_fn)`.

## 9. Pytest Asyncio Scoping & Custom Marker Registration
* **Rule:** In test modules containing both synchronous (`def`) and asynchronous (`async def`) tests, do NOT declare global module-level `pytestmark = pytest.mark.asyncio`. Decorate `async def` test functions individually with `@pytest.mark.asyncio`. All custom markers MUST be registered in `pyproject.toml` under `[tool.pytest.ini_options].markers`.

## 10. Subprocess Process Group Cleanup
* **Rule:** Background test servers MUST use `preexec_fn=os.setsid` and `os.killpg(os.getpgid(pid), signal.SIGTERM)` in `finally` blocks to guarantee zero zombie processes or port leaks.

## 11. Worktree Environment Path Alignment
* **Rule:** When executing test suites inside isolated git worktrees, ensure `pip install -e .` is run or pass `PYTHONPATH=src` so pytest imports modules from the current worktree rather than stale global site-packages.

## 12. Hypothesis Test Scope Isolation
* **Rule:** Property test modules MUST NOT call `settings.load_profile()` or `settings.register_profile()` at module import scope. Decorate individual test functions with `@settings(max_examples=100)` to prevent cross-test settings mutation.

## 13. Security Contract BDD Feature Coverage
* **Rule:** Whenever code under `src/` is added or modified to introduce or alter security-relevant validation, policy enforcement, or interception behavior, corresponding `pytest-bdd` security contract `.feature` files under `tests/features/` and executable step definition files under `tests/step_defs/` MUST be added or updated across both the component feature file (e.g. `tests/features/advanced_threat_detection.feature`) and the enterprise integration feature file (`tests/features/blackwall_enterprise_mesh.feature`). Every BDD scenario MUST contain explicit `Given`, `When`, and `Then` steps to exercise the behavior and assert expected outcomes/exceptions.

## 14. Dense Window Performance & Limit Bound Verification
* **Rule:** Performance regression tests for correlation engines MUST test dense event windows (e.g. 150+ events in a 300s window) to verify sub-500ms execution SLA and assert parameter limit bounding (`max_nodes`, `max_paths`, `max_depth`, and non-positive limit parameter rejections).



## 15. Weave Marker Collection-Time Skip and Detector Suite Contract
* **Rule:** The `@pytest.mark.weave` marker MUST be registered in `pyproject.toml` under `[tool.pytest.ini_options].markers` with a human-readable description referencing the conftest skip hook. The `pytest_collection_modifyitems` hook in `tests/conftest.py` MUST auto-skip every item carrying this marker (via `item.add_marker(pytest.mark.skip(...))`) when `_weave_available()` returns False — checked by probing `WEAVE_DISABLED`, `WEAVE_OFFLINE`, `WANDB_API_KEY`, and importability of the `weave` package — so that `@pytest.mark.weave` tests produce a clean skip rather than an `ImportError`. When Weave is available, the `detector_suite` pytest fixture MUST use `request.node.get_closest_marker("weave") is not None` to determine `force_traced`, and pass that value to `build_detector_suite()`. The factory MUST perform no internal marker detection; marker state flows in exclusively through `force_traced`. Tests without `@pytest.mark.weave` MUST receive bare, undecorated detector components with zero Weave overhead regardless of environment variables.

## 16. Technical Specification BDD Subtask Matrix Alignment
* **Rule:** All technical specification task matrices (`tasks.md`) MUST include explicit Gherkin BDD subtasks (`tests/features/*.feature` and `tests/step_defs/test_*_steps.py`) alongside unit test subtasks for every execution track. Submitting PRs with unit test coverage alone is insufficient to satisfy Greptile PR compliance guardrails.

## 17. Hypothesis Property Constraint & Rejection Testing
* **Rule:** Hypothesis property test suites (`tests/property/test_*_properties.py`) targeting components with Pydantic models or public threshold parameters MUST assert **both** valid acceptance (`test_property_*_valid_acceptance`) using valid input strategies (`st.uuids(version=4)`, UTC datetimes, non-empty text) AND invalid rejection (`test_property_*_rejection`) using invalid strategies (`st.text().filter(lambda s: not s.strip())`, naive/non-UTC datetimes, malformed UUIDs). Rejection tests MUST assert that invalid inputs raise `pydantic.ValidationError` or `ValueError`.
* **Rationale:** Property tests validating happy-path behavior alone miss contract violations and fail compliance review guardrails for model boundary enforcement.

## 18. Property-Based Redaction Coverage for Secret Sanitizers
* **Rule:** All secret redaction and argument sanitization modules MUST include Hypothesis property-based tests using `@given(st.text(...))` and `@settings(...)` asserting that:
  1. Arbitrary generated vendor credential formats (e.g., `sk-<segment>-<string>`, `AIza<string>`) are completely stripped from sanitized outputs and full serialized reports (`to_json()`, `to_markdown()`).
  2. Arbitrary text values stored under sensitive key names (`password`, `passwd`, `pwd`, `secret`, `api_key`) are stripped regardless of casing or nesting.
* **Rationale:** Fixed example-based tests (e.g., testing `sk-1234567890`) miss multi-segment API key formats (like OpenAI `sk-proj-...` or Anthropic `sk-ant-...`) and JSON key-quoting edge cases, leading to security regression findings during automated code reviews.

## 19. Task Dependency Wave Alignment for New Components
* **Rule:** In technical task specifications (`tasks.md`), property test subtasks and BDD feature test subtasks for new components MUST be scheduled in dependency graph waves that occur **at or after** the wave where the underlying component classes are implemented. Test tasks MUST NOT be placed in earlier verification waves prior to component creation.
* **Rationale:** Placing test subtasks in early waves (e.g. wave 19 testing `ActiveReactionEngine` before its wave 31 implementation) causes wave-by-wave implementation and verification loops to fail due to missing symbols.





