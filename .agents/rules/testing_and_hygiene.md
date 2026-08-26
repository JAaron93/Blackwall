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
* **Rule (Honey-Tokens and Synthetics):** When creating synthetic test inputs or honey-token strings in unit/integration tests, NEVER use strings containing cloud provider keyword patterns (e.g. `AWS_KEY`, `AKIA`, `SLACK_TOKEN`) or high-entropy literals with `secret_`/`key_`/`pass_` prefixes. Always use generic prefixes such as `BW_SYNTHETIC_MOCK_SECRET_0192` to prevent secret scanners (GitGuardian) from triggering false-positive alerts.
* **Rule (GitHub Push Protection & Secret Scanner Safe Tokens):** In evaluation datasets, benchmark suites, and test fixtures (e.g., `gcp_eval_datasets.py`, `test_hygiene_eval_dataset.py`), NEVER use realistic secret formats (such as OpenAI `sk-proj-*`, Stripe live `sk_live_*`, Slack `xoxb-*`, or valid base64 JWTs `eyJhbGci...`). All synthetic credentials MUST use explicit dummy mock prefixes (e.g., `sk-mock-dummy-...`, `sk_test_mock_...`, `xoxb-mock-...`, `eyJ_mock_...`, `MOCKAKIA...`) to prevent GitHub Push Protection (GH013) and GitGuardian CI scans from failing remote pushes.

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



## 15. Google Cloud Trace & GCP Vertex AI Evaluation Testing Standards
* **Rule (Zero-SaaS Evaluation Invariant):** Evaluation test suites MUST NOT import or depend on Weights & Biases (`weave`, `wandb`) or require `WANDB_API_KEY`. All evaluation tests MUST authenticate exclusively via Application Default Credentials (ADC) in 100% GCP Vertex AI mode.
* **Rule (EvalTask & Cloud Trace Integration):** Offline and online evaluation tests targeting `GCPVertexAIEvaluationHarness` MUST validate execution using `vertexai.preview.evaluation.EvalTask`, `PointwiseMetric`, `PairwiseMetric`, and OpenTelemetry trace spans exported to Google Cloud Trace (`opentelemetry-exporter-gcp-trace`).
* **Rule (Containment Scoping):** Synthetic evaluation events generated in tests MUST carry explicit evaluation markers (`is_evaluation=True`, `evaluation_env_id`) and route to isolated evaluation stores to guarantee zero pollution of production threat graphs.

## 16. Technical Specification BDD Subtask Matrix Alignment
* **Rule:** All technical specification task matrices (`tasks.md`) MUST include explicit Gherkin BDD subtasks (`tests/features/*.feature` and `tests/step_defs/test_*_steps.py`) alongside unit test subtasks for every execution track. Submitting PRs with unit test coverage alone is insufficient to satisfy Greptile PR compliance guardrails.

## 17. Hypothesis Property Constraint & Rejection Testing
* **Rule (Acceptance vs. Rejection):** Hypothesis property test suites (`tests/property/test_*_properties.py`) targeting components with Pydantic models or public threshold parameters MUST assert **both** valid acceptance (`test_property_*_valid_acceptance`) using valid input strategies (`st.uuids(version=4)`, UTC datetimes, non-empty text) AND invalid rejection (`test_property_*_rejection`) using invalid strategies (`st.text().filter(lambda s: not s.strip())`, naive/non-UTC datetimes, malformed UUIDs). Rejection tests MUST assert that invalid inputs raise `pydantic.ValidationError` or `ValueError`.
* **Rule (Non-Empty Text Strategy Constraint):** When generating valid string inputs for fields validated by `validate_non_empty_string` (e.g. `agent_id`, `threat_type`, `package_name`, `title`, `description`), property tests MUST NOT use bare `st.text(min_size=1)`. Tests MUST use `st.from_regex(r"[a-zA-Z0-9_-]{1,20}", fullmatch=True)` or `st.text(min_size=1, max_size=N).filter(lambda s: bool(s.strip()))`. Bare `st.text(min_size=1)` generates whitespace characters (`\r`, `\n`, `\t`, ` `) which trigger `ValidationError` and cause false-failing valid property tests.
* **Rationale:** Property tests validating happy-path behavior alone miss contract violations, while unfiltered string strategies generate whitespace strings that trip strict Pydantic non-empty validators.

## 18. Property-Based Redaction Coverage for Secret Sanitizers
* **Rule:** All secret redaction and argument sanitization modules MUST include Hypothesis property-based tests using `@given(st.text(...))` and `@settings(...)` asserting that:
  1. Arbitrary generated vendor credential formats (e.g., `sk-<segment>-<string>`, `AIza<string>`) are completely stripped from sanitized outputs and full serialized reports (`to_json()`, `to_markdown()`).
  2. Arbitrary text values stored under sensitive key names (`password`, `passwd`, `pwd`, `secret`, `api_key`) are stripped regardless of casing or nesting.
* **Rationale:** Fixed example-based tests (e.g., testing `sk-1234567890`) miss multi-segment API key formats (like OpenAI `sk-proj-...` or Anthropic `sk-ant-...`) and JSON key-quoting edge cases, leading to security regression findings during automated code reviews.

## 19. Task Dependency Wave Alignment for New Components
* **Rule:** In technical task specifications (`tasks.md`), property test subtasks and BDD feature test subtasks for new components MUST be scheduled in dependency graph waves that occur **at or after** the wave where the underlying component classes are implemented. Test tasks MUST NOT be placed in earlier verification waves prior to component creation.
* **Rationale:** Placing test subtasks in early waves (e.g. wave 19 testing `ActiveReactionEngine` before its wave 31 implementation) causes wave-by-wave implementation and verification loops to fail due to missing symbols.

## 20. Pytest Major Version Pinning for Fixture Scoping & Performance SLAs
* **Rule:** Dependencies in `pyproject.toml` MUST maintain upper-bound constraints on `pytest` and `pytest-bdd` (`pytest>=8.0.0,<9.0.0` and `pytest-bdd>=8.0.0,<9.0.0`). Automated package security upgrades (e.g. `pip-audit --fix`) MUST NOT upgrade `pytest` to `9.0.0+`.
* **Rationale:** Upgrading to Pytest 9.0+ alters internal test fixture scoping and setup/teardown timing, causing latency-sensitive SLA benchmark tests (`test_latency_requirement`) to exceed the 5ms SLA limit.

## 21. Strict File Parsing in Evaluation Test Harnesses
* **Rule:** Evaluation report generators, test harness loaders (`ReportGenerator._load_evalset`, `ReportGenerator._load_results`), and benchmark parsers MUST use strict JSON parsing (`json.loads`) that raises explicit `JSONDecodeError` on malformed or empty files. They MUST NOT use fallback-swallowing utilities (like `parse_json_safely`) that substitute empty default structures.
* **Rationale:** Swallowing JSON decode errors in evaluation harnesses converts corrupted or missing evalsets/results into zero-case evaluation runs, producing misleading false-pass report metrics.

## 22. Cross-Package Multi-Pillar Test Coverage for Domain Scanners
* **Rule:** Unit and property test suites for specialized threat monitors (e.g. `PackageRegistryMonitor`, `KubernetesDefenseLayer`) MUST include explicit test cases verifying both:
  1. **Single-Target False-Positive Rejection**: Multiple repeated failures/retries (e.g. 5x 404s) for the same single entity/package MUST NOT be flagged as multi-target reconnaissance or scanning.
  2. **Mixed-Pillar Graph Isolation**: Generic non-domain events in a shared `AttackGraphStore` (e.g. generic HTTP 404s from general tool calls or API endpoints) MUST NOT be misclassified as domain-specific threats (such as package registry scanning).
* **Rationale:** Testing only homogeneous multi-target scenarios misses false-positive bugs caused by client retries and cross-pillar event pollution in shared database stores.

## 23. Paced Continuous Streaming Harnesses for Sustained Throughput SLAs
* **Rule:** Throughput SLA tests validating sustained processing rates (e.g. >= 1,000 events/second sustained for >= 5 minutes) MUST NOT measure isolated sub-second in-memory bursts in isolation. Tests MUST employ paced streaming loops across multiple successive intervals/windows, asserting that:
  1. Throughput rate exceeds the target threshold on every individual window and across aggregate runtime.
  2. Zero events are dropped or error out across all streaming slices.
  3. Memory consumption, cache growth, and connection pool utilization remain strictly bounded without degradation over prolonged ingestion.
  4. Tests support an extended duration mode via environment variable (e.g. `BLACKWALL_EXTENDED_LOAD_TEST=true` for 300-second load tests) alongside fast CI execution defaults.
* **Rationale:** Sub-second burst benchmarks pass easily in memory but fail to expose memory leaks, unbounded cache growth, connection pool starvation, and garbage collection pauses that only appear under continuous streaming ingestion.

## 24. Historical Retrospective Window Offsets in Testing
* **Rule:** When generating synthetic multi-day historical events for testing retention boundaries (e.g. `<= 30` day retention), test fixtures MUST ensure event timestamps stay strictly within the active retention window (`now - timedelta(days=29)`) rather than spanning beyond the cutoff horizon (`days=30, hours=2`), preventing false assertions during retention purge tests.
* **Rationale:** Generating events at or beyond the exact boundary creates subtle sub-day discrepancies where events are legitimately purged as expired, causing test failures on valid retention invariants.

## 25. Structural Test Coverage Measurement via Knowledge Graph

* **Rule:** When auditing test coverage gaps, agents MUST use `codebase-memory-mcp` TESTS edges as the primary structural metric rather than line-coverage tools. The standard methodology is:
  1. Query total source symbols: `MATCH (src) WHERE (src:Function OR src:Method OR src:Class) AND src.file_path STARTS WITH 'src/' AND src.is_test = false RETURN src.file_path, count(src) AS total_symbols`
  2. Query tested symbols: `MATCH (test)-[:TESTS]->(src) WHERE src.file_path STARTS WITH 'src/' RETURN src.file_path, count(DISTINCT src) AS tested_symbols`
  3. Compute per-file and global coverage ratios.
  4. Prioritize untested symbols by fan-in (hotspot rank), cyclomatic complexity (`src.complexity`), and security criticality.
* **Rule:** Coverage remediation tasks MUST reference `.kiro/specs/blackwall-test-coverage-remediation/tasks.md` for the canonical backlog and mark tasks complete as they are implemented.
* **Rationale:** Line-coverage tools require instrumented test runs and miss structural relationships. Knowledge graph TESTS edges provide instant, zero-overhead structural coverage measurements that identify exactly which functions/methods/classes lack any dedicated test verification.

## 26. Audit Hook Runtime State Cleanup in Test Fixtures

* **Rule (Extension of Rule 4):** Test modules that instantiate `AuditHookManager` and call `manager.start()` MUST call `manager.stop()` in a `finally` block or pytest fixture teardown to remove the instance from the module-level `_active_managers` list. Failure to stop managers causes ordering-dependent flakiness where subsequent test modules trigger audit hook violations from residual manager instances.
* **Rule:** When testing `AuditHookManager` methods directly (e.g. `_validate_subprocess`, `_validate_open`), prefer calling the method directly on an un-started manager instance rather than invoking `manager.start()` — this avoids registering the permanent `sys.addaudithook` and polluting process state for all subsequent tests.
* **Rationale:** `sys.addaudithook` is permanent and cannot be unregistered. While Rule 4 prevents import-scope registration, runtime `_active_managers.append(self)` in `start()` creates cross-module state pollution even when hooks are deferred to function scope. Tests that call `start()` without `stop()` leave zombie managers that intercept subsequent test operations (e.g. subprocess spawning in unrelated integration tests).

## 27. Hypothesis Property Tests with Async Operations

* **Rule:** Hypothesis `@given` decorators apply to synchronous functions only. Property tests exercising async code (e.g. `InterceptionQueue.enqueue`, `SyncResolver.evaluate`) MUST use a synchronous `_run()` helper that creates a fresh event loop per test invocation:
  ```python
  def _run(coro):
      loop = asyncio.new_event_loop()
      try:
          return loop.run_until_complete(coro)
      finally:
          loop.close()
  ```
* **Rule:** The `_run()` helper MUST create a new loop each invocation (not reuse a module-level loop) because Hypothesis may call the test function hundreds of times and a closed or errored loop from a previous example would fail subsequent examples.
* **Rule:** All hypothesis async property tests MUST include `deadline=None` in `@settings()` to prevent Hypothesis from failing tests due to event loop overhead timing.
* **Rationale:** Using `asyncio.run()` inside Hypothesis tests creates and destroys the default event loop, which conflicts with pytest-asyncio's event loop management. The fresh-loop-per-invocation pattern avoids both loop reuse failures and pytest-asyncio conflicts.

## 28. Greptile PR Review Filter, Status Checks, & Severity Governance
* **Rule (High Strictness & P0/P1 Enforcement Only):** Automated PR code reviews MUST be configured to `High` strictness level, commenting exclusively on **P0** (critical security vulnerabilities, architectural boundary violations) and **P1** (functional logic errors, data integrity failures) while ignoring P2s.
* **Rule (Required Confidence Threshold):** GitHub PR status checks for Greptile MUST enforce a passing confidence threshold of **4/5** (scorable at `>= 4/5` or `conclusion == "success"`), preventing pedantic heuristic oscillations on edge cases from blocking valid PR merges.
* **Rule (Comment Type Scope):** `.greptile/config.json` MUST maintain `commentTypes: ["logic", "syntax"]`, strictly omitting `"style"` and `"info"` to prevent noisy stylistic nits from delaying PR review and merge cycles.
* **Rationale:** Focusing AI review automation on high-severity security, architecture, and correctness invariants at the 4/5 threshold eliminates review fatigue and pedantic oscillation loops on cosmetic or theoretical bounds while maintaining strict engineering rigor.

## 29. AlertBus Query Interface & Test Inspection Invariants
* **Rule:** Unit, property, and BDD test suites querying stored alerts from `AlertBus` MUST call `alert_bus.get_alerts(severity=..., threat_type=..., agent_id=...)`. Tests MUST NOT invoke non-existent or deprecated method names (such as `get_recent_alerts` or `query_alerts`).
* **Rationale:** `AlertBus` stores and filters in-memory and pending alerts exclusively via `get_alerts()`. Using inconsistent method names causes collection or runtime `AttributeError` exceptions across test suites.

## 30. Redaction Placeholder Safety & Zero-Threshold Rejection Test Coverage
* **Rule:** Unit and property test suites for payload sanitizers, prompt injection scanners, and content redaction engines MUST include explicit test cases verifying:
  1. **Zero-Threshold Rejection**: Verifying that `confidence_threshold=0.0` is explicitly rejected with `ValueError` during constructor parameter validation.
  2. **Backreference Safety**: Verifying that replacement placeholders containing regex backreference syntax (e.g., `\g<0>`, `\1`) are inserted literally without re-inserting matched threat spans or raising unhandled `re.error` exceptions.
* **Rationale:** Example-based tests using simple alphanumeric placeholders fail to catch template injection and backreference re-insertion vulnerabilities in regex substitution engines.


## 31. Agent-as-a-Judge Evaluation Pattern (Antigravity SDK)

* **Rule (Paid-Tier Enforcement):** Evaluation pipeline runners and judge agent factories MUST validate `GEMINI_TIER=paid` and `BLACKWALL_TIER=paid` at startup. If either is unset or not `paid`, the pipeline MUST exit immediately with a descriptive error rather than silently degrading to free-tier rate limits (4 RPM), which causes cascading timeouts across 9+ concurrent judge agents requiring 300+ RPM.
* **Rule (Judge Agent Configuration):** All evaluation judge agents MUST be instantiated via Google Antigravity SDK with `LocalAgentConfig(vertex=True, project=GCP_PROJECT, location=GCP_LOCATION, response_schema=<PydanticRubric>, capabilities=CapabilitiesConfig(agent_behavior=AgentBehavior.AUTONOMOUS))`. Freeform text responses from judges are forbidden; all scoring MUST use structured Pydantic `BaseModel` rubrics with `ConfigDict(extra="forbid")`, score fields `Field(ge=1, le=5)`, `justification: str = Field(min_length=10)`, and `is_fallback: bool = Field(default=False)`.
* **Rule (Prompt Ordering for Cache Optimization):** Judge prompt templates MUST follow this strict ordering: `<system_instruction>` → `<rubric>` (static, shared across all scenarios in a domain) → `<evaluation_context>` (per-scenario dynamic data). The rubric block MUST precede evaluation context to form a stable >32k token prefix eligible for Gemini implicit context caching (90% input cost discount). Never place per-scenario data before the rubric.
* **Rule (Zero-Trust Prompt Delimitation):** All untrusted evaluation inputs (agent trajectories, verdicts, evidence payloads, tool call arguments) MUST be enclosed in `<untrusted_input type="...">` XML tags. Before insertion, inputs MUST be regex-sanitized to neutralize: (a) special LLM instruction tokens (`[INST]`, `[/INST]`, `<<SYS>>`, `<|im_start|>`, `<|im_end|>`), (b) instruction override attempts (`\b(ignore|disregard|forget|bypass|override)\b.*\binstructions?\b`), and (c) scoring manipulation directives (multi-verb + nonnumeric/numeric forced-score patterns).
* **Rule (Fallback Isolation in Aggregation):** When a judge agent fails (Vertex AI unavailable, timeout, schema validation failure after 3 retries), the heuristic fallback scorer MUST set `is_fallback=True` on the returned rubric. Aggregate mean score computation MUST filter out `is_fallback=True` rows. If an entire domain consists of fallback rows, report `None`/`NaN` for judge quality metrics — never report heuristic values as genuine judge measurements. Include `fallback_count` and `fallback_rate` in all pipeline summary reports.
* **Rationale:** The Agent-as-a-Judge pattern provides richer multi-dimensional evaluation than static `PointwiseMetric` templates, but requires strict configuration contracts (paid quota), prompt safety (injection resistance), ordering discipline (cache economics), and fallback transparency (metric integrity) to produce reliable CI quality gates. See `.kiro/specs/blackwall-gcp-evaluation-coverage/` for the governing specification.

## 32. Module-Qualified `asyncio.sleep` Patching in Unit Tests


* **Rule:** When patching `asyncio.sleep` in unit tests that target a class or module which imports `asyncio` at the top level, always use the fully qualified module path as the patch target:
  ```python
  with patch("blackwall.mcp.gti_client.asyncio.sleep", new_callable=AsyncMock, side_effect=[None, asyncio.CancelledError()]):
      ...
  ```
  Using `patch("asyncio.sleep")` patches the name in the `asyncio` module itself, which has no effect on code that already holds a module-level reference to the `asyncio` namespace (e.g. `import asyncio` at top of file then calls `asyncio.sleep(...)`). The mock must replace the name as it is *looked up* at call time, not as it is *defined*.
* **Rationale:** This is a widespread source of silent mock failures in Python unit tests. `patch("asyncio.sleep")` succeeds without error but the target code never sees the mock, causing tests to execute real sleeps, time out, or produce nondeterministic results.

## 33. Background Constructor Task Cancellation Before Direct Coroutine Testing

* **Rule:** When unit-testing classes whose `__init__` auto-starts a background asyncio task (e.g. via an `_ensure_task_started()` pattern calling `loop.create_task(self._some_loop())`), tests that directly `await` the same underlying loop coroutine (e.g. `await tracker._replenish_loop()`) MUST first cancel and clear the constructor-started task:
  ```python
  async def test_replenish_loop_increments_tokens(self):
      tracker = SomeTracker()
      tracker.close()  # ← cancels constructor's background task before direct invocation
      with patch("package.module.asyncio.sleep", new_callable=AsyncMock,
                 side_effect=[None, asyncio.CancelledError()]):
          await tracker._replenish_loop()
  ```
  Omitting the cancellation creates two competing coroutines consuming the same finite `AsyncMock(side_effect=[...])` sequence: the background task exhausts the first side-effect entries, leaving the directly-invoked coroutine with `StopIteration`, nondeterministic assertion outcomes, or unhandled background exceptions surfaced through pytest's asyncio event loop.
* **Rationale:** Identified during Phase 1 test coverage remediation (PR #91, `test_gti_client_internals.py`) via a Greptile P1 review comment. The constructor-spawned replenishment task races directly-invoked test coroutines when both share a mocked sleep.

## 34. Python 3.14+ Event Loop API Compatibility in Test Classes

* **Rule:** Sync test methods (`def test_*`) inside `unittest.TestCase` subclasses or plain test classes MUST NOT use `asyncio.get_event_loop().run_until_complete(...)` to execute async code. In Python 3.14+, `asyncio.get_event_loop()` raises `RuntimeError('There is no current event loop in thread ...')` when no event loop is bound to the current thread — which is the default under pytest-asyncio's `asyncio_mode = "auto"`.
* **Rule:** Any test class method that exercises async code MUST be declared `async def` so pytest-asyncio manages the event loop:
  ```python
  # ❌ Broken on Python 3.14+
  def test_close_cancels_task(self):
      async def _inner():
          tracker = GTIQueryBudgetTracker()
          tracker.close()
          assert tracker._replenish_task is None
      asyncio.get_event_loop().run_until_complete(_inner())

  # ✅ Correct
  async def test_close_cancels_task(self):
      tracker = GTIQueryBudgetTracker()
      assert tracker._replenish_task is not None
      tracker.close()
      assert tracker._replenish_task is None
  ```
* **Rationale:** Python 3.12 deprecated the implicit creation of a running event loop in `asyncio.get_event_loop()` and Python 3.14 removed it. Using `asyncio.new_event_loop()` via the Hypothesis helper (Rule 27) is the correct pattern for Hypothesis property tests. For all other async tests, rely on pytest-asyncio's `asyncio_mode = "auto"` to provide the loop automatically.

## 35. Cross-Module Enum Value Mapping Verification in Adapter Tests

* **Rule:** When testing adapter methods that translate between two internally-defined enum types (e.g. `CriticalSinkType` → `SinkType` in `CodebaseMemoryClient.query()`), always verify the actual enum member values at the start of test authoring before asserting on the translated output:
  ```python
  # Verify the mapping compiles at dev time — before writing assertions
  from blackwall.mcp.codebase_memory import CriticalSinkType
  from blackwall.models import SinkType
  print([e.value for e in CriticalSinkType])  # SQL_QUERY, COMMAND_EXEC, FILE_WRITE, NETWORK_CALL
  print([e.value for e in SinkType])           # FILE_SYSTEM, NETWORK, DATABASE, PROCESS
  ```
  If the enum values differ (as they do in this codebase — `"SQL_QUERY"` has no matching `SinkType` value), adapters that perform `SinkType(source_enum.value)` will silently catch `ValueError` and produce an empty list. Tests MUST assert the **actual runtime behavior** (e.g. `assert resp.critical_sinks == []`) rather than the idealized semantic intent (e.g. `assert len(resp.critical_sinks) >= 1`).
* **Rationale:** Asserting idealized intent on a silently-failing enum mapping causes false-passing tests (if the test is skipped by wrong assertion polarity) or persistent false-failing tests (if the assertion expects content that can never be produced). The correct path is to assert the ground truth, then separately file a bug/spec issue for the mapping gap if the semantic intent matters.

## 36. Testing `callable()` Dispatch Chains: MagicMock Is Always Callable

* **Rule:** When testing a method whose dispatch logic begins with `if callable(dep):` followed by `elif "method" in dir(dep):` branches, `MagicMock()` MUST NOT be used as the test stub for the `elif` branches. `MagicMock` implements `__call__` so `callable(MagicMock())` is always `True`, causing the stub to take the first `if callable(dep)` branch unconditionally and never reach any `elif` branch.

  To test an `elif "method_name" in dir(dep)` branch, write a purpose-built non-callable class that exposes only the target method:
  ```python
  class _NonCallableBroadcaster:
      def __init__(self):
          self.calls = []

      def broadcast(self, payload_dict):
          self.calls.append(payload_dict)

  broadcaster = _NonCallableBroadcaster()
  # callable(broadcaster) → False   ← skips the first if-branch
  # "broadcast" in dir(broadcaster) → True  ← enters the elif branch
  ```

* **Rule:** The same caveat applies to `spec=SomeClass` mocks when `SomeClass` defines `__call__`, and to `NonCallableMock` from `unittest.mock` as an alternative explicit opt-out.

* **Rationale:** Discovered during Phase 3 test coverage remediation (PR #93). A `MagicMock`-based test for the `broadcast()` method dispatch branch appeared to pass (no exception, `result is True`) while actually exercising the *callable* branch instead. The error was caught only because the test asserted `len(broadcaster.calls) == 1` — which was zero — signalling the wrong branch had fired. Without that assertion the test would have provided misleading coverage over the wrong code path.

## 37. `asyncio.gather` Concurrency Tests Require an `await` Yield Point

* **Rule:** Concurrency tests that stress idempotency or shared-state invariants (e.g. "all N concurrent callers obtain the same singleton") MUST include at least one `await` suspension point inside each inner coroutine passed to `asyncio.gather`. A coroutine containing no `await` expression runs to completion before the event loop yields to the next — `asyncio.gather` does **not** introduce interleaving for purely synchronous coroutines. The canonical fix is `await asyncio.sleep(0)` at the top of the worker, which forces the scheduler to queue all N tasks before any of them begins work:
  ```python
  # ❌ Broken: no await — runs sequentially, cannot detect races
  async def worker():
      result = manager.get_or_create_environment(env_id)
      results.append(result)

  # ✅ Correct: yield at entry so all N coroutines interleave before the operation
  async def worker():
      await asyncio.sleep(0)  # yield to scheduler; all tasks queued first
      result = manager.get_or_create_environment(env_id)
      results.append(result)

  await asyncio.gather(*[worker() for _ in range(20)])
  ```
* **Rationale:** Identified during Phase 2 test coverage remediation (PR #92, `test_evaluation_environment.py`). The test passed trivially for any implementation — including broken ones — because `asyncio.gather` over zero-await coroutines is indistinguishable from a plain `for` loop. The bug is invisible at write time: no error is raised, yet the concurrency invariant is never tested.

## 38. Scenario-Scoped Persistent Event Loops for Stateful Async BDD Fixtures

* **Rule:** When writing `pytest-bdd` step definitions for stateful async components that maintain internal `asyncio.Lock` primitives or spawn background tasks (e.g. `GTIQueryBudgetTracker`), step definitions MUST NOT execute consecutive steps using disjoint, temporary event loops via repeated standalone `run_async()` calls.
* **Pattern:** The scenario state fixture MUST manage a persistent event loop across steps and execute coroutines through a runner method:
  ```python
  class ScenarioState:
      def __init__(self):
          self.loop = asyncio.new_event_loop()
          self.tracker = None

      def run(self, coro):
          return self.loop.run_until_complete(coro)

      def cleanup(self):
          if self.tracker and self.tracker._replenish_task and not self.tracker._replenish_task.done():
              self.tracker._replenish_task.cancel()
              try:
                  self.loop.run_until_complete(self.tracker._replenish_task)
              except (asyncio.CancelledError, Exception):
                  pass
          if not self.loop.is_closed():
              self.loop.close()

  @pytest.fixture
  def state():
      st = ScenarioState()
      yield st
      st.cleanup()
  ```
* **Rationale:** Discovered during Phase 6 BDD feature remediation (PR #96) via Greptile review. Reusing lock-bound async objects across separate short-lived event loops causes cross-loop binding errors and unhandled task cancellation warnings.

## 39. Composite Resolver Signal Ingestion Assertions in BDD

* **Rule:** BDD feature steps asserting security verdicts from orchestrating resolvers (`SyncResolver`, `BatchResolver`) MUST assert on the resolver's resulting `Verdict` attributes (`verdict.reasoning`, `verdict.confidence_score`, `verdict.decision`) to verify that signals returned by subsidiary MCP clients (CBM AST blast radius, GTI threat intelligence) were actively consumed and reflected in the verdict calculation. Step definitions MUST NOT rely exclusively on querying the sidecar client directly.
* **Rationale:** Verifying only the subsidiary adapter's response allows broken ingestion pipelines, missing scoring weights, or malformed adapter mappings inside the resolver to pass BDD test scenarios unnoticed.

## 40. Evaluation Metric Zero-Division Safeguards
* **Rule:** All offline, online, and autorater evaluation metric aggregators (`calculateMetrics`, `GCPVertexEvalMetrics`) MUST explicitly guard all division denominators (`tp + fp == 0`, `tp + fn == 0`, `precision + recall == 0.0`, `len(reference) == 0`) and return safe `0.0` / float defaults rather than permitting `ZeroDivisionError` exceptions during zero-count or empty-candidate evaluation runs.
* **Rationale:** Real-world evaluation datasets and adversarial test runs frequently produce zero true positives, zero false positives, or empty candidate trajectories on edge cases. Unhandled zero division crashes evaluation batch jobs and masks upstream quality metrics.

## 41. Security Fix Test Update — Re-Supply Bypassed Credentials
* **Rule:** When a security fix removes an optional-parameter bypass path (e.g., converting `if headers is not None and remote_addr is not None: validate(...)` to unconditional `validate(headers or {}, remote_addr or "")`), ALL existing integration and BDD tests that previously exercised the "parameter omitted → bypass" path MUST be updated to supply valid credentials for the now-enforced gate (e.g., `remote_addr="127.0.0.1"` for loopback-enforced callers) so they correctly reach the intended downstream behavior (rate limiter, parser, etc.) rather than failing at the newly enforced authorization check with the wrong error code.
* **Rationale:** Hardening a conditional validation gate to unconditional changes the "no params → pass through" contract to "no params → rejected with auth error." Tests that asserted a specific downstream error code (e.g., `-32000` rate limit) now receive an upstream auth error (`-32600`) instead, causing assertion failures that are valid test hygiene issues rather than regressions in the production security fix.
* **Extension — Regression Test Sufficiency:** Regression tests for security bypass fixes MUST cover all relevant configuration permutations, not just the most obvious attack path. For boolean `enforce_*` flags combined with optional allow-list sets, tests MUST include at minimum:
  1. **Strict mode** (allow-list configured) + absent headers → assert rejected.
  2. **Strict mode** + present headers NOT in allow-list → assert rejected.
  3. **Strict mode** + present headers IN allow-list → assert accepted.
  4. **Permissive mode** (allow-list unconfigured) + `enforce_*=False` + absent headers → assert rejected (via the independent baseline gate, e.g. gate 2b requiring at least one identifying header).
  5. **Permissive mode** + at least one identifying header present and valid (e.g. Host in a separately configured `allowed_hosts`) → assert accepted.
  Failure to cover all permutations allows secondary bypass paths to survive code review undetected (as observed in greploop iterations 2→3 on PR #98, where the permissive-mode empty-header path was missed in the first regression test).

## 42. Async Context Manager Mocking & Strict Typing Hygiene
* **Rule (Explicit Mock Classes for Context Managers):**
  When mocking objects used as async context managers (e.g. Antigravity `Agent`), prefer explicit helper classes implementing `__aenter__` and `__aexit__` over bare `AsyncMock()` to prevent unwired inner mock instances where `__aenter__` returns an unconfigured mock:
  ```python
  class MockJudgeAgent:
      def __init__(self, response_text: str | None = None, raise_error: bool = False) -> None:
          self.response_text = response_text
          self.raise_error = raise_error

      async def __aenter__(self) -> Self:
          return self

      async def __aexit__(
          self,
          exc_type: type[BaseException] | None,
          exc_val: BaseException | None,
          exc_tb: TracebackType | None,
      ) -> None:
          pass
  ```
* **Rule (Strict Typing for `__aexit__`):**
  Always annotate `__aexit__` parameters with `type[BaseException] | None`, `BaseException | None`, and `TracebackType | None` to comply with Ruff `PYI036` and Pyright typing rules.
* **Rationale:** Discovered during Track B BDD feature development on PR #100. Using standard `AsyncMock()` with async context managers creates subtle mock nesting bugs during execution, while unannotated mock method parameters violate Python typing conventions and static analysis checks.


