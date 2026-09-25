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
* **Rule:** Markdown documentation files in `docs/` must use **repo-relative markdown paths** (e.g. `tests/integration/helpers.py`), and must **never** hard-code local environment URI patterns (such as `file:///<local_user_path>/...` or `C:\<local_user_path>\...`).


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
  with patch("blackwall.threat_intel.otx.asyncio.sleep", new_callable=AsyncMock, side_effect=[None, asyncio.CancelledError()]):
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
* **Rationale:** Identified during Phase 1 test coverage remediation (PR #91 historical test suite test_gti_client_internals.py, retired in TASK-G03) via a Greptile P1 review comment. The constructor-spawned replenishment task races directly-invoked test coroutines when both share a mocked sleep.

## 34. Python 3.14+ Event Loop API Compatibility in Test Classes

* **Rule:** Sync test methods (`def test_*`) inside `unittest.TestCase` subclasses or plain test classes MUST NOT use `asyncio.get_event_loop().run_until_complete(...)` to execute async code. In Python 3.14+, `asyncio.get_event_loop()` raises `RuntimeError('There is no current event loop in thread ...')` when no event loop is bound to the current thread — which is the default under pytest-asyncio's `asyncio_mode = "auto"`.
* **Rule:** Any test class method that exercises async code MUST be declared `async def` so pytest-asyncio manages the event loop:
  ```python
  # ❌ Broken on Python 3.14+
  def test_close_cancels_task(self):
      async def _inner():
          tracker = TokenBucketLimiter(capacity=100, refill_rate=10.0)
          tracker.close()
          assert tracker._replenish_task is None
      asyncio.get_event_loop().run_until_complete(_inner())

  # ✅ Correct
  async def test_close_cancels_task(self):
      tracker = TokenBucketLimiter(capacity=100, refill_rate=10.0)
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

* **Rule:** When writing `pytest-bdd` step definitions for stateful async components that maintain internal `asyncio.Lock` primitives or spawn background tasks (e.g. `TokenBucketLimiter`), step definitions MUST NOT execute consecutive steps using disjoint, temporary event loops via repeated standalone `run_async()` calls.
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

* **Rule:** BDD feature steps asserting security verdicts from orchestrating resolvers (`SyncResolver`, `BatchResolver`) MUST assert on the resolver's resulting `Verdict` attributes (`verdict.reasoning`, `verdict.confidence_score`, `verdict.decision`) to verify that signals returned by subsidiary MCP clients (CBM AST blast radius, threat intelligence reputation) were actively consumed and reflected in the verdict calculation. Step definitions MUST NOT rely exclusively on querying the sidecar client directly.
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

## 43. Agent-as-a-Judge Evaluation Tier Contract & Upfront Validation Invariant
* **Rule (Upfront Tier Contract Enforcement):**
  Evaluation judge agents (`BaseJudgeAgent`) and pipelines targeting 100% GCP Vertex AI Mode must enforce the 300+ RPM quota contract (`GEMINI_TIER=paid`, `BLACKWALL_TIER=paid`, and `GCP_PROJECT`) upfront when `enforce_tier=True`.
* **Rule (Fail-Fast Configuration Errors):**
  Upfront tier configuration errors must fail fast and must NEVER be caught by generic agent runtime retry/fallback handlers (`try...except Exception`), preventing unconfigured tier environments from silently converting configuration failures into passing fallback evaluations.
* **Rule (Test Fixture Tier Alignment):**
  Test suites and test fixtures (`conftest.py`) must configure both `GEMINI_TIER="paid"` and `BLACKWALL_TIER="paid"` alongside `GCP_PROJECT` and `GOOGLE_GENAI_USE_VERTEXAI="true"` in autouse fixtures (`fixture_gcp_vertex_ai_env`) to maintain paid-tier contract validity during local test executions.
* **Rationale:** Discovered during Track C implementation and PR #101 review cycles. Broad exception handlers in evaluation judges that catch `Exception` during `_get_agent()` risk masking missing paid-tier configurations by returning ground-truth-aware fallback rubrics, allowing PRs to pass CI without authenticating or executing the required Vertex AI judge.

## 44. Automated Review Agent Circuit Breaker & Anti-Oscillation Protocol
* **Rule (Circuit Breaker Triggering):**
  During automated AI review loops (e.g. Greptile, CodeRabbit), agents MUST NOT enter recursive code-churn cycles (>2-3 iterations) attempting to satisfy contradictory, oscillating, or pedantic micro-edge-case review comments. When an automated reviewer re-flags previously resolved topics, applies contradictory requirements, or enters an edge-case spiral (e.g., demanding ad-hoc token splitting that violates RFC/protocol specifications), the agent MUST invoke the `review-agent-circuit-breaker` skill.
* **Rule (Configuration & Rule Synthesis):**
  Instead of writing defensive, brittle code workarounds to satisfy reviewer pedantry:
  1. **Halt Code Ping-Ponging**: Cease speculative code modifications.
  2. **Synthesize Reviewer Rulebooks**: Update repository-level reviewer instructions (e.g. `.greptile/rules.md` Anti-Oscillation Directive and explicit grammar/RFC boundaries) to clarify design invariants.
  3. **Strict Standard Invariants**: Enforce unambiguous standard protocol/RFC boundaries (such as Rust `std::net::Ipv6Addr` whole-token validation) without fallback heuristics that manufacture invalid data.
  4. **Verification & Resolution**: Verify full test suite pass rates, push configuration updates, resolve GraphQL review threads, and re-trigger review to achieve passing status with zero churn.
* **Extension (Correlation Cycle Deduplication Invariant):**
  - Deduplication caches for multi-agent correlation passes (e.g. `_published_covert_cycles` in `orchestrator.py`) MUST pair memory limits (e.g. 100-entry capacity ceiling) with activity TTL (`max(300.0, temporal_window * 2)`) and explicit completion methods (`complete_correlation_cycle`). AI review comments that oscillate between demanding memory caps and flagging TTL eviction of inactive cycles must be halted via the circuit breaker and resolved via `.greptile/rules.md` rather than cyclic code refactoring.
* **Rationale:** AI reviewers evaluate PR diffs statelessly and can fall into contradictory loops or micro-edge-case spirals. Establishing clear repository-level reviewer rules breaks churn loops and stabilizes review confidence scores deterministically.

## 45. MCP Gateway Transport & Remote Authentication Testing Invariants
* **Rule (End-to-End Remote Authentication Test Matrix):** Unit and BDD test suites covering non-loopback HTTP bindings MUST test all three branches of the remote authentication boundary:
  1. **Startup Guard Failure**: Verify that `blackwall serve --host 0.0.0.0` without an auth token fails to start and exits with a clear error.
  2. **Unauthenticated Rejection**: Verify that requests without a token or with an invalid token receive HTTP 401 before any JSON-RPC evaluation.
  3. **Valid-Token Happy Path**: Verify that `blackwall serve --host 0.0.0.0 --auth-token <token>` starts cleanly and successfully processes authorized requests with `Authorization: Bearer <token>`.
* **Rule (Hardware Baseline Budget Verification):** Core daemon performance tests must profile and enforce the 2019 Intel MacBook Pro baseline: ≤60MB idle RAM, ≤150MB active evaluation RAM, ~0% idle CPU, and <2s startup time through lazy module initialization.
* **Rationale:** Discovered during Greptile review iterations 1-3 on PR #108. Testing only negative/rejection paths (401 and startup failure) leaves the valid-token execution path unverified, risking shipping an auth gate that rejects all requests or fails to bind properly.

## 46. macOS LaunchAgent Plist & Service Lifecycle Test Invariants
* **Rule (LaunchAgent Plist Generation Test Matrix):** Unit tests covering macOS service managers (`blackwall service install`) MUST assert:
  1. **XML Validity & Structure**: Generated `com.blackwall.gateway.plist` parses as valid XML with correct `Label`, `ProgramArguments`, `RunAtLoad`, and log path keys.
  2. **Environment Variable Injection**: Plist contains an `EnvironmentVariables` dictionary with `GCP_PROJECT`, `GEMINI_TIER`, `PATH`, and credential paths.
  3. **Upstream Flag Inclusion**: `ProgramArguments` array includes `--config` (defaulting to `~/.blackwall/gateway.yaml`) or `--wrap`.
  4. **Throttle & Backoff Guards**: Plist specifies `ThrottleInterval=30` and `KeepAlive` with `SuccessfulExit=false`.
  5. **Install-Time Validation Rejection**: Installation fails with non-zero exit when `GCP_PROJECT` is absent.
* **Rationale:** Ensures plist generation logic does not omit critical environment or upstream flags that would cause silent failures or crash loops in production `launchd` environments.

## 47. Linux Systemd Unit & DGX Co-Existence Test Invariants
* **Rule (Systemd Unit Generation Test Matrix):** Unit tests covering Linux service generation (`blackwall service install`) MUST assert:
  1. **Syntax & Sectioning**: `StartLimitBurst=5` and `StartLimitIntervalSec=60s` are strictly placed under `[Unit]`; `Restart=on-failure`, `RestartSec=5s`, `Type=exec`, `PIDFile=`, `MemoryHigh=320M`, and `MemoryMax=350M` are placed under `[Service]`.
  2. **Zero Unexpanded Tildes**: Generated service definition strings contain 0 raw `~` characters (`Path.resolve()` enforced).
  3. **Non-Root Execution**: When `--system` is specified, `User=` and `Group=` are configured and non-root, strictly rejecting `User=root`.
  4. **FHS Directory Directives**: System units configure `RuntimeDirectory=blackwall`, `StateDirectory=blackwall`, and `LogsDirectory=blackwall`.
  5. **Foreground Execution & PID Creation**: `ExecStart` passes `--foreground`, `--pidfile`, `--logfile`, and `--db`. Tests assert that `--foreground` creates the designated PID file when `--pidfile` is supplied.
* **Rule (DGX Co-Existence Test Scoping):** Conformance tests checking `/proc/<daemon_pid>/fd/` for `/dev/nvidia*` character devices MUST target the running daemon process (resolved via `~/.blackwall/blackwall.pid`, `/run/blackwall/blackwall.pid`, or the daemon subprocess handle), rather than inspecting the test runner (`/proc/self/fd/`).
* **Rationale:** Ensures systemd unit generation, process supervision, and hardware co-existence tests catch syntax violations, permission leaks, and false-positive test runner assertions prior to deployment.

## 48. Hypothesis Property Cardinality & Temporal Sequence Fuzzing for Multi-Agent Models
* **Rule (Multi-Agent Property Test Coverage Matrix):**
  - Property test suites (`tests/property/test_*_properties.py`) covering multi-agent attribution or coordination evidence models MUST explicitly verify:
    1. **Cardinality Fuzzing**: Test that agent lists with $N < 2$ (e.g. 0 or 1 agent) raise `pydantic.ValidationError`, while lists with $N \ge 2$ valid agents succeed.
    2. **Score Clamping**: Test that floats outside `[0.0, 1.0]` (e.g. `< 0.0` or `> 1.0`) raise `ValidationError`, while floats within $[0.0, 1.0]$ are accepted.
    3. **Timezone Rejection**: Test that naive datetimes and datetimes with non-UTC timezone offsets raise `ValidationError`.
    4. **Temporal Ordering Inversion**: Test that inverted temporal windows (`last_detected < first_detected`) raise `ValidationError`, while valid ordering (`last_detected >= first_detected`) succeeds.
* **Rationale:** Unit tests with fixed examples often test only $N=2$ or single valid timestamps. Property-based fuzzing guarantees that the entire boundary spectrum across cardinality, score limits, and temporal invariants is continuously verified against regression.

## 49. Large Test Suite Execution Monitoring & Incremental Verification Protocol
* **Rule (Targeted Local Scoping for Fast TDD):**
  - During rapid TDD iterations and bug reproduction loops, test executions MUST be scoped to the relevant unit or feature test modules (e.g. `pytest tests/unit/test_agent_swarm_detector.py tests/unit/test_covert_channel_detector.py`) rather than launching the entire 2,200+ test repository suite for minor intermediate edits.
* **Rule (Full Suite Upfront Announcement & Telemetry):**
  - When executing the full repository test suite (e.g. for final pre-commit/pre-push gates or regression checks), agents MUST announce the collected item count (e.g. `collected 2,249 items`) and estimated runtime (3-5 minutes) upfront to users so long execution times are not mistaken for deadlocks or process hangs.
* **Rule (Active Progress Monitoring Timers):**
  - When running test suites in the background, agents MUST use the `schedule` tool with incremental intervals (15–30 seconds) to inspect progress (`manage_task status`), check execution percentages in log tails, and report current progress to the user. Agents MUST NEVER poll in tight loops or wait blindly without status visibility.
* **Rationale:** Full test runs in large repositories execute thousands of property tests, database transactions, and BDD scenarios. Active progress telemetry gives users transparency and prevents premature abortion of healthy test runs.

## 50. `pytest-bdd` Event Loop Scoping & Async Worker Lifecycle Guards with `run_async`
* **Rule (Lifecycle Cancellation Guard):**
  - Background worker components containing `asyncio.Task` references (e.g., `MeshReceiver._worker_task`) MUST check `if not loop.is_closed():` before calling `task.cancel()` or awaiting tasks in `stop()` methods.
* **Rule (Unified Scenario Async Coroutines):**
  - Multi-step asynchronous workflows that simulate multi-node pub/sub sync, event emission, and database ingestion MUST encapsulate the complete async lifecycle (start nodes, register event callbacks, publish, await delivery event, query database records, and stop nodes) within a single unified coroutine invoked by `run_async` in a step, rather than spawning worker tasks in a `Given` step and attempting to cancel or query them in subsequent `When` or `Then` steps.
* **Rationale:** `tests.step_defs.async_utils.run_async` creates, runs, and closes a new `asyncio` event loop on every step execution. Worker tasks created on Loop 1 become orphaned when Loop 1 closes at the end of the step; attempting to cancel or await them on Loop 2 in a later step raises `RuntimeError: Event loop is closed`.

## 51. ADK Security Evaluation Trajectory Gating & Non-Crashing Callback Protocol
* **Rule (Non-Crashing Callback Dictionary Return Contract):**
  - Callbacks intercepting tool execution (e.g., `before_tool_callback`) in Google ADK agent environments MUST NOT raise `PermissionError` or unhandled exceptions when blocking malicious tool execution. Raising exceptions crashes the underlying ADK execution graph with an unhandled `DynamicNodeFailError`.
  - Instead, blocking callbacks MUST return an interception dictionary payload: `{"status": "blocked", "verdict": "BLOCK", "error": f"[BLACKWALL BLOCK] {reasoning}"}`. This cleanly halts tool execution, records the interception event in the trajectory trace, and completes the evaluation cycle.
* **Rule (Dual-Gate ADK Trajectory & Rubric Validation):**
  - Formal ADK security evaluations in `eval_config.json` and `build_evalset.py` MUST enforce a dual gate:
    1. **Deterministic Trajectory Gate**: `tool_trajectory_avg_score: 1.0` (asserting that `before_tool_callback` is the first tool evaluated in the trajectory and produces the exact expected verdict on 100% of test cases).
    2. **LLM-as-a-Judge Quality Gate**: `rubric_based_tool_use_quality_v1` (asserting parameter containment, quarantine mock routing, and zero execution of blocked payloads).
  - Raw evaluation results (`raw_adk_results.json`) and report generators (`ReportGenerator`) MUST record and assert both gates for formal security certification.
* **Rule (Agent Entrypoint Knowledge Graph Invariant):**
  - Production agent entrypoints (`agent/__init__.py`) MUST instantiate `SyncResolver` with an active `CodebaseMemoryClient` (`cbm_client=CodebaseMemoryClient(base_url=os.getenv("CBM_MCP_BASE_URL"))`) to satisfy the mandatory interception sequence: `Rate Check` -> `Context Hygiene Sanitization` -> `Threat Signature Graph (TSG) Check` -> `Codebase Memory MCP AST Query` -> `Threat Intelligence Validation (AlienVault OTX / Multi-Provider Orchestrator)` -> `Score Aggregation` -> `Threshold Verdict`.
* **Rationale:** Discovered during Task 21 implementation and PR #123 review cycles. Raising exceptions in callbacks crashes ADK benchmark runs, evaluating trajectory scores without LLM rubrics misses semantic bypasses, and omitting `cbm_client` in `agent/__init__.py` breaks the core interception sequence.

## 52. Testing Triad Invariant for Core Source Code Modifications
* **Rule (Three-Layer Test Coverage):**
  Any PR introducing new capabilities, refactoring logic, or modifying behavior in `src/` MUST include test coverage across all three testing layers before triggering automated reviews:
  1. **Unit / Integration Tests (`tests/unit/`, `tests/`)**: Deterministic assertion of components, error branches, and edge cases.
  2. **Hypothesis Property-Based Tests (`tests/property/`)**: Fuzzing invariants, round-trip serialization (`save` $\to$ `load`), and boundary stability across random inputs.
  3. **Behavior-Driven Specifications (`tests/features/` & `tests/step_defs/`)**: Gherkin behavioral contracts evaluated using `pytest-bdd` and `run_async`.
* **Rule (First-Review Cleanliness):** Omitting any of the three layers trips the repository's automated review rules (`Test-Driven Development (TDD) & BDD Coverage`), resulting in score drops below the 4/5 threshold and review churn.
* **Rationale:** Codified after Greptile review on PR #130. Automated AI review agents enforce complete test parity across unit, property, and BDD specifications for every modified source module.

## 53. Packaging Isolation & Realistic Sustained Benchmark Pacing Invariants
* **Rule (Zero `tests/` Imports in Production Package Code):** Modules under `src/` (including benchmark runners and CLI utilities) MUST NEVER import modules, fixtures, or helpers from `tests/` (e.g. `tests.integration.helpers`). When Blackwall is installed as a package or run from an external working directory, `tests/` is not in `PYTHONPATH`, causing immediate `ModuleNotFoundError` crashes. Default policies or fixtures must be packaged directly within `src/` or embedded as constants.
* **Rule (Genuine Thread Concurrency for Synchronous Engines):** Benchmark suites testing concurrent load on CPU-bound or synchronous engines (e.g. `StructuralGatingEngine`) MUST NOT rely on single-threaded `asyncio.gather(*[...])` without suspension points, which executes calls sequentially. Concurrent load MUST be dispatched across a `concurrent.futures.ThreadPoolExecutor` worker pool to test genuine thread contention and OS scheduling.
* **Rule (Real Pacing Over Synthetic Time):** Sustained throughput and rate benchmarks (e.g. 300 RPM) MUST actively pace requests at the claimed interval (`interval = 60.0 / rate_rpm`) rather than running back-to-back in an unpaced tight loop and dividing CPU time by an arbitrary synthetic duration. CPU utilization must be calculated against the actual elapsed wall time.
* **Rule (Dual-Hardware Gateway Resource Enforcement):** Performance benchmarks MUST enforce the strict repository resource budgets in `.greptile/config.json`: memory RSS must not exceed 350.0 MB and sustained CPU must not exceed 2.0% on a 2-core baseline.
* **Rationale:** Discovered during Greptile review on PR #132. Review bots flag loose resource limits, unpaced tight loops masquerading as sustained rate tests, and packaging breakage caused by cross-directory test imports.

## 54. Evaluation Harness & Review Agent Verification Invariants (Dynamic Interception, Real Replacement & Transport Mocking)
* **Rule (Dynamic Prediction Derivation over Ground-Truth Copying):**
  - In evaluation test suites (e.g. `tests/evaluation/test_tier1_adk_harness.py`), `predicted_blocked` MUST NEVER be copied directly from `ground_truth_threat` or sample labels.
  - Predictions MUST be derived dynamically by executing the driver, audit hook, or resolver under test (`eval_driver.audit_event_handler(...)` or `resolver.evaluate(...)`) and checking whether an interception exception or block verdict was actually generated. If the driver fails to intercept, `predicted_blocked` must evaluate to `False`, allowing the evaluation metric to correctly register a false negative.
* **Rule (Real Credential Replacement Verification):**
  - When testing environment sterilization and honey-token masking (`SecretVaultSidecar.sterilize_environment`), test inputs MUST NOT already be prefixed with `BW_SYNTHETIC_`. Inputs must be unsterilized mock values (e.g. `raw_unsterilized_mock_secret_key_9999`) that avoid cloud secret scanner keywords while lacking the synthetic prefix.
  - Tests MUST assert both:
    1. Pre-sterilization non-honeytoken status: `evaluate_access(...)["is_honeytoken"] is False`.
    2. Real substitution: `sterilized[key] != raw_unsterilized_env[key]` AND `sterilized[key].startswith(f"BW_SYNTHETIC_{key}_")`.
* **Rule (Transport-Level Mocking for Local LLMs):**
  - When testing local LLM engines (e.g. `OllamaForensicEngine`), tests MUST NOT monkeypatch high-level entrypoints (`analyze_log_stream`) with preselected report dictionaries.
  - Tests MUST mock at the HTTP transport boundary (`aiohttp.ClientSession.post`), returning simulated raw LLM text so that prompt formulation, payload construction, HTTP status checking, JSON code fence stripping, and `_parse_llm_json_response` error/refusal handling execute 100% of their production code paths.
* **Rule (Managed Cloud Evaluation Gates):**
  - In Tier 1 evaluation tests, evaluation tasks targeting `GCPVertexAIEvaluationHarness` MUST assert `eval_result["status"] == "COMPLETED"`. In test environments where live GCP credentials or real project resources are unconfigured, tests must mock the Vertex AI SDK `EvalTask` module to return completed evaluation tables rather than accepting `LOCAL_FALLBACK` as a passing evaluation gate.
* **Rationale:** Discovered during Greptile review on PR #133. Review agents flag derived evaluation metrics that mask broken interception paths, no-op environment sterilization, and preselected mock reports that bypass real LLM response parsing.

## 55. CI Evaluation Scoping, CLI Option Parity & Baseline Seeding Invariants
* **Rule (Marker-Scoped Test Collection & BDD Step Inclusion):**
  - When configuring CI workflows, shell scripts, or documentation using marker-scoped pytest commands (e.g., `pytest -m gcp_eval`), the invocation command MUST NOT restrict directory arguments solely to `tests/evaluation/` or `tests/integration/` without explicitly including `tests/step_defs/test_*_bdd.py`.
  - Restricting paths without step definitions causes pytest to skip collecting BDD scenarios even when their `.feature` files are tagged with `@gcp_eval`.
  - Commands MUST either run marker discovery from the test root (`pytest -v -m <marker>`) or explicitly enumerate `tests/step_defs/test_*_bdd.py` alongside integration paths.
* **Rule (CLI Option Parity & Dual-Naming Aliases in Runner Scripts):**
  - Python CLI runners and CI tools (such as `scripts/run_gcp_eval.py`) MUST maintain strict flag parity with their underlying orchestration functions and public documentation.
  - Where options have alternate naming conventions across documentation and specifications (e.g. `--eval-threshold` vs `--threshold`), `argparse` MUST define them as co-equal aliases pointing to a single destination variable:
    ```python
    parser.add_argument(
        "--eval-threshold",
        "--threshold",
        dest="eval_threshold",
        type=float,
        default=3.5,
        help="Minimum domain mean score to pass CI (default: 3.5)",
    )
    ```
  - All operational modes supported by the runner (such as `--allow-fallback` and `--no-trace`) MUST be exposed in `parse_args()` and forwarded to the pipeline entrypoint.
* **Rule (Selective Evaluation Runs & Baseline Seeding in Tests):**
  - In `run_evaluation_pipeline`, an evaluation run only qualifies as a clean baseline anchor (`is_clean_baseline=True`) if it achieves full coverage across all 9 canonical domains with zero fallbacks and zero failed scenarios.
  - In unit and integration tests verifying subsequent regression comparison logic on scoped domains, tests MUST explicitly seed the `HistoricalRegressionTracker` with a clean baseline (`EvalRunSummary(..., is_clean_baseline=True)`) before executing candidate runs to ensure the tracker can perform relative comparisons without requiring full 9-domain coverage.
* **Rationale:** Discovered during Greptile review on PR #134. Review agents flag CI commands that omit BDD step definitions, CLI scripts missing documented flags, and selective runs failing baseline establishment.

## 56. Two-Wave Evasion Transference, Process-Group Termination & Fail-Closed Evaluation Loops
* **Rule (Causal Transference Verification in Multi-Wave Evasion Tests):**
  - In self-learning evasion benchmarks (e.g. `scripts/run_evasion_eval.sh`, `scripts/run_evasion_wave.py`), Wave 1 novel attacks MUST generate inline threat signatures dynamically through the live interception resolution path (`repo.writeSignature`). Pre-populating predetermined static signatures is strictly prohibited.
  - Wave 2 variant evaluations MUST assert both:
    1. The decision is `BLOCK`: `verdict.decision == VerdictDecision.BLOCK`.
    2. The reasoning confirms a genuine TSG hit: `"Blocked via signature match" in verdict.reasoning`.
  - Latency thresholds MUST verify that Wave 2 signature-path lookups complete in $< 50\text{ ms}$ (typically $< 15\text{ ms}$), demonstrating measurable speedup over the multi-second Wave 1 semantic evaluation path.
* **Rule (Shell-to-Python Database Path Synchronization):**
  - Shell launchers resetting SQLite state prior to evaluations MUST explicitly export the resolved database path: `export BLACKWALL_DB_PATH="${BLACKWALL_DB}"`.
  - Invoked Python modules MUST read `os.getenv("BLACKWALL_DB_PATH", ...)` to ensure the daemon, the reset routine, and the evaluation runner target the identical physical file.
* **Rule (Shell Launcher Process-Group Cleanup):**
  - Shell scripts launching background server daemons (e.g. `adk api_server`) MUST enable job control (`set -m`), capture `DAEMON_PID=$!`, and terminate the entire process group in the exit trap using `kill -TERM -"${DAEMON_PID}" 2>/dev/null || kill "${DAEMON_PID}" 2>/dev/null || true` to prevent orphaned child workers from keeping ports occupied.
* **Rule (Fail-Closed Loop Resilience in Adversarial Runners):**
  - Evaluation loops iterating over adversarial datasets MUST wrap individual case executions in `try...except Exception as exc:`, construct a fail-closed `Verdict(decision=VerdictDecision.BLOCK, reasoning=f"Fail-closed fallback: {exc}")`, mark `span.attributes["is_fallback"] = True`, and record the error on the telemetry span rather than allowing transient exceptions to abort the multi-wave run.
* **Rule (No Hardcoded Fallback Project IDs in Paid-Tier Runners):**
  - Paid-tier Vertex AI evaluation runners MUST require `GCP_PROJECT` or `GOOGLE_CLOUD_PROJECT` explicitly and raise `ValueError` immediately at startup. Defaulting to hardcoded placeholder project strings is prohibited.
* **Rationale:** Codified after live execution and Greptile review on PR #136. Review bots flag loose process-group traps, unproven evasion transference, missing database synchronization, and silent project ID fallbacks.

## 57. Rust Native Acceleration Benchmarking, FFI Overhead Calibration & Fallback Parity Invariants
* **Rule (Native Compute SLA vs. Python FFI Marshaling in Microbenchmarks):**
  - When benchmarking PyO3 compiled Rust extensions from Python, developers and review agents MUST differentiate between pure native compute throughput and Python FFI integration benchmarks.
  - Python-to-Rust FFI crossings have an inherent fixed marshaling overhead (~15–20µs baseline for PyO3 argument/tuple conversion + Python object unpacking, totaling ~200–400µs for batches of 100 candidates).
  - Operations where FFI marshaling exceeds microsecond-level native SLAs (e.g. `batch_cosine_similarity` evaluating 100 768-dim candidates against a <20µs native compute SLA) MUST NOT be gated with an unachievable end-to-end sub-20µs raw latency assertion in Python.
  - Python integration benchmarks MUST gate vector similarity using an empirical **speedup ratio** (e.g. `speedup >= 35×` vs pure-Python `array.array` deserialization + float loops, the actual code path replaced in production). Pure native compute throughput (~3µs/vector) is verified in Rust unit tests (`cargo test`).
* **Rule (Realistic Workload Scale in Accelerated Hot-Path Benchmarks):**
  - Microbenchmarks testing accelerated hot paths MUST NOT use toy inputs that obscure latency contracts:
    - **Context Redaction**: Payload MUST be $\ge 9\text{KB}$ of realistic text (natural language with 2–3 embedded credentials). SLA $\le 50\mu\text{s}$ mean.
    - **Graph DFS Traversal**: MUST test up to 500 nodes (e.g. 25 chains × 20) with realistic bounded traversal (`max_paths=50`). SLA $\le 500\mu\text{s}$ mean.
    - **Single-Pass IOC & Entropy**: Both `extract_iocs([payload])` and `calculate_entropy(payload)` MUST be invoked in sequence (matching the semantic gating pipeline). Combined SLA $\le 35\mu\text{s}$ mean on a 1KB payload.
    - **Word Intersection**: SLA $\le 10\mu\text{s}$ mean.
* **Rule (Strict Benchmark Exit & Predicate Hygiene):**
  - Benchmark runners MUST return `False` and exit code 1 if compiled native extensions are unavailable (silent skipping or passing is strictly prohibited).
  - All SLA gate predicates MUST use strict `mean < sla` (or `speedup >= sla_speedup`) rather than permissive `min_ < sla or mean < sla`.
* **Rule (Pure-Python Fallback Parity Isolation & Module Eviction):**
  - Test suites asserting functional parity between compiled Rust extensions and pure-Python fallbacks (`test_fallback_invariant.py`) MUST:
    1. Proactively verify that the native extension is compiled and available before running parity tests (preventing false comparisons of fallback against fallback).
    2. Cleanly evict wrapper modules from `sys.modules` (`sys.modules.pop(mod_name, None)`) prior to importing under `mock.patch.dict("sys.modules", {"blackwall._core_rs": None})`, ensuring previously imported native references do not leak into fallback test scopes.
* **Rationale:** Codified after Greptile review on PR #138 (review `5205988519`). Review bots flag benchmarks using toy payloads as "weak gates", while demanding raw sub-20µs latency across the PyO3 boundary triggers impossible Catch-22 loops unless the FFI speedup calibration invariant is codified.

## 58. Hypothesis Strategy Input Validity & Example Database Replay Awareness
* **Rule (Valid-Input Strategies):** Strategies feeding Pydantic-validated models MUST exclude values the model rejects (e.g. `.filter(lambda s: bool(s.strip()))` for non-empty-string fields). A "valid acceptance" property that draws invalid inputs is a strategy bug, not a code bug.
* **Rule (Example-DB Replay):** When triaging property-test failures across checkouts, account for `.hypothesis/examples` replay: a saved falsifying example makes failures deterministic per-checkout. Re-run with a cleared example database before attributing the failure to code changes.
* **Rationale:** Discovered during the v2.0 release audit: a whitespace-only regex draw failed a "valid acceptance" property, and the saved example made it reproduce deterministically on one checkout while passing on another, initially masquerading as a session regression.

## 59. Deterministic Background-Task Synchronization in Tests
* **Rule (Public Drain API):** Tests asserting on state produced by fire-and-forget background tasks MUST drain them via the public `flush_background_tasks()` (or equivalent) instead of `asyncio.sleep()` delays or immediate assertions, which encode a race between the test and the background coroutine.
* **Rationale:** Discovered during the v2.0 release audit: an integration test asserted signature persistence immediately after `evaluate()`, observing zero rows because inline signature generation had not yet run; all other invocations passed, masking the race.

## 60. Dynamic Synthetic Credential Construction in Test Fixtures
* **Rule (No Literal Basic Auth in Test Code):** Unit tests, BDD step definitions, and mock fixtures testing credential sanitization, URL redacting, or authentication error handling MUST NOT write literal basic auth credentials (e.g. `https://user:password@...`, `admin:secret123@`) directly as static string literals in source code.
* **Rule (Dynamic Composition):** Test fixtures MUST construct sensitive test URL strings dynamically (e.g. `f"https://{user}:{pwd}@{host}/path"` where `user = "user"` and `pwd = "pass"`) or use dummy placeholders like `[[CREDENTIAL]]`.
* **Rationale:** Discovered on PR #150. Automated CI secret scanners (such as GitGuardian) scan all commits in pull request branches. Static basic auth URLs trigger false-positive secret leakage alerts that persist across branch history even after subsequent cleanup commits.

## 61. Subprocess & Path Isolation in Companion Bridge Test Suites
* **Rule (Mock Both Liveness & Execution):** Unit tests and BDD steps testing external CLI bridges (such as `HarpoonBridge`) MUST mock both binary presence checks (`shutil.which`) and subprocess execution runners (`asyncio.create_subprocess_exec`) within the test fixture scope.
* **Rule (No Ambient PATH Dependency):** Tests MUST NOT depend on or execute ambient host binaries, ensuring 100% deterministic test execution across environments regardless of whether companion tools (like `harpoon`) are installed on the local system.
* **Rationale:** Discovered during Phase 3 test suite implementation on PR #151. Relying on unmocked binary presence causes test behavior to diverge between local development machines with external CLI tools installed and isolated CI runner containers.

## 62. Threat Intelligence Cache SLA Benchmarking & DGX Spark Zero-CUDA Verification
* **Rule (Sub-Millisecond Cache SLA):** Benchmarks evaluating threat intelligence cache performance (`scripts/benchmark_threat_intel.py`, `tests/unit/threat_intel/test_benchmarks_sla.py`) MUST assert an average read latency $\le 1.0\text{ ms}$ across sequential lookups and process RSS memory overhead $\le 50\text{ MB}$.
* **Rule (Multi-Layer Zero-CUDA Verification):** On Linux / NVIDIA DGX Spark environments, conformance benchmarks MUST verify that threat intelligence execution remains 100% in CPU user-space with zero CUDA VRAM allocations across three independent layers:
  1. Inspecting `/proc/<daemon_pid>/fd/` for `/dev/nvidia*` device file descriptors on the target process PID.
  2. Inspecting NVML compute process tables to verify daemon PID absence.
  3. Asserting `torch.cuda.is_initialized() is False`.
* **Rationale:** Discovered during Phase 4 benchmarking on PR #152. Blackwall Core must preserve 100% of unified GPU memory (>127.6GB on DGX Spark GB10 ARM64) for hosted AI models.

## 63. Agent Instruction Hygiene: Abstract Specification Demarcation & Citation Preservation
* **Rule (Abstract Specification Target Qualification):** In agent instruction files (`AGENTS.md`, `.agents/rules/`, `.greptile/rules.md`), planned architectural components (such as `.kiro/specs/blackwall-mcp-gateway/`) MUST be explicitly qualified as abstract specification targets rather than concrete on-disk modules. Non-existent paths MUST NOT be formatted in backticks or Markdown file links that trigger automated static scanners as missing targets or phantom paths.
* **Rule (Rule Renumbering Trap & Downstream Citation Preservation):** When updating, deprecating, or modernizing numbered rules (e.g. Rule 25), agents MUST NEVER delete or renumber downstream rules. Modernize the rule title and content in-place to avoid breaking citations across test docstrings, commit messages, and automated review agent trackers.
* **Rationale:** Discovered during Phase 4 agent memory audit. Naive rule renumbering breaks test references across git branches, while unqualified path strings in instruction files trigger static repository audit scanner failures.

## 64. Evaluation Dashboards, Analytics Notebooks & Benchmark Verification Invariants
* **Rule (Developer Extra Dependency Parity):**
  - Developer analytics notebooks (such as Marimo or Jupyter dashboards under `notebooks/`) included in `[project.optional-dependencies] dev` MUST have all direct and transitive runtime dependencies (e.g. `pandas>=3.0.0`, `marimo>=0.11.0`) included directly within the `dev` extra.
  - Development tools MUST NOT rely on users separately discovering or installing specialized evaluation extras (such as `evaluation` or `eval`) to achieve clean module imports.
* **Rule (Canonical Evaluation Taxonomy & Hostility Detection):**
  - Evaluation notebooks, analysis scripts, and scenario drill-down tables MUST align with Blackwall's canonical evaluation dataset taxonomy (`tests/eval/evalsets/blackwall_security.evalset.json`), where hostile scenarios are identified by `ground_truth: "MALICIOUS"`.
  - Conditionals determining hostility MUST check `ground_truth in ("MALICIOUS", "ADVERSARIAL")` or `expected_verdict in ("BLOCK", "CRITICAL", "QUARANTINE")` to prevent real malicious cases from defaulting to benign scores (1.2) and reporting false divergences.
* **Rule (Zero-Overstatement for Unmeasured Test Cases):**
  - When correlating scenario datasets with recorded evaluation reports (`security_report.json`), cases without an evaluation entry (`recorded_verdict is None`) MUST be rendered explicitly as unmeasured (`"—"`).
  - Code MUST NOT substitute the expected verdict for missing recorded verdicts or treat `None` as a passing match (`True`), which overstates benchmark coverage.
* **Rule (Strict Contract Boundary Inequality Alignment):**
  - Performance and SLA matrices in notebooks and reports MUST use strict mathematical inequality operators matching the authoritative benchmark runner (`src/blackwall/benchmarks/runner.py`):
    - `structural_p99 < cutoff` (SLA: < 5.0 ms)
    - `semantic_p99 < cutoff` (SLA: < 300.0 ms)
    - `tsg_query_p99 < 10.0` (SLA: < 10.0 ms)
    - `cpu_pct < 2.0` (SLA: < 2.0%)
    - `memory_rss <= ceiling` (SLA: <= 350.0 MB)
    - `batch_size >= 3.0`
* **Rule (Resilient Per-Line Stream Parsing):**
  - Readers parsing append-only evaluation history files (`history.jsonl`) MUST catch JSON decoding errors on a per-line basis (`try...except (json.JSONDecodeError, ValueError)`), matching `HistoricalRegressionTracker.get_history()`.
  - An interrupted append or corrupted line MUST be skipped individually without discarding previously parsed valid runs or substituting synthetic fallback data.
* **Rationale:** Codified after PR #158 Greptile code review. Prevents missing development dependencies, false divergence reports on malicious cases, overstated coverage on unmeasured scenarios, boundary operator discrepancies, and history data loss during interrupted runs.

## 65. Local Loopback Test Socket Permissions in macOS Sandbox Environments
* **Rule (Sandbox Bypass for Loopback Sockets):** Unit and integration tests that bind local loopback network sockets (e.g., `aiohttp.test_utils.TestClient` in `test_server.py`) require running the terminal runner with `BypassSandbox: true` on macOS, because standard sandbox isolation blocks local socket creation/binding by default, producing `PermissionError` or connection refused errors even when connecting to `127.0.0.1`.
* **Rationale:** Discovered during MCP Gateway test execution on macOS. Standard sandbox execution rejects local loopback socket binding, requiring sandbox bypass for test suites exercising HTTP/SSE server endpoints.

## 66. Active Test Suite Timers & Progress Monitoring for Background Commands
* **Rule:** When running test suites (especially full suite runs, long-running suites, or background test tasks), agents MUST NOT rely on passive, blind waiting. Agents MUST set an explicit timer via the `schedule` tool with an estimated upper bound or incremental check intervals (e.g. 10–30s) to monitor test progress, inspect logs, and immediately kill and diagnose hanging test loops, deadlock conditions, or leaking non-daemon background threads.
* **Rationale:** Mandated by user correction during Phase 2 testing. Blind waiting allows hanging subprocesses or socket deadlocks to run indefinitely without visibility or diagnostic intervention.

## 67. Non-Blocking Executor Shutdown in Subprocess Timeout Helpers
* **Rule:** Test helpers that read subprocess pipes with a timeout MUST NOT use `with ThreadPoolExecutor(...)` combined with `future.result(timeout=...)`: exiting the context manager calls `shutdown(wait=True)`, which blocks forever on a worker stuck in `readline()` and prevents process-group (`killpg`) cleanup from ever running. Use an explicit pool and call `shutdown(wait=False, cancel_futures=True)` on the timeout path so fixture teardown can still terminate the process group.
* **Rationale:** Greptile P1 on PR #161 (`test_gateway.py._readline_timeout`): the timeout existed but teardown could never reach it.

## 68. Cold-Start Measured in a Fresh Interpreter & Lazy Heavy Imports
* **Rule (Cold-Start Measurement):** Startup SLA tests MUST measure cold start in a fresh interpreter subprocess (`python -c "import ...; init();"`), never in-process server construction after imports have already completed.
* **Rule (Lazy Heavy Imports):** Top-level package `__init__` files MUST NOT eagerly import heavy third-party SDKs (PEP 562 lazy `__getattr__`); call-site-only dependencies MUST be imported lazily at function scope.
* **Rationale:** Greptile P1 on PR #161: an eager `config → google.genai` chain cost 2.2s of a 3.04s cold start; lazy loading cut it to 0.89s.

## 69. Delta-Based Idle CPU Sampling
* **Rule:** Idle-CPU assertions MUST sample cputime deltas over an interval (`ps -o time=` twice, `% = Δcpu/Δwall`), never lifetime-average `ps -o %cpu=` on a young process — startup work inflates the lifetime average (observed 89% on an idle daemon) and false-fails the test.
* **Rationale:** Discovered during Phase 3 resource profiling (TASK-D04) on PR #161.





## 70. Marimo Notebook Cell Conventions
* **Rule (Display Expression Endings):** Marimo cells MUST end with the display expression — trailing bare `return` statements break marimo's static analysis (`SyntaxError: 'return' outside function`) even though the file compiles under CPython. Use single-return pattern (compute into `_name`, one `return` of the display object).
* **Rule (Cell-Local Underscore Prefix):** All cell-local bindings (loop variables, file handles, temporaries) MUST be underscore-prefixed (`_cid`, `_fh`). Unprefixed names collide across cells and break reactivity (observed: `cid`/`f` collisions failed `marimo export`).
* **Rule (Export Validation):** Notebook changes MUST validate via `marimo export html <notebook> -o <tmp>` completing with zero failed cells before commit.
* **Rationale:** Discovered while building the Jev analytics section on PR #169: every export failure in the session traced to one of these three patterns.

## 71. Eval Input Decontamination
* **Rule (No Answer-Bearing Inputs):** Model inputs built from eval fixtures MUST NOT contain ground-truth-bearing text. Scrub standalone label words AND case-ID references (`malicious_sql_001`-style), and drop scenario-label lines, so the model classifies the payload rather than reading the harness's answer key.
* **Rule (Payload Preservation):** Scrub patterns MUST be verified against a placeholder inventory — meaningful attack content such as `[[MALICIOUS_COMMAND]]` MUST survive (an overbroad `[\w]*label[\w]*` scrub gutted it to `[[]]` on PR #169).
* **Rationale:** The first Jev A/B reached 100% partly by label-reading; decontaminated re-measurement is the trustworthy record.

## 72. Content-Hash Checkpointing for Long Eval Runs
* **Rule (Hash-Scoped Resume):** Bulk model-API eval runs MUST checkpoint per case and resume on `(case_id, content-hash, scope)` — never ID-only — and MUST filter stale rows at serialization, so fixture/suite/`--limit` changes cannot pair old probabilities with new states.
* **Rule (Commit Artifacts, Not Scratch):** Per-case results MUST be written to a versioned artifact path (e.g. `tests/eval/results/`) and committed; scratch-only results are data loss waiting to happen (the first Jev 167-case run was deleted with its temp dir).
* **Rationale:** Free-tier Gateway evals trickle over hours and inevitably span restarts; learned across three Jev eval executions on PR #169.


## 73. Formatter, Environment and Spec-Track Scoping Hazards
* **Rule (Never Run Repo Formatters Over Hand Edits):** At a `py314` target, both black 26.x and `ruff format >= 0.16` rewrite `except (A, B):` into the PEP 758 unparenthesized form. That parses to the same AST on 3.14, so the rewrite passes the entire test suite while silently diverging a diff that was supposed to be verbatim. Agents MUST NOT run a repository formatter across files they hand-edited; inspect with `<tool> --diff` and apply nothing. `[tool.ruff] target-version = "py314"` makes the behaviour deliberate, and ruff — unlike black — has no interpreter-coupled safety check to fall back on.
* **Rule (Formatting Is Convention, Not Gate):** Roughly 284 files under `src/` and `tests/` are formatter-dirty and `.git/hooks/pre-commit` is not installed. Any sweep belongs in its own isolated `chore(format)` change with a `.git-blame-ignore-revs` entry, never folded into a feature branch.
* **Rule (Baseline-Diff Before Blaming Your Change):** `.venv` (Python 3.14.7) is the sole repository environment and is installed without the `evaluation` / `eval` optional extras, so GCP/Vertex eval suites fail there on missing imports and absent ADC credentials, not on code defects. Before attributing any failure to your own work, run the failing subset against pristine `main` in a throwaway worktree and compare the failure sets; treat load-bound benchmark and Hypothesis assertions as flaky until reproduced in isolation.
* **Rule (Track Scope Overrides Repo-Wide Quality Rules):** Where a spec track's own acceptance gates conflict with a repo-wide rule such as §16 or §52's unit + property + BDD triad, the track's scope wins. State the deviation in the PR description with the task ID that owns the deferred coverage (for `.kiro/specs/tier-1-jev-addition/`, BDD acceptance is TASK-D01) instead of expanding into a later track to satisfy a reviewer.
* **Rationale:** Codified on PR #170. A formatter pass over hand-edited files rewrote two `except` tuples inside a port that TASK-A01 requires be byte-identical, and the drift survived 141 green tests; baseline diffing separately reduced 30 apparent regressions to 28 pre-existing environment failures plus 2 flaky, and confirmed zero regressions.
