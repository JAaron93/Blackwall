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

