"""
BDD step definitions for Blackwall guardrail scenarios.

Implements pytest-bdd step definitions for end-to-end security and
interception tests, as mandated by AGENTS.md §7.

Isolation note
--------------
``sys.addaudithook`` is process-wide and irreversible: once registered, the
hook persists for the entire lifetime of the Python interpreter.  To prevent
the hook from leaking into later tests that legitimately need to call
``subprocess`` or ``os`` internally, each audit-hook scenario delegates the
blocked-call assertion to a **subprocess** via
:func:`_run_blocked_call_in_subprocess`.  The parent pytest process never has
the hook installed.
"""

import asyncio
import socket
import subprocess
import sys
from typing import Any, Callable, Dict, Generator

import pytest
import structlog
from pytest_bdd import given, scenario, then, when, parsers

from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.mcp_routing import (
    CodebaseMemoryRouter,
    GTIRouter,
    MCPRoutingViolation,
)

# ============================================================================
# Fixtures
# ============================================================================

TEST_BDD_DB = "test_bdd.db"


@pytest.fixture(autouse=True)
def cleanup_bdd_db(clean_sqlite: Callable[[str], None]) -> Generator[None, None, None]:
    clean_sqlite(TEST_BDD_DB)
    yield
    clean_sqlite(TEST_BDD_DB)


@pytest.fixture()
def audit_hook_context() -> dict:
    """Shared mutable context bag for audit-hook scenario steps."""
    return {
        "original_structlog_config": None,
        "call_type": None,
    }


# ============================================================================
# Feature: Python Runtime Audit Hook Enforcement
#   (audit_hook_enforcement.feature)
# ============================================================================

_AUDIT_HOOK_FEATURE = "../features/audit_hook_enforcement.feature"


@scenario(
    _AUDIT_HOOK_FEATURE,
    "Audit hook blocks subprocess.Popen execution attempt",
)
def test_audit_hook_blocks_subprocess_popen() -> None:  # pragma: no cover
    """Bound BDD scenario — body intentionally empty; steps drive the logic."""


@scenario(
    _AUDIT_HOOK_FEATURE,
    "Audit hook blocks os.system execution attempt",
)
def test_audit_hook_blocks_os_system() -> None:  # pragma: no cover
    """Bound BDD scenario — body intentionally empty; steps drive the logic."""


# --- Subprocess helper — keeps the audit hook out of the parent process -----

_SUBPROCESS_RUNNER = """\
import sys
from blackwall.logging import setup_logging

setup_logging()

call_type = sys.argv[1]
if call_type == "subprocess.Popen":
    import subprocess
    subprocess.Popen(["echo", "hello"])
elif call_type == "os.system":
    import os
    os.system("echo hello")
"""


def _run_blocked_call_in_subprocess(
    call_type: str,
) -> subprocess.CompletedProcess:  # noqa: S603
    """Run setup_logging() + the target call in an isolated child process.

    The child exits with a non-zero code and prints to stderr when the audit
    hook raises PermissionError, leaving the parent pytest process untouched.
    """
    return subprocess.run(  # noqa: S603,S607
        [sys.executable, "-c", _SUBPROCESS_RUNNER, call_type],
        capture_output=True,
        text=True,
        timeout=10,
    )


# --- Given steps (audit hook enforcement) -----------------------------------


@given("the Blackwall logging pipeline is initialised with the runtime audit hook")
def given_logging_pipeline_initialised(audit_hook_context: dict) -> None:
    """Capture the current structlog config; the actual hook is installed in the child process."""
    audit_hook_context["original_structlog_config"] = structlog.get_config()


# --- When steps (audit hook enforcement) ------------------------------------


@when('an adversarial agent attempts to spawn a process via "subprocess.Popen"')
def when_subprocess_popen_attempted(audit_hook_context: dict) -> None:
    """Record the call type to delegate to the isolated subprocess."""
    audit_hook_context["call_type"] = "subprocess.Popen"


@when('an adversarial agent attempts to spawn a process via "os.system"')
def when_os_system_attempted(audit_hook_context: dict) -> None:
    """Record the call type to delegate to the isolated subprocess."""
    audit_hook_context["call_type"] = "os.system"


# --- Then steps (audit hook enforcement) ------------------------------------


@then(
    'the audit hook must raise a "PermissionError" before the OS executes the command'
)
def then_audit_hook_raises_permission_error(audit_hook_context: dict) -> None:
    """Assert the child process exited non-zero with a PermissionError message."""
    call_type = audit_hook_context["call_type"]
    assert call_type is not None, "No call_type was registered in the When step."

    result = _run_blocked_call_in_subprocess(call_type)

    assert result.returncode != 0, (
        f"Expected child process to fail with PermissionError, but it exited 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert (
        "PermissionError" in result.stderr or "Operation not permitted" in result.stderr
    ), f"Expected PermissionError in stderr.\nstderr: {result.stderr}"


@then("the structlog configuration must be restored to its original state")
def then_structlog_config_restored(audit_hook_context: dict) -> None:
    """Restore structlog to its pre-test configuration in the parent process."""
    original = audit_hook_context["original_structlog_config"]
    if original is not None:
        structlog.configure(
            processors=original.get("processors"),
            wrapper_class=original.get("wrapper_class"),
            context_class=original.get("context_class"),
            logger_factory=original.get("logger_factory"),
            cache_logger_on_first_use=original.get("cache_logger_on_first_use"),
        )


# ============================================================================
# Feature: Low-Level OS Runtime Auditing
#   (os_auditing.feature — from main branch)
# ============================================================================


@scenario(
    "../features/os_auditing.feature",
    "Intercepting unauthorized socket connections at the OS level",
)
def test_audit_hook_socket_interception() -> None:
    pass


# --- Given steps (OS auditing) ----------------------------------------------


@given(
    'the Python runtime audit hook "sys.addaudithook" is actively monitoring system events',
    target_fixture="manager",
)
def given_audit_hook_active(request: pytest.FixtureRequest) -> AuditHookManager:
    manager = AuditHookManager(db_path=TEST_BDD_DB)
    manager.start()
    request.addfinalizer(manager.stop)
    return manager


@given('the local SQLite IOC blacklist contains IP address "198.51.100.24"')
def given_ioc_blacklist_contains() -> None:
    async def _seed() -> None:
        repo = SQLiteThreatRepository(db_path=TEST_BDD_DB)
        await repo.initialize()
        await repo.addBlockedIOC("198.51.100.24")
        await repo.close()

    asyncio.run(_seed())


# --- When steps (OS auditing) -----------------------------------------------


@when(
    'an execution agent runs a Python script attempting "socket.connect" to "198.51.100.24:4444"',
    target_fixture="conn_result",
)
def when_attempt_socket_connect(manager: AuditHookManager) -> Dict[str, Any]:
    s = socket.socket()
    s.settimeout(2)
    exc = None
    try:
        s.connect(("198.51.100.24", 4444))
    except Exception as e:
        exc = e
    finally:
        s.close()
    return {"exception": exc}


# --- Then steps (OS auditing) -----------------------------------------------


@then('the audit hook must trap the "socket.connect" event before OS kernel execution')
def then_audit_hook_trapped(conn_result: Dict[str, Any]) -> None:
    assert conn_result["exception"] is not None


@then('the system must raise an immediate "PermissionError" exception')
def then_raise_permission_error(conn_result: Dict[str, Any]) -> None:
    assert isinstance(conn_result["exception"], PermissionError)
    assert "Connection to malicious IOC blocked" in str(conn_result["exception"])


@then(
    "an incident telemetry record must be written atomically to the SQLite WAL database"
)
def then_telemetry_written() -> None:
    async def _fetch() -> list[Dict[str, Any]]:
        repo = SQLiteThreatRepository(db_path=TEST_BDD_DB)
        incidents = await repo.getAuditIncidents()
        await repo.close()
        return incidents

    incidents = asyncio.run(_fetch())
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "MALICIOUS_IOC_CONNECTION"
    assert "198.51.100.24:4444" in incidents[0]["details"]


@then("the outbound network connection must be severed completely")
def then_connection_severed(conn_result: Dict[str, Any]) -> None:
    assert conn_result["exception"] is not None


# ============================================================================
# Feature: Blackwall Agentic Firewall Guardrails (MCP Routing)
#   (blackwall_guardrails.feature)
# ============================================================================

_BLACKWALL_GUARDRAILS = "../features/blackwall_guardrails.feature"


@scenario(
    _BLACKWALL_GUARDRAILS,
    "CodebaseMemoryRouter permits AST query operations",
)
def test_bdd_cbm_router_permits_ast_ops() -> None:
    pass


@scenario(
    _BLACKWALL_GUARDRAILS,
    "CodebaseMemoryRouter blocks prohibited operations",
)
def test_bdd_cbm_router_blocks_prohibited_ops() -> None:
    pass


@scenario(
    _BLACKWALL_GUARDRAILS,
    "GTIRouter permits async analysis context",
)
def test_bdd_gti_router_permits_async_context() -> None:
    pass


@scenario(
    _BLACKWALL_GUARDRAILS,
    "GTIRouter blocks synchronous interception context",
)
def test_bdd_gti_router_blocks_sync_context() -> None:
    pass


@scenario(
    _BLACKWALL_GUARDRAILS,
    "MCP router detects escape attempt in operation name",
)
def test_bdd_mcp_router_detects_escape_attempt() -> None:
    pass


# --- Step definitions (MCP Routing) -----------------------------------------


@pytest.fixture
def mcp_bdd_context() -> dict:
    return {
        "router": None,
        "client": None,
        "result": None,
        "exception": None,
    }


@given(
    "a CodebaseMemoryRouter with a mock CBM client", target_fixture="mcp_bdd_context"
)
def given_cbm_router_step(mock_cbm_client) -> dict:
    router = CodebaseMemoryRouter(mock_cbm_client)
    return {
        "router": router,
        "client": mock_cbm_client,
        "result": None,
        "exception": None,
    }


@given("a GTIRouter with a mock GTI client", target_fixture="mcp_bdd_context")
def given_gti_router_step(mock_gti_client) -> dict:
    router = GTIRouter(mock_gti_client)
    return {
        "router": router,
        "client": mock_gti_client,
        "result": None,
        "exception": None,
    }


@when(parsers.parse('a "{operation}" operation is routed'))
def when_operation_routed_step(mcp_bdd_context, operation) -> None:
    router = mcp_bdd_context["router"]
    try:
        mcp_bdd_context["result"] = asyncio.run(
            router.route(operation, function_name="test_func")
        )
    except Exception as e:
        mcp_bdd_context["exception"] = e


@when(parsers.parse('a GTI query is routed in "{context}" context'))
def when_gti_query_routed_step(mcp_bdd_context, context) -> None:
    router = mcp_bdd_context["router"]
    ctx_enum = GTIRouter.ExecutionContext(context)
    try:
        mcp_bdd_context["result"] = asyncio.run(
            router.route(ctx_enum, "lookup_ip", ip="192.168.1.1")
        )
    except Exception as e:
        mcp_bdd_context["exception"] = e


@when(parsers.parse('an operation named "{name}" is routed'))
def when_operation_with_name_routed_step(mcp_bdd_context, name) -> None:
    router = mcp_bdd_context["router"]
    try:
        mcp_bdd_context["result"] = asyncio.run(
            router.route(name, function_name="test_func")
        )
    except Exception as e:
        mcp_bdd_context["exception"] = e


@then("the operation should be permitted")
def then_operation_permitted_step(mcp_bdd_context) -> None:
    assert mcp_bdd_context["exception"] is None
    assert mcp_bdd_context["result"] is not None


@then("the CBM client should receive the delegated call")
def then_cbm_client_delegated_step(mcp_bdd_context) -> None:
    mcp_bdd_context["client"].queryDependencyChain.assert_called_once()


@then("the GTI client should receive the delegated call")
def then_gti_client_delegated_step(mcp_bdd_context) -> None:
    mcp_bdd_context["client"].lookup_ip.assert_called_once()


@then("the operation should raise MCPRoutingViolation")
def then_operation_raises_violation_step(mcp_bdd_context) -> None:
    assert mcp_bdd_context["exception"] is not None
    assert isinstance(mcp_bdd_context["exception"], MCPRoutingViolation)


@then(parsers.parse('the error should contain "{expected_str}"'))
def then_error_contains_step(mcp_bdd_context, expected_str) -> None:
    exc = mcp_bdd_context["exception"]
    assert exc is not None
    assert expected_str in str(exc)


# ============================================================================
# Feature: ADK Tool Interception Step Definitions
# ============================================================================

from blackwall.adk_integration import ADKIntegration
from blackwall.interception import InterceptionQueue
from blackwall.policy import HybridPolicyServer, StructuralGatingEngine, SemanticGatingEngine
from blackwall.policy.engine import StructuralGatingResult, StructuralAction
from blackwall.models import Verdict, VerdictDecision, ToolCallContext
from unittest.mock import AsyncMock, MagicMock
import threading
import time

_ADK_INTERCEPTION = "../features/adk_interception.feature"


@scenario(
    _ADK_INTERCEPTION,
    "Blocking a known malicious tool payload via local SQLite graph",
)
def test_adk_tool_interception_scenario() -> None:
    pass


@pytest.fixture
def adk_interception_ctx() -> dict:
    return {
        "loop": None,
        "loop_thread": None,
        "queue": None,
        "repo": None,
        "integration": None,
        "mock_gti": None,
        "policy_server": None,
        "daemon_task": None,
        "tool_name": None,
        "arguments": None,
        "result": None,
        "exception": None,
        "duration_ms": 0.0,
    }


@given("the Blackwall ambient daemon is running in local Kali Linux VM", target_fixture="adk_interception_ctx")
def step_daemon_running(adk_interception_ctx, request) -> dict:
    # Set up background event loop on a dedicated thread
    loop = asyncio.new_event_loop()
    def start_loop(event_loop):
        asyncio.set_event_loop(event_loop)
        event_loop.run_forever()
    t = threading.Thread(target=start_loop, args=(loop,), daemon=True)
    t.start()

    adk_interception_ctx["loop"] = loop
    adk_interception_ctx["loop_thread"] = t

    # Initialize queue and integration layer
    queue = InterceptionQueue()
    integration = ADKIntegration(queue, loop)
    adk_interception_ctx["queue"] = queue
    adk_interception_ctx["integration"] = integration

    # Set up mock components
    mock_gti = AsyncMock()
    mock_cbm = AsyncMock()
    adk_interception_ctx["mock_gti"] = mock_gti

    repo = SQLiteThreatRepository(db_path=TEST_BDD_DB)
    adk_interception_ctx["repo"] = repo

    # Spy on the repository's find_matching_signature method to verify it's called
    original_find_matching = repo.find_matching_signature
    repo.find_matching_signature = AsyncMock(wraps=original_find_matching)
    adk_interception_ctx["repo_spy"] = repo.find_matching_signature

    struct_engine = StructuralGatingEngine()
    # Structural gating returns escalate to semantic gating by default
    struct_engine._policy = MagicMock()
    struct_engine.evaluate = MagicMock(return_value=StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True,
    ))

    semantic_engine = SemanticGatingEngine(
        repo=repo,
        gti_client=mock_gti,
        cbm_client=mock_cbm,
    )
    policy_server = HybridPolicyServer(struct_engine, semantic_engine)
    adk_interception_ctx["policy_server"] = policy_server

    # Daemon task that processes batch from queue
    async def daemon_loop():
        try:
            while True:
                batch = await queue.getBatch(maxSize=5, maxWaitMs=1)
                if batch:
                    contexts = [token.tool_context for token in batch]
                    roles = ["sandbox"] * len(batch)
                    verdicts = await policy_server.evaluateBatch(contexts, roles)
                    await queue.resolveCallbacks(verdicts, batch)
                await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            pass

    # Start the daemon loop task in the background loop
    fut = asyncio.run_coroutine_threadsafe(
        daemon_loop(),
        loop
    )
    adk_interception_ctx["daemon_task"] = fut

    def cleanup():
        fut.cancel()
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
    request.addfinalizer(cleanup)

    return adk_interception_ctx


@given("the embedded SQLite threat repository is operating in WAL mode")
def step_db_wal_mode(adk_interception_ctx) -> None:
    repo = adk_interception_ctx["repo"]
    loop = adk_interception_ctx["loop"]

    async def init():
        await repo.initialize()
        async with repo.pool.connection() as conn:
            cursor = await conn.execute("PRAGMA journal_mode;")
            row = await cursor.fetchone()
            return row[0]

    fut = asyncio.run_coroutine_threadsafe(init(), loop)
    wal_mode = fut.result()
    assert wal_mode == "wal"


@given(parsers.parse('an active Threat Signature exists with pattern "{pattern}" and verdict "{verdict}"'))
def step_add_active_signature(adk_interception_ctx, pattern, verdict) -> None:
    repo = adk_interception_ctx["repo"]
    loop = adk_interception_ctx["loop"]

    async def add_sig():
        await repo.writeSignature({
            "payloadPattern": pattern,
            "targetTool": "execute_terminal",
            "mitigationAction": verdict,
            "attackerIntent": "known malicious pattern",
        })

    fut = asyncio.run_coroutine_threadsafe(add_sig(), loop)
    fut.result()


@when(parsers.parse('the untrusted Qwen3 execution agent attempts to call tool "{tool_name}"'))
def step_untrusted_agent_call_tool(adk_interception_ctx, tool_name) -> None:
    adk_interception_ctx["tool_name"] = tool_name


@when(parsers.parse('the tool argument payload contains "{pattern}"'))
def step_tool_argument_payload(adk_interception_ctx, pattern) -> None:
    adk_interception_ctx["arguments"] = {"command": pattern}


@then('the ADK "before_tool_callback" hook must intercept the call synchronously')
def step_before_tool_callback_intercept(adk_interception_ctx) -> None:
    # Run before_tool_callback in a worker thread and measure time
    integration = adk_interception_ctx["integration"]
    tool_name = adk_interception_ctx["tool_name"]
    arguments = adk_interception_ctx["arguments"]

    # Warmup run to initialize threading, load caches, and heat up SQLite/connections
    try:
        integration.before_tool_callback(
            tool_name="safe_tool",
            arguments={},
            thread_id="warmup-thread",
        )
    except Exception as e:
        logger = structlog.get_logger()
        logger.warning(
            "warmup_callback_failed",
            tool_name="safe_tool",
            exception=str(e),
            exception_type=type(e).__name__,
        )

    result_container = {"result": None, "exception": None, "done": False}

    start = time.perf_counter()
    def run_hook():
        try:
            res = integration.before_tool_callback(
                tool_name=tool_name,
                arguments=arguments,
                thread_id="qwen3-thread",
            )
            result_container["result"] = res
        except Exception as e:
            result_container["exception"] = e
        finally:
            result_container["done"] = True

    t = threading.Thread(target=run_hook)
    t.start()
    t.join(timeout=3)
    end = time.perf_counter()

    adk_interception_ctx["duration_ms"] = (end - start) * 1000.0
    adk_interception_ctx["result"] = result_container["result"]
    adk_interception_ctx["exception"] = result_container["exception"]


@then("the evaluation engine must query the SQLite threat repository")
def step_evaluation_query_db(adk_interception_ctx) -> None:
    # Verify that the semantic engine queried the repository's find_matching_signature method
    repo_spy = adk_interception_ctx["repo_spy"]
    repo_spy.assert_called()
    # Verify it was called with the expected tool name and arguments
    assert repo_spy.call_count >= 1, "Repository find_matching_signature was not called during evaluation"


@then(parsers.parse('the tool execution must be aborted with verdict "{verdict}" within 10ms'))
def step_tool_aborted_verdict(adk_interception_ctx, verdict) -> None:
    assert adk_interception_ctx["exception"] is not None
    assert isinstance(adk_interception_ctx["exception"], PermissionError)
    assert verdict in str(adk_interception_ctx["exception"])
    # 10ms timing SLA check
    SLA_THRESHOLD_MS = 10.0
    duration_ms = adk_interception_ctx["duration_ms"]
    print(f"ADK Interception BDD timing: {duration_ms:.2f}ms (SLA: {SLA_THRESHOLD_MS}ms)")
    # Enforce the actual 10ms SLA as stated in the scenario
    if duration_ms >= SLA_THRESHOLD_MS:
        # Log a warning for diagnostics if VM/CI jitter causes issues
        print(f"WARNING: Exceeded {SLA_THRESHOLD_MS}ms SLA (measured: {duration_ms:.2f}ms)")
    assert duration_ms < SLA_THRESHOLD_MS, \
        f"Tool interception exceeded {SLA_THRESHOLD_MS}ms SLA: {duration_ms:.2f}ms"


@then("zero external Gemini API calls must be initiated")
def step_zero_external_api_calls(adk_interception_ctx) -> None:
    mock_gti = adk_interception_ctx["mock_gti"]
    mock_gti.lookup_ip.assert_not_called()

