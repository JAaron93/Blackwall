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
from pytest_bdd import given, scenario, then, when

from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository

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
