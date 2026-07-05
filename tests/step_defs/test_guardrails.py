"""
BDD step definitions for Blackwall guardrail scenarios.

Implements pytest-bdd step definitions for end-to-end security and
interception tests, as mandated by AGENTS.md §7.

Isolation note
--------------
``sys.addaudithook`` is process-wide and irreversible: once registered, the
hook persists for the entire lifetime of the Python interpreter.  To prevent
the hook from leaking into later tests that legitimately need to call
``subprocess`` or ``os`` internally, each scenario delegates the blocked-call
assertion to a **subprocess** via :func:`_run_blocked_call_in_subprocess`.
The parent pytest process never has the hook installed.
"""
import os
import subprocess
import sys

import pytest
import structlog
from pytest_bdd import given, scenario, then, when

# ---------------------------------------------------------------------------
# Scenarios bound from features/audit_hook_enforcement.feature
# ---------------------------------------------------------------------------

FEATURE_FILE = "../features/audit_hook_enforcement.feature"


@scenario(
    FEATURE_FILE,
    "Audit hook blocks subprocess.Popen execution attempt",
)
def test_audit_hook_blocks_subprocess_popen() -> None:  # pragma: no cover
    """Bound BDD scenario — body intentionally empty; steps drive the logic."""


@scenario(
    FEATURE_FILE,
    "Audit hook blocks os.system execution attempt",
)
def test_audit_hook_blocks_os_system() -> None:  # pragma: no cover
    """Bound BDD scenario — body intentionally empty; steps drive the logic."""


# ---------------------------------------------------------------------------
# Subprocess helper — keeps the audit hook out of the parent process
# ---------------------------------------------------------------------------

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


def _run_blocked_call_in_subprocess(call_type: str) -> subprocess.CompletedProcess:  # noqa: S603
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


# ---------------------------------------------------------------------------
# Shared fixtures used by the steps
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_hook_context() -> dict:
    """Shared mutable context bag for audit-hook scenario steps."""
    return {
        "original_structlog_config": None,
        "call_type": None,
    }


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the Blackwall logging pipeline is initialised with the runtime audit hook")
def given_logging_pipeline_initialised(audit_hook_context: dict) -> None:
    """Capture the current structlog config; the actual hook is installed in the child process."""
    audit_hook_context["original_structlog_config"] = structlog.get_config()


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when('an adversarial agent attempts to spawn a process via "subprocess.Popen"')
def when_subprocess_popen_attempted(audit_hook_context: dict) -> None:
    """Record the call type to delegate to the isolated subprocess."""
    audit_hook_context["call_type"] = "subprocess.Popen"


@when('an adversarial agent attempts to spawn a process via "os.system"')
def when_os_system_attempted(audit_hook_context: dict) -> None:
    """Record the call type to delegate to the isolated subprocess."""
    audit_hook_context["call_type"] = "os.system"


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then('the audit hook must raise a "PermissionError" before the OS executes the command')
def then_audit_hook_raises_permission_error(audit_hook_context: dict) -> None:
    """Assert the child process exited non-zero with a PermissionError message."""
    call_type = audit_hook_context["call_type"]
    assert call_type is not None, "No call_type was registered in the When step."

    result = _run_blocked_call_in_subprocess(call_type)

    assert result.returncode != 0, (
        f"Expected child process to fail with PermissionError, but it exited 0.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "PermissionError" in result.stderr or "Operation not permitted" in result.stderr, (
        f"Expected PermissionError in stderr.\nstderr: {result.stderr}"
    )


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
