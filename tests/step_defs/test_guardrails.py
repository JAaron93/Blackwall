"""
BDD step definitions for Blackwall guardrail scenarios.

Implements pytest-bdd + pytest-asyncio step definitions for end-to-end
security and interception tests, as mandated by AGENTS.md §7.
"""
import os
import subprocess

import pytest
import structlog
from pytest_bdd import given, scenario, then, when

from blackwall.logging import setup_logging

# ---------------------------------------------------------------------------
# Scenarios bound from features/blackwall_guardrails.feature
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
# Shared fixtures used by the steps
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_hook_context() -> dict:
    """Shared mutable context bag for audit-hook scenario steps."""
    return {
        "original_structlog_config": None,
        "attempt_callable": None,
        "raised_exception": None,
    }


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the Blackwall logging pipeline is initialised with the runtime audit hook")
def given_logging_pipeline_initialised(audit_hook_context: dict) -> None:
    """Capture structlog config and run setup_logging to register the audit hook."""
    audit_hook_context["original_structlog_config"] = structlog.get_config()
    setup_logging()


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when('an adversarial agent attempts to spawn a process via "subprocess.Popen"')
def when_subprocess_popen_attempted(audit_hook_context: dict) -> None:
    """Record subprocess.Popen as the callable to exercise in the Then step."""
    audit_hook_context["attempt_callable"] = lambda: subprocess.Popen(  # noqa: S603,S607
        ["echo", "hello"]
    )


@when('an adversarial agent attempts to spawn a process via "os.system"')
def when_os_system_attempted(audit_hook_context: dict) -> None:
    """Record os.system as the callable to exercise in the Then step."""
    audit_hook_context["attempt_callable"] = lambda: os.system("echo hello")  # noqa: S605,S607


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then('the audit hook must raise a "PermissionError" before the OS executes the command')
def then_audit_hook_raises_permission_error(audit_hook_context: dict) -> None:
    """Assert the registered audit hook blocks the execution with PermissionError."""
    attempt = audit_hook_context["attempt_callable"]
    assert attempt is not None, "No callable was registered in the When step."
    with pytest.raises(PermissionError, match="Operation not permitted"):
        attempt()


@then("the structlog configuration must be restored to its original state")
def then_structlog_config_restored(audit_hook_context: dict) -> None:
    """Restore structlog to its pre-test configuration."""
    original = audit_hook_context["original_structlog_config"]
    if original is not None:
        structlog.configure(
            processors=original.get("processors"),
            wrapper_class=original.get("wrapper_class"),
            context_class=original.get("context_class"),
            logger_factory=original.get("logger_factory"),
            cache_logger_on_first_use=original.get("cache_logger_on_first_use"),
        )
