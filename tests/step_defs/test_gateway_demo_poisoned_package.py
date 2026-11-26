"""BDD steps for TASK-G04 The Poisoned Package (TDD — written first).

OWASP LLM05 (https://genai.owasp.org/) /
MITRE ATLAS AML.T0049 (https://atlas.mitre.org/techniques/AML.T0049)

Invariants: absolute imports (Rule 6), centralized run_async (Rule 2),
audit hook isolation in child subprocess (Rule 4), synthetic-only fixtures (Rule 5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, scenarios, then, when

from tests.step_defs.async_utils import run_async

scenarios("../features/gateway_demo_poisoned_package.feature")


def _run(coro: Any) -> Any:
    return run_async(coro)


@pytest.fixture
def poisoned_pkg_state(tmp_path: Path) -> dict[str, Any]:
    from blackwall.audit import manager as audit_manager_mod

    return {
        "tmpdir": tmp_path,
        "result": None,
        "before_hook_registered": audit_manager_mod._hook_registered,
        "before_active_managers": list(audit_manager_mod._active_managers),
    }


@given("the poisoned package demo isolation with synthetic credentials and mock package")
def poisoned_pkg_isolation(poisoned_pkg_state: dict[str, Any]) -> None:
    from scripts.gateway_demo.scenario_poisoned_package import ensure_synthetic_fixtures

    async def _setup() -> None:
        ensure_synthetic_fixtures(poisoned_pkg_state["tmpdir"])

    _run(_setup())


@when(
    "the agent installs the poisoned package through the gateway and the postinstall "
    "executes in an isolated audited child subprocess"
)
def poisoned_pkg_run_chain(poisoned_pkg_state: dict[str, Any]) -> None:
    from blackwall.audit import manager as audit_manager_mod
    from scripts.gateway_demo.scenario_poisoned_package import run_poisoned_package

    poisoned_pkg_state["before_hook_registered"] = audit_manager_mod._hook_registered
    poisoned_pkg_state["before_active_managers"] = list(
        audit_manager_mod._active_managers
    )

    async def _run_chain() -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, run_poisoned_package, poisoned_pkg_state["tmpdir"]
        )

    poisoned_pkg_state["result"] = _run(_run_chain())


@then("the run_command call is allowed by the MCP gateway")
def poisoned_pkg_gateway_allowed(poisoned_pkg_state: dict[str, Any]) -> None:
    resp = poisoned_pkg_state["result"]["run_command_response"]
    assert "error" not in resp
    assert resp["result"]["echoedTool"] == "run_command"


@then(
    "the Python audit hook blocks subprocess.Popen, os.system, and socket.connect independently"
)
def poisoned_pkg_audit_blocks_all_three(poisoned_pkg_state: dict[str, Any]) -> None:
    state = poisoned_pkg_state["result"]
    assert state["intercepted"] == [
        "subprocess.Popen",
        "os.system",
        "socket.connect",
    ]
    assert state["audit_incident_count"] >= 3


@then("all three runtime escape blocks are recorded in the audit incident database")
def poisoned_pkg_audit_incidents_recorded(poisoned_pkg_state: dict[str, Any]) -> None:
    state = poisoned_pkg_state["result"]
    assert {
        "SUBPROCESS_EXECUTION",
        "SYSTEM_COMMAND_INJECTION",
        "MALICIOUS_IOC_CONNECTION",
    }.issubset(set(state["audit_incident_types"]))


@then("the parent test process audit hook state is unchanged")
def poisoned_pkg_parent_isolated(poisoned_pkg_state: dict[str, Any]) -> None:
    from blackwall.audit import manager as audit_manager_mod

    assert (
        audit_manager_mod._hook_registered
        == poisoned_pkg_state["before_hook_registered"]
    )
    assert (
        list(audit_manager_mod._active_managers)
        == poisoned_pkg_state["before_active_managers"]
    )
