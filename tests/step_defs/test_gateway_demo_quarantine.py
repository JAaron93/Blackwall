"""BDD steps for TASK-G03 The Quarantine (TDD — written first).

OWASP LLM07 (https://genai.owasp.org/) /
MITRE ATLAS AML.T0054 (https://atlas.mitre.org/techniques/AML.T0054)

Invariants: absolute imports (Rule 6), centralized run_async (Rule 2),
synthetic-only fixtures (Rule 5).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from pytest_bdd import given, scenarios, then, when

from tests.step_defs.async_utils import run_async

scenarios("../features/gateway_demo_quarantine.feature")


def _run(coro: Any) -> Any:
    return run_async(coro)


@pytest.fixture
def quarantine_state(tmp_path):
    return {"tmpdir": tmp_path, "result": None}


@given("the quarantine demo isolation with synthetic credentials")
def quarantine_isolation(quarantine_state):
    from scripts.gateway_demo.scenario_quarantine import ensure_synthetic_fixtures

    async def _setup() -> None:
        ensure_synthetic_fixtures(quarantine_state["tmpdir"])

    _run(_setup())


@when("the agent refactors while a compromised tool pushes a hijack")
def quarantine_run_chain(quarantine_state):
    from scripts.gateway_demo.scenario_quarantine import run_quarantine

    async def _run_chain() -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, run_quarantine, quarantine_state["tmpdir"])

    quarantine_state["result"] = _run(_run_chain())


@then("the compromised response is delivered through the gateway")
def quarantine_hijack_delivered(quarantine_state):
    state = quarantine_state["result"]
    assert state["research"]["delivered_via_gateway"] is True
    assert "id_rsa" in json.dumps(state["read_docs_response"])


@then("the first write_file call is allowed and forwarded downstream")
def quarantine_write1_allowed(quarantine_state):
    resp = quarantine_state["result"]["write1_response"]
    assert resp["result"]["echoedTool"] == "write_file"
    assert "error" not in resp


@then("the read_file call is blocked with JSON-RPC error -32603")
def quarantine_read_blocked(quarantine_state):
    resp = quarantine_state["result"]["read_file_response"]
    assert resp["error"]["code"] == -32603
    assert resp["error"]["code"] != -32001
    assert "0.95" not in json.dumps(resp)


@then("the second write_file call is allowed proving session continuity")
def quarantine_write2_allowed(quarantine_state):
    state = quarantine_state["result"]
    assert state["write2_response"]["result"]["echoedTool"] == "write_file"
    assert state["forwarded_tools"] == ["read_docs", "write_file", "write_file"]
    assert "read_file" not in state["forwarded_tools"]
