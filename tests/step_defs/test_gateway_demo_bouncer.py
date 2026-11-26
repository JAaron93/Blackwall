"""BDD steps for TASK-G05 The Bouncer (TDD — written first).

OWASP LLM01 (https://genai.owasp.org/) /
MITRE ATLAS AML.T0051 (https://atlas.mitre.org/techniques/AML.T0051)

Invariants: absolute imports (Rule 6), centralized run_async (Rule 2),
synthetic-only fixtures (Rule 5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, scenarios, then, when

from tests.step_defs.async_utils import run_async

scenarios("../features/gateway_demo_bouncer.feature")


def _run(coro: Any) -> Any:
    return run_async(coro)


@pytest.fixture
def bouncer_state(tmp_path: Path) -> dict[str, Any]:
    return {
        "tmpdir": tmp_path,
        "result": None,
        "act1_done": False,
        "act2_done": False,
        "act3_done": False,
    }


@given("the bouncer demo isolation with synthetic credentials")
def bouncer_isolation(bouncer_state: dict[str, Any]) -> None:
    from scripts.gateway_demo.scenario_bouncer import ensure_synthetic_fixtures

    async def _setup() -> None:
        ensure_synthetic_fixtures(bouncer_state["tmpdir"])

    _run(_setup())


# ---------------------------------------------------------------------------
# Act 1 — benign database_query
# ---------------------------------------------------------------------------


@when("the agent issues a benign database_query through the gateway")
def bouncer_act1_run(bouncer_state: dict[str, Any]) -> None:
    from scripts.gateway_demo.scenario_bouncer import run_bouncer

    async def _run_it() -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, run_bouncer, bouncer_state["tmpdir"]
        )

    bouncer_state["result"] = _run(_run_it())
    bouncer_state["act1_done"] = True


@then("the gateway returns ALLOW via the Tier-1 Jev fast path")
def bouncer_act1_allow(bouncer_state: dict[str, Any]) -> None:
    act1 = bouncer_state["result"]["act1"]
    assert act1["verdict"] == "ALLOW"
    assert "error" not in act1["gateway_response"]
    assert act1["backend"] == "jev"


@then("no Tier-2 escalation is triggered after the benign query")
def bouncer_act1_no_tier2(bouncer_state: dict[str, Any]) -> None:
    assert bouncer_state["result"]["tier2_calls_after_act1"] == 0


# ---------------------------------------------------------------------------
# Act 2 — SQL-injection via execute_bash (clear-high BLOCK)
# ---------------------------------------------------------------------------


@when("the agent issues an execute_bash SQL-injection payload through the gateway")
def bouncer_act2_run(bouncer_state: dict[str, Any]) -> None:
    if not bouncer_state["act1_done"]:
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        async def _run_it() -> Any:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, run_bouncer, bouncer_state["tmpdir"]
            )

        bouncer_state["result"] = _run(_run_it())
        bouncer_state["act1_done"] = True
    bouncer_state["act2_done"] = True


@then("the gateway returns BLOCK via the Tier-1 Jev clear-high path")
def bouncer_act2_block(bouncer_state: dict[str, Any]) -> None:
    act2 = bouncer_state["result"]["act2"]
    assert act2["verdict"] == "BLOCK"
    assert act2["gateway_response"]["error"]["code"] == -32603
    assert act2["backend"] == "jev"
    assert act2["tier2_invoked"] is False


@then("no Tier-2 escalation is triggered after the SQL-injection block")
def bouncer_act2_no_tier2(bouncer_state: dict[str, Any]) -> None:
    assert bouncer_state["result"]["tier2_calls_after_act2"] == 0


# ---------------------------------------------------------------------------
# Act 3 — C2 beacon in ambiguity band → Tier-2 escalation
# ---------------------------------------------------------------------------


@when("the agent issues an http_request C2 beacon in the Jev ambiguity band")
def bouncer_act3_run(bouncer_state: dict[str, Any]) -> None:
    if not bouncer_state["act1_done"]:
        from scripts.gateway_demo.scenario_bouncer import run_bouncer

        async def _run_it() -> Any:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, run_bouncer, bouncer_state["tmpdir"]
            )

        bouncer_state["result"] = _run(_run_it())
        bouncer_state["act1_done"] = True
    bouncer_state["act3_done"] = True


@then("the gateway escalates the call to Tier-2 Gemini deep reasoning")
def bouncer_act3_escalated(bouncer_state: dict[str, Any]) -> None:
    act3 = bouncer_state["result"]["act3"]
    assert act3["tier2_invoked"] is True
    assert bouncer_state["result"]["tier2_calls_after_act3"] == 1


@then("the Tier-2 verdict is BLOCK")
def bouncer_act3_tier2_block(bouncer_state: dict[str, Any]) -> None:
    act3 = bouncer_state["result"]["act3"]
    assert act3["verdict"] == "BLOCK"
    assert act3["gateway_response"]["error"]["code"] == -32603
    assert act3["backend"] == "gemini-tier-2"


@then("a TSG threat signature is persisted after the Tier-2 block")
def bouncer_act3_signature_persisted(bouncer_state: dict[str, Any]) -> None:
    assert bouncer_state["result"]["persisted_signature_count"] >= 1
