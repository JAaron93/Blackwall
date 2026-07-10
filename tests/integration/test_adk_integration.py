import asyncio
import logging
import threading
import subprocess
import sys
import pytest
from typing import Any, Dict

from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision
from blackwall.interception import InterceptionQueue
from blackwall.adk_integration import ADKIntegration


@pytest.mark.asyncio
async def test_before_tool_callback_suspends_and_resumes_allow() -> None:
    queue = InterceptionQueue()
    loop = asyncio.get_running_loop()
    integration = ADKIntegration(queue, loop)

    tool_name = "execute_terminal"
    arguments = {"command": "echo 'hello'"}
    result_container = {"result": None, "exception": None, "done": False}

    def worker():
        try:
            res = integration.before_tool_callback(
                tool_name=tool_name,
                arguments=arguments,
                thread_id="test-thread-allow",
            )
            result_container["result"] = res
        except Exception as e:
            result_container["exception"] = e
        finally:
            result_container["done"] = True

    t = threading.Thread(target=worker)
    t.start()

    # Wait for the token to be enqueued
    for _ in range(50):
        if queue.size() == 1:
            break
        await asyncio.sleep(0.01)

    assert queue.size() == 1
    assert not result_container["done"]

    # Dequeue the token
    token = await queue.dequeue(timeout_ms=10)
    assert token.tool_context.tool_name == tool_name
    assert token.tool_context.arguments == arguments

    # Resolve with ALLOW verdict
    allow_verdict = Verdict(
        decision=VerdictDecision.ALLOW,
        reasoning="All looks good",
        confidence_score=0.0,
    )
    await queue.resolveCallbacks([allow_verdict], [token])

    t.join(timeout=2)
    assert result_container["done"]
    assert result_container["exception"] is None
    assert result_container["result"] == arguments


@pytest.mark.asyncio
async def test_before_tool_callback_block() -> None:
    queue = InterceptionQueue()
    loop = asyncio.get_running_loop()
    integration = ADKIntegration(queue, loop)

    tool_name = "execute_terminal"
    arguments = {"command": "rm -rf /"}
    result_container = {"result": None, "exception": None, "done": False}

    def worker():
        try:
            res = integration.before_tool_callback(
                tool_name=tool_name,
                arguments=arguments,
                thread_id="test-thread-block",
            )
            result_container["result"] = res
        except Exception as e:
            result_container["exception"] = e
        finally:
            result_container["done"] = True

    t = threading.Thread(target=worker)
    t.start()

    for _ in range(50):
        if queue.size() == 1:
            break
        await asyncio.sleep(0.01)

    token = await queue.dequeue(timeout_ms=10)
    
    block_verdict = Verdict(
        decision=VerdictDecision.BLOCK,
        reasoning="Blocked by policy",
        confidence_score=1.0,
    )
    await queue.resolveCallbacks([block_verdict], [token])

    t.join(timeout=2)
    assert result_container["done"]
    assert isinstance(result_container["exception"], PermissionError)
    assert "blocked by Blackwall" in str(result_container["exception"])


@pytest.mark.asyncio
async def test_before_tool_callback_quarantine() -> None:
    queue = InterceptionQueue()
    loop = asyncio.get_running_loop()
    integration = ADKIntegration(queue, loop)

    tool_name = "execute_terminal"
    arguments = {"command": "curl http://evil.com"}
    result_container = {"result": None, "exception": None, "done": False}

    def worker():
        try:
            res = integration.before_tool_callback(
                tool_name=tool_name,
                arguments=arguments,
                thread_id="test-thread-quarantine",
            )
            result_container["result"] = res
        except Exception as e:
            result_container["exception"] = e
        finally:
            result_container["done"] = True

    t = threading.Thread(target=worker)
    t.start()

    for _ in range(50):
        if queue.size() == 1:
            break
        await asyncio.sleep(0.01)

    token = await queue.dequeue(timeout_ms=10)
    
    quarantine_verdict = Verdict(
        decision=VerdictDecision.QUARANTINE,
        reasoning="Suspicious activity, sandboxing",
        confidence_score=0.8,
    )
    await queue.resolveCallbacks([quarantine_verdict], [token])

    t.join(timeout=2)
    assert result_container["done"]
    assert result_container["exception"] is None
    assert isinstance(result_container["result"], dict)
    assert "stdout" in result_container["result"]
    assert "quarantined/mocked" in result_container["result"]["stdout"]

def test_audit_hook_logs_critical_bypass() -> None:
    code = """
import sys
from blackwall.logging import setup_logging
setup_logging()
try:
    import os
    os.system("echo bypass")
except PermissionError:
    pass
"""
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    output = result.stdout
    err = result.stderr
    assert "Raw execution bypass attempt detected via audit hook" in output or "Raw execution bypass attempt detected via audit hook" in err, f"Bypass log not found. stdout: {output}, stderr: {err}"
    assert "CRITICAL" in output or "error" in output or "CRITICAL" in err or "error" in err
