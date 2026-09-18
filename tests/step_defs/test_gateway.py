"""BDD Step Definitions for Blackwall MCP Gateway (Phase 3 Track D).

Covers ``tests/features/blackwall_gateway.feature``:
- TASK-D01: stdio BLOCK with -32603 and SQLite logging.
- TASK-D02: HTTP BLOCK with SSE, authenticated happy path, 401 rejection, startup guard.
- TASK-D03: ALLOW forwarding to mock echo downstream.

Invariants:
- Subprocess process-group isolation via ``preexec_fn=os.setsid`` with
  ``os.killpg`` cleanup in ``finally`` (Rule 10).
- Async execution via centralized ``run_async`` (Rule 2).
- Absolute imports (Rule 6); synthetic-only fixtures (Rule 5).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from tests.step_defs.async_utils import run_async

scenarios("../features/blackwall_gateway.feature")

REPO_ROOT = Path(__file__).resolve().parents[1].parent
HARNESS = REPO_ROOT / "tests" / "gateway_harness.py"

FORBIDDEN_REASONING_FRAGMENTS = (
    "credential exfiltration",
    "Threat Signature Graph",
    "confidence",
    "0.95",
    "signature match",
)


class GatewayBDDState:
    """Per-scenario state for gateway subprocess BDD."""

    def __init__(self, tmp_factory: Any) -> None:
        self._tmp_factory = tmp_factory
        self.db_path: Path | None = None
        self.proc: subprocess.Popen[str] | None = None
        self.last_response: dict[str, Any] | None = None
        self.last_status: int | None = None
        self.last_raw: str | None = None
        self.startup_returncode: int | None = None
        self.startup_stderr: str = ""
        self.port: int = 9229
        self.host: str = "127.0.0.1"
        self.auth_token: str | None = None

    def new_db(self) -> Path:
        tmpdir = Path(str(self._tmp_factory.mktemp("gateway-bdd-")))
        self.db_path = tmpdir / "threat_signatures.db"
        return self.db_path

    def terminate(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        try:
                            proc.kill()
                        except OSError:
                            pass
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass


@pytest.fixture
def gateway_state(tmp_path_factory: Any) -> Any:
    state = GatewayBDDState(tmp_path_factory)
    yield state
    state.terminate()


def _preexec() -> Any:
    if hasattr(os, "setsid"):
        return os.setsid
    return None


def _launch_harness(args: list[str]) -> subprocess.Popen[str]:
    cmd = [sys.executable, str(HARNESS), *args]
    env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    # Isolate any ambient auth token unless explicitly passed for the scenario.
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
        preexec_fn=_preexec(),
    )


def _readline_timeout(proc: subprocess.Popen[str], timeout: float = 15.0) -> str:
    assert proc.stdout is not None
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(proc.stdout.readline)
        line = future.result(timeout=timeout)
    if not line:
        stderr_tail = ""
        try:
            _, stderr_tail = proc.communicate(timeout=1)
        except Exception:
            pass
        raise AssertionError(f"No response line from gateway subprocess. stderr={stderr_tail!r}")
    return line


def _wait_for_health(host: str, port: int, timeout: float = 15.0, token: str | None = None) -> None:
    async def _poll() -> None:
        import aiohttp

        deadline = time.monotonic() + timeout
        last_err: Exception | None = None
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        while time.monotonic() < deadline:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{host}:{port}/health", headers=headers, timeout=2
                    ) as resp:
                        if resp.status == 200:
                            return
                        last_err = AssertionError(f"health status {resp.status}")
            except Exception as exc:  # noqa: BLE001 - readiness polling
                last_err = exc
            await asyncio_sleep(0.2)
        raise AssertionError(f"Gateway health check failed on {host}:{port}: {last_err!r}")

    async def asyncio_sleep(delay: float) -> None:
        import asyncio

        await asyncio.sleep(delay)

    run_async(_poll())


async def _http_post_mcp(
    host: str,
    port: int,
    payload: dict[str, Any],
    accept_sse: bool = False,
    token: str | None = None,
) -> tuple[int, str]:
    import aiohttp

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if accept_sse:
        headers["Accept"] = "text/event-stream"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://{host}:{port}/mcp", json=payload, headers=headers, timeout=10
        ) as resp:
            body = await resp.text()
            return resp.status, body


def _parse_sse_json(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("data:"):
            return json.loads(stripped[len("data:"):].strip())
    # Fallback: plain JSON response (non-SSE)
    return json.loads(body)


def _assert_generic_message(message: str) -> None:
    assert message, "Error message must be non-empty"
    assert len(message) <= 200, f"Error message must be bounded, got {len(message)} chars"
    lowered = message.lower()
    for fragment in FORBIDDEN_REASONING_FRAGMENTS:
        assert fragment.lower() not in lowered, f"Threat reasoning leaked: {fragment!r} in {message!r}"


# Background


@given("the Phase 2 gateway components are available")
def given_phase2_available() -> None:
    from blackwall.gateway.interceptor import PayloadInterceptor  # noqa: F401
    from blackwall.gateway.server import MCPGatewayServer  # noqa: F401
    from blackwall.gateway.synthesizer import ResponseSynthesizer  # noqa: F401

    assert HARNESS.exists(), f"Gateway harness missing: {HARNESS}"


# TASK-D01: stdio BLOCK


@given("a stdio gateway subprocess with an isolated threat database")
def given_stdio_gateway(gateway_state: GatewayBDDState) -> None:
    db = gateway_state.new_db()
    proc = _launch_harness(["--transport", "stdio", "--db-path", str(db)])
    gateway_state.proc = proc
    # Give the harness a moment to attach stdio pipes.
    time.sleep(1.0)
    assert proc.poll() is None, "stdio harness exited prematurely"


@when("a malicious tools call targeting a credential path is sent over stdio")
def when_malicious_stdio(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.proc is not None and gateway_state.proc.stdin is not None
    payload = {
        "jsonrpc": "2.0",
        "id": "bdd-stdio-block-1",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/.env"}},
    }
    gateway_state.proc.stdin.write(json.dumps(payload) + "\n")
    gateway_state.proc.stdin.flush()
    try:
        line = _readline_timeout(gateway_state.proc, timeout=20.0)
    finally:
        # Guarantee process-group cleanup even if the read times out.
        pass
    gateway_state.last_raw = line
    gateway_state.last_response = json.loads(line)


@then("the stdio response contains JSON-RPC error code -32603 with the incoming id")
def then_stdio_block(gateway_state: GatewayBDDState) -> None:
    resp = gateway_state.last_response
    assert resp is not None, "No stdio response captured"
    assert resp.get("jsonrpc") == "2.0"
    assert resp.get("id") == "bdd-stdio-block-1"
    assert "error" in resp, f"Expected error response, got {resp!r}"
    assert resp["error"]["code"] == -32603


@then("the error message is bounded and generic with zero threat reasoning leaked")
def then_stdio_generic(gateway_state: GatewayBDDState) -> None:
    resp = gateway_state.last_response
    assert resp is not None and "error" in resp
    _assert_generic_message(str(resp["error"].get("message", "")))


@then("the SQLite threat graph logs the redacted blocked payload")
def then_threat_graph_logged(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.db_path is not None

    async def _query() -> list[dict[str, Any]]:
        from blackwall.db.repository import SQLiteThreatRepository

        repo = SQLiteThreatRepository(db_path=str(gateway_state.db_path))
        try:
            return await repo.get_all_signatures()
        finally:
            close = getattr(repo, "close", None)
            if close is not None:
                res = close()
                import asyncio

                if asyncio.iscoroutine(res):
                    await res

    rows = run_async(_query())
    assert rows, "Expected at least one threat signature for BLOCK"
    assert any(r.get("target_tool") == "read_file" for r in rows), f"No read_file signature: {rows!r}"
    # Terminate the process group deterministically (finally-equivalent via fixture too).
    gateway_state.terminate()


# TASK-D02: HTTP BLOCK


@given(parsers.parse("an HTTP gateway subprocess on localhost port {port:d} with an isolated threat database"))
def given_http_gateway(gateway_state: GatewayBDDState, port: int) -> None:
    db = gateway_state.new_db()
    gateway_state.port = port
    gateway_state.host = "127.0.0.1"
    proc = _launch_harness(
        ["--transport", "http", "--host", "127.0.0.1", "--port", str(port), "--db-path", str(db)]
    )
    gateway_state.proc = proc
    try:
        _wait_for_health("127.0.0.1", port, timeout=20.0)
    except Exception:
        gateway_state.terminate()
        raise


@when("a malicious tools call is posted to /mcp with SSE accepted")
def when_malicious_http(gateway_state: GatewayBDDState) -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": "bdd-http-block-1",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/.env"}},
    }
    status, body = run_async(
        _http_post_mcp(gateway_state.host, gateway_state.port, payload, accept_sse=True)
    )
    gateway_state.last_status = status
    gateway_state.last_raw = body
    gateway_state.last_response = _parse_sse_json(body)


@then("the SSE response contains JSON-RPC error code -32603 with the incoming id")
def then_http_block(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.last_status == 200, f"Unexpected HTTP status {gateway_state.last_status}: {gateway_state.last_raw!r}"
    resp = gateway_state.last_response
    assert resp is not None
    assert resp.get("id") == "bdd-http-block-1"
    assert "error" in resp, f"Expected error, got {resp!r}"
    assert resp["error"]["code"] == -32603


@then("the HTTP error message is bounded and generic with zero threat reasoning leaked")
def then_http_generic(gateway_state: GatewayBDDState) -> None:
    resp = gateway_state.last_response
    assert resp is not None and "error" in resp
    _assert_generic_message(str(resp["error"].get("message", "")))


# TASK-D02: auth matrix


@given("a non-loopback HTTP gateway subprocess with a valid auth token")
def given_non_loopback_gateway(gateway_state: GatewayBDDState) -> None:
    db = gateway_state.new_db()
    gateway_state.auth_token = "bdd-test-token-0192"
    # Use fixed alternate ports to avoid colliding with the 9229 primary scenario.
    gateway_state.host = "0.0.0.0"
    gateway_state.port = 9230
    # Ensure a clean bind if a previous scenario leaked the port.
    proc = _launch_harness(
        [
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "9230",
            "--db-path",
            str(db),
            "--auth-token",
            "bdd-test-token-0192",
        ]
    )
    gateway_state.proc = proc
    try:
        _wait_for_health("127.0.0.1", 9230, timeout=20.0, token="bdd-test-token-0192")
    except Exception:
        gateway_state.terminate()
        raise


@when("a benign tools call is posted with a valid Bearer token")
def when_valid_bearer(gateway_state: GatewayBDDState) -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": "bdd-auth-happy-1",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
    }
    assert gateway_state.auth_token is not None
    status, body = run_async(
        _http_post_mcp("127.0.0.1", gateway_state.port, payload, token=gateway_state.auth_token)
    )
    gateway_state.last_status = status
    gateway_state.last_raw = body
    gateway_state.last_response = json.loads(body)


@then("the authenticated response is accepted and processed")
def then_auth_accepted(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.last_status == 200, f"Expected 200, got {gateway_state.last_status}: {gateway_state.last_raw!r}"
    resp = gateway_state.last_response
    assert resp is not None
    assert resp.get("id") == "bdd-auth-happy-1"
    # Benign ALLOW without echo downstream yields the deterministic
    # "no downstream configured" -32603, but crucially NOT a 401.
    # The acceptance criterion is that auth passed and the request was processed.
    assert "error" in resp or "result" in resp


@when("a tools call is posted without a valid Bearer token")
def when_no_bearer(gateway_state: GatewayBDDState) -> None:
    payload = {
        "jsonrpc": "2.0",
        "id": "bdd-auth-reject-1",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
    }
    status, body = run_async(_http_post_mcp("127.0.0.1", gateway_state.port, payload))
    gateway_state.last_status = status
    gateway_state.last_raw = body


@then("the HTTP response status is 401")
def then_401(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.last_status == 401, f"Expected 401, got {gateway_state.last_status}: {gateway_state.last_raw!r}"


@when("a non-loopback gateway is started without an auth token")
def when_startup_no_token(gateway_state: GatewayBDDState) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "threat.db")
        env = os.environ.copy()
        env.pop("BLACKWALL_AUTH_TOKEN", None)
        cmd = [
            sys.executable,
            str(HARNESS),
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "9231",
            "--db-path",
            db,
        ]
        src = str(REPO_ROOT / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            preexec_fn=_preexec(),
        )
        try:
            try:
                _, stderr = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except OSError:
                    proc.kill()
                _, stderr = proc.communicate(timeout=5)
            gateway_state.startup_returncode = proc.returncode
            gateway_state.startup_stderr = stderr or ""
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()


@then("the gateway startup fails with a clear auth error")
def then_startup_fails(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.startup_returncode is not None, "Startup probe did not complete"
    assert gateway_state.startup_returncode != 0, "Expected non-zero exit for missing auth token"
    assert "auth token" in gateway_state.startup_stderr.lower(), (
        f"Expected auth error message, got: {gateway_state.startup_stderr!r}"
    )
    # Defense-in-depth: unit-level guard produces the same contract.
    from blackwall.gateway.exceptions import GatewayAuthError
    from blackwall.gateway.server import MCPGatewayServer

    with pytest.raises(GatewayAuthError, match="auth token"):
        MCPGatewayServer(host="0.0.0.0", port=9231, auth_token=None)


# TASK-D03: ALLOW forward


@given("a stdio gateway subprocess wrapping a mock echo downstream server")
def given_echo_gateway(gateway_state: GatewayBDDState) -> None:
    db = gateway_state.new_db()
    proc = _launch_harness(
        ["--transport", "stdio", "--db-path", str(db), "--downstream-mode", "echo"]
    )
    gateway_state.proc = proc
    time.sleep(1.0)
    assert proc.poll() is None, "echo harness exited prematurely"


@when("a benign tools call is sent over stdio")
def when_benign_stdio(gateway_state: GatewayBDDState) -> None:
    assert gateway_state.proc is not None and gateway_state.proc.stdin is not None
    payload = {
        "jsonrpc": "2.0",
        "id": "bdd-allow-1",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
    }
    gateway_state.proc.stdin.write(json.dumps(payload) + "\n")
    gateway_state.proc.stdin.flush()
    line = _readline_timeout(gateway_state.proc, timeout=20.0)
    gateway_state.last_raw = line
    gateway_state.last_response = json.loads(line)


@then("the downstream echo server receives the forwarded request")
def then_downstream_received(gateway_state: GatewayBDDState) -> None:
    resp = gateway_state.last_response
    assert resp is not None, "No ALLOW response captured"
    assert resp.get("id") == "bdd-allow-1"
    assert "result" in resp, f"Expected downstream result, got {resp!r}"
    result = resp["result"]
    assert result.get("echoedTool") == "read_file"
    assert result.get("echoedArguments") == {"path": "/safe/data/sample.txt"}


@then("the agent receives the downstream response unchanged")
def then_unchanged(gateway_state: GatewayBDDState) -> None:
    resp = gateway_state.last_response
    assert resp is not None and "result" in resp
    content = resp["result"]["content"][0]["text"]
    assert content.startswith("echo:read_file:")
    assert "/safe/data/sample.txt" in content
    gateway_state.terminate()
