"""
Unit tests for Upstream Tool Server Manager (TASK-C02).

Validates:
- StdioUpstreamServer child process lifecycle (spawning, JSON-RPC streaming, SIGTERM cleanup).
- HttpUpstreamServer connection pooling and request forwarding.
- UpstreamManager in --wrap mode.
- UpstreamManager in multi-server gateway.yaml mode (discovery, routing, aggregation).
- Error handling (UpstreamServerNotFoundError, UpstreamProcessError, UpstreamTimeoutError, InvalidGatewayConfigError).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

from blackwall.gateway.exceptions import (
    InvalidGatewayConfigError,
    UpstreamProcessError,
    UpstreamServerNotFoundError,
    UpstreamTimeoutError,
)
from blackwall.gateway.upstream import (
    HttpUpstreamServer,
    StdioUpstreamServer,
    UpstreamManager,
)


ECHO_STDIO_SCRIPT = """
import sys, json

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
        method = req.get("method")
        req_id = req.get("id")
        
        if method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {"name": "echo_tool", "description": "Echoes input"}
                    ]
                }
            }
        elif method == "tools/call":
            params = req.get("params", {})
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Echo: {params.get('arguments', {})}"}]
                }
            }
        elif method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "echo-stdio", "version": "1.0.0"}
                }
            }
        elif method.startswith("notifications/"):
            continue
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}

        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    except Exception as exc:
        sys.stderr.write(f"Err: {exc}\\n")
        sys.stderr.flush()
"""


HANG_STDIO_SCRIPT = """
import sys, time
for line in sys.stdin:
    # Intentionally hang and never respond
    time.sleep(3600)
"""


@pytest.fixture
def echo_script(tmp_path: Path) -> Path:
    """Writes the echo stdio script to a file."""
    script = tmp_path / "echo_server.py"
    script.write_text(ECHO_STDIO_SCRIPT)
    return script


@pytest.fixture
def hang_script(tmp_path: Path) -> Path:
    """Writes the hanging stdio script to a file."""
    script = tmp_path / "hang_server.py"
    script.write_text(HANG_STDIO_SCRIPT)
    return script


class TestStdioUpstreamServer:
    """Unit tests for StdioUpstreamServer."""

    @pytest.mark.asyncio
    async def test_stdio_spawn_and_request(self, echo_script: Path) -> None:
        """Starts a child stdio process, forwards request, and validates response."""
        cmd = f"{sys.executable} -u {echo_script}"
        server = StdioUpstreamServer(name="echo-test", command=cmd)

        try:
            await server.start()
            assert await server.is_healthy() is True

            # Test tools/list
            list_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            resp = await server.send_request(list_req, timeout=5.0)
            assert resp["id"] == 1
            assert resp["result"]["tools"][0]["name"] == "echo_tool"

            # Test tools/call
            call_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "echo_tool", "arguments": {"msg": "hello"}},
            }
            call_resp = await server.send_request(call_req, timeout=5.0)
            assert call_resp["id"] == 2
            assert "Echo: {'msg': 'hello'}" in call_resp["result"]["content"][0]["text"]
        finally:
            await server.stop()

        assert await server.is_healthy() is False

    @pytest.mark.asyncio
    async def test_stdio_graceful_sigterm_cleanup(self, echo_script: Path) -> None:
        """Verifies child process and process group are killed on stop (Rule 10)."""
        cmd = f"{sys.executable} -u {echo_script}"
        server = StdioUpstreamServer(name="cleanup-test", command=cmd)

        await server.start()
        pid = server.pid
        assert pid is not None

        # Terminate server
        await server.stop()

        # Check process is terminated
        with pytest.raises((ProcessLookupError, OSError)):
            os.kill(pid, 0)

    @pytest.mark.asyncio
    async def test_stdio_timeout_handling(self, hang_script: Path) -> None:
        """Verifies that a hanging upstream server raises UpstreamTimeoutError."""
        cmd = f"{sys.executable} -u {hang_script}"
        server = StdioUpstreamServer(name="hang-test", command=cmd)

        try:
            await server.start()
            req = {
                "jsonrpc": "2.0",
                "id": "hang-1",
                "method": "tools/call",
                "params": {"name": "hang"},
            }
            with pytest.raises(UpstreamTimeoutError):
                await server.send_request(req, timeout=0.2)
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_stdio_abrupt_exit_fails_in_flight_requests_immediately(
        self, tmp_path: Path
    ) -> None:
        """When downstream process exits abruptly, in-flight requests fail with UpstreamProcessError immediately."""
        crash_script = tmp_path / "crash_server.py"
        crash_script.write_text(
            "import sys, time\n"
            "line = sys.stdin.readline()\n"
            "time.sleep(0.05)\n"
            "sys.exit(1)\n"
        )
        cmd = f"{sys.executable} -u {crash_script}"
        server = StdioUpstreamServer(name="crash-test", command=cmd)

        try:
            await server.start()
            req = {
                "jsonrpc": "2.0",
                "id": "crash-1",
                "method": "tools/call",
                "params": {"name": "test"},
            }
            # Timeout is 5s, but process dies in 50ms. Must fail fast without waiting 5s.
            with pytest.raises(UpstreamProcessError):
                await server.send_request(req, timeout=5.0)
        finally:
            await server.stop()


class TestHttpUpstreamServer:
    """Unit tests for HttpUpstreamServer."""

    @pytest.mark.asyncio
    async def test_http_request_forwarding(self) -> None:
        """Verifies HTTP POST forwarding to an HTTP MCP server with connection pooling."""
        from aiohttp import web

        async def mcp_handler(request: web.Request) -> web.Response:
            data = await request.json()
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {"status": "http-ok", "params": data.get("params")},
                }
            )

        app = web.Application()
        app.router.add_post("/mcp", mcp_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()

        # Get dynamically assigned port
        sockets = site._server.sockets  # type: ignore[union-attr]
        port = sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"

        server = HttpUpstreamServer(name="http-mock", url=url)
        try:
            await server.start()
            req = {
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {"name": "remote_tool", "arguments": {"x": 1}},
            }
            resp = await server.send_request(req, timeout=5.0)
            assert resp["id"] == 100
            assert resp["result"]["status"] == "http-ok"
        finally:
            await server.stop()
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_http_connection_failure_raises_upstream_error(self) -> None:
        """Verifies connection failure to an unreachable HTTP endpoint raises UpstreamProcessError."""
        server = HttpUpstreamServer(name="unreachable", url="http://127.0.0.1:59999/mcp")
        try:
            await server.start()
            req = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
            with pytest.raises(UpstreamProcessError):
                await server.send_request(req, timeout=1.0)
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_http_invalid_json_raises_upstream_process_error(self) -> None:
        """Verifies HTTP server returning 200 with invalid JSON body raises UpstreamProcessError."""
        from aiohttp import web

        async def bad_json_handler(request: web.Request) -> web.Response:
            return web.Response(text="Non-JSON raw HTML or error payload", status=200, content_type="text/plain")

        app = web.Application()
        app.router.add_post("/mcp", bad_json_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()

        sockets = site._server.sockets  # type: ignore[union-attr]
        port = sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/mcp"

        server = HttpUpstreamServer(name="http-bad-json", url=url)
        try:
            await server.start()
            req = {"jsonrpc": "2.0", "id": 55, "method": "tools/call", "params": {"name": "foo"}}
            with pytest.raises(UpstreamProcessError):
                await server.send_request(req, timeout=2.0)
        finally:
            await server.stop()
            await runner.cleanup()


class TestUpstreamManager:
    """Unit tests for UpstreamManager."""

    @pytest.mark.asyncio
    async def test_wrap_mode(self, echo_script: Path) -> None:
        """Validates UpstreamManager in --wrap mode wrapping a single stdio server."""
        cmd = f"{sys.executable} -u {echo_script}"
        manager = UpstreamManager(wrap_command=cmd)

        try:
            await manager.start()

            # Verify tool discovery on wrapped server
            tools_resp = await manager.handle_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            )
            assert tools_resp["id"] == 1
            tools = tools_resp["result"]["tools"]
            assert len(tools) == 1
            assert tools[0]["name"] == "echo_tool"

            # Verify tools/call execution
            call_resp = await manager.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "echo_tool", "arguments": {"key": "val"}},
                }
            )
            assert call_resp["id"] == 2
            assert "Echo: {'key': 'val'}" in call_resp["result"]["content"][0]["text"]
        finally:
            await manager.stop()

    @pytest.mark.asyncio
    async def test_multi_server_yaml_mode(self, tmp_path: Path) -> None:
        """Validates multi-server routing and tool aggregation from gateway.yaml."""
        server1_file = tmp_path / "server1.py"
        server1_file.write_text("""import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m = req.get("method")
    rid = req.get("id")
    if m == "tools/list":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "tool_server1"}]}}) + "\\n")
    elif m == "tools/call":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"server": "s1"}}) + "\\n")
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}}) + "\\n")
    sys.stdout.flush()
""")

        server2_file = tmp_path / "server2.py"
        server2_file.write_text("""import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m = req.get("method")
    rid = req.get("id")
    if m == "tools/list":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "tool_server2"}]}}) + "\\n")
    elif m == "tools/call":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"server": "s2"}}) + "\\n")
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}}) + "\\n")
    sys.stdout.flush()
""")

        s1_cmd = f"{sys.executable} -u {server1_file}"
        s2_cmd = f"{sys.executable} -u {server2_file}"

        config = {
            "upstream_servers": [
                {"name": "server1", "command": s1_cmd, "transport": "stdio"},
                {"name": "server2", "command": s2_cmd, "transport": "stdio"},
            ]
        }
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(yaml.safe_dump(config))

        manager = UpstreamManager(config_path=str(config_file))
        try:
            await manager.start()

            # 1. Verify tools/list aggregates both tools
            list_resp = await manager.handle_request(
                {"jsonrpc": "2.0", "id": "list-all", "method": "tools/list", "params": {}}
            )
            assert list_resp["id"] == "list-all"
            tools = list_resp["result"]["tools"]
            tool_names = [t["name"] for t in tools]
            assert "tool_server1" in tool_names
            assert "tool_server2" in tool_names

            # 2. Call tool_server1 -> routes to server1
            resp1 = await manager.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": "c1",
                    "method": "tools/call",
                    "params": {"name": "tool_server1", "arguments": {}},
                }
            )
            assert resp1["id"] == "c1"
            assert resp1["result"]["server"] == "s1"

            # 3. Call tool_server2 -> routes to server2
            resp2 = await manager.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": "c2",
                    "method": "tools/call",
                    "params": {"name": "tool_server2", "arguments": {}},
                }
            )
            assert resp2["id"] == "c2"
            assert resp2["result"]["server"] == "s2"

            # 4. Call unknown tool -> raises UpstreamServerNotFoundError
            with pytest.raises(UpstreamServerNotFoundError):
                await manager.handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": "c3",
                        "method": "tools/call",
                        "params": {"name": "nonexistent_tool", "arguments": {}},
                    }
                )
        finally:
            await manager.stop()

    def test_invalid_config_raises_error(self, tmp_path: Path) -> None:
        """Invalid YAML or missing required keys raises InvalidGatewayConfigError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("invalid_key: true\n")

        with pytest.raises(InvalidGatewayConfigError):
            UpstreamManager(config_path=str(bad_file))

    @pytest.mark.asyncio
    async def test_multi_server_null_result_coalescing(self, tmp_path: Path) -> None:
        """Verifies discover_tools and handle_request gracefully handle explicit null result/params (Rule 86)."""
        null_server_file = tmp_path / "null_server.py"
        null_server_file.write_text("""import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    m = req.get("method")
    if m == "tools/list":
        # Server returns explicit null result (e.g. standard JSON-RPC error or null response)
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": None, "error": {"code": -32601, "message": "unsupported"}}) + "\\n")
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}}) + "\\n")
    sys.stdout.flush()
""")
        cmd = f"{sys.executable} -u {null_server_file}"
        config = {
            "upstream_servers": [
                {"name": "null_server", "command": cmd, "transport": "stdio"},
            ]
        }
        config_file = tmp_path / "gateway.yaml"
        config_file.write_text(yaml.safe_dump(config))

        manager = UpstreamManager(config_path=str(config_file))
        try:
            # discover_tools must not raise AttributeError when result is null
            await manager.start()
            assert manager.servers[0].tools == []

            # handle_request with null params must raise ValueError rather than AttributeError
            with pytest.raises(ValueError, match="Missing 'name' in tools/call params"):
                await manager.handle_request(
                    {"jsonrpc": "2.0", "id": "null-param-1", "method": "tools/call", "params": None}
                )
        finally:
            await manager.stop()
