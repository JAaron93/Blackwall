import asyncio
import json
import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, TestClient, TestServer

from blackwall.gateway.exceptions import GatewayAuthError
from blackwall.gateway.flow import FlowController
from blackwall.gateway.interceptor import PayloadInterceptor
from blackwall.gateway.server import MCPGatewayServer
from blackwall.gateway.synthesizer import ResponseSynthesizer
from blackwall.models import ToolCallContext, Verdict, VerdictDecision


class MockResolver:
    """Mock security resolver for testing gateway verdicts."""

    def __init__(self, verdict: Verdict | None = None):
        self.verdict = verdict or Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Mock allowed",
            confidence_score=0.0,
        )

    async def evaluate(self, context: ToolCallContext) -> Verdict:
        return self.verdict


class TestMCPGatewayServerUnit:
    """Unit tests for server configuration, startup guards, and security validation."""

    def test_default_loopback_initialization(self):
        server = MCPGatewayServer()
        assert server.host == "127.0.0.1"
        assert server.port == 9229
        assert server.is_loopback is True

    def test_startup_guard_fails_on_non_loopback_without_auth_token(self):
        with pytest.raises(GatewayAuthError) as exc_info:
            MCPGatewayServer(host="0.0.0.0")
        assert "auth token" in str(exc_info.value).lower()

    def test_startup_guard_fails_on_public_ip_without_auth_token(self):
        with pytest.raises(GatewayAuthError):
            MCPGatewayServer(host="192.168.1.100")

    def test_startup_guard_succeeds_on_non_loopback_with_auth_token(self):
        server = MCPGatewayServer(host="0.0.0.0", auth_token="test-token-12345")
        assert server.host == "0.0.0.0"
        assert server.auth_token == "test-token-12345"
        assert server.is_loopback is False

    def test_startup_guard_succeeds_via_env_var(self, monkeypatch):
        monkeypatch.setenv("BLACKWALL_AUTH_TOKEN", "env-secret-token")
        server = MCPGatewayServer(host="0.0.0.0")
        assert server.auth_token == "env-secret-token"


class TestMCPGatewayServerHTTP:
    """HTTP transport and security integration tests using aiohttp TestClient."""

    @pytest.mark.asyncio
    async def test_origin_header_validation_rejects_malicious_origin(self):
        server = MCPGatewayServer(host="127.0.0.1", port=9229)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # Malicious external origin must be rejected with 403
            resp = await client.post(
                "/mcp",
                headers={
                    "Origin": "http://malicious-attacker.com",
                    "Host": "127.0.0.1:9229",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert resp.status == 403
            text = await resp.text()
            assert "Origin" in text
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_host_header_validation_rejects_rebinding_attack(self):
        server = MCPGatewayServer(host="127.0.0.1", port=9229)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # Rebinding Host header must be rejected with 403
            resp = await client.post(
                "/mcp",
                headers={
                    "Host": "attacker-controlled-dns-rebind.com",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert resp.status == 403
            text = await resp.text()
            assert "Host" in text
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_host_header_validation_allows_ipv6_loopback(self):
        server = MCPGatewayServer(host="::1")
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            resp = await client.post(
                "/mcp",
                headers={"Host": "[::1]:9229"},
                json={"jsonrpc": "2.0", "id": "ipv6-1", "method": "ping"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "ipv6-1"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_remote_binding_authentication_matrix(self):
        server = MCPGatewayServer(host="0.0.0.0", auth_token="valid-secret-token")
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # 1. Unauthenticated request without token -> 401
            resp = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert resp.status == 401

            # 2. Invalid token -> 401
            resp = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer wrong-token"},
                json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            )
            assert resp.status == 401

            # 3. Valid token happy path -> 200
            resp = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer valid-secret-token"},
                json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == 3
            assert data["jsonrpc"] == "2.0"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_post_mcp_tools_call_block_verdict(self):
        block_verdict = Verdict(
            decision=VerdictDecision.BLOCK,
            reasoning="Credential exfiltration signature match",
            confidence_score=0.9,
        )
        resolver = MockResolver(verdict=block_verdict)
        server = MCPGatewayServer(resolver=resolver)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            payload = {
                "jsonrpc": "2.0",
                "id": "block-req-1",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/shadow"},
                },
            }
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json=payload,
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "block-req-1"
            assert "error" in data
            assert data["error"]["code"] == -32603
            assert data["error"]["message"] == "Blackwall Firewall: Execution blocked"
            # Invariant: zero threat reasoning leaked
            assert "Credential" not in str(data)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_post_mcp_tools_call_allow_verdict(self):
        allow_verdict = Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Benign query",
            confidence_score=0.99,
        )
        resolver = MockResolver(verdict=allow_verdict)

        received_by_downstream = []

        async def mock_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            received_by_downstream.append(payload)
            return {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {
                    "content": [{"type": "text", "text": "Downstream execution success"}]
                },
            }

        server = MCPGatewayServer(resolver=resolver, downstream_handler=mock_downstream)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            payload = {
                "jsonrpc": "2.0",
                "id": "allow-req-1",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/workspace/README.md"},
                },
            }
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json=payload,
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "allow-req-1"
            assert "result" in data
            assert data["result"]["content"][0]["text"] == "Downstream execution success"
            assert len(received_by_downstream) == 1
            assert received_by_downstream[0]["method"] == "tools/call"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_tools_list_forwarded_to_downstream(self):
        async def mock_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {
                    "tools": [
                        {
                            "name": "calc",
                            "description": "Calculate math",
                            "inputSchema": {"type": "object"},
                        }
                    ]
                },
            }

        server = MCPGatewayServer(downstream_handler=mock_downstream)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json={"jsonrpc": "2.0", "id": "list-1", "method": "tools/list"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "list-1"
            assert len(data["result"]["tools"]) == 1
            assert data["result"]["tools"][0]["name"] == "calc"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_resolver_timeout_covers_evaluation(self):
        class SlowHangingResolver:
            async def evaluate(self, context: ToolCallContext) -> Verdict:
                await asyncio.sleep(5.0)
                return Verdict(decision=VerdictDecision.ALLOW, reasoning="Slow")

        server = MCPGatewayServer(
            resolver=SlowHangingResolver(),
            timeout_seconds=0.2,
        )
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            payload = {
                "jsonrpc": "2.0",
                "id": "slow-req-1",
                "method": "tools/call",
                "params": {
                    "name": "bash",
                    "arguments": {"cmd": "sleep 10"},
                },
            }
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json=payload,
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "slow-req-1"
            assert "error" in data
            assert data["error"]["code"] == -32000
            assert "timed out" in data["error"]["message"].lower()
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_post_mcp_duplicate_request_id_returns_error(self):
        server = MCPGatewayServer()
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # Hold request manually
            await server.flow_controller.hold_request("dup-1", "tools/call", {})
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json={
                    "jsonrpc": "2.0",
                    "id": "dup-1",
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": {}},
                },
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["id"] == "dup-1"
            assert data["error"]["code"] == -32600
            assert "duplicate" in data["error"]["message"].lower()
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_mcp_sse_session_registry_and_broadcast(self):
        server = MCPGatewayServer()
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # Connect via GET /mcp
            resp = await client.get(
                "/mcp",
                headers={"Host": "127.0.0.1:9229", "Accept": "text/event-stream"},
            )
            assert resp.status == 200
            assert server.active_sse_sessions == 1

            # Read initial connection line and empty delimiter line
            initial_line = await resp.content.readline()
            assert b"connected session=" in initial_line
            empty_line = await resp.content.readline()
            assert empty_line == b"\n"

            # Broadcast an event
            delivered = await server.broadcast_sse("alert", {"rule": "blackwall_guard"})
            assert delivered == 1

            event_line = await resp.content.readline()
            assert b"event: alert" in event_line
            data_line = await resp.content.readline()
            assert b"blackwall_guard" in data_line
        finally:
            await server.stop()
            await client.close()

    @pytest.mark.asyncio
    async def test_post_mcp_sse_streaming(self):
        server = MCPGatewayServer()
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            payload = {
                "jsonrpc": "2.0",
                "id": "sse-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            resp = await client.post(
                "/mcp",
                headers={
                    "Host": "127.0.0.1:9229",
                    "Accept": "text/event-stream",
                },
                json=payload,
            )
            assert resp.status == 200
            assert "text/event-stream" in resp.headers.get("Content-Type", "")
            body = await resp.text()
            assert "event: message" in body
            assert "data: " in body
            assert "2025-03-26" in body
        finally:
            await client.close()


class TestMCPGatewayServerStdio:
    """Stdio transport stream tests."""

    @pytest.mark.asyncio
    async def test_stdio_bidirectional_stream(self):
        block_verdict = Verdict(
            decision=VerdictDecision.BLOCK,
            reasoning="Malicious command injection",
            confidence_score=0.99,
        )
        resolver = MockResolver(verdict=block_verdict)
        server = MCPGatewayServer(resolver=resolver)

        # Simulate stdin / stdout pipes with StreamReader and StreamWriter mocks
        reader = asyncio.StreamReader()
        writer_buffer = bytearray()

        class MockWriter:
            def write(self, data: bytes):
                writer_buffer.extend(data)

            async def drain(self):
                pass

        mock_writer = MockWriter()

        # Feed a tools/call line into reader
        req_payload = {
            "jsonrpc": "2.0",
            "id": "stdio-req-1",
            "method": "tools/call",
            "params": {
                "name": "execute_bash",
                "arguments": {"cmd": "rm -rf /"},
            },
        }
        reader.feed_data((json.dumps(req_payload) + "\n").encode("utf-8"))
        reader.feed_eof()

        await server.handle_stdio_stream(reader, mock_writer)

        output_lines = writer_buffer.decode("utf-8").strip().split("\n")
        assert len(output_lines) == 1

        response = json.loads(output_lines[0])
        assert response["id"] == "stdio-req-1"
        assert response["error"]["code"] == -32603
        assert response["error"]["message"] == "Blackwall Firewall: Execution blocked"

    @pytest.mark.asyncio
    async def test_notification_forwarding_never_returns_response(self):
        downstream_called = []

        async def mock_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            downstream_called.append(payload)
            # Even if downstream returns a dict or raises, notifications should produce no response
            return {"jsonrpc": "2.0", "result": "downstream-result"}

        server = MCPGatewayServer(downstream_handler=mock_downstream)
        app = server.create_app()
        client = TestClient(TestServer(app))
        await client.start_server()

        try:
            # 1. HTTP POST of a notification -> 204 No Content
            resp = await client.post(
                "/mcp",
                headers={"Host": "127.0.0.1:9229"},
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/custom_event",
                    "params": {"data": "test"},
                },
            )
            assert resp.status == 204
            assert len(downstream_called) == 1

            # 2. Stdio notification -> no bytes written to stdout
            reader = asyncio.StreamReader()
            writer_buffer = bytearray()

            class MockWriter:
                def write(self, data: bytes):
                    writer_buffer.extend(data)

                async def drain(self):
                    pass

            notif = {
                "jsonrpc": "2.0",
                "method": "notifications/another_event",
                "params": {},
            }
            reader.feed_data((json.dumps(notif) + "\n").encode("utf-8"))
            reader.feed_eof()

            await server.handle_stdio_stream(reader, MockWriter())
            assert len(writer_buffer) == 0
            assert len(downstream_called) == 2
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_stdio_backpressure_concurrency_bound(self):
        server = MCPGatewayServer()
        server.flow_controller.max_queue_size = 2

        active_count = 0
        max_concurrent_seen = 0

        async def mock_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal active_count, max_concurrent_seen
            active_count += 1
            max_concurrent_seen = max(max_concurrent_seen, active_count)
            await asyncio.sleep(0.05)
            active_count -= 1
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

        server.downstream_handler = mock_downstream

        reader = asyncio.StreamReader()
        writer_buffer = bytearray()

        class MockWriter:
            def write(self, data: bytes):
                writer_buffer.extend(data)

            async def drain(self):
                pass

        # Feed 6 pipelined passthrough requests
        for i in range(6):
            msg = {"jsonrpc": "2.0", "id": f"pipe-{i}", "method": "tools/list"}
            reader.feed_data((json.dumps(msg) + "\n").encode("utf-8"))
        reader.feed_eof()

        await server.handle_stdio_stream(reader, MockWriter())

        # Assert concurrency never exceeded max_queue_size
        assert max_concurrent_seen <= 2
        lines = [line for line in writer_buffer.decode("utf-8").strip().split("\n") if line]
        assert len(lines) == 6

