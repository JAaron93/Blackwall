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
            reasoning="Benign",
            confidence_score=0.01,
        )
        resolver = MockResolver(verdict=allow_verdict)
        server = MCPGatewayServer(resolver=resolver)
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
        finally:
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
