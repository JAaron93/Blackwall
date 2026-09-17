"""
End-to-End Pipeline Wiring tests (TASK-C01).

Validates complete interception flow:
MCPGatewayServer -> PayloadInterceptor -> SyncResolver -> ResponseSynthesizer / Downstream Handler.
Verifies:
- ALLOW verdicts route downstream and return downstream responses.
- BLOCK verdicts return synthesized JSON-RPC error -32603 without leaking threat reasoning.
- QUARANTINE verdicts return synthesized JSON-RPC error -32001.
- Sensitive credentials in arguments are sanitized before reaching SyncResolver.
- Gateway overhead remains strictly sub-10ms in benchmarking tests.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from blackwall.gateway.server import MCPGatewayServer
from blackwall.gateway.synthesizer import ResponseSynthesizer
from blackwall.models import ToolCallContext, Verdict, VerdictDecision
from blackwall.sync_resolver import SyncResolver


def _create_mock_sync_resolver() -> SyncResolver:
    """Helper to instantiate a real SyncResolver with a mocked Gemini client."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "benign pattern"
    mock_client.models.generate_content.return_value = mock_response

    return SyncResolver(
        client=mock_client,
        threat_intel=None,
        cbm_client=None,
        repo=None,
        demo_mode=False,
    )


class TestPipelineWiring:
    """Tests for Gateway -> Interceptor -> SyncResolver -> Synthesizer wiring."""

    @pytest.mark.asyncio
    async def test_pipeline_allow_verdict_forwards_to_downstream(self) -> None:
        """Benign tool call evaluated by SyncResolver receives ALLOW and executes downstream."""
        resolver = _create_mock_sync_resolver()

        downstream_called = False
        downstream_payload: dict[str, Any] = {}

        async def downstream_handler(payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal downstream_called, downstream_payload
            downstream_called = True
            downstream_payload = payload
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "content": [{"type": "text", "text": "File read successfully."}]
                },
            }

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=downstream_handler,
        )

        request_payload = {
            "jsonrpc": "2.0",
            "id": "req-allow-1",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/safe/data/sample.txt"},
            },
        }

        response = await server.process_message(request_payload)

        assert downstream_called is True
        assert downstream_payload == request_payload
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == "req-allow-1"
        assert "result" in response
        assert response["result"]["content"][0]["text"] == "File read successfully."
        assert "error" not in response

    @pytest.mark.asyncio
    async def test_pipeline_block_verdict_synthesizes_error(self) -> None:
        """Malicious tool call triggers BLOCK verdict, returning -32603 without downstream invocation."""
        resolver = _create_mock_sync_resolver()

        # Mock evaluate to return a BLOCK verdict
        resolver.evaluate = AsyncMock(  # type: ignore[method-assign]
            return_value=Verdict(
                decision=VerdictDecision.BLOCK,
                reasoning="Credential exfiltration detected against private key fixture",
                confidence_score=0.95,
            )
        )

        downstream_called = False

        async def downstream_handler(payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal downstream_called
            downstream_called = True
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=downstream_handler,
        )

        request_payload = {
            "jsonrpc": "2.0",
            "id": "req-block-1",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/root/.ssh/id_rsa"},
            },
        }

        response = await server.process_message(request_payload)

        # Downstream handler must NEVER be called on BLOCK
        assert downstream_called is False
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == "req-block-1"
        assert "error" in response
        assert response["error"]["code"] == -32603
        assert (
            response["error"]["message"]
            == ResponseSynthesizer.GENERIC_BLOCK_MESSAGE
        )
        # Zero threat reasoning leaked
        assert "Credential" not in response["error"]["message"]
        assert "exfiltration" not in response["error"]["message"]

    @pytest.mark.asyncio
    async def test_pipeline_quarantine_verdict_synthesizes_error(self) -> None:
        """Suspicious tool call triggers QUARANTINE verdict, returning -32001 without downstream invocation."""
        resolver = _create_mock_sync_resolver()

        resolver.evaluate = AsyncMock(  # type: ignore[method-assign]
            return_value=Verdict(
                decision=VerdictDecision.QUARANTINE,
                reasoning="Anomaly score within quarantine band [0.10, 0.20)",
                confidence_score=0.15,
            )
        )

        downstream_called = False

        async def downstream_handler(payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal downstream_called
            downstream_called = True
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=downstream_handler,
        )

        request_payload = {
            "jsonrpc": "2.0",
            "id": "req-quarantine-1",
            "method": "tools/call",
            "params": {
                "name": "network_ping",
                "arguments": {"target": "192.168.1.105"},
            },
        }

        response = await server.process_message(request_payload)

        assert downstream_called is False
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == "req-quarantine-1"
        assert "error" in response
        assert response["error"]["code"] == -32001
        assert (
            response["error"]["message"]
            == ResponseSynthesizer.GENERIC_QUARANTINE_MESSAGE
        )
        assert "Anomaly" not in response["error"]["message"]

    @pytest.mark.asyncio
    async def test_pipeline_credential_redaction_before_resolver(self) -> None:
        """Verifies credentials in tool arguments are sanitized via ContextHygiene before reaching SyncResolver."""
        resolver = _create_mock_sync_resolver()

        captured_context: ToolCallContext | None = None

        async def inspect_eval(ctx: ToolCallContext) -> Verdict:
            nonlocal captured_context
            captured_context = ctx
            return Verdict(
                decision=VerdictDecision.ALLOW,
                reasoning="Sanitized context evaluated",
                confidence_score=0.0,
            )

        resolver.evaluate = inspect_eval  # type: ignore[method-assign]

        async def dummy_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=dummy_downstream,
        )

        request_payload = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com",
                    "api_key": "sk-proj-1234567890abcdef12345678",
                },
            },
        }

        await server.process_message(request_payload)

        assert captured_context is not None
        assert captured_context.tool_name == "http_request"
        # The credential MUST be redacted in the ToolCallContext passed to the resolver
        assert captured_context.arguments["api_key"] == "[[API_KEY]]"
        assert "sk-proj-" not in captured_context.arguments["api_key"]

    @pytest.mark.asyncio
    async def test_pipeline_downstream_handler_exception_synthesizes_error(self) -> None:
        """If downstream handler crashes, gateway safely catches it and returns JSON-RPC -32603."""
        resolver = _create_mock_sync_resolver()

        async def failing_downstream(payload: dict[str, Any]) -> dict[str, Any]:
            raise ConnectionResetError("Downstream server died unexpectedly")

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=failing_downstream,
        )

        request_payload = {
            "jsonrpc": "2.0",
            "id": "downstream-fail-1",
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"cmd": "ls"},
            },
        }

        response = await server.process_message(request_payload)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == "downstream-fail-1"
        assert response["error"]["code"] == -32603
        assert response["error"]["message"] == "Downstream tool execution failed"

    @pytest.mark.asyncio
    async def test_pipeline_sub_10ms_gateway_overhead_benchmark(self) -> None:
        """
        NFR-02 SLA Benchmark: Demonstrates gateway interception, parsing, flow control,
        and response handling overhead is strictly < 10ms.
        """
        # Fast mock resolver that executes synchronously in ~0.01ms
        fast_resolver = MagicMock()
        fast_verdict = Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Fast pass",
            confidence_score=0.0,
        )

        async def _eval(ctx: ToolCallContext) -> Verdict:
            return fast_verdict

        fast_resolver.evaluate = _eval

        # Fast downstream handler that echoes immediately
        async def _downstream(p: dict[str, Any]) -> dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "id": p.get("id"),
                "result": {"status": "ok"},
            }

        server = MCPGatewayServer(
            resolver=fast_resolver,
            downstream_handler=_downstream,
        )

        payload = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "tools/call",
            "params": {
                "name": "benchmark_tool",
                "arguments": {"param1": "val1", "count": 42},
            },
        }

        # Warm up JIT / cache (10 runs)
        for i in range(10):
            payload["id"] = f"warmup-{i}"
            await server.process_message(payload)

        # Measure 100 iterations
        iterations = 100
        t0 = time.perf_counter()
        for i in range(iterations):
            payload["id"] = f"bench-{i}"
            resp = await server.process_message(payload)
            assert resp["result"]["status"] == "ok"
        t1 = time.perf_counter()

        total_time_ms = (t1 - t0) * 1000.0
        avg_overhead_ms = total_time_ms / iterations

        # Target: sub-10ms gateway overhead (NFR-02 SLA requirement)
        assert avg_overhead_ms < 10.0, f"Average gateway overhead {avg_overhead_ms:.3f}ms exceeded 10ms SLA!"

    @pytest.mark.asyncio
    async def test_pipeline_structural_policy_blocks_tool_call(self, tmp_path: Path) -> None:
        """P1: Verifies that a structural policy rule loaded via policy.yaml blocks matching tool calls at gateway level."""
        from blackwall.policy.engine import StructuralGatingEngine
        from blackwall.policy.semantic import SemanticGatingEngine
        from blackwall.policy.server import HybridPolicyServer
        from blackwall.cli import DEFAULT_POLICY_YAML

        policy_path = tmp_path / "test_policy.yaml"
        policy_path.write_text(DEFAULT_POLICY_YAML)

        struct_engine = StructuralGatingEngine()
        struct_engine.load_policy(str(policy_path))
        sem_engine = SemanticGatingEngine()
        policy_server = HybridPolicyServer(
            structural_engine=struct_engine,
            semantic_engine=sem_engine,
        )

        mock_client = MagicMock()
        resolver = SyncResolver(
            client=mock_client,
            policy_server=policy_server,
            repo=None,
        )

        downstream_called = False
        async def _downstream(p: dict[str, Any]) -> dict[str, Any]:
            nonlocal downstream_called
            downstream_called = True
            return {"jsonrpc": "2.0", "id": p.get("id"), "result": {}}

        server = MCPGatewayServer(
            resolver=resolver,
            downstream_handler=_downstream,
        )

        # In DEFAULT_POLICY_YAML, execute_bash in production is BLOCKED
        blocked_payload = {
            "jsonrpc": "2.0",
            "id": "block-test-1",
            "method": "tools/call",
            "params": {
                "name": "execute_bash",
                "arguments": {"command": "cat /etc/passwd"},
                "_meta": {"environment_role": "production"},
            },
        }

        resp = await server.process_message(blocked_payload)
        assert "error" in resp
        assert resp["error"]["code"] == -32603
        assert downstream_called is False

