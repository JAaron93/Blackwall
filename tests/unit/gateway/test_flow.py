import asyncio
import time
import pytest

from blackwall.gateway.exceptions import QueueOverflowError
from blackwall.gateway.flow import FlowController
from blackwall.gateway.synthesizer import ResponseSynthesizer


class TestFlowController:
    """Test suite for MCP FlowController and in-flight request tracking (TASK-A02)."""

    @pytest.mark.asyncio
    async def test_pause_and_resolve_request(self):
        controller = FlowController()
        req_id = "req-pause-1"

        future = await controller.hold_request(
            request_id=req_id,
            method="tools/call",
            params={"name": "test_tool", "arguments": {}},
        )

        assert controller.active_count == 1
        assert controller.has_in_flight(req_id)

        # Simulate async background verdict resolution
        expected_response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": "executed"}]},
        }
        resolved = controller.resolve_request(req_id, expected_response)
        assert resolved is True

        response = await controller.wait_for_verdict(req_id)
        assert response == expected_response
        assert controller.active_count == 0

    @pytest.mark.asyncio
    async def test_concurrent_request_isolation(self):
        controller = FlowController()
        ids = [f"concurrent-{i}" for i in range(5)]

        futures = {}
        for req_id in ids:
            futures[req_id] = await controller.hold_request(
                request_id=req_id,
                method="tools/call",
                params={"name": f"tool_{req_id}", "arguments": {}},
            )

        assert controller.active_count == 5

        # Resolve out of order
        for req_id in reversed(ids):
            controller.resolve_request(
                req_id,
                {"jsonrpc": "2.0", "id": req_id, "result": {"id": req_id}},
            )

        for req_id in ids:
            resp = await controller.wait_for_verdict(req_id)
            assert resp["id"] == req_id
            assert resp["result"]["id"] == req_id

        assert controller.active_count == 0

    @pytest.mark.asyncio
    async def test_queue_overflow_enforcement(self):
        controller = FlowController(max_queue_size=2)

        await controller.hold_request("req-1", "tools/call", {})
        await controller.hold_request("req-2", "tools/call", {})

        # Exceeding queue bounds must raise QueueOverflowError
        with pytest.raises(QueueOverflowError):
            await controller.hold_request("req-3", "tools/call", {})

    @pytest.mark.asyncio
    async def test_request_timeout_handling(self):
        controller = FlowController(request_timeout=0.05)
        req_id = "req-timeout"

        await controller.hold_request(
            request_id=req_id,
            method="tools/call",
            params={"name": "slow_tool", "arguments": {}},
        )

        # Do not resolve; wait for timeout
        response = await controller.wait_for_verdict(req_id)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == req_id
        assert response["error"]["code"] == -32000
        assert "timed out" in response["error"]["message"].lower()
        assert controller.active_count == 0

    @pytest.mark.asyncio
    async def test_cancellation_handling(self):
        controller = FlowController()
        req_id = "req-cancel"

        await controller.hold_request(
            request_id=req_id,
            method="tools/call",
            params={},
        )

        cancelled = controller.cancel_request(req_id)
        assert cancelled is True

        response = await controller.wait_for_verdict(req_id)
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == req_id
        assert response["error"]["code"] == -32000
        assert "cancelled" in response["error"]["message"].lower()
        assert controller.active_count == 0

    @pytest.mark.asyncio
    async def test_deterministic_abandoned_request_cleanup(self):
        controller = FlowController(request_timeout=1.0)
        req_id = "req-abandoned"

        await controller.hold_request(req_id, "tools/call", {})
        # Artificially age the in-flight request
        controller._in_flight[req_id].created_at = time.monotonic() - 100.0

        cleaned = controller.cleanup_abandoned(max_age_seconds=10.0)
        assert cleaned == 1
        assert controller.active_count == 0
        assert not controller.has_in_flight(req_id)

    def test_non_tool_methods_passthrough_classification(self):
        controller = FlowController()

        assert controller.is_passthrough("initialize") is True
        assert controller.is_passthrough("notifications/initialized") is True
        assert controller.is_passthrough("notifications/cancelled") is True
        assert controller.is_passthrough("tools/list") is True
        assert controller.is_passthrough("ping") is True

        assert controller.is_passthrough("tools/call") is False
        assert controller.is_tool_call("tools/call") is True
        assert controller.is_tool_call("initialize") is False
