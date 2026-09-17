import pytest

from blackwall.models import Verdict, VerdictDecision
from blackwall.gateway.synthesizer import ResponseSynthesizer
from blackwall.gateway.exceptions import InvalidVerdictError


class TestResponseSynthesizer:
    """Test suite for MCP JSON-RPC ResponseSynthesizer (TASK-B02)."""

    def test_synthesize_block_verdict(self):
        synthesizer = ResponseSynthesizer()
        verdict = Verdict(
            decision=VerdictDecision.BLOCK,
            reasoning="Secret internal threat rule: /etc/shadow read match",
            confidence_score=0.95,
        )
        request_id = "call-abc-123"

        response = synthesizer.synthesize_verdict(verdict, request_id)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == request_id
        assert "result" not in response
        assert "error" in response
        assert response["error"]["code"] == -32603
        assert response["error"]["message"] == "Blackwall Firewall: Execution blocked"

        # Security invariant: zero threat reasoning or internal score leaked
        response_str = str(response)
        assert "/etc/shadow" not in response_str
        assert "0.95" not in response_str
        assert "threat rule" not in response_str

    def test_synthesize_quarantine_verdict(self):
        synthesizer = ResponseSynthesizer()
        verdict = Verdict(
            decision=VerdictDecision.QUARANTINE,
            reasoning="Anomalous tool usage detected",
            confidence_score=0.15,
        )
        request_id = 9999

        response = synthesizer.synthesize_verdict(verdict, request_id)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 9999
        assert response["error"]["code"] == -32001
        assert (
            response["error"]["message"]
            == "Blackwall Firewall: Execution quarantined pending review"
        )
        assert "Anomalous" not in str(response)

    def test_synthesize_allow_verdict_raises_exception(self):
        synthesizer = ResponseSynthesizer()
        verdict = Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Safe benign call",
            confidence_score=0.01,
        )

        with pytest.raises(InvalidVerdictError) as exc_info:
            synthesizer.synthesize_verdict(verdict, "req-1")

        assert "ALLOW" in str(exc_info.value)

    def test_synthesize_custom_error(self):
        synthesizer = ResponseSynthesizer()
        response = synthesizer.synthesize_error(
            code=-32000,
            message="Server queue overflow",
            request_id="overflow-id",
        )

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == "overflow-id"
        assert response["error"]["code"] == -32000
        assert response["error"]["message"] == "Server queue overflow"
