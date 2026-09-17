"""
JSON-RPC Response Synthesizer for Blackwall MCP Gateway.

Translates security verdicts into MCP-compliant JSON-RPC error responses
while maintaining zero threat reasoning leakage.
"""

from __future__ import annotations

import logging
from typing import Any

from blackwall.gateway.exceptions import InvalidVerdictError
from blackwall.models import Verdict, VerdictDecision

logger = logging.getLogger(__name__)


class ResponseSynthesizer:
    """
    Synthesizes MCP-compliant JSON-RPC 2.0 error responses from security verdicts.

    Invariants:
    - BLOCK verdicts synthesize Error Code -32603 with bounded, generic message.
    - QUARANTINE verdicts synthesize Error Code -32001 with bounded, generic message.
    - ALLOW verdicts are strictly rejected with InvalidVerdictError (allowed calls
      must be forwarded to downstream tool servers without synthesis).
    - Incoming request `id` is preserved and reused.
    - Zero internal threat reasoning or rule data is leaked into the response.
    """

    GENERIC_BLOCK_MESSAGE = "Blackwall Firewall: Execution blocked"
    GENERIC_QUARANTINE_MESSAGE = (
        "Blackwall Firewall: Execution quarantined pending review"
    )

    BLOCK_ERROR_CODE = -32603
    QUARANTINE_ERROR_CODE = -32001

    def synthesize_verdict(
        self, verdict: Verdict, request_id: Any
    ) -> dict[str, Any]:
        """
        Translates a Verdict into a JSON-RPC 2.0 error response dictionary.

        Args:
            verdict: The resolved security verdict.
            request_id: The original JSON-RPC request identifier.

        Returns:
            JSON-RPC 2.0 error response dictionary.

        Raises:
            InvalidVerdictError: If verdict decision is ALLOW.
        """
        if verdict.decision == VerdictDecision.ALLOW:
            raise InvalidVerdictError(
                "ResponseSynthesizer cannot synthesize response for ALLOW verdict; "
                "allowed requests must be forwarded intact to downstream tool servers."
            )

        if verdict.decision == VerdictDecision.BLOCK:
            logger.info(
                "Synthesizing BLOCK error (-32603) for request_id=%s", request_id
            )
            return self.synthesize_error(
                code=self.BLOCK_ERROR_CODE,
                message=self.GENERIC_BLOCK_MESSAGE,
                request_id=request_id,
            )

        if verdict.decision == VerdictDecision.QUARANTINE:
            logger.warning(
                "Synthesizing QUARANTINE error (-32001) for request_id=%s. Logging for manual review.",
                request_id,
            )
            return self.synthesize_error(
                code=self.QUARANTINE_ERROR_CODE,
                message=self.GENERIC_QUARANTINE_MESSAGE,
                request_id=request_id,
            )

        raise InvalidVerdictError(f"Unsupported verdict decision: {verdict.decision}")

    def synthesize_error(
        self,
        code: int,
        message: str,
        request_id: Any,
        data: Any = None,
    ) -> dict[str, Any]:
        """
        Constructs a standard JSON-RPC 2.0 error response.

        Args:
            code: JSON-RPC error code.
            message: Bounded error message.
            request_id: Identifier of the triggering request.
            data: Optional auxiliary error data.

        Returns:
            JSON-RPC 2.0 error response dictionary.
        """
        error_obj: dict[str, Any] = {
            "code": code,
            "message": message,
        }
        if data is not None:
            error_obj["data"] = data

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error_obj,
        }
