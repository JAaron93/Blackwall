"""
Payload Interceptor for Blackwall MCP Gateway.

Extracts tool invocation intent from MCP JSON-RPC 2.0 payloads, redacts sensitive
credentials via ContextHygiene, and constructs ToolCallContext models for evaluation.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

from blackwall.gateway.exceptions import (
    MalformedPayloadError,
    MissingArgumentError,
)
from blackwall.models import ToolCallContext
from blackwall.resolver import ContextHygiene

logger = logging.getLogger(__name__)


class PayloadInterceptor:
    """
    Parses and sanitizes MCP tools/call JSON-RPC 2.0 requests.

    Invariants:
    - MCP tools/call payloads are strictly validated against JSON-RPC 2.0 specification.
    - Malformed or missing arguments raise specific exceptions (MalformedPayloadError / MissingArgumentError).
    - Sensitive values (API keys, tokens, passwords, AWS/GCP secrets) are redacted
      via ContextHygiene before ToolCallContext construction.
    - Blocked payloads are redacted prior to persistence into Threat Signature Graph.
    """

    def __init__(self, hygiene: ContextHygiene | None = None) -> None:
        self.hygiene = hygiene or ContextHygiene(preserve_iocs=True)

    def intercept(
        self, payload: dict[str, Any] | str
    ) -> tuple[ToolCallContext, Any]:
        """
        Intercepts and parses an MCP tools/call JSON-RPC payload.

        Args:
            payload: JSON string or dictionary representation of the JSON-RPC request.

        Returns:
            Tuple of (sanitized ToolCallContext, original JSON-RPC request_id).

        Raises:
            MalformedPayloadError: On invalid JSON or schema violations.
            MissingArgumentError: When required fields (e.g. tool name) are absent.
        """
        parsed = self._parse_json(payload)

        if not isinstance(parsed, dict):
            raise MalformedPayloadError(
                f"Expected JSON-RPC request object, got {type(parsed).__name__}"
            )

        if parsed.get("jsonrpc") != "2.0":
            raise MalformedPayloadError(
                f"Invalid or missing 'jsonrpc' version. Expected '2.0', got: {parsed.get('jsonrpc')!r}"
            )

        method = parsed.get("method")
        if method != "tools/call":
            raise MalformedPayloadError(
                f"PayloadInterceptor only intercepts 'tools/call' requests, got: {method!r}"
            )

        params = parsed.get("params")
        if not isinstance(params, dict):
            raise MalformedPayloadError(
                f"'params' must be a dictionary in tools/call requests, got: {type(params).__name__}"
            )

        tool_name = params.get("name")
        if not tool_name or not isinstance(tool_name, str):
            raise MissingArgumentError(
                "Missing or invalid required 'name' field in 'params'"
            )

        raw_arguments = params.get("arguments", {})
        if raw_arguments is None:
            raw_arguments = {}
        elif not isinstance(raw_arguments, dict):
            raise MalformedPayloadError(
                f"'arguments' in 'params' must be a dictionary, got: {type(raw_arguments).__name__}"
            )

        request_id = parsed.get("id")

        # Context Hygiene: redact sensitive credentials, tokens, and passwords
        sanitized_arguments = self._sanitize_value(raw_arguments)

        meta = params.get("_meta")
        context_metadata: dict[str, Any] = {
            "request_id": request_id,
            "method": method,
        }
        if isinstance(meta, dict):
            context_metadata.update(meta)

        context = ToolCallContext(
            tool_name=tool_name,
            arguments=sanitized_arguments,
            metadata=context_metadata,
        )

        logger.debug(
            "Intercepted tool call '%s' (id=%s) with %d arguments",
            tool_name,
            request_id,
            len(sanitized_arguments),
        )

        return context, request_id

    def _sanitize_value(self, val: Any, key_name: str | None = None) -> Any:
        if key_name and isinstance(val, str):
            k_lower = key_name.lower().replace("-", "_")
            if k_lower in ("password", "passwd", "pwd"):
                return "[[PASSWORD]]"
            if k_lower in ("api_key", "apikey", "secret_key", "auth_token", "access_token"):
                return "[[API_KEY]]"
        if isinstance(val, str):
            return self.hygiene.sanitize_string(val)
        elif isinstance(val, dict):
            return {k: self._sanitize_value(v, key_name=str(k)) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._sanitize_value(v, key_name=key_name) for v in val]
        return val

    def redact_for_storage(self, payload: dict[str, Any] | str) -> dict[str, Any]:
        """
        Redacts sensitive values from a payload dictionary prior to persistence in the Threat Signature Graph.

        Args:
            payload: JSON string or dictionary representation of the request.

        Returns:
            A deep-copied, sanitized dictionary safe for persistence.
        """
        parsed = self._parse_json(payload)
        if not isinstance(parsed, dict):
            return {"sanitized": str(parsed)}

        redacted = copy.deepcopy(parsed)
        params = redacted.get("params")
        if isinstance(params, dict):
            args = params.get("arguments")
            if isinstance(args, dict):
                params["arguments"] = self._sanitize_value(args)
            elif isinstance(args, (list, str)):
                params["arguments"] = self._sanitize_value(args)

        return redacted

    def _parse_json(self, payload: dict[str, Any] | str) -> Any:
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except json.JSONDecodeError as exc:
                raise MalformedPayloadError(
                    f"Malformed JSON in payload: {exc}"
                ) from exc
        return payload
