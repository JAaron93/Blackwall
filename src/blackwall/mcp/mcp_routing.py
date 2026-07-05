"""MCP Routing Layer for Blackwall Agentic Firewall.

Enforces hardcoded routing boundaries for codebase-memory-mcp and GTI MCP.
Prevents agent escape attempts and blocks unauthorized tool invocations.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from blackwall.mcp.codebase_memory import CodebaseMemoryClient
from blackwall.mcp.gti_client import GTIClient

logger = logging.getLogger("blackwall.mcp_routing")

# Escape-attempt detection patterns and lists
INVALID_CHARS = {"/", "\\", ";", "|", "&", "`", "$", "\x00"}
ARG_INVALID_CHARS = {";", "|", "&", "`", "$", "\x00"}
DENY_KEYWORDS = {
    "exec",
    "eval",
    "import",
    "spawn",
    "system",
    "popen",
    "subprocess",
    "compile",
    "globals",
    "locals",
    "__",
}


class MCPRoutingViolation(RuntimeError):
    """Raised when an MCP call violates hardcoded routing boundaries."""

    def __init__(self, router: str, operation: str, reason: str) -> None:
        self.router = router
        self.operation = operation
        self.reason = reason
        super().__init__(f"[{router}] Blocked '{operation}': {reason}")


def _detect_escape_attempt(router_name: str, operation: str, kwargs: dict[str, Any]) -> None:
    """Helper to detect potential escape attempts in operation name and arguments."""
    # 1. Canonicalise and check operation name
    canonical_op = operation.strip().lower()

    # Check for invalid characters in operation name
    if any(char in operation for char in INVALID_CHARS):
        msg = f"[ESCAPE_ATTEMPT] Operation name '{operation}' contains restricted characters."
        logger.warning(msg)
        raise MCPRoutingViolation(router_name, operation, msg)

    # Check for deny keywords in operation name
    if any(kw in canonical_op for kw in DENY_KEYWORDS):
        msg = f"[ESCAPE_ATTEMPT] Operation name '{operation}' contains restricted keywords."
        logger.warning(msg)
        raise MCPRoutingViolation(router_name, operation, msg)

    # 2. Check string arguments in kwargs (shallow inspection)
    for key, val in kwargs.items():
        if isinstance(val, str):
            if any(char in val for char in ARG_INVALID_CHARS):
                msg = f"[ESCAPE_ATTEMPT] Argument '{key}' contains restricted characters: {val}"
                logger.warning(msg)
                raise MCPRoutingViolation(router_name, operation, msg)
            val_lower = val.lower()
            if any(kw in val_lower for kw in DENY_KEYWORDS):
                msg = f"[ESCAPE_ATTEMPT] Argument '{key}' contains restricted keywords: {val}"
                logger.warning(msg)
                raise MCPRoutingViolation(router_name, operation, msg)


class CodebaseMemoryRouter:
    """Sandboxes codebase-memory-mcp to AST/structural queries only.

    Permitted operations (hardcoded allowlist):
        query_dependency_chain  - AST call-chain parsing
        identify_critical_sinks - sink-type detection
        trace_data_flow         - taint analysis
        get_blast_radius        - impact calculation
    """

    PERMITTED_OPS: frozenset[str] = frozenset(
        {
            "query_dependency_chain",
            "identify_critical_sinks",
            "trace_data_flow",
            "get_blast_radius",
        }
    )

    CBM_METHOD_MAP = {
        "query_dependency_chain": "queryDependencyChain",
        "identify_critical_sinks": "identifyCriticalSinks",
        "trace_data_flow": "traceDataFlow",
        "get_blast_radius": "getBlastRadius",
    }

    def __init__(self, client: CodebaseMemoryClient) -> None:
        self.client = client

    def _map_kwargs(self, operation: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        mapped = {}
        for k, v in kwargs.items():
            if k == "function_name":
                if operation == "identify_critical_sinks":
                    mapped["moduleName"] = v
                elif operation == "get_blast_radius":
                    mapped["targetNode"] = v
                else:
                    mapped["functionName"] = v
            elif k == "module_name":
                mapped["moduleName"] = v
            elif k == "variable_name" or k == "source":
                mapped["variableName"] = v
            elif k == "context" or k == "sink":
                mapped["context"] = v
            elif k == "target_node":
                mapped["targetNode"] = v
            else:
                mapped[k] = v
        return mapped

    async def route(self, operation: str, **kwargs: Any) -> Any:
        """Validate operation and arguments, then delegate to CodebaseMemoryClient."""
        _detect_escape_attempt("CodebaseMemoryRouter", operation, kwargs)
        self._validate(operation)

        # Delegate execution to client method dynamically (map to camelCase method name)
        client_method_name = self.CBM_METHOD_MAP.get(operation, operation)
        method = getattr(self.client, client_method_name)
        mapped_args = self._map_kwargs(operation, kwargs)
        logger.debug("CodebaseMemoryRouter allowed and routed '%s'", operation)
        return await method(**mapped_args)

    def _validate(self, operation: str) -> None:
        """Raise MCPRoutingViolation if operation is not in PERMITTED_OPS."""
        canonical_op = operation.strip()
        if canonical_op not in self.PERMITTED_OPS:
            reason = f"Operation '{operation}' is not in permitted list."
            logger.warning("CodebaseMemoryRouter blocked '%s': %s", operation, reason)
            raise MCPRoutingViolation("CodebaseMemoryRouter", operation, reason)




class GTIRouter:
    """Restricts GTI MCP queries to the asynchronous analysis path only.

    GTI queries are FORBIDDEN inside the synchronous interception path.
    """

    class ExecutionContext(str, Enum):
        ASYNC_ANALYSIS = "async_analysis"
        BATCH_RESOLUTION = "batch_resolution"
        SYNC_INTERCEPTION = "sync_interception"

    PERMITTED_CONTEXTS: frozenset[ExecutionContext] = frozenset(
        {
            ExecutionContext.ASYNC_ANALYSIS,
            ExecutionContext.BATCH_RESOLUTION,
        }
    )

    PERMITTED_OPS: frozenset[str] = frozenset(
        {
            "lookup_ip",
            "lookup_url",
            "lookup_domain",
            "lookup_file_hash",
        }
    )

    def __init__(self, client: GTIClient) -> None:
        self.client = client

    async def route(self, context: ExecutionContext, operation: str, **kwargs: Any) -> Any:
        """Validate execution context and operation, then delegate to GTIClient."""
        _detect_escape_attempt("GTIRouter", operation, kwargs)
        self._validate_context(context, operation)
        self._validate_operation(operation)

        # Delegate execution to client method dynamically
        method = getattr(self.client, operation)
        logger.debug("GTIRouter allowed and routed '%s' in context '%s'", operation, context.value)
        return await method(**kwargs)

    def _validate_context(self, context: ExecutionContext, operation: str) -> None:
        """Raise MCPRoutingViolation if context is not permitted."""
        if context not in self.PERMITTED_CONTEXTS:
            reason = f"Execution context '{context.value}' is forbidden."
            logger.warning("GTIRouter blocked '%s': %s", operation, reason)
            raise MCPRoutingViolation("GTIRouter", operation, reason)


    def _validate_operation(self, operation: str) -> None:
        """Raise MCPRoutingViolation if operation is not in PERMITTED_OPS."""
        canonical_op = operation.strip()
        if canonical_op not in self.PERMITTED_OPS:
            reason = f"Operation '{operation}' is not permitted on GTI router."
            logger.warning("GTIRouter blocked '%s': %s", operation, reason)
            raise MCPRoutingViolation("GTIRouter", operation, reason)
