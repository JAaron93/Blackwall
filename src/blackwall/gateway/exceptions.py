"""
Domain-specific exceptions for Blackwall MCP Gateway.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base exception for all Blackwall MCP Gateway errors."""


class GatewayAuthError(GatewayError):
    """Raised when authentication fails or is missing on non-loopback bindings."""


class SecurityOriginError(GatewayError):
    """Raised when an Origin header fails security validation (e.g. DNS rebinding/CORS probe)."""


class SecurityHostError(GatewayError):
    """Raised when a Host header fails validation (e.g. DNS rebinding attack)."""


class MalformedPayloadError(GatewayError):
    """Raised when an MCP protocol payload fails JSON-RPC 2.0 structure validation."""


class MissingArgumentError(MalformedPayloadError):
    """Raised when required arguments are missing from an MCP tools/call request."""


class QueueOverflowError(GatewayError):
    """Raised when the in-flight request queue exceeds its maximum capacity."""


class RequestTimeoutError(GatewayError):
    """Raised when an intercepted tool call times out awaiting verdict resolution."""


class DuplicateRequestIdError(GatewayError):
    """Raised when an incoming request attempts to reuse an ID that is already actively in flight."""


class InvalidVerdictError(GatewayError, ValueError):
    """Raised when ResponseSynthesizer receives an invalid verdict (such as ALLOW)."""
