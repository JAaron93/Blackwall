"""
Blackwall MCP Gateway.

Standalone MCP security daemon providing protocol gateway, request tracking,
payload interception, and verdict synthesis.
"""

from __future__ import annotations

from blackwall.gateway.exceptions import (
    DuplicateRequestIdError,
    GatewayAuthError,
    GatewayError,
    InvalidVerdictError,
    MalformedPayloadError,
    MissingArgumentError,
    QueueOverflowError,
    RequestTimeoutError,
    SecurityHostError,
    SecurityOriginError,
)
from blackwall.gateway.flow import FlowController, InFlightRequest
from blackwall.gateway.interceptor import PayloadInterceptor
from blackwall.gateway.server import MCPGatewayServer
from blackwall.gateway.synthesizer import ResponseSynthesizer

__all__ = [
    "GatewayError",
    "GatewayAuthError",
    "SecurityOriginError",
    "SecurityHostError",
    "MalformedPayloadError",
    "MissingArgumentError",
    "QueueOverflowError",
    "RequestTimeoutError",
    "DuplicateRequestIdError",
    "InvalidVerdictError",
    "InFlightRequest",
    "FlowController",
    "PayloadInterceptor",
    "ResponseSynthesizer",
    "MCPGatewayServer",
]
