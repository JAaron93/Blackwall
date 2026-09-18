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
    InvalidGatewayConfigError,
    InvalidVerdictError,
    MalformedPayloadError,
    MissingArgumentError,
    QueueOverflowError,
    RequestTimeoutError,
    SecurityHostError,
    SecurityOriginError,
    UpstreamProcessError,
    UpstreamServerNotFoundError,
    UpstreamTimeoutError,
)
from blackwall.gateway.flow import FlowController, InFlightRequest
from blackwall.gateway.interceptor import PayloadInterceptor
from blackwall.gateway.server import MCPGatewayServer
from blackwall.gateway.service import (
    build_service_command_prefix,
    configure_system_service,
    configure_user_service,
    derive_system_user,
    detect_platform,
    ensure_system_user,
    generate_launchd_plist,
    generate_systemd_unit,
    install_service,
    resolve_adc_path,
    service_status,
    start_service,
    stop_service,
    uninstall_service,
)
from blackwall.gateway.synthesizer import ResponseSynthesizer
from blackwall.gateway.upstream import (
    BaseUpstreamServer,
    HttpUpstreamServer,
    StdioUpstreamServer,
    UpstreamManager,
)

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
    "UpstreamServerNotFoundError",
    "UpstreamProcessError",
    "UpstreamTimeoutError",
    "InvalidGatewayConfigError",
    "InFlightRequest",
    "FlowController",
    "PayloadInterceptor",
    "ResponseSynthesizer",
    "MCPGatewayServer",
    "build_service_command_prefix",
    "configure_system_service",
    "configure_user_service",
    "derive_system_user",
    "detect_platform",
    "ensure_system_user",
    "generate_launchd_plist",
    "generate_systemd_unit",
    "install_service",
    "resolve_adc_path",
    "service_status",
    "start_service",
    "stop_service",
    "uninstall_service",
    "BaseUpstreamServer",
    "StdioUpstreamServer",
    "HttpUpstreamServer",
    "UpstreamManager",
]
