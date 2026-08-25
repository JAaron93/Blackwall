"""Inbound Protocol Filter for MCP and A2A Protocol Interception (Pillar 6 Task 25).

Provides ingress RPC inspection, Origin/Host validation, sliding-window rate-limiting,
two-pass JSON-RPC sanitization, and MCP-compliant error response synthesis.
"""

import collections
import ipaddress
import json
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any, Mapping, Optional, Set, Tuple
from urllib.parse import urlparse

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    InboundMethodType,
    InboundProtocolType,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    InboundProtocolMessage,
)
from blackwall.validators import validate_non_empty_string

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.inbound_filter")

# Sensitive key name patterns for Pass 1 pre-serialization redaction
_SENSITIVE_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)password"),
    re.compile(r"(?i)passwd"),
    re.compile(r"(?i)\bpwd\b"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)token"),
    re.compile(r"(?i)api[_-]?key"),
    re.compile(r"(?i)access[_-]?key"),
    re.compile(r"(?i)private[_-]?key"),
    re.compile(r"(?i)auth"),
    re.compile(r"(?i)credential"),
    re.compile(r"(?i)bearer"),
]

# Regex patterns for Pass 2 value inspection
_REDACTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "API_KEY",
        re.compile(r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})"),
        "[[API_KEY]]",
    ),
    (
        "OPENAI_KEY",
        # Matches: sk-abc123, sk-proj-abc-def123, sk-or-v1-abc, sk-ant-abc etc.
        re.compile(r"sk-(?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]{8,}"),
        "[[OPENAI_API_KEY]]",
    ),
    (
        "GOOGLE_KEY",
        re.compile(r"AIza[a-zA-Z0-9_\-]{10,}"),
        "[[GOOGLE_API_KEY]]",
    ),
    (
        "SECRET_VALUE",
        re.compile(r"(?i)(secret|api_key|apikey)[\s:\"']*:[\s\"']*[a-zA-Z0-9_\-]{8,}"),
        "[[SECRET_VALUE]]",
    ),
    (
        "PASSWORD",
        re.compile(r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)"),
        "[[PASSWORD]]",
    ),
]


def _is_sensitive_key(key: str) -> bool:
    """Return True if key name matches any known sensitive credential pattern."""
    return any(pat.search(key) for pat in _SENSITIVE_KEY_PATTERNS)


def _sanitize_value(value: Any) -> Any:
    """Recursively sanitize values using two-pass secret redaction."""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in value.items():
            if _is_sensitive_key(k):
                result[k] = f"[[{k.upper()}_REDACTED]]"
            else:
                result[k] = _sanitize_value(v)
        return result
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for _name, pattern, placeholder in _REDACTION_PATTERNS:
            try:
                redacted = pattern.sub(placeholder, redacted)
            except re.error as exc:
                logger.warning("Sanitization pattern failed: %s", exc)
                continue
        return redacted
    return value


def _sanitize_dict_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Sanitize dictionary payload applying key-based and regex-based redactions."""
    try:
        # Pass 1: Key-name inspection
        pass1: dict[str, Any] = {}
        for k, v in payload.items():
            if _is_sensitive_key(k):
                pass1[k] = f"[[{k.upper()}_REDACTED]]"
            else:
                pass1[k] = _sanitize_value(v)

        # Pass 2: Regex scan over serialized string
        serialized = json.dumps(pass1)
        redacted = serialized
        for _name, pattern, placeholder in _REDACTION_PATTERNS:
            try:
                redacted = pattern.sub(placeholder, redacted)
            except re.error as exc:
                logger.warning("Sanitization pattern failed: %s", exc)
                continue

        return json.loads(redacted)
    except Exception as exc:
        logger.error("Payload sanitization failed: %s", exc)
        return {"sanitization_error": "[REDACTED DUE TO SANITIZATION FAILURE]"}


class InboundProtocolFilter:
    """Ingress protocol filter for A2A and MCP JSON-RPC requests."""

    def __init__(
        self,
        alert_bus: Optional[AlertBus] = None,
        rate_limit_per_window: int = 100,
        sliding_window_sec: int = 60,
        allowed_origins: Optional[Set[str]] = None,
        allowed_hosts: Optional[Set[str]] = None,
        allowed_auth_tokens: Optional[Set[str]] = None,
        enforce_loopback: bool = True,
    ) -> None:
        if isinstance(rate_limit_per_window, bool) or not isinstance(rate_limit_per_window, int) or rate_limit_per_window <= 0:
            raise ValueError("rate_limit_per_window must be a positive integer")
        if isinstance(sliding_window_sec, bool) or not isinstance(sliding_window_sec, int) or sliding_window_sec <= 0:
            raise ValueError("sliding_window_sec must be a positive integer")

        self.alert_bus = alert_bus
        self.rate_limit_per_window = rate_limit_per_window
        self.sliding_window_sec = sliding_window_sec
        self.allowed_origins = set(allowed_origins) if allowed_origins is not None else None
        self.allowed_hosts = set(allowed_hosts) if allowed_hosts is not None else None
        self.allowed_auth_tokens = set(allowed_auth_tokens) if allowed_auth_tokens is not None else set()
        self.enforce_loopback = enforce_loopback

        self._sender_windows: dict[str, collections.deque[float]] = {}

    def _is_loopback(self, addr: str) -> bool:
        """Determine whether the specified IP or host is a loopback endpoint."""
        clean = addr.strip()
        if not clean:
            return False

        if clean.lower() == "localhost":
            return True

        # Handle bracketed IPv6 with optional port (e.g. [::1] or [::1]:8000)
        if clean.startswith("["):
            if "]" not in clean:
                return False
            close_idx = clean.index("]")
            suffix = clean[close_idx + 1:]
            if suffix:
                if not suffix.startswith(":") or not suffix[1:].isdigit():
                    return False
                port = int(suffix[1:])
                if not (1 <= port <= 65535):
                    return False
            clean = clean[1:close_idx]
        elif clean.count(":") == 1:
            # Potential ipv4:port or host:port (single colon)
            parts = clean.split(":")
            if parts[1].isdigit() and (1 <= int(parts[1]) <= 65535):
                clean = parts[0]
            else:
                return False

        try:
            ip = ipaddress.ip_address(clean)
            if ip.is_loopback:
                return True
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback:
                return True
        except ValueError:
            # Check IPv4 loopback prefix in mapped strings
            if clean.lower().startswith("::ffff:127.") or clean.lower().startswith("0:0:0:0:0:ffff:127."):
                return True
            return False

        return False

    def _is_allowed_origin(self, origin: str) -> bool:
        """Validate if Origin header matches allowed origins or loopback."""
        if not origin:
            return True

        clean_origin = origin.strip()
        if not clean_origin:
            return False

        try:
            parsed = urlparse(clean_origin)
            netloc = parsed.netloc
            if not netloc or not parsed.scheme:
                return False
        except Exception:
            return False

        if self.allowed_origins is not None:
            if clean_origin in self.allowed_origins:
                return True
            origin_base = f"{parsed.scheme}://{netloc}"
            if origin_base in self.allowed_origins:
                return True

        # Check loopback origin tolerance if loopback enforced
        if self.enforce_loopback:
            if self._is_allowed_host(netloc):
                return True

        return False

    def _is_allowed_host(self, host: str) -> bool:
        """Validate if Host header matches allowed hosts or loopback."""
        if not host:
            return True

        clean_host = host.strip()
        if not clean_host:
            return False

        if clean_host.startswith("["):
            if "]" not in clean_host:
                return False
            close_idx = clean_host.index("]")
            ip_str = clean_host[1:close_idx]
            bracketed_ip = clean_host[:close_idx + 1]
            suffix = clean_host[close_idx + 1:]
            if suffix:
                if not suffix.startswith(":") or not suffix[1:].isdigit() or not (1 <= int(suffix[1:]) <= 65535):
                    return False

            if self.allowed_hosts is not None:
                if (
                    clean_host in self.allowed_hosts
                    or ip_str in self.allowed_hosts
                    or bracketed_ip in self.allowed_hosts
                ):
                    return True

            if self.enforce_loopback:
                if self._is_loopback(ip_str):
                    return True

            return False

        # Non-bracketed host
        if clean_host.count(":") == 1:
            parts = clean_host.split(":")
            if parts[1].isdigit() and (1 <= int(parts[1]) <= 65535):
                hostname = parts[0]
            else:
                return False
        else:
            hostname = clean_host

        if self.allowed_hosts is not None:
            if clean_host in self.allowed_hosts or hostname in self.allowed_hosts:
                return True

        if self.enforce_loopback:
            if self._is_loopback(hostname):
                return True

        return False

    async def validate_headers_and_origin(
        self,
        headers: Mapping[str, Any],
        remote_addr: str,
    ) -> bool:
        """Validate Origin/Host headers and restrict unauthenticated remote access."""
        # Case-insensitive header dictionary lookup
        normalized_headers = {str(k).lower(): str(v) for k, v in headers.items()}

        # 1. Check authorization tokens if provided
        auth_header = normalized_headers.get("authorization") or normalized_headers.get("x-api-key")
        is_authenticated = False
        if auth_header and self.allowed_auth_tokens:
            token = auth_header
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            if token in self.allowed_auth_tokens:
                is_authenticated = True

        # 2. Check loopback binding if loopback enforced and unauthenticated
        if self.enforce_loopback and not is_authenticated:
            if not self._is_loopback(remote_addr):
                logger.warning(
                    "Rejected inbound connection from non-loopback address %s (unauthenticated)",
                    remote_addr,
                )
                return False

        # 2b. When loopback enforcement is disabled and the caller is unauthenticated,
        # at minimum one identifying header (Origin or Host) MUST be present.
        # A fully anonymous remote caller with zero metadata must always be rejected
        # regardless of allow-list configuration — absence of any identifying information
        # cannot be treated as permission to proceed.
        if not self.enforce_loopback and not is_authenticated:
            origin_present = bool(normalized_headers.get("origin"))
            host_present = bool(normalized_headers.get("host"))
            if not origin_present and not host_present:
                logger.warning(
                    "Rejected inbound connection from %s: unauthenticated caller must "
                    "provide at least one identifying header (Origin or Host) when "
                    "loopback enforcement is disabled",
                    remote_addr or "<unknown>",
                )
                return False

        # 3. Check Origin header.
        # If allowed_origins is configured, the Origin header MUST be present and in the allow-list.
        # Absence is only tolerated when the list is unconfigured (None = permissive mode) and the
        # caller is either authenticated or the loopback check already passed above.
        origin = normalized_headers.get("origin")
        if self.allowed_origins is not None:
            # Strict mode: origin header required and must be in allow-list
            if not origin or not self._is_allowed_origin(origin):
                logger.warning(
                    "Rejected inbound connection: Origin header %s not in allow-list",
                    repr(origin),
                )
                return False
        elif origin and not self._is_allowed_origin(origin):
            # Permissive mode (no allow-list): only reject if origin is present and disallowed
            logger.warning("Rejected inbound connection with disallowed Origin: %s", origin)
            return False

        # 4. Check Host header.
        # If allowed_hosts is configured, the Host header MUST be present and in the allow-list.
        host = normalized_headers.get("host")
        if self.allowed_hosts is not None:
            # Strict mode: host header required and must be in allow-list
            if not host or not self._is_allowed_host(host):
                logger.warning(
                    "Rejected inbound connection: Host header %s not in allow-list",
                    repr(host),
                )
                return False
        elif host and not self._is_allowed_host(host):
            # Permissive mode (no allow-list): only reject if host is present and disallowed
            logger.warning("Rejected inbound connection with disallowed Host: %s", host)
            return False

        return True


    async def check_inbound_rate_limit(
        self,
        sender_id: str,
        sliding_window_sec: Optional[int] = None,
    ) -> bool:
        """Enforce sliding-window inbound rate-limiting per sender identity."""
        clean_sender = validate_non_empty_string(sender_id, field_name="sender_id")
        window_sec = sliding_window_sec if sliding_window_sec is not None else self.sliding_window_sec
        now = time.monotonic()

        if clean_sender not in self._sender_windows:
            self._sender_windows[clean_sender] = collections.deque()

        timestamps = self._sender_windows[clean_sender]

        # Evict timestamps outside sliding window
        cutoff = now - window_sec
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if len(timestamps) >= self.rate_limit_per_window:
            logger.warning(
                "Inbound rate limit exceeded for sender %s: %d requests in %ds",
                clean_sender,
                len(timestamps),
                window_sec,
            )
            if self.alert_bus is not None:
                alert = Alert(
                    severity=AlertSeverity.HIGH,
                    threat_type="INBOUND_RATE_LIMIT_EXCEEDED",
                    title=f"Inbound rate limit exceeded for sender {clean_sender}",
                    description=(
                        f"Sender {clean_sender} exceeded sliding-window limit of "
                        f"{self.rate_limit_per_window} requests per {window_sec}s"
                    ),
                    agent_id=clean_sender,
                )
                await self.alert_bus.publish(alert)
            return False

        timestamps.append(now)
        return True

    async def sanitize_incoming_rpc(
        self,
        message: InboundProtocolMessage,
    ) -> InboundProtocolMessage:
        """Extract and sanitize JSON-RPC payloads before host agent execution."""
        payload_copy = dict(message.payload)

        # Sanitize tools/call arguments specifically if present
        if message.method == InboundMethodType.TOOLS_CALL and "params" in payload_copy and isinstance(payload_copy["params"], dict):
            params = dict(payload_copy["params"])
            if "arguments" in params and isinstance(params["arguments"], dict):
                params["arguments"] = _sanitize_dict_payload(params["arguments"])
                payload_copy["params"] = params
            else:
                payload_copy["params"] = _sanitize_dict_payload(params)
        else:
            payload_copy = _sanitize_dict_payload(payload_copy)

        return InboundProtocolMessage(
            message_id=message.message_id,
            sender_id=message.sender_id,
            recipient_agent_id=message.recipient_agent_id,
            protocol=message.protocol,
            method=message.method,
            payload=payload_copy,
            timestamp=message.timestamp,
        )

    def synthesize_error_response(
        self,
        error_code: int = -32600,
        message: str = "Invalid Request",
        request_id: Any = None,
    ) -> dict[str, Any]:
        """Synthesize an MCP/JSON-RPC compliant error response without leaking internal state."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": error_code,
                "message": message,
            },
        }

    async def parse_and_validate_rpc(
        self,
        raw_data: str | bytes | dict[str, Any],
        sender_id: str,
        recipient_agent_id: str,
        protocol: InboundProtocolType = InboundProtocolType.MCP_SSE,
    ) -> Tuple[Optional[InboundProtocolMessage], Optional[dict[str, Any]]]:
        """Parse raw incoming RPC data, validate JSON-RPC schema, and return error response on failure."""
        data: dict[str, Any]
        if isinstance(raw_data, (str, bytes)):
            try:
                parsed = json.loads(raw_data)
                if not isinstance(parsed, dict):
                    return None, self.synthesize_error_response(
                        error_code=-32600,
                        message="Invalid Request: payload must be a JSON object",
                        request_id=None,
                    )
                data = parsed
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.warning("JSON parse error on incoming RPC: %s", exc)
                return None, self.synthesize_error_response(
                    error_code=-32700,
                    message="Parse error",
                    request_id=None,
                )
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            return None, self.synthesize_error_response(
                error_code=-32600,
                message="Invalid Request: unexpected payload type",
                request_id=None,
            )

        req_id = data.get("id")

        # 1. Validate jsonrpc version
        if data.get("jsonrpc") != "2.0":
            return None, self.synthesize_error_response(
                error_code=-32600,
                message="Invalid Request: 'jsonrpc' must be '2.0'",
                request_id=req_id,
            )

        # 2. Validate method
        method_str = data.get("method")
        if not method_str or not isinstance(method_str, str):
            return None, self.synthesize_error_response(
                error_code=-32600,
                message="Invalid Request: 'method' must be specified",
                request_id=req_id,
            )

        try:
            method_type = InboundMethodType(method_str)
        except ValueError:
            logger.warning("Unsupported RPC method: %s", method_str)
            return None, self.synthesize_error_response(
                error_code=-32601,
                message=f"Method not found: {method_str}",
                request_id=req_id,
            )

        # 3. Construct InboundProtocolMessage
        try:
            msg = InboundProtocolMessage(
                sender_id=sender_id,
                recipient_agent_id=recipient_agent_id,
                protocol=protocol,
                method=method_type,
                payload=data,
            )
            return msg, None
        except Exception as exc:
            logger.warning("InboundProtocolMessage validation error: %s", exc)
            return None, self.synthesize_error_response(
                error_code=-32602,
                message="Invalid params",
                request_id=req_id,
            )
