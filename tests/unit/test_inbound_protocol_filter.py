"""Unit tests for Inbound Protocol Interception and Cross-Agent Inspection (Task 25).

Validates Requirements 23.1, 23.2, 23.3, 23.4, 15.11.
"""

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    InboundMethodType,
    InboundProtocolType,
)
from blackwall.enterprise.advanced_threat_detection.inbound_filter import (
    InboundProtocolFilter,
)
from blackwall.enterprise.advanced_threat_detection.models import InboundProtocolMessage


def test_message_parsing() -> None:
    """Test InboundProtocolMessage creation and schema validation (Req 15.11, 23.4)."""
    msg_id = uuid.uuid4()
    now = datetime.now(UTC)

    # Valid message
    msg = InboundProtocolMessage(
        message_id=msg_id,
        sender_id="remote-agent-alpha",
        recipient_agent_id="host-agent-primary",
        protocol=InboundProtocolType.MCP_SSE,
        method=InboundMethodType.TOOLS_CALL,
        payload={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "query_db", "arguments": {"id": 42}}},
        timestamp=now,
    )
    assert msg.message_id == msg_id
    assert msg.sender_id == "remote-agent-alpha"
    assert msg.recipient_agent_id == "host-agent-primary"
    assert msg.protocol == InboundProtocolType.MCP_SSE
    assert msg.method == InboundMethodType.TOOLS_CALL
    assert msg.payload["params"]["name"] == "query_db"
    assert msg.timestamp == now

    # Rejection: empty sender_id
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id="",
            recipient_agent_id="host-agent-primary",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"action": "test"},
        )

    # Rejection: empty recipient_agent_id
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id="remote-agent-alpha",
            recipient_agent_id="   ",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"action": "test"},
        )

    # Rejection: empty payload dict
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id="remote-agent-alpha",
            recipient_agent_id="host-agent-primary",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={},
        )

    # Rejection: invalid UUID
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id="not-a-valid-uuid",
            sender_id="remote-agent-alpha",
            recipient_agent_id="host-agent-primary",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"action": "test"},
        )

    # Rejection: naive datetime without timezone
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id="remote-agent-alpha",
            recipient_agent_id="host-agent-primary",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"action": "test"},
            timestamp=datetime.now(),  # naive
        )


@pytest.mark.asyncio
async def test_header_validation() -> None:
    """Test Origin and Host header validation and loopback enforcement (Req 23.1)."""
    filter_engine = InboundProtocolFilter()

    # 1. Valid loopback IPv4 requests
    headers_valid = {"Host": "localhost:8000", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_valid, remote_addr="127.0.0.1") is True
    assert await filter_engine.validate_headers_and_origin(headers_valid, remote_addr="127.0.0.2") is True

    # 2. Valid loopback IPv6 and mapped IPv6 requests
    assert await filter_engine.validate_headers_and_origin(headers_valid, remote_addr="::1") is True
    assert await filter_engine.validate_headers_and_origin(headers_valid, remote_addr="[::1]") is True
    assert await filter_engine.validate_headers_and_origin(headers_valid, remote_addr="::ffff:127.0.0.1") is True

    headers_ipv6 = {"Host": "[::1]:8000", "Origin": "http://[::1]:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_ipv6, remote_addr="::1") is True
    assert await filter_engine.validate_headers_and_origin(headers_ipv6, remote_addr="[::1]") is True
    assert await filter_engine.validate_headers_and_origin(headers_ipv6, remote_addr="127.0.0.1") is True

    headers_ipv6_full = {"Host": "[0:0:0:0:0:0:0:1]:8000", "Origin": "http://[0:0:0:0:0:0:0:1]:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_ipv6_full, remote_addr="::1") is True
    assert await filter_engine.validate_headers_and_origin(headers_ipv6_full, remote_addr="[::1]") is True
    assert await filter_engine.validate_headers_and_origin(headers_ipv6_full, remote_addr="127.0.0.1") is True

    # 3. Invalid/Disallowed Origin from external attacker
    headers_bad_origin = {"Host": "localhost:8000", "Origin": "https://malicious-attacker.io"}
    assert await filter_engine.validate_headers_and_origin(headers_bad_origin, remote_addr="127.0.0.1") is False

    # 4. Disallowed and Malformed Host headers
    headers_bad_host = {"Host": "attacker.com", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_bad_host, remote_addr="127.0.0.1") is False

    headers_malformed_bracket1 = {"Host": "[::1]evil", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_malformed_bracket1, remote_addr="127.0.0.1") is False

    headers_malformed_bracket2 = {"Host": "[::ffff:127.0.0.1].attacker", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_malformed_bracket2, remote_addr="127.0.0.1") is False

    headers_malformed_port = {"Host": "localhost:evil", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_malformed_port, remote_addr="127.0.0.1") is False

    headers_malformed_bracket_port = {"Host": "[::1]:8000evil", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_malformed_bracket_port, remote_addr="127.0.0.1") is False

    # 5. Remote unauthenticated request (non-loopback remote_addr) rejected when loopback enforced
    headers_remote = {"Host": "localhost:8000", "Origin": "http://localhost:8000"}
    assert await filter_engine.validate_headers_and_origin(headers_remote, remote_addr="192.168.1.50") is False
    assert await filter_engine.validate_headers_and_origin(headers_remote, remote_addr="10.0.0.1") is False

    # 6. Custom allowed origins and hosts
    custom_filter = InboundProtocolFilter(
        allowed_origins={"https://app.blackwall.internal"},
        allowed_hosts={"app.blackwall.internal"},
        enforce_loopback=False,
    )
    headers_custom = {"Host": "app.blackwall.internal", "Origin": "https://app.blackwall.internal"}
    assert await custom_filter.validate_headers_and_origin(headers_custom, remote_addr="10.0.0.5") is True

    # 7. Authenticated remote access with auth token
    auth_filter = InboundProtocolFilter(
        allowed_origins={"http://localhost:8000"},
        allowed_hosts={"localhost:8000"},
        enforce_loopback=True,
        allowed_auth_tokens={"BW_SECRET_AUTH_TOKEN_9912"},
    )
    headers_auth = {
        "Host": "localhost:8000",
        "Origin": "http://localhost:8000",
        "Authorization": "Bearer BW_SECRET_AUTH_TOKEN_9912",
    }
    assert await auth_filter.validate_headers_and_origin(headers_auth, remote_addr="192.168.1.100") is True


@pytest.mark.asyncio
async def test_rate_limiting() -> None:
    """Test sliding-window inbound rate-limiting per sender identity (Req 23.2)."""
    alert_bus = AlertBus()
    filter_engine = InboundProtocolFilter(
        alert_bus=alert_bus,
        rate_limit_per_window=5,
        sliding_window_sec=60,
    )

    sender = "agent-burst-01"

    # Send 5 allowed requests
    for _ in range(5):
        allowed = await filter_engine.check_inbound_rate_limit(sender)
        assert allowed is True

    # 6th request must be rate limited and dropped
    dropped = await filter_engine.check_inbound_rate_limit(sender)
    assert dropped is False

    # Verify an alert was emitted to the AlertBus
    alerts = alert_bus.get_alerts(threat_type="INBOUND_RATE_LIMIT_EXCEEDED")
    assert len(alerts) >= 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert alerts[0].agent_id == sender

    # Different sender should have separate quota
    other_sender = "agent-benign-02"
    assert await filter_engine.check_inbound_rate_limit(other_sender) is True


@pytest.mark.asyncio
async def test_rpc_sanitization() -> None:
    """Test two-pass JSON-RPC tools/call parameter sanitization (Req 23.3)."""
    filter_engine = InboundProtocolFilter()

    # Incoming message containing credentials in key names (Pass 1) and in values (Pass 2)
    raw_payload = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "connect_service",
            "arguments": {
                "password": "super-secret-password-123",
                "api_key": "sk-proj-1234567890abcdef12345678",
                "nested_config": {
                    "token": "BW_SYNTHETIC_MOCK_TOKEN_9999",
                    "safe_field": "public_data",
                },
                "instructions": "Use key AIzaSyD98765432101234567890 to connect to server",
            },
        },
    }

    msg = InboundProtocolMessage(
        sender_id="sender-agent",
        recipient_agent_id="host-agent",
        protocol=InboundProtocolType.MCP_SSE,
        method=InboundMethodType.TOOLS_CALL,
        payload=raw_payload,
    )

    sanitized_msg = await filter_engine.sanitize_incoming_rpc(msg)

    args = sanitized_msg.payload["params"]["arguments"]
    # Key-based redaction
    assert args["password"] == "[[PASSWORD_REDACTED]]"
    assert args["api_key"] == "[[API_KEY_REDACTED]]"
    assert args["nested_config"]["token"] == "[[TOKEN_REDACTED]]"
    assert args["nested_config"]["safe_field"] == "public_data"

    # Embedded regex redaction
    assert "AIzaSy" not in args["instructions"]
    assert "[[GOOGLE_API_KEY]]" in args["instructions"]


@pytest.mark.asyncio
async def test_malformed_rpc_error_synthesis() -> None:
    """Test malformed JSON-RPC handling and error response synthesis without context leakage (Req 23.4)."""
    filter_engine = InboundProtocolFilter()

    # 1. Invalid JSON string
    msg, err = await filter_engine.parse_and_validate_rpc(
        raw_data="{invalid_json_payload",
        sender_id="sender-x",
        recipient_agent_id="host-y",
    )
    assert msg is None
    assert err is not None
    assert err["jsonrpc"] == "2.0"
    assert err["error"]["code"] == -32700  # Parse error
    assert "internal" not in err["error"]["message"].lower()

    # 2. Missing jsonrpc version
    msg, err = await filter_engine.parse_and_validate_rpc(
        raw_data={"method": "tools/call", "params": {}},
        sender_id="sender-x",
        recipient_agent_id="host-y",
    )
    assert msg is None
    assert err is not None
    assert err["error"]["code"] == -32600  # Invalid Request

    # 3. Unsupported method
    msg, err = await filter_engine.parse_and_validate_rpc(
        raw_data={"jsonrpc": "2.0", "method": "unsupported/method", "id": 10},
        sender_id="sender-x",
        recipient_agent_id="host-y",
    )
    assert msg is None
    assert err is not None
    assert err["error"]["code"] == -32601  # Method not found
    assert err["id"] == 10

    # 4. Valid JSON-RPC payload
    valid_payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "fetch_file", "arguments": {"path": "/tmp/test"}},
        "id": 42,
    }
    msg, err = await filter_engine.parse_and_validate_rpc(
        raw_data=valid_payload,
        sender_id="sender-x",
        recipient_agent_id="host-y",
    )
    assert err is None
    assert msg is not None
    assert msg.method == InboundMethodType.TOOLS_CALL
    assert msg.payload["id"] == 42
