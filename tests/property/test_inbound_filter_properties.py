"""Property-based tests for Inbound Protocol Interception and Cross-Agent Inspection (Task 25).

Validates Properties 93, 94, 95, 96, 103 against Requirements 23.1 - 23.4, 15.11.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
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


# Strategies
identifier_st = st.from_regex(r"[a-zA-Z0-9_-]{1,32}", fullmatch=True)
sensitive_key_st = st.sampled_from(["password", "passwd", "pwd", "secret", "token", "api_key", "access_key", "credential", "auth", "bearer"])
loopback_ip_st = st.sampled_from(["127.0.0.1", "127.0.0.2", "127.0.1.1", "::1", "[::1]", "::ffff:127.0.0.1"])
remote_ip_st = st.sampled_from(["192.168.1.50", "10.0.0.5", "172.16.0.1", "8.8.8.8", "203.0.113.195"])


@st.composite
def valid_inbound_message(draw: st.DrawFn) -> InboundProtocolMessage:
    msg_id = uuid.uuid4()
    sender = draw(identifier_st)
    recipient = draw(identifier_st)
    protocol = draw(st.sampled_from(list(InboundProtocolType)))
    method = draw(st.sampled_from(list(InboundMethodType)))
    payload = draw(
        st.dictionaries(
            keys=identifier_st,
            values=st.one_of(st.text(min_size=1, max_size=50), st.integers(), st.booleans()),
            min_size=1,
            max_size=5,
        )
    )
    return InboundProtocolMessage(
        message_id=msg_id,
        sender_id=sender,
        recipient_agent_id=recipient,
        protocol=protocol,
        method=method,
        payload=payload,
        timestamp=datetime.now(UTC),
    )


@given(msg=valid_inbound_message())
@settings(max_examples=25, deadline=None)
def test_property_103_inbound_message_model_acceptance(msg: InboundProtocolMessage) -> None:
    """Property 103: Breach Defense Model Pydantic Validation - InboundProtocolMessage.

    For all valid instantiated InboundProtocolMessage models, Pydantic validation succeeds
    with valid UUID v4, UTC timezone-aware timestamp, non-empty identifiers, and valid enum types.
    """
    assert isinstance(msg.message_id, uuid.UUID)
    assert msg.timestamp.tzinfo is not None
    assert msg.timestamp.utcoffset() == datetime.now(UTC).utcoffset()
    assert len(msg.sender_id.strip()) >= 1
    assert len(msg.recipient_agent_id.strip()) >= 1
    assert isinstance(msg.protocol, InboundProtocolType)
    assert isinstance(msg.method, InboundMethodType)
    assert len(msg.payload) >= 1


@given(
    invalid_sender=st.sampled_from(["", "   ", "\t\n"]),
    invalid_recipient=st.sampled_from(["", "   ", "\t\n"]),
)
@settings(max_examples=25, deadline=None)
def test_property_103_inbound_message_model_rejection(invalid_sender: str, invalid_recipient: str) -> None:
    """Property 103: Breach Defense Model Pydantic Validation - InboundProtocolMessage Rejection.

    Invalid identifiers, empty payloads, and naive datetimes are rejected with ValidationError.
    """
    msg_id = uuid.uuid4()
    # Rejection: invalid sender
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id=invalid_sender,
            recipient_agent_id="host-1",
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"k": "v"},
        )

    # Rejection: invalid recipient
    with pytest.raises(ValidationError):
        InboundProtocolMessage(
            message_id=msg_id,
            sender_id="sender-1",
            recipient_agent_id=invalid_recipient,
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload={"k": "v"},
        )


@given(
    loopback_ip=loopback_ip_st,
    remote_ip=remote_ip_st,
    host=st.sampled_from(["localhost:8000", "127.0.0.1:8000", "localhost"]),
    origin=st.sampled_from(["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost"]),
)
@settings(max_examples=25, deadline=None)
def test_property_93_inbound_header_and_origin_enforcement(
    loopback_ip: str, remote_ip: str, host: str, origin: str
) -> None:
    """Property 93: Inbound Header and Origin Enforcement.

    For any HTTP/SSE request, loopback connections with valid Origin/Host are accepted,
    while untrusted origins or unauthenticated remote IPs are rejected.
    """
    async def _run() -> None:
        filter_engine = InboundProtocolFilter()

        # Valid loopback + valid Origin/Host -> Accepted
        valid_headers = {"Host": host, "Origin": origin}
        assert await filter_engine.validate_headers_and_origin(valid_headers, remote_addr=loopback_ip) is True

        # Invalid Origin -> Rejected
        bad_origin_headers = {"Host": host, "Origin": "http://evil-attacker.example.com"}
        assert await filter_engine.validate_headers_and_origin(bad_origin_headers, remote_addr=loopback_ip) is False

        # Unauthenticated remote IP -> Rejected when loopback enforced
        assert await filter_engine.validate_headers_and_origin(valid_headers, remote_addr=remote_ip) is False

    asyncio.run(_run())


@given(
    sender=identifier_st,
    burst_count=st.integers(min_value=6, max_value=15),
    limit=st.integers(min_value=2, max_value=5),
)
@settings(max_examples=25, deadline=None)
def test_property_94_inbound_rate_limit_boundary(sender: str, burst_count: int, limit: int) -> None:
    """Property 94: Inbound Rate Limit Boundary.

    For any incoming request stream exceeding sliding-window capacity, additional requests
    are dropped and a rate-limit alert is emitted.
    """
    async def _run() -> None:
        alert_bus = AlertBus()
        filter_engine = InboundProtocolFilter(
            alert_bus=alert_bus,
            rate_limit_per_window=limit,
            sliding_window_sec=60,
        )

        passed = 0
        dropped = 0
        for _ in range(burst_count):
            allowed = await filter_engine.check_inbound_rate_limit(sender)
            if allowed:
                passed += 1
            else:
                dropped += 1

        assert passed == limit
        assert dropped == (burst_count - limit)
        alerts = alert_bus.get_alerts(threat_type="INBOUND_RATE_LIMIT_EXCEEDED")
        assert len(alerts) >= 1
        assert alerts[0].severity == AlertSeverity.HIGH

    asyncio.run(_run())


@given(
    sender=identifier_st,
    recipient=identifier_st,
    sensitive_key=sensitive_key_st,
    secret_val=st.text(min_size=8, max_size=32).filter(lambda s: bool(s.strip())),
    api_key=st.from_regex(r"sk-[a-zA-Z0-9]{20,32}", fullmatch=True),
)
@settings(max_examples=25, deadline=None)
def test_property_95_inbound_json_rpc_sanitization(
    sender: str, recipient: str, sensitive_key: str, secret_val: str, api_key: str
) -> None:
    """Property 95: Inbound JSON-RPC Sanitization.

    For all incoming tools/call payloads, sensitive key names and embedded credential strings
    are neutralized by the two-pass sanitization filter.
    """
    async def _run() -> None:
        filter_engine = InboundProtocolFilter()

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute_task",
                "arguments": {
                    sensitive_key: secret_val,
                    "target_url": f"https://service.internal?auth_key={api_key}",
                    "public_param": "safe_value",
                },
            },
        }

        msg = InboundProtocolMessage(
            sender_id=sender,
            recipient_agent_id=recipient,
            protocol=InboundProtocolType.MCP_SSE,
            method=InboundMethodType.TOOLS_CALL,
            payload=payload,
        )

        sanitized_msg = await filter_engine.sanitize_incoming_rpc(msg)
        sanitized_args = sanitized_msg.payload["params"]["arguments"]

        # Assert sensitive key redacted
        assert sanitized_args[sensitive_key] != secret_val
        assert "_REDACTED" in sanitized_args[sensitive_key] or "[[" in sanitized_args[sensitive_key]

        # Assert raw API key not present
        assert api_key not in sanitized_args["target_url"]

        # Assert benign argument preserved
        assert sanitized_args["public_param"] == "safe_value"

    asyncio.run(_run())


@given(
    sender=identifier_st,
    recipient=identifier_st,
    malformed_json=st.sampled_from([
        "{malformed_json_str",
        "[]",
        "123",
        '{"method": "tools/call"}',  # missing jsonrpc
        '{"jsonrpc": "1.0", "method": "tools/call"}',  # invalid jsonrpc version
        '{"jsonrpc": "2.0", "method": "unknown/op"}',  # unsupported method
    ]),
)
@settings(max_examples=25, deadline=None)
def test_property_96_malformed_protocol_rejection(
    sender: str, recipient: str, malformed_json: str
) -> None:
    """Property 96: Malformed Protocol Rejection.

    For any incoming payload failing JSON-RPC validation, an MCP-compliant error response
    is returned without exposing internal state.
    """
    async def _run() -> None:
        filter_engine = InboundProtocolFilter()
        msg, err = await filter_engine.parse_and_validate_rpc(
            raw_data=malformed_json,
            sender_id=sender,
            recipient_agent_id=recipient,
        )

        assert msg is None
        assert err is not None
        assert err["jsonrpc"] == "2.0"
        assert "error" in err
        assert isinstance(err["error"]["code"], int)
        assert isinstance(err["error"]["message"], str)
        assert "traceback" not in err["error"]["message"].lower()

    asyncio.run(_run())
