"""BDD Step Definitions for Inbound Protocol Filter (`tests/features/inbound_protocol_filter.feature`)."""

import uuid
from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

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
from tests.step_defs.async_utils import run_async

scenarios("../features/inbound_protocol_filter.feature")


class InboundFilterBDDState:
    """State holder for Inbound Protocol Filter BDD scenarios."""

    def __init__(self) -> None:
        self.alert_bus: AlertBus = AlertBus()
        self.filter: InboundProtocolFilter | None = None
        self.last_result: bool | None = None
        self.permitted_count: int = 0
        self.dropped_count: int = 0
        self.last_message: InboundProtocolMessage | None = None
        self.sanitized_message: InboundProtocolMessage | None = None
        self.error_response: dict[str, Any] | None = None


@pytest.fixture
def bdd_state() -> InboundFilterBDDState:
    return InboundFilterBDDState()


# Scenario 1


@given("an Inbound Protocol Filter configured for loopback endpoints")
def given_filter_loopback(bdd_state: InboundFilterBDDState) -> None:
    bdd_state.filter = InboundProtocolFilter(
        alert_bus=bdd_state.alert_bus,
        enforce_loopback=True,
    )


@when(
    parsers.parse(
        'an incoming request arrives from "{remote_ip}" with Origin "{origin}"'
    )
)
def when_request_with_origin(
    bdd_state: InboundFilterBDDState, remote_ip: str, origin: str
) -> None:
    assert bdd_state.filter is not None
    headers = {"Host": "localhost:8000", "Origin": origin}
    bdd_state.last_result = run_async(
        bdd_state.filter.validate_headers_and_origin(headers, remote_addr=remote_ip)
    )


@then("the header and origin validation rejects the request")
def then_validation_rejects(bdd_state: InboundFilterBDDState) -> None:
    assert bdd_state.last_result is False


# Scenario 2


@given(
    parsers.parse(
        "an Inbound Protocol Filter with a rate limit of {limit:d} requests per 60 seconds"
    )
)
def given_filter_with_rate_limit(
    bdd_state: InboundFilterBDDState, limit: int
) -> None:
    bdd_state.filter = InboundProtocolFilter(
        alert_bus=bdd_state.alert_bus,
        rate_limit_per_window=limit,
        sliding_window_sec=60,
    )


@when(
    parsers.parse(
        'agent "{agent_id}" sends {count:d} consecutive incoming requests'
    )
)
def when_agent_sends_burst(
    bdd_state: InboundFilterBDDState, agent_id: str, count: int
) -> None:
    assert bdd_state.filter is not None
    for _ in range(count):
        allowed = run_async(bdd_state.filter.check_inbound_rate_limit(agent_id))
        if allowed:
            bdd_state.permitted_count += 1
        else:
            bdd_state.dropped_count += 1


@then(
    parsers.parse(
        "{permitted:d} requests are permitted and {dropped:d} request is dropped"
    )
)
def then_rate_limit_enforced(
    bdd_state: InboundFilterBDDState, permitted: int, dropped: int
) -> None:
    assert bdd_state.permitted_count == permitted
    assert bdd_state.dropped_count == dropped


@then("an inbound rate limit alert is emitted to the Alert Bus")
def then_rate_limit_alert_emitted(bdd_state: InboundFilterBDDState) -> None:
    alerts = bdd_state.alert_bus.get_alerts(
        threat_type="INBOUND_RATE_LIMIT_EXCEEDED"
    )
    assert len(alerts) >= 1
    assert alerts[0].severity == AlertSeverity.HIGH


# Scenario 3


@given("an Inbound Protocol Filter instance")
def given_default_filter(bdd_state: InboundFilterBDDState) -> None:
    bdd_state.filter = InboundProtocolFilter(alert_bus=bdd_state.alert_bus)


@when(
    parsers.parse(
        'an incoming tools/call message is received containing "{secret1}" and "{secret2}"'
    )
)
def when_tools_call_with_secrets(
    bdd_state: InboundFilterBDDState, secret1: str, secret2: str
) -> None:
    assert bdd_state.filter is not None
    payload = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "login",
            "arguments": {
                secret1: "mypassword123",
                "auth_header": f"Bearer {secret2}",
                "safe_field": "valid_user",
            },
        },
    }
    msg = InboundProtocolMessage(
        sender_id="sender-agent",
        recipient_agent_id="host-agent",
        protocol=InboundProtocolType.MCP_SSE,
        method=InboundMethodType.TOOLS_CALL,
        payload=payload,
    )
    bdd_state.last_message = msg
    bdd_state.sanitized_message = run_async(
        bdd_state.filter.sanitize_incoming_rpc(msg)
    )


@then("the message payload is sanitized with secret placeholders before host agent execution")
def then_payload_sanitized(bdd_state: InboundFilterBDDState) -> None:
    assert bdd_state.sanitized_message is not None
    args = bdd_state.sanitized_message.payload["params"]["arguments"]
    assert args["password"] != "mypassword123"
    assert "_REDACTED" in args["password"] or "[[" in args["password"]
    assert "sk-proj-1234567890abcdef12345678" not in args["auth_header"]
    assert args["safe_field"] == "valid_user"


# Scenario 4


@when('a malformed JSON-RPC payload without a valid "jsonrpc" version is parsed')
def when_malformed_json_parsed(bdd_state: InboundFilterBDDState) -> None:
    assert bdd_state.filter is not None
    raw_payload = {"method": "tools/call", "params": {"name": "run"}}
    _, err = run_async(
        bdd_state.filter.parse_and_validate_rpc(
            raw_data=raw_payload,
            sender_id="remote-sender",
            recipient_agent_id="local-host",
        )
    )
    bdd_state.error_response = err


@then(
    parsers.parse(
        "an MCP compliant JSON-RPC error response with code {code:d} is synthesized"
    )
)
def then_error_code_synthesized(
    bdd_state: InboundFilterBDDState, code: int
) -> None:
    assert bdd_state.error_response is not None
    assert bdd_state.error_response["jsonrpc"] == "2.0"
    assert bdd_state.error_response["error"]["code"] == code
