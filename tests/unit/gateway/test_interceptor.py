import json
import pytest

from blackwall.gateway.exceptions import (
    MalformedPayloadError,
    MissingArgumentError,
)
from blackwall.gateway.interceptor import PayloadInterceptor
from blackwall.models import ToolCallContext


class TestPayloadInterceptor:
    """Test suite for MCP PayloadInterceptor (TASK-B01)."""

    def test_intercept_valid_tool_call(self):
        interceptor = PayloadInterceptor()
        raw_payload = {
            "jsonrpc": "2.0",
            "id": "call-101",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/normal_file.txt"},
            },
        }

        context, req_id = interceptor.intercept(raw_payload)

        assert isinstance(context, ToolCallContext)
        assert context.tool_name == "read_file"
        assert context.arguments == {"path": "/tmp/normal_file.txt"}
        assert req_id == "call-101"
        assert context.metadata is not None
        assert context.metadata.get("request_id") == "call-101"

    def test_intercept_sanitizes_credentials(self):
        interceptor = PayloadInterceptor()
        raw_payload = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com",
                    "headers": {
                        "Authorization": "Bearer sk-1234567890abcdef123456",
                        "password": "SuperSecretPassword123!",
                    },
                },
            },
        }

        context, req_id = interceptor.intercept(raw_payload)

        headers = context.arguments["headers"]
        # Invariant: raw secrets must be redacted with generic placeholders
        assert "sk-1234567890abcdef123456" not in str(headers)
        assert "SuperSecretPassword123!" not in str(headers)
        assert (
            "[[OPENAI_API_KEY]]" in str(headers)
            or "[[API_KEY]]" in str(headers)
            or "[[BEARER_TOKEN]]" in str(headers)
        )
        assert "[[PASSWORD]]" in str(headers)

    def test_intercept_json_string(self):
        interceptor = PayloadInterceptor()
        raw_str = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "str-id",
                "method": "tools/call",
                "params": {"name": "test_tool", "arguments": {"foo": "bar"}},
            }
        )

        context, req_id = interceptor.intercept(raw_str)
        assert context.tool_name == "test_tool"
        assert req_id == "str-id"

    def test_intercept_invalid_json_string(self):
        interceptor = PayloadInterceptor()
        with pytest.raises(MalformedPayloadError):
            interceptor.intercept("{ invalid json ...")

    def test_intercept_missing_jsonrpc_version(self):
        interceptor = PayloadInterceptor()
        payload = {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {}},
        }
        with pytest.raises(MalformedPayloadError):
            interceptor.intercept(payload)

    def test_intercept_non_tool_call_method(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
        with pytest.raises(MalformedPayloadError) as exc_info:
            interceptor.intercept(payload)
        assert "tools/call" in str(exc_info.value)

    def test_intercept_missing_params(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
        }
        with pytest.raises(MalformedPayloadError):
            interceptor.intercept(payload)

    def test_intercept_missing_tool_name(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {}},
        }
        with pytest.raises(MissingArgumentError):
            interceptor.intercept(payload)

    def test_intercept_malformed_arguments_type(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "test_tool", "arguments": "not-a-dict"},
        }
        with pytest.raises(MalformedPayloadError):
            interceptor.intercept(payload)

    def test_redact_for_storage(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "cmd": "curl -H 'Authorization: Bearer sk-1234567890abcdef123456' http://test.com"
                },
            },
        }

        redacted = interceptor.redact_for_storage(payload)
        assert "sk-1234567890abcdef123456" not in str(redacted)
        assert redacted["params"]["name"] == "bash"
