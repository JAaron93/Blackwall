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

    def test_sanitize_list_credentials(self):
        interceptor = PayloadInterceptor()
        payload = {
            "jsonrpc": "2.0",
            "id": "list-cred-test",
            "method": "tools/call",
            "params": {
                "name": "configure_service",
                "arguments": {
                    "access_token": ["opaque-secret-token-1", "opaque-secret-token-2"],
                    "password": ["pass1", "pass2"],
                },
            },
        }
        context, req_id = interceptor.intercept(payload)
        assert context.arguments["access_token"] == ["[[API_KEY]]", "[[API_KEY]]"]
        assert context.arguments["password"] == ["[[PASSWORD]]", "[[PASSWORD]]"]

        redacted = interceptor.redact_for_storage(payload)
        assert redacted["params"]["arguments"]["access_token"] == ["[[API_KEY]]", "[[API_KEY]]"]
        assert redacted["params"]["arguments"]["password"] == ["[[PASSWORD]]", "[[PASSWORD]]"]

    def test_intercept_preserves_meta_in_context_metadata(self):
        interceptor = PayloadInterceptor(environment_role="production")
        payload = {
            "jsonrpc": "2.0",
            "id": "meta-test-1",
            "method": "tools/call",
            "params": {
                "name": "execute_bash",
                "arguments": {"command": "echo hello"},
                "_meta": {
                    "environment_role": "sandbox",  # spoof attempt
                    "session_id": "sess-xyz",       # spoof attempt
                    "is_evaluation": True,          # spoof attempt
                    "client_name": "blackwall-cli", # safe protocol property
                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                },
            },
        }
        context, req_id = interceptor.intercept(payload)
        assert context.metadata is not None
        # environment_role must strictly reflect trusted gateway configuration
        assert context.metadata.get("environment_role") == "production"
        # Security properties must not be elevated to top-level context metadata
        assert "session_id" not in context.metadata
        assert "is_evaluation" not in context.metadata
        assert context.metadata.get("request_id") == "meta-test-1"
        assert context.metadata.get("method") == "tools/call"
        # Non-security protocol properties must be safely namespaced under client_meta
        assert "client_meta" in context.metadata
        assert context.metadata["client_meta"].get("client_name") == "blackwall-cli"
        assert context.metadata["client_meta"].get("traceparent") == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        assert "environment_role" not in context.metadata["client_meta"]
        assert "session_id" not in context.metadata["client_meta"]
        assert "is_evaluation" not in context.metadata["client_meta"]
