"""Unit tests for true MCP JSON-RPC 2.0 adapters and transport layer.

Tests cover:
1. Low-level JSON-RPC 2.0 HTTP transport (`call_mcp_tool_http`).
2. Error mapping (`MCPConnectionError`, `MCPTimeoutError`, `MCPRemoteError`).
3. `CodebaseMemoryClient` MCP tool execution, payload dispatch, and result deserialization.
4. `GTIMCPClient` dual-mode endpoint detection, JSON-RPC query execution, and response normalization.
5. Backward compatibility with VirusTotal v3 REST endpoints.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blackwall.mcp.codebase_memory import (
    BlastRadiusIsolation,
    BlastRadiusReport,
    CodebaseMemoryClient,
    CriticalSink,
    CriticalSinkType,
    DataFlowPath,
    DependencyChain,
)
from blackwall.mcp.gti_client import GTIMCPClient, GTIQueryBudgetTracker
from blackwall.mcp.transport import (
    MCPConnectionError,
    MCPRemoteError,
    MCPTimeoutError,
    call_mcp_tool_http,
)
from blackwall.models import GTIResponse, IndicatorType

# ===========================================================================
# Section 1: Low-level MCP JSON-RPC 2.0 HTTP Transport Tests
# ===========================================================================


class MockHttpResponse:
    def __init__(self, status: int, json_data: dict | None = None, text_data: str = ""):
        self.status = status
        self._json_data = json_data or {}
        self._text_data = text_data

    def raise_for_status(self):
        if self.status >= 400:
            import aiohttp

            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=self.status,
                message=f"HTTP {self.status}",
            )

    async def json(self):
        return self._json_data

    async def text(self):
        return self._text_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockHttpSession:
    def __init__(self, response: MockHttpResponse):
        self._response = response
        self.recorded_post_url: str | None = None
        self.recorded_post_json: dict | None = None
        self.recorded_post_headers: dict | None = None

    def post(self, url: str, json: dict, headers: dict, **kwargs):
        self.recorded_post_url = url
        self.recorded_post_json = json
        self.recorded_post_headers = headers
        return self._response

    def get(self, url: str, headers: dict, **kwargs):
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockTimeoutSession:
    def post(self, *args, **kwargs):
        raise TimeoutError("Timed out")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_call_mcp_tool_http_success():
    """Verify call_mcp_tool_http formats JSON-RPC 2.0 payload and returns result."""
    response_payload = {
        "jsonrpc": "2.0",
        "id": "test-uuid",
        "result": {"status": "ok", "value": 42},
    }
    mock_resp = MockHttpResponse(200, json_data=response_payload)
    mock_session = MockHttpSession(mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await call_mcp_tool_http(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="trace_path",
            arguments={"qualified_name": "ProcessOrder"},
            api_key="secret-key",
            timeout=2.0,
        )

    assert result == {"status": "ok", "value": 42}
    assert mock_session.recorded_post_url == "http://localhost:8080/mcp"
    assert mock_session.recorded_post_json["jsonrpc"] == "2.0"
    assert mock_session.recorded_post_json["method"] == "tools/call"
    assert mock_session.recorded_post_json["params"]["name"] == "trace_path"
    assert mock_session.recorded_post_json["params"]["arguments"] == {
        "qualified_name": "ProcessOrder"
    }
    assert mock_session.recorded_post_headers["x-apikey"] == "secret-key"


@pytest.mark.asyncio
async def test_call_mcp_tool_http_bearer_auth():
    """Verify call_mcp_tool_http formats Authorization header for Bearer tokens."""
    response_payload = {
        "jsonrpc": "2.0",
        "id": "test-uuid",
        "result": {"status": "ok"},
    }
    mock_resp = MockHttpResponse(200, json_data=response_payload)
    mock_session = MockHttpSession(mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await call_mcp_tool_http(
            endpoint_url="https://gti.googleapis.com/mcp",
            tool_name="lookup_indicator",
            arguments={"indicator": "1.1.1.1"},
            api_key="Bearer ya29.oauth-token",
        )

    assert (
        mock_session.recorded_post_headers["Authorization"] == "Bearer ya29.oauth-token"
    )
    assert "x-apikey" not in mock_session.recorded_post_headers


@pytest.mark.asyncio
async def test_call_mcp_tool_http_jsonrpc_error():
    """Verify call_mcp_tool_http raises MCPRemoteError on server error response."""
    error_payload = {
        "jsonrpc": "2.0",
        "id": "test-uuid",
        "error": {"code": -32601, "message": "Method not found", "data": "trace_path"},
    }
    mock_resp = MockHttpResponse(200, json_data=error_payload)
    mock_session = MockHttpSession(mock_resp)

    with (
        patch("aiohttp.ClientSession", return_value=mock_session),
        pytest.raises(MCPRemoteError) as exc_info,
    ):
        await call_mcp_tool_http(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="unknown_tool",
            arguments={},
        )

    assert exc_info.value.code == -32601
    assert "Method not found" in exc_info.value.message
    assert exc_info.value.data == "trace_path"


@pytest.mark.asyncio
async def test_call_mcp_tool_http_http_error():
    """Verify call_mcp_tool_http raises MCPConnectionError on HTTP >= 400."""
    mock_resp = MockHttpResponse(502, text_data="Bad Gateway")
    mock_session = MockHttpSession(mock_resp)

    with (
        patch("aiohttp.ClientSession", return_value=mock_session),
        pytest.raises(MCPConnectionError) as exc_info,
    ):
        await call_mcp_tool_http(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="trace_path",
            arguments={},
        )

    assert "HTTP 502: Bad Gateway" in str(exc_info.value)
    assert isinstance(exc_info.value, ConnectionError)


@pytest.mark.asyncio
async def test_call_mcp_tool_http_timeout():
    """Verify call_mcp_tool_http raises MCPTimeoutError on asyncio.TimeoutError."""
    with (
        patch("aiohttp.ClientSession", return_value=MockTimeoutSession()),
        pytest.raises(MCPTimeoutError) as exc_info,
    ):
        await call_mcp_tool_http(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="slow_tool",
            arguments={},
            timeout=0.1,
        )

    assert "timed out" in str(exc_info.value)
    assert isinstance(exc_info.value, TimeoutError)


# ===========================================================================
# Section 2: CodebaseMemoryClient Remote MCP Integration Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_codebase_memory_query_dependency_chain_mcp():
    """Verify CodebaseMemoryClient invokes trace_path over MCP and deserializes DependencyChain."""
    client = CodebaseMemoryClient(base_url="http://localhost:8080/mcp")

    mcp_result = {
        "rootFunction": "AuthenticateUser",
        "callChain": ["AuthenticateUser", "CheckPassword", "QueryDB"],
        "depth": 3,
        "hasCriticalSink": True,
        "criticalSinks": ["QueryDB"],
    }

    with patch(
        "blackwall.mcp.codebase_memory.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        chain = await client.queryDependencyChain("AuthenticateUser")

        mock_call.assert_called_once_with(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="trace_path",
            arguments={"qualified_name": "AuthenticateUser"},
            timeout=2.0,
        )

        assert isinstance(chain, DependencyChain)
        assert chain.rootFunction == "AuthenticateUser"
        assert chain.depth == 3
        assert chain.hasCriticalSink is True
        assert chain.criticalSinks == ["QueryDB"]


@pytest.mark.asyncio
async def test_codebase_memory_identify_critical_sinks_mcp():
    """Verify CodebaseMemoryClient invokes query_graph over MCP and deserializes CriticalSink list."""
    client = CodebaseMemoryClient(base_url="http://localhost:8080/mcp")

    mcp_result = {
        "sinks": [
            {
                "sinkType": "SQL_QUERY",
                "functionName": "ExecuteRawSQL",
                "modulePath": "src/db.py",
                "isUnsafe": True,
                "mitigationHint": "Use parameterized queries.",
            }
        ]
    }

    with patch(
        "blackwall.mcp.codebase_memory.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        sinks = await client.identifyCriticalSinks("src/db.py")

        assert len(sinks) == 1
        assert isinstance(sinks[0], CriticalSink)
        assert sinks[0].sinkType == CriticalSinkType.SQL_QUERY
        assert sinks[0].functionName == "ExecuteRawSQL"
        assert sinks[0].isUnsafe is True


@pytest.mark.asyncio
async def test_codebase_memory_trace_data_flow_mcp():
    """Verify CodebaseMemoryClient invokes trace_path for data flow and deserializes DataFlowPath."""
    client = CodebaseMemoryClient(base_url="http://localhost:8080/mcp")

    mcp_result = {
        "sourceNode": "request_param",
        "sinkNode": "os_system",
        "intermediateNodes": ["parse_request"],
        "isTainted": True,
        "sanitizationPoints": [],
    }

    with patch(
        "blackwall.mcp.codebase_memory.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        path = await client.traceDataFlow("request_param", "os_system")

        assert isinstance(path, DataFlowPath)
        assert path.isTainted is True
        assert path.sourceNode == "request_param"
        assert path.sinkNode == "os_system"


@pytest.mark.asyncio
async def test_codebase_memory_get_blast_radius_mcp():
    """Verify CodebaseMemoryClient invokes get_architecture and deserializes BlastRadiusReport."""
    client = CodebaseMemoryClient(base_url="http://localhost:8080/mcp")

    mcp_result = {
        "targetNode": "AuthService",
        "affectedModules": ["api", "auth", "db"],
        "affectedFunctions": ["login", "verify_token"],
        "riskScore": 0.85,
        "isolation": "LOW",
    }

    with patch(
        "blackwall.mcp.codebase_memory.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        report = await client.getBlastRadius("AuthService")

        assert isinstance(report, BlastRadiusReport)
        assert report.targetNode == "AuthService"
        assert report.riskScore == 0.85
        assert report.isolation == BlastRadiusIsolation.LOW


@pytest.mark.asyncio
async def test_codebase_memory_content_text_json_unwrapping():
    """Verify CodebaseMemoryClient correctly unwraps MCP content text JSON strings."""
    client = CodebaseMemoryClient(base_url="http://localhost:8080/mcp")

    raw_json_str = (
        '{"rootFunction": "WrappedFunc", "callChain": ["WrappedFunc"], '
        '"depth": 1, "hasCriticalSink": false, "criticalSinks": []}'
    )
    mcp_result = {"content": [{"type": "text", "text": raw_json_str}]}

    with patch(
        "blackwall.mcp.codebase_memory.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        chain = await client.queryDependencyChain("WrappedFunc")

        assert isinstance(chain, DependencyChain)
        assert chain.rootFunction == "WrappedFunc"
        assert chain.depth == 1


# ===========================================================================
# Section 3: GTIMCPClient Dual-Mode Protocol Detection & MCP Queries
# ===========================================================================


def test_gti_is_mcp_endpoint_detection():
    """Verify _is_mcp_endpoint correctly discriminates MCP endpoints from REST."""
    mock_repo = MagicMock()

    # MCP endpoints
    client_mcp1 = GTIMCPClient(
        repo=mock_repo, base_url="https://gti.googleapis.com/mcp"
    )
    assert client_mcp1._is_mcp_endpoint() is True

    client_mcp2 = GTIMCPClient(repo=mock_repo, base_url="http://localhost:8080/mcp/")
    assert client_mcp2._is_mcp_endpoint() is True

    client_mcp3 = GTIMCPClient(repo=mock_repo, base_url="https://api.domain.org/mcp/v1")
    assert client_mcp3._is_mcp_endpoint() is True

    # REST endpoints
    client_rest1 = GTIMCPClient(
        repo=mock_repo, base_url="https://www.virustotal.com/api/v3"
    )
    assert client_rest1._is_mcp_endpoint() is False

    client_rest2 = GTIMCPClient(
        repo=mock_repo, base_url="https://virustotal.com/api/v3/"
    )
    assert client_rest2._is_mcp_endpoint() is False

    # Empty / None
    client_none = GTIMCPClient(repo=mock_repo, base_url="")
    assert client_none._is_mcp_endpoint() is False


@pytest.mark.asyncio
async def test_gti_mcp_jsonrpc_query_execution():
    """Verify GTIMCPClient executes lookup_indicator via JSON-RPC 2.0 when base_url is an MCP endpoint."""
    mock_repo = MagicMock()
    mock_repo.get_cached_gti_response = AsyncMock(return_value=None)
    mock_repo.cache_gti_response = AsyncMock()

    tracker = GTIQueryBudgetTracker(capacity=10)
    client = GTIMCPClient(
        repo=mock_repo,
        api_key="mcp-api-key",
        base_url="https://gti.googleapis.com/mcp",
        budget_tracker=tracker,
    )
    client.is_high_risk = AsyncMock(return_value=True)

    mcp_result = {
        "indicator": "198.51.100.1",
        "is_malicious": True,
        "threat_categories": ["c2-botnet", "trojan"],
        "detection_rate": 45.0,
        "last_analysis_date": "2026-09-12T10:00:00Z",
        "related_campaigns": ["c2-infrastructure"],
        "confidence": 0.45,
    }

    with patch(
        "blackwall.mcp.gti_client.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        response = await client.queryIOC("198.51.100.1", IndicatorType.IP_ADDRESS)

        mock_call.assert_called_once_with(
            endpoint_url="https://gti.googleapis.com/mcp",
            tool_name="lookup_indicator",
            arguments={"indicator": "198.51.100.1", "type": "IP_ADDRESS"},
            api_key="mcp-api-key",
            timeout=5.0,
        )

        assert isinstance(response, GTIResponse)
        assert response.indicator == "198.51.100.1"
        assert response.is_malicious is True
        assert response.threat_categories == ["c2-botnet", "trojan"]
        assert response.detection_rate == 45.0
        assert response.confidence == 0.45
        mock_repo.cache_gti_response.assert_called_once()

    tracker.close()


@pytest.mark.asyncio
async def test_gti_mcp_content_text_json_normalization():
    """Verify GTIMCPClient unwraps MCP text content payloads."""
    mock_repo = MagicMock()
    mock_repo.get_cached_gti_response = AsyncMock(return_value=None)
    mock_repo.cache_gti_response = AsyncMock()

    tracker = GTIQueryBudgetTracker(capacity=10)
    client = GTIMCPClient(
        repo=mock_repo,
        api_key="mcp-api-key",
        base_url="https://gti.googleapis.com/mcp",
        budget_tracker=tracker,
    )
    client.is_high_risk = AsyncMock(return_value=True)

    json_str = (
        '{"indicator": "malicious.org", "is_malicious": true, '
        '"threat_categories": ["phishing"], "detection_rate": 30.0, "confidence": 0.3}'
    )
    mcp_result = {"content": [{"type": "text", "text": json_str}]}

    with patch(
        "blackwall.mcp.gti_client.call_mcp_tool_http", new_callable=AsyncMock
    ) as mock_call:
        mock_call.return_value = mcp_result

        response = await client.queryIOC("malicious.org", IndicatorType.DOMAIN)

        assert isinstance(response, GTIResponse)
        assert response.indicator == "malicious.org"
        assert response.is_malicious is True
        assert response.threat_categories == ["phishing"]
        assert response.detection_rate == 30.0

    tracker.close()


@pytest.mark.asyncio
async def test_gti_virustotal_rest_backward_compatibility():
    """Verify GTIMCPClient continues to use VirusTotal v3 REST when pointed at REST URL."""
    mock_repo = MagicMock()
    mock_repo.get_cached_gti_response = AsyncMock(return_value=None)
    mock_repo.cache_gti_response = AsyncMock()

    tracker = GTIQueryBudgetTracker(capacity=10)
    client = GTIMCPClient(
        repo=mock_repo,
        api_key="vt-api-key",
        base_url="https://www.virustotal.com/api/v3",
        budget_tracker=tracker,
    )
    client.is_high_risk = AsyncMock(return_value=True)

    vt_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 0,
                },
                "last_analysis_results": {},
                "tags": ["c2-network"],
            }
        }
    }

    mock_resp = MockHttpResponse(200, json_data=vt_payload)
    mock_session = MockHttpSession(mock_resp)

    # Patch ClientSession to return our MockHttpSession
    with patch("aiohttp.ClientSession", return_value=mock_session):
        response = await client.queryIOC("198.51.100.5", IndicatorType.IP_ADDRESS)

        assert isinstance(response, GTIResponse)
        assert response.indicator == "198.51.100.5"
        assert response.is_malicious is True
        assert response.detection_rate == 20.0  # (8+2)/50 * 100
        assert "c2-network" in response.related_campaigns

    tracker.close()


@pytest.mark.asyncio
async def test_call_mcp_tool_http_tool_execution_error_is_error():
    """Verify call_mcp_tool_http raises MCPRemoteError when result.isError is true."""
    error_payload = {
        "jsonrpc": "2.0",
        "id": "test-uuid",
        "result": {
            "isError": True,
            "content": [{"type": "text", "text": "Indicator lookup failed on server"}],
        },
    }
    mock_resp = MockHttpResponse(200, json_data=error_payload)
    mock_session = MockHttpSession(mock_resp)

    with (
        patch("aiohttp.ClientSession", return_value=mock_session),
        pytest.raises(MCPRemoteError) as exc_info,
    ):
        await call_mcp_tool_http(
            endpoint_url="http://localhost:8080/mcp",
            tool_name="lookup_indicator",
            arguments={"indicator": "bad.com"},
        )

    assert "Indicator lookup failed on server" in exc_info.value.message
    assert exc_info.value.code == -32000


@pytest.mark.asyncio
async def test_gti_mcp_credential_resolution_failure_stops_request():
    """Verify GTIMCPClient raises ValueError on credential resolution failure without sending request."""
    mock_repo = MagicMock()
    mock_repo.get_cached_gti_response = AsyncMock(return_value=None)

    tracker = GTIQueryBudgetTracker(capacity=10)
    client = GTIMCPClient(
        repo=mock_repo,
        api_key="tmp_invalid_or_expired_token",
        base_url="https://gti.googleapis.com/mcp",
        budget_tracker=tracker,
    )
    client.is_high_risk = AsyncMock(return_value=True)

    with (
        patch(
            "blackwall.mcp.gti_client.call_mcp_tool_http", new_callable=AsyncMock
        ) as mock_call,
        pytest.raises(ValueError) as exc_info,
    ):
        await client.queryIOC("198.51.100.1", IndicatorType.IP_ADDRESS)

    assert "API credential resolution failed" in str(exc_info.value)
    mock_call.assert_not_called()
    tracker.close()


@pytest.mark.asyncio
async def test_gti_mcp_tool_error_triggers_failure_handling():
    """Verify GTIMCPClient records failure when remote MCP tool raises MCPRemoteError."""
    mock_repo = MagicMock()
    mock_repo.get_cached_gti_response = AsyncMock(return_value=None)

    tracker = GTIQueryBudgetTracker(capacity=10)
    client = GTIMCPClient(
        repo=mock_repo,
        api_key="valid-key",
        base_url="https://gti.googleapis.com/mcp",
        budget_tracker=tracker,
    )
    client.is_high_risk = AsyncMock(return_value=True)

    with (
        patch(
            "blackwall.mcp.gti_client.call_mcp_tool_http",
            side_effect=MCPRemoteError(-32000, "Tool failure"),
        ),
        pytest.raises(MCPRemoteError),
    ):
        await client.queryIOC("198.51.100.1", IndicatorType.IP_ADDRESS)

    assert client.consecutive_failures == 1
    tracker.close()

