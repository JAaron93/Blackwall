"""
MCP JSON-RPC 2.0 HTTP transport client.

Provides low-level client logic for communicating with Model Context Protocol (MCP)
servers over HTTP POST using JSON-RPC 2.0 standards.
"""

from __future__ import annotations

import functools
import logging
import ssl
import uuid
from typing import Any

import aiohttp
import certifi

logger = logging.getLogger("blackwall.mcp.transport")


@functools.lru_cache(maxsize=4)
def get_certifi_ssl_context(cafile: str | None = None) -> ssl.SSLContext:
    """Return a cached, reusable SSLContext backed by certifi's CA trust bundle."""
    resolved_ca = cafile or certifi.where()
    return ssl.create_default_context(cafile=resolved_ca)


class MCPTransportError(Exception):
    """Base exception for MCP transport errors."""



class MCPConnectionError(MCPTransportError, ConnectionError):
    """Exception raised when connection to MCP server fails."""



class MCPTimeoutError(MCPTransportError, TimeoutError):
    """Exception raised when an MCP tool call times out."""



class MCPRemoteError(MCPTransportError):
    """Exception raised when MCP server returns a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"MCP JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


async def call_mcp_tool_http(
    endpoint_url: str,
    tool_name: str,
    arguments: dict[str, Any],
    api_key: str | None = None,
    timeout: float = 2.0,
) -> dict[str, Any]:
    """
    Invokes an MCP tool on a remote server using JSON-RPC 2.0 over HTTP POST.

    Args:
        endpoint_url: Remote MCP HTTP endpoint (e.g. 'http://localhost:8080/mcp').
        tool_name: Name of tool to execute (e.g. 'trace_path', 'lookup_indicator').
        arguments: Tool argument dictionary.
        api_key: Optional API key or bearer token.
        timeout: Execution timeout in seconds.

    Returns:
        The 'result' field of the JSON-RPC 2.0 response.
    """
    request_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        if api_key.startswith("Bearer "):
            headers["Authorization"] = api_key
        else:
            headers["x-apikey"] = api_key

    ssl_context = get_certifi_ssl_context()

    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context)
        ) as session, session.post(
            endpoint_url,
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise MCPConnectionError(
                    f"MCP server returned HTTP {resp.status}: {text}"
                )
            data = await resp.json()

        if not isinstance(data, dict):
            raise MCPTransportError(f"Invalid JSON-RPC response format: {data}")

        if data.get("error"):
            err = data["error"]
            code = err.get("code", -32603) if isinstance(err, dict) else -32603
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise MCPRemoteError(
                code, msg, err.get("data") if isinstance(err, dict) else None
            )

        result = data.get("result", {})
        if isinstance(result, dict) and (
            result.get("isError") or result.get("is_error")
        ):
            msg = "MCP tool execution failed"
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and "text" in first:
                    msg = str(first["text"])
            elif "message" in result:
                msg = str(result["message"])
            raise MCPRemoteError(code=-32000, message=msg, data=result)

        return result if isinstance(result, dict) else {"data": result}

    except TimeoutError as exc:
        logger.warning(
            "MCP call timed out for %s at %s: %s", tool_name, endpoint_url, exc
        )
        raise MCPTimeoutError(
            f"MCP tool call '{tool_name}' timed out after {timeout}s"
        ) from exc
    except (
        aiohttp.ClientConnectorError,
        aiohttp.ClientConnectionError,
        ConnectionRefusedError,
        OSError,
    ) as exc:
        logger.warning(
            "MCP connection failed for %s at %s: %s", tool_name, endpoint_url, exc
        )
        raise MCPConnectionError(
            f"Failed to connect to MCP server at {endpoint_url}: {exc}"
        ) from exc
