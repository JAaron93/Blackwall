"""
MCP Protocol Gateway Server for Blackwall.

Provides high-performance bidirectional JSON-RPC 2.0 streaming over both stdio
and MCP Streamable HTTP (POST /mcp + SSE) targeting MCP 2025-03-26.
Enforces transport security (Origin/Host validation, loopback default, bearer auth).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.parse
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from aiohttp import web

from blackwall.gateway.exceptions import (
    DuplicateRequestIdError,
    GatewayAuthError,
    MalformedPayloadError,
    QueueOverflowError,
    RequestTimeoutError,
)
from blackwall.gateway.flow import FlowController
from blackwall.gateway.interceptor import PayloadInterceptor
from blackwall.gateway.synthesizer import ResponseSynthesizer
from blackwall.models import ToolCallContext, VerdictDecision

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class MCPGatewayServer:
    """
    Protocol Gateway Server for the Model Context Protocol (MCP 2025-03-26 revision).

    Transports:
    - stdio: Stdin/stdout newline-delimited JSON-RPC streaming.
    - HTTP: Streamable HTTP (POST /mcp with application/json or SSE text/event-stream).

    Security Invariants:
    - Binds to loopback (127.0.0.1:9229) by default.
    - Validates Host header to prevent DNS rebinding attacks.
    - Validates Origin header for browser/web-bound requests.
    - Startup guard: refuses to bind to non-loopback host without an auth token.
    - Rejects unauthenticated non-loopback requests with HTTP 401.
    - Zero Node.js dependencies.
    """

    PROTOCOL_VERSION = "2025-03-26"
    SERVER_NAME = "blackwall-mcp-gateway"
    SERVER_VERSION = "2.0.0"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9229,
        auth_token: str | None = None,
        flow_controller: FlowController | None = None,
        interceptor: PayloadInterceptor | None = None,
        synthesizer: ResponseSynthesizer | None = None,
        resolver: Any = None,
        downstream_handler: (
            Callable[[dict[str, Any]], Awaitable[dict[str, Any]]] | None
        ) = None,
        timeout_seconds: float = 30.0,
        allowed_origins: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.is_loopback = self._is_loopback_host(host)

        # Authentication boundary & startup guard
        resolved_token = auth_token or os.getenv("BLACKWALL_AUTH_TOKEN")
        if not self.is_loopback and not resolved_token:
            raise GatewayAuthError(
                f"Refusing to start MCP Gateway on non-loopback host '{host}' "
                f"without an auth token. Provide --auth-token or set BLACKWALL_AUTH_TOKEN."
            )
        self.auth_token = resolved_token

        self.flow_controller = flow_controller or FlowController()
        self.interceptor = interceptor or PayloadInterceptor()
        self.synthesizer = synthesizer or ResponseSynthesizer()
        self.resolver = resolver
        self.downstream_handler = downstream_handler
        self.timeout_seconds = timeout_seconds

        self.allowed_origins = set(allowed_origins or [])
        self.allowed_hosts = set(allowed_hosts or [])

        self._sse_sessions: dict[str, asyncio.Queue[str]] = {}
        self._shutdown_event = asyncio.Event()

        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        """Determines whether a host address is a local loopback interface."""
        if host in LOOPBACK_HOSTS:
            return True
        if host.startswith("127."):
            return True
        return False

    def create_app(self) -> web.Application:
        """Configures the aiohttp web application with transport security middlewares."""
        app = web.Application(middlewares=[self._security_middleware])
        app.router.add_post("/mcp", self._handle_post_mcp)
        app.router.add_get("/mcp", self._handle_get_mcp)
        app.router.add_get("/health", self._handle_health)
        self._app = app
        return app

    @web.middleware
    async def _security_middleware(
        self, request: web.Request, handler: Any
    ) -> web.StreamResponse:
        """Enforces Host validation, Origin checking, and Bearer token authentication."""
        # 1. Host header validation (prevent DNS rebinding)
        host_hdr = request.headers.get("Host", "")
        if host_hdr:
            try:
                parsed_host = urllib.parse.urlsplit(f"http://{host_hdr}").hostname
                hostname = parsed_host or host_hdr.split(":")[0].strip()
            except Exception:
                hostname = host_hdr.split(":")[0].strip()

            allowed = (
                hostname in LOOPBACK_HOSTS
                or f"[{hostname}]" in LOOPBACK_HOSTS
                or hostname.startswith("127.")
                or hostname == self.host
                or f"[{hostname}]" == self.host
                or hostname in self.allowed_hosts
                or host_hdr in self.allowed_hosts
            )
            if not allowed:
                logger.warning("Rejected request with unauthorized Host: %s", host_hdr)
                return web.Response(
                    status=403,
                    text=f"Host header validation failed: '{host_hdr}' is not allowed.",
                )

        # 2. Origin header validation (prevent unauthorized web origins)
        origin_hdr = request.headers.get("Origin", "")
        if origin_hdr:
            parsed_origin = urllib.parse.urlparse(origin_hdr)
            origin_hostname = parsed_origin.hostname or ""
            allowed_origin = (
                origin_hostname in LOOPBACK_HOSTS
                or origin_hostname.startswith("127.")
                or origin_hostname == self.host
                or origin_hdr in self.allowed_origins
            )
            if not allowed_origin:
                logger.warning(
                    "Rejected request with unauthorized Origin: %s", origin_hdr
                )
                return web.Response(
                    status=403,
                    text=f"Origin validation failed: '{origin_hdr}' is not an authorized origin.",
                )

        # 3. Authentication check for non-loopback bindings
        if not self.is_loopback:
            auth_header = request.headers.get("Authorization", "")
            expected_auth = f"Bearer {self.auth_token}"
            if not auth_header or auth_header != expected_auth:
                logger.warning("Rejected unauthenticated request to non-loopback host")
                return web.Response(
                    status=401,
                    text="Unauthorized: Missing or invalid Bearer token.",
                    headers={"WWW-Authenticate": 'Bearer realm="Blackwall MCP Gateway"'},
                )

        return await handler(request)

    async def _handle_post_mcp(self, request: web.Request) -> web.StreamResponse:
        """Handles POST /mcp JSON-RPC requests, supporting JSON and SSE streaming."""
        try:
            payload = await request.json()
        except Exception as exc:
            err = self.synthesizer.synthesize_error(
                code=-32700, message=f"Parse error: {exc}", request_id=None
            )
            return web.json_response(err, status=200)

        response = await self.process_message(payload)

        # Support MCP 2025-03-26 Streamable HTTP text/event-stream responses
        accept_hdr = request.headers.get("Accept", "")
        if "text/event-stream" in accept_hdr:
            sse_resp = web.StreamResponse(
                status=200,
                headers={
                    "Content-Type": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )
            await sse_resp.prepare(request)
            event_payload = (
                f"event: message\ndata: {json.dumps(response)}\n\n"
            )
            await sse_resp.write(event_payload.encode("utf-8"))
            return sse_resp

        return web.json_response(response, status=200)

    async def _handle_get_mcp(self, request: web.Request) -> web.StreamResponse:
        """SSE channel for server-to-client streaming with active session registry."""
        session_id = str(uuid.uuid4())
        session_queue: asyncio.Queue[str] = asyncio.Queue()
        self._sse_sessions[session_id] = session_queue

        sse_resp = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await sse_resp.prepare(request)

        # Send initial connection acknowledgment with session identifier
        initial_msg = f": connected session={session_id}\n\n"
        await sse_resp.write(initial_msg.encode("utf-8"))

        try:
            while not self._shutdown_event.is_set():
                try:
                    payload = await asyncio.wait_for(session_queue.get(), timeout=15.0)
                    if self._shutdown_event.is_set() and payload == "":
                        break
                    await sse_resp.write(payload.encode("utf-8"))
                except asyncio.TimeoutError:
                    await sse_resp.write(b": ping\n\n")
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self._sse_sessions.pop(session_id, None)

        return sse_resp

    @property
    def active_sse_sessions(self) -> int:
        """Returns the count of active client SSE streaming sessions."""
        return len(self._sse_sessions)

    async def broadcast_sse(self, event: str, data: dict[str, Any]) -> int:
        """Broadcasts an SSE event to all connected streaming clients."""
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        delivered = 0
        for queue in list(self._sse_sessions.values()):
            try:
                queue.put_nowait(payload)
                delivered += 1
            except Exception:
                pass
        return delivered


    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response(
            {
                "status": "ok",
                "version": self.SERVER_VERSION,
                "protocol_version": self.PROTOCOL_VERSION,
                "active_requests": self.flow_controller.active_count,
            }
        )

    async def process_message(
        self, message: dict[str, Any] | str
    ) -> dict[str, Any]:
        """
        Unified JSON-RPC 2.0 message processor across both HTTP and stdio transports.

        Routes tools/call through interceptor -> flow control -> resolver -> synthesizer.
        Passes through non-tool methods (initialize, tools/list, notifications/*) directly.
        """
        if isinstance(message, str):
            try:
                data = json.loads(message)
            except Exception as exc:
                return self.synthesizer.synthesize_error(
                    code=-32700, message=f"Parse error: {exc}", request_id=None
                )
        else:
            data = message

        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
            return self.synthesizer.synthesize_error(
                code=-32600,
                message="Invalid Request: 'jsonrpc' must be '2.0'",
                request_id=data.get("id") if isinstance(data, dict) else None,
            )

        req_id = data.get("id")
        method = data.get("method", "")
        params = data.get("params", {})

        # 1. Passthrough non-tool methods
        if self.flow_controller.is_passthrough(method):
            return await self._handle_passthrough(data, req_id, method, params)

        # 2. Gated tool call interception
        if self.flow_controller.is_tool_call(method):
            return await self._handle_tool_call(data, req_id, method, params)

        # 3. Unknown method
        return self.synthesizer.synthesize_error(
            code=-32601,
            message=f"Method not found: '{method}'",
            request_id=req_id,
        )

    async def _handle_passthrough(
        self,
        raw_data: dict[str, Any],
        req_id: Any,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Handles non-tool MCP protocol methods."""
        if method == "notifications/cancelled":
            cancel_id = params.get("requestId") or params.get("id")
            if cancel_id:
                self.flow_controller.cancel_request(cancel_id)

        # If a downstream tool server handler is attached, forward pass-through requests
        if self.downstream_handler is not None:
            try:
                return await self.downstream_handler(raw_data)
            except Exception as exc:
                logger.error(
                    "Downstream passthrough error for method '%s': %s", method, exc
                )
                return self.synthesizer.synthesize_error(
                    code=-32603,
                    message=f"Downstream error handling '{method}'",
                    request_id=req_id,
                )

        # Standalone defaults when no downstream handler is attached
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION,
                    },
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": []},
            }

        if method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        if method.startswith("notifications/"):
            return {}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        }

    async def _handle_tool_call(
        self,
        raw_payload: dict[str, Any],
        req_id: Any,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluates tools/call requests through Blackwall threat intelligence pipeline."""
        try:
            context, extracted_id = self.interceptor.intercept(raw_payload)
        except MalformedPayloadError as exc:
            return self.synthesizer.synthesize_error(
                code=-32602, message=f"Invalid params: {exc}", request_id=req_id
            )

        try:
            await self.flow_controller.hold_request(req_id, method, params)
        except QueueOverflowError as exc:
            return self.synthesizer.synthesize_error(
                code=-32000, message=str(exc), request_id=req_id
            )
        except DuplicateRequestIdError as exc:
            return self.synthesizer.synthesize_error(
                code=-32600, message=str(exc), request_id=req_id
            )

        # Start background evaluation and execution so timeout covers the entire operation
        eval_task = asyncio.create_task(
            self._evaluate_and_execute(req_id, context, raw_payload)
        )

        try:
            response = await self.flow_controller.wait_for_verdict(
                req_id, timeout=self.timeout_seconds
            )
            return response
        finally:
            if not eval_task.done():
                eval_task.cancel()

    async def _evaluate_and_execute(
        self,
        req_id: Any,
        context: ToolCallContext,
        raw_payload: dict[str, Any],
    ) -> None:
        """Evaluates policy and forwards allowed tool execution to downstream handler."""
        try:
            if self.resolver is not None:
                verdict = await self.resolver.evaluate(context)
                if verdict.decision in (
                    VerdictDecision.BLOCK,
                    VerdictDecision.QUARANTINE,
                ):
                    err_response = self.synthesizer.synthesize_verdict(
                        verdict, req_id
                    )
                    self.flow_controller.resolve_request(req_id, err_response)
                    return

            # ALLOW verdict (or standalone without attached resolver)
            if self.downstream_handler is not None:
                try:
                    downstream_response = await self.downstream_handler(raw_payload)
                    self.flow_controller.resolve_request(req_id, downstream_response)
                except Exception as down_exc:
                    logger.error(
                        "Downstream execution error on req_id=%s: %s", req_id, down_exc
                    )
                    err_resp = self.synthesizer.synthesize_error(
                        code=-32603,
                        message="Downstream tool execution failed",
                        request_id=req_id,
                    )
                    self.flow_controller.resolve_request(req_id, err_resp)
            else:
                err_resp = self.synthesizer.synthesize_error(
                    code=-32603,
                    message="Blackwall Gateway: Tool call allowed by policy, but no downstream server is configured to execute it",
                    request_id=req_id,
                )
                self.flow_controller.resolve_request(req_id, err_resp)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Resolver evaluation error on req_id=%s: %s", req_id, exc)
            err_resp = self.synthesizer.synthesize_error(
                code=-32603,
                message="Blackwall Firewall: Internal evaluation error",
                request_id=req_id,
            )
            self.flow_controller.resolve_request(req_id, err_resp)

    async def handle_stdio_stream(
        self,
        reader: asyncio.StreamReader,
        writer: Any,
    ) -> None:
        """Processes continuous newline-delimited JSON-RPC streams over stdio asynchronously."""
        logger.info("Started MCP stdio transport stream handler")
        active_tasks: set[asyncio.Task[Any]] = set()

        async def _handle_line(line_text: str) -> None:
            try:
                response = await self.process_message(line_text)
                if response:
                    out_bytes = (json.dumps(response) + "\n").encode("utf-8")
                    writer.write(out_bytes)
                    if hasattr(writer, "drain"):
                        await writer.drain()
            except Exception as exc:
                logger.error("Error processing stdio message: %s", exc)

        try:
            while True:
                line = await reader.readline()
                if not line:
                    logger.info("Stdio stream reached EOF")
                    break

                text = line.decode("utf-8").strip()
                if not text:
                    continue

                task = asyncio.create_task(_handle_line(text))
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)
        finally:
            if active_tasks:
                await asyncio.gather(*active_tasks, return_exceptions=True)

    async def start_http(self) -> None:
        """Starts the asynchronous HTTP server on the configured host and port."""
        app = self.create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        logger.info(
            "Blackwall MCP Gateway HTTP server listening on http://%s:%d (loopback=%s)",
            self.host,
            self.port,
            self.is_loopback,
        )

    async def stop(self) -> None:
        """Gracefully shuts down the HTTP server, clears pending requests, and closes SSE streams."""
        self._shutdown_event.set()
        for queue in list(self._sse_sessions.values()):
            try:
                queue.put_nowait("")
            except Exception:
                pass
        self._sse_sessions.clear()

        if self._site:
            await self._site.stop()
            self._site = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self.flow_controller.cleanup_abandoned(max_age_seconds=0.0)
        logger.info("Blackwall MCP Gateway server stopped")

