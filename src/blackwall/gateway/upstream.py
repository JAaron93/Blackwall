"""
Upstream Tool Server Manager for Blackwall MCP Gateway.

Manages downstream MCP tool server lifecycles and request forwarding:
- Wrap mode (--wrap): Spawns a single downstream MCP tool server as a stdio child process.
- Multi-server mode (gateway.yaml): Parses YAML configuration, manages multiple downstream
  servers (stdio and HTTP), routes tools/call requests by tool name, and aggregates tools/list.
- Process group isolation (os.setsid on POSIX) and clean SIGTERM/SIGKILL shutdown (Rule 10).
- HTTP connection pooling via aiohttp.ClientSession.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import signal
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import aiohttp
import yaml

from blackwall.gateway.exceptions import (
    InvalidGatewayConfigError,
    UpstreamProcessError,
    UpstreamServerNotFoundError,
    UpstreamTimeoutError,
)

logger = logging.getLogger(__name__)


class BaseUpstreamServer(ABC):
    """Abstract base class for upstream tool servers."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._tools: list[dict[str, Any]] = []

    @property
    def tools(self) -> list[dict[str, Any]]:
        """List of tools registered by this upstream server."""
        return self._tools

    @abstractmethod
    async def start(self) -> None:
        """Starts the upstream server connection or child process."""

    @abstractmethod
    async def stop(self) -> None:
        """Stops the upstream server and releases resources."""

    @abstractmethod
    async def send_request(
        self, payload: dict[str, Any], timeout: float = 30.0
    ) -> dict[str, Any]:
        """Sends a JSON-RPC 2.0 payload and returns the response."""

    @abstractmethod
    async def is_healthy(self) -> bool:
        """Returns True if the upstream server is operational."""


class StdioUpstreamServer(BaseUpstreamServer):
    """
    Manages an MCP tool server running as a child process over stdio.

    Features:
    - Process-group isolation (preexec_fn=os.setsid) on POSIX.
    - Continuous newline-delimited JSON-RPC communication.
    - Request ID tracking with pending asyncio.Futures.
    - Graceful SIGTERM shutdown with SIGKILL fallback (Rule 10).
    """

    def __init__(
        self,
        name: str,
        command: str | list[str],
        env: dict[str, str] | None = None,
    ) -> None:
        super().__init__(name)
        if isinstance(command, str):
            self.command_args = shlex.split(command)
        else:
            self.command_args = list(command)

        if not self.command_args:
            raise ValueError(f"StdioUpstreamServer '{name}' command cannot be empty.")

        self.env = env
        self._proc: asyncio.subprocess.Process | None = None
        self._pending: dict[Any, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._stopping = False

    @property
    def pid(self) -> int | None:
        """Returns the process ID of the child process if running."""
        return self._proc.pid if self._proc else None

    async def start(self) -> None:
        """Spawns the child process in its own process group."""
        if self._proc is not None:
            return

        self._stopping = False
        preexec = os.setsid if hasattr(os, "setsid") else None

        merged_env = os.environ.copy()
        if self.env:
            merged_env.update(self.env)

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self.command_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=preexec,
                env=merged_env,
            )
        except Exception as exc:
            raise UpstreamProcessError(
                f"Failed to spawn stdio upstream '{self.name}': {exc}"
            ) from exc

        self._reader_task = asyncio.create_task(self._stdout_loop())
        self._stderr_task = asyncio.create_task(self._stderr_loop())
        logger.info(
            "Spawned stdio upstream server '%s' (PID %s): %s",
            self.name,
            self._proc.pid,
            " ".join(self.command_args),
        )

    def _reap_process(self) -> None:
        """Explicitly reaps the child process using poll() to prevent zombie processes."""
        if self._proc is not None:
            if hasattr(self._proc, "poll"):
                self._proc.poll()
            elif hasattr(self._proc, "_transport") and self._proc._transport:
                subproc = self._proc._transport.get_extra_info("subprocess")
                if subproc and hasattr(subproc, "poll"):
                    subproc.poll()

    async def _stdout_loop(self) -> None:
        """Continuously reads newline-delimited JSON-RPC responses from stdout."""
        if not self._proc or not self._proc.stdout:
            return

        while not self._stopping:
            try:
                line = await self._proc.stdout.readline()
                if not line:
                    self._reap_process()
                    if not self._stopping:
                        for req_id, fut in list(self._pending.items()):
                            if not fut.done():
                                fut.set_exception(
                                    UpstreamProcessError("Upstream process exited abruptly")
                                )
                        self._pending.clear()
                    break

                text = line.decode("utf-8").strip()
                if not text:
                    continue

                try:
                    data = json.loads(text)
                except Exception:
                    logger.debug(
                        "Malformed JSON on stdout from '%s': %s", self.name, text
                    )
                    continue

                if isinstance(data, dict):
                    req_id = data.get("id")
                    if req_id is not None and req_id in self._pending:
                        fut = self._pending.pop(req_id)
                        if not fut.done():
                            fut.set_result(data)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                if not self._stopping:
                    logger.error(
                        "Error reading stdout from upstream '%s': %s", self.name, exc
                    )
                    for req_id, fut in list(self._pending.items()):
                        if not fut.done():
                            fut.set_exception(
                                UpstreamProcessError(
                                    f"Upstream server '{self.name}' reader failed: {exc}"
                                )
                            )
                    self._pending.clear()
                break

    async def _stderr_loop(self) -> None:
        """Drains stderr to prevent buffer deadlocks and logs warnings."""
        if not self._proc or not self._proc.stderr:
            return

        while not self._stopping:
            try:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    logger.debug("[%s stderr] %s", self.name, text)
            except (asyncio.CancelledError, Exception):
                break

    async def send_request(
        self, payload: dict[str, Any], timeout: float = 30.0
    ) -> dict[str, Any]:
        """Sends a JSON-RPC message over stdin and awaits the response."""
        if self._proc is None or self._proc.returncode is not None:
            raise UpstreamProcessError(
                f"Cannot send request: stdio upstream '{self.name}' is not running."
            )

        req_id = payload.get("id")
        line = json.dumps(payload) + "\n"

        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] | None = None
        if req_id is not None:
            future = loop.create_future()
            self._pending[req_id] = future

        try:
            async with self._lock:
                if not self._proc or not self._proc.stdin:
                    raise UpstreamProcessError(
                        f"Process stdin unavailable for '{self.name}'."
                    )
                self._proc.stdin.write(line.encode("utf-8"))
                await self._proc.stdin.drain()

            if future is None:
                # Notification without ID
                return {}

            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            if req_id is not None:
                self._pending.pop(req_id, None)
            raise UpstreamTimeoutError(
                f"Upstream server '{self.name}' timed out after {timeout}s on request ID '{req_id}'"
            ) from exc
        except Exception as exc:
            if req_id is not None:
                self._pending.pop(req_id, None)
            if not isinstance(exc, (UpstreamTimeoutError, UpstreamProcessError)):
                raise UpstreamProcessError(
                    f"Error communicating with upstream '{self.name}': {exc}"
                ) from exc
            raise

    async def is_healthy(self) -> bool:
        """Returns True if the child process is alive and running."""
        return self._proc is not None and self._proc.returncode is None

    async def stop(self) -> None:
        """Terminates the process group cleanly with SIGTERM and SIGKILL fallback (Rule 10)."""
        self._stopping = True

        for req_id, fut in list(self._pending.items()):
            if not fut.done():
                fut.set_exception(
                    UpstreamProcessError(
                        f"Upstream server '{self.name}' stopped while request '{req_id}' was in flight."
                    )
                )
        self._pending.clear()

        proc = self._proc
        self._proc = None

        if proc is not None and proc.returncode is None:
            pid = proc.pid
            try:
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    try:
                        pgid = os.getpgid(pid)
                        os.killpg(pgid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                else:
                    proc.terminate()

                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                        try:
                            pgid = os.getpgid(pid)
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            except (ProcessLookupError, OSError):
                pass

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None

        logger.info("Stopped stdio upstream server '%s'", self.name)


class HttpUpstreamServer(BaseUpstreamServer):
    """
    Manages an HTTP upstream MCP server with connection pooling.

    Features:
    - Connection-pooled aiohttp.ClientSession.
    - Target URL configuration (e.g. http://localhost:3001/mcp).
    - Custom headers (e.g. bearer authentication).
    """

    def __init__(
        self,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        super().__init__(name)
        self.url = url
        self.headers = headers or {}
        self._session = session
        self._owns_session = session is None

    async def start(self) -> None:
        """Initializes connection-pooled ClientSession."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers=self.headers,
            )
            self._owns_session = True

    async def send_request(
        self, payload: dict[str, Any], timeout: float = 30.0
    ) -> dict[str, Any]:
        """Sends a JSON-RPC 2.0 payload via HTTP POST."""
        if self._session is None or self._session.closed:
            await self.start()

        assert self._session is not None
        req_id = payload.get("id")

        client_timeout = aiohttp.ClientTimeout(total=timeout)
        try:
            async with self._session.post(
                self.url,
                json=payload,
                timeout=client_timeout,
            ) as resp:
                if resp.status == 204:
                    return {}

                if resp.status != 200:
                    text = await resp.text()
                    raise UpstreamProcessError(
                        f"HTTP upstream '{self.name}' returned status {resp.status}: {text}"
                    )

                data = await resp.json()
                if not isinstance(data, dict):
                    raise UpstreamProcessError(
                        f"HTTP upstream '{self.name}' returned non-dict response."
                    )
                return data
        except asyncio.TimeoutError as exc:
            raise UpstreamTimeoutError(
                f"HTTP upstream '{self.name}' timed out after {timeout}s on request '{req_id}'"
            ) from exc
        except (aiohttp.ClientError, json.JSONDecodeError) as exc:
            raise UpstreamProcessError(
                f"HTTP connection or payload error to upstream '{self.name}' ({self.url}): {exc}"
            ) from exc

    async def is_healthy(self) -> bool:
        """Returns True if the session is initialized and open."""
        return self._session is not None and not self._session.closed

    async def stop(self) -> None:
        """Closes the client session if owned."""
        if self._owns_session and self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None
        logger.info("Stopped HTTP upstream server '%s'", self.name)


class UpstreamManager:
    """
    Coordinates upstream tool servers for Blackwall MCP Gateway.

    Modes:
    1. Wrap Mode (--wrap <command>): Spawns a single downstream MCP tool server as a child process.
    2. Multi-Server Mode (gateway.yaml): Manages multiple downstream servers, discovers tools,
       aggregates tools/list results, and routes tools/call requests by registered tool name.
    """

    def __init__(
        self,
        wrap_command: str | None = None,
        config_path: str | Path | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.wrap_command = wrap_command
        self.config_path = Path(config_path) if config_path else None
        self.servers: list[BaseUpstreamServer] = []
        self._tool_to_server: dict[str, BaseUpstreamServer] = {}

        if wrap_command:
            # Wrap mode
            self.servers.append(
                StdioUpstreamServer(name="wrapped", command=wrap_command)
            )
        elif config is not None or config_path is not None:
            # Multi-server mode from config
            cfg = config if config is not None else self._load_yaml_config(self.config_path)
            self._configure_from_dict(cfg)
        else:
            raise InvalidGatewayConfigError(
                "UpstreamManager requires either 'wrap_command' or 'config_path'/'config'."
            )

    @staticmethod
    def _load_yaml_config(path: Path | None) -> dict[str, Any]:
        """Loads and parses gateway.yaml."""
        if not path or not path.exists():
            raise InvalidGatewayConfigError(f"Gateway configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise InvalidGatewayConfigError(
                    f"Gateway configuration at '{path}' must be a YAML dictionary."
                )
            return data
        except yaml.YAMLError as exc:
            raise InvalidGatewayConfigError(
                f"Failed to parse gateway YAML config at '{path}': {exc}"
            ) from exc

    def _configure_from_dict(self, cfg: dict[str, Any]) -> None:
        """Parses upstream_servers configuration."""
        raw_servers = cfg.get("upstream_servers")
        if not isinstance(raw_servers, list) or not raw_servers:
            raise InvalidGatewayConfigError(
                "Gateway configuration must contain a non-empty 'upstream_servers' list."
            )

        for entry in raw_servers:
            if not isinstance(entry, dict):
                raise InvalidGatewayConfigError(
                    "Each entry in 'upstream_servers' must be a dictionary."
                )
            name = entry.get("name")
            if not name:
                raise InvalidGatewayConfigError(
                    "Upstream server entry missing required 'name' field."
                )

            transport = entry.get("transport", "stdio").lower()
            if transport == "stdio":
                cmd = entry.get("command")
                if not cmd:
                    raise InvalidGatewayConfigError(
                        f"Stdio upstream '{name}' requires a 'command' field."
                    )
                self.servers.append(
                    StdioUpstreamServer(
                        name=name,
                        command=cmd,
                        env=entry.get("env"),
                    )
                )
            elif transport == "http":
                url = entry.get("url")
                if not url:
                    raise InvalidGatewayConfigError(
                        f"HTTP upstream '{name}' requires a 'url' field."
                    )
                self.servers.append(
                    HttpUpstreamServer(
                        name=name,
                        url=url,
                        headers=entry.get("headers"),
                    )
                )
            else:
                raise InvalidGatewayConfigError(
                    f"Unsupported transport '{transport}' for upstream server '{name}'. "
                    "Expected 'stdio' or 'http'."
                )

    async def start(self) -> None:
        """Starts all upstream servers and discovers registered tools."""
        started_servers: list[BaseUpstreamServer] = []
        try:
            for server in self.servers:
                await server.start()
                started_servers.append(server)

            # Tool discovery
            await self.discover_tools()
        except Exception:
            for s in started_servers:
                try:
                    await s.stop()
                except Exception as stop_exc:
                    logger.warning(
                        "Error stopping server '%s' during startup rollback: %s",
                        s.name,
                        stop_exc,
                    )
            raise

    async def discover_tools(self) -> None:
        """Queries tools/list on each upstream server and builds routing table."""
        self._tool_to_server.clear()

        for server in self.servers:
            try:
                list_req = {
                    "jsonrpc": "2.0",
                    "id": f"disc-{server.name}",
                    "method": "tools/list",
                    "params": {},
                }
                resp = await server.send_request(list_req, timeout=10.0)
                tools = (resp.get("result") or {}).get("tools") or []
                if isinstance(tools, list):
                    server._tools = tools
                    for t in tools:
                        if isinstance(t, dict):
                            t_name = t.get("name")
                            if t_name:
                                self._tool_to_server[t_name] = server
                                logger.info(
                                    "Registered upstream tool '%s' -> server '%s'",
                                    t_name,
                                    server.name,
                                )
            except Exception as exc:
                logger.warning(
                    "Failed tool discovery for upstream server '%s': %s",
                    server.name,
                    exc,
                )

    async def stop(self) -> None:
        """Stops all upstream servers gracefully."""
        for server in self.servers:
            try:
                await server.stop()
            except Exception as exc:
                logger.error("Error stopping server '%s': %s", server.name, exc)
        self.servers.clear()
        self._tool_to_server.clear()

    async def handle_request(self, raw_payload: dict[str, Any]) -> dict[str, Any]:
        """
        Routes incoming MCP JSON-RPC requests to the appropriate upstream server.

        - tools/list: Returns aggregated tool list from all upstream servers.
        - tools/call: Routes to the server that registered the requested tool.
        - initialize: Routes to primary server or returns merged capabilities.
        - notifications/*: Dispatches to all servers.
        """
        method = raw_payload.get("method", "")
        req_id = raw_payload.get("id")
        params = raw_payload.get("params") or {}

        # 1. tools/list aggregation
        if method == "tools/list":
            if self.wrap_command and len(self.servers) == 1:
                return await self.servers[0].send_request(raw_payload)

            aggregated_tools: list[dict[str, Any]] = []
            for s in self.servers:
                aggregated_tools.extend(s.tools)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": aggregated_tools},
            }

        # 2. tools/call routing
        if method == "tools/call":
            tool_name = params.get("name")
            if not tool_name:
                raise ValueError("Missing 'name' in tools/call params.")

            if self.wrap_command and len(self.servers) == 1:
                return await self.servers[0].send_request(raw_payload)

            server = self._tool_to_server.get(tool_name)
            if server is None:
                raise UpstreamServerNotFoundError(
                    f"No upstream server registered for tool '{tool_name}'."
                )

            return await server.send_request(raw_payload)

        # 3. initialize handling
        if method == "initialize":
            if self.servers:
                # Forward to primary server
                return await self.servers[0].send_request(raw_payload)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "blackwall-gateway", "version": "2.0.0"},
                },
            }

        # 4. Notifications (no response expected)
        if method.startswith("notifications/") or req_id is None:
            for s in self.servers:
                try:
                    await s.send_request(raw_payload)
                except Exception:
                    pass
            return {}

        # 5. Default pass-through to primary server
        if self.servers:
            return await self.servers[0].send_request(raw_payload)

        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
