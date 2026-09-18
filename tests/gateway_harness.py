"""Deterministic test harness for Blackwall MCP Gateway Phase 3 BDD scenarios.

Runs a real ``MCPGatewayServer`` in a subprocess with a deterministic,
GCP-free test resolver so BDD tests can exercise stdio/HTTP transports,
process-group isolation, auth boundaries, and SQLite threat-graph logging
without requiring Vertex AI credentials.

Resolver policy (deterministic, no network):
- ``read_file`` targeting credential markers (``.env``, ``id_rsa``,
  ``application_default_credentials``, ``.ssh/``) -> BLOCK.
- ``http_request`` targeting exfil markers (``exfil``, ``:8765``) -> BLOCK.
- All other tool calls -> ALLOW and forwarded to downstream echo (if enabled).

On BLOCK the harness persists a redacted signature to the isolated
``SQLiteThreatRepository`` using camelCase keys so the parent BDD process
can assert threat-graph logging.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

# Ensure ``src/`` is importable when launched as ``python tests/gateway_harness.py``.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from blackwall.db.repository import SQLiteThreatRepository  # noqa: E402
from blackwall.gateway.interceptor import PayloadInterceptor  # noqa: E402
from blackwall.gateway.server import MCPGatewayServer  # noqa: E402
from blackwall.models import ToolCallContext, Verdict, VerdictDecision  # noqa: E402

logger = logging.getLogger("gateway_harness")

CREDENTIAL_PATH_MARKERS = (
    ".env",
    "id_rsa",
    "application_default_credentials",
    ".ssh/",
    ".aws/credentials",
)

EXFIL_MARKERS = (
    "exfil",
    ":8765",
    "attacker",
)


def _is_malicious(tool_name: str, arguments: Any) -> bool:
    try:
        blob = json.dumps(arguments, default=str).lower()
    except Exception:
        blob = str(arguments).lower()
    name = (tool_name or "").lower()
    if name == "read_file":
        return any(m in blob for m in CREDENTIAL_PATH_MARKERS)
    if name == "http_request":
        return any(m in blob for m in EXFIL_MARKERS)
    if name in ("execute_command", "run_command", "execute_bash"):
        return any(m in blob for m in EXFIL_MARKERS)
    return False


class DeterministicTestResolver:
    """GCP-free resolver with SQLite BLOCK persistence for BDD."""

    def __init__(self, repo: SQLiteThreatRepository, interceptor: PayloadInterceptor) -> None:
        self._repo = repo
        self._interceptor = interceptor

    async def evaluate(self, context: ToolCallContext) -> Verdict:
        if _is_malicious(context.tool_name, context.arguments):
            redacted = self._interceptor.redact_for_storage(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": context.tool_name,
                        "arguments": context.arguments,
                    },
                }
            )
            try:
                params = redacted.get("params", {})
                await self._repo.writeSignature(
                    {
                        "signatureId": str(uuid.uuid4()),
                        "attackerIntent": "credential_exfiltration_attempt",
                        "payloadPattern": json.dumps(params.get("arguments", {}), default=str)[:2000],
                        "targetTool": context.tool_name,
                        "targetSink": "credential_store",
                        "mitigationAction": "BLOCK",
                        "matchCount": 1,
                        "falsePositiveCount": 0,
                        "metadata": {"harness": "phase3-bdd", "decision": "BLOCK"},
                    }
                )
            except Exception as exc:
                logger.warning("Failed persisting BLOCK signature: %s", exc)
            return Verdict(
                decision=VerdictDecision.BLOCK,
                reasoning="Harness BLOCK: credential-path pattern matched in Threat Signature Graph.",
                confidence_score=0.95,
            )
        return Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Harness ALLOW: no threat pattern matched.",
            confidence_score=0.0,
        )


def _build_echo_downstream() -> Any:
    async def _echo(payload: dict[str, Any]) -> dict[str, Any]:
        params = payload.get("params", {}) if isinstance(payload, dict) else {}
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"echo:{params.get('name', '')}:{json.dumps(params.get('arguments', {}), default=str)}",
                    }
                ],
                "echoedTool": params.get("name", ""),
                "echoedArguments": params.get("arguments", {}),
            },
        }

    return _echo


async def _run_stdio(db_path: str, downstream_mode: str) -> None:
    repo = SQLiteThreatRepository(db_path=db_path)
    interceptor = PayloadInterceptor()
    resolver = DeterministicTestResolver(repo, interceptor)
    downstream = _build_echo_downstream() if downstream_mode == "echo" else None
    server = MCPGatewayServer(resolver=resolver, downstream_handler=downstream)
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    w_transport, w_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    # Signal readiness to parent via stderr (not stdout which is JSON-RPC stream).
    print("HARNESS_READY", file=sys.stderr, flush=True)
    await server.handle_stdio_stream(reader, writer)
    close = getattr(repo, "close", None)
    if close is not None:
        res = close()
        if asyncio.iscoroutine(res):
            await res


async def _run_http(host: str, port: int, db_path: str, auth_token: str | None, downstream_mode: str) -> None:
    repo = SQLiteThreatRepository(db_path=db_path)
    interceptor = PayloadInterceptor()
    resolver = DeterministicTestResolver(repo, interceptor)
    downstream = _build_echo_downstream() if downstream_mode == "echo" else None
    # MCPGatewayServer enforces the non-loopback startup guard here.
    server = MCPGatewayServer(
        host=host,
        port=port,
        auth_token=auth_token,
        resolver=resolver,
        downstream_handler=downstream,
    )
    await server.start_http()
    print(f"HARNESS_READY {host}:{port}", file=sys.stderr, flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()
        close = getattr(repo, "close", None)
        if close is not None:
            res = close()
            if asyncio.iscoroutine(res):
                await res


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 3 gateway BDD harness")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9229)
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--auth-token", default=None)
    parser.add_argument("--downstream-mode", choices=["none", "echo"], default="none")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.WARNING)
    args = parse_args(argv)
    try:
        if args.transport == "stdio":
            asyncio.run(_run_stdio(args.db_path, args.downstream_mode))
        else:
            asyncio.run(_run_http(args.host, args.port, args.db_path, args.auth_token, args.downstream_mode))
    except Exception as exc:
        print(f"HARNESS_ERROR: {exc}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
