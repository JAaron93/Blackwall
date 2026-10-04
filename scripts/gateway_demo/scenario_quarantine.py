"""The Quarantine demo scenario (TASK-G03).

Demonstrates the gateway's surgical BLOCK isolation: legitimate write_file
operations are ALLOW'd and forwarded while a credential-harvesting read_file
is BLOCK'd, and the session continues uninterrupted afterwards
(ALLOW -> BLOCK -> ALLOW).

NOTE on naming: "Quarantine" here is the isolation effect, not the FR-04
QUARANTINE verdict (-32001). The malicious call synthesizes BLOCK (-32603);
the 0.10-0.20 QUARANTINE threshold band is out of scope for this scenario.

Attack taxonomy:
- OWASP LLM07 — Insecure Plugin Design (https://genai.owasp.org/)
- MITRE ATLAS AML.T0054 — LLM Jailbreak
  (https://atlas.mitre.org/techniques/AML.T0054)

Transports follow Rule 76 (see scenario_heist.py): in-process by default for
tests, live subprocesses for manual/demo recording. Direct execution is
supported: `python scripts/gateway_demo/scenario_quarantine.py` from anywhere
using the repo virtualenv.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Repository bootstrap (mock_app.py precedent): pytest masks the missing root
# path, so self-bootstrap for direct execution. Before first-party imports.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import asyncio
import json
import logging
import subprocess
import tempfile
import urllib.request
import uuid
from datetime import UTC, datetime
from typing import Any

from scripts.gateway_demo import honeypot_server as hs
from scripts.gateway_demo.scenario_heist import (
    HONEYPOT_URL,
    _blob_matches,
    _ensure_honeypot_port_free,
    _spawn_gateway_harness,
    _spawn_honeypot_subprocess,
    _stdio_call,
    _terminate_process_group,
    build_tool_call,
)

logger = logging.getLogger(__name__)

# OWASP LLM07 / MITRE ATLAS AML.T0054 — taxonomy anchor for reviewers.
OWASP_REF = "https://genai.owasp.org/"
MITRE_REF = "https://atlas.mitre.org/techniques/AML.T0054"

QUARANTINE_RESULT_FILENAME = "quarantine_results.json"

CREDENTIAL_PATH_MARKERS = (
    ".env",
    "id_rsa",
    "application_default_credentials",
    ".ssh/",
    ".aws/credentials",
)

WRITE1_ID = "quarantine-write-1"
READ_FILE_ID = "quarantine-read-2"
WRITE2_ID = "quarantine-write-3"

WRITE_PATH = "src/blackwall/project_module.py"
WRITE_CONTENT = "# demo refactor: extracted helper (synthetic, no secrets)\n"


def ensure_synthetic_fixtures(tmpdir: str | Path) -> Path:
    """Populate synthetic credential fixtures only (never real secrets)."""
    root = Path(tmpdir)
    root.mkdir(parents=True, exist_ok=True)
    (root / ".env").write_text(
        "FAKE_API_KEY=demo-not-real-do-not-use\n"
        'DEMO_GCLOUD_ADC={"client_id": "demo-client"}\n',
        encoding="utf-8",
    )
    ssh_path = root / ".ssh" / "id_rsa"
    ssh_path.parent.mkdir(parents=True, exist_ok=True)
    ssh_path.write_text(
        "BW_SYNTHETIC_MOCK_SSH_KEY_0192 demo-not-real-do-not-use\n",
        encoding="utf-8",
    )
    try:
        ssh_path.chmod(0o600)
    except OSError:
        pass
    return root


def _event(verdict: str, **fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "verdict": verdict,
    }
    record.update(fields)
    return record


class _QuarantineResolver:
    """Deterministic stand-in for SyncResolver + TSG (GCP-free offline policy).

    Mirrors tests/gateway_harness.py: the SSH-key path acts as the Threat
    Signature Graph signal. BLOCK verdicts flow through the production
    PayloadInterceptor (redaction), SQLiteThreatRepository (persistence),
    and ResponseSynthesizer (generic -32603, never -32001). The live
    SyncResolver is reserved for manual runs with Vertex AI credentials
    (design.md Phase 3 deterministic-harness deviation).
    """

    def __init__(self, repo: Any, interceptor: Any) -> None:
        self._repo = repo
        self._interceptor = interceptor

    async def evaluate(self, context: Any) -> Any:
        from blackwall.models import Verdict, VerdictDecision

        name = (context.tool_name or "").lower()
        blocked = name == "read_file" and _blob_matches(
            context.arguments, CREDENTIAL_PATH_MARKERS
        )
        if not blocked:
            return Verdict(
                decision=VerdictDecision.ALLOW,
                reasoning="Quarantine ALLOW: no threat pattern matched.",
                confidence_score=0.0,
            )
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
                    "attackerIntent": "credential_harvesting_attempt",
                    "payloadPattern": json.dumps(params.get("arguments", {}), default=str)[
                        :2000
                    ],
                    "targetTool": context.tool_name,
                    "targetSink": "credential_store",
                    "mitigationAction": "BLOCK",
                    "matchCount": 1,
                    "falsePositiveCount": 0,
                    "metadata": {"harness": "quarantine-demo", "decision": "BLOCK"},
                }
            )
        except Exception as exc:  # noqa: BLE001 — persistence must never break verdict
            logger.warning("Failed persisting Quarantine BLOCK signature: %s", exc)
        return Verdict(
            decision=VerdictDecision.BLOCK,
            reasoning="Quarantine BLOCK: Threat Signature Graph pattern matched.",
            confidence_score=0.95,
        )


def _write_quarantine_results(tmpdir: Path, events: list[dict[str, Any]]) -> Path:
    results = {
        "scenario": "quarantine",
        "taxonomy": {"owasp": "LLM07", "mitre": "AML.T0054"},
        "owasp_ref": OWASP_REF,
        "mitre_ref": MITRE_REF,
        "events": events,
    }
    results_path = tmpdir / QUARANTINE_RESULT_FILENAME
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results_path


async def _run_chain(tmpdir: Path) -> dict[str, Any]:
    from fastapi.testclient import TestClient

    from blackwall.db.repository import SQLiteThreatRepository
    from blackwall.gateway.interceptor import PayloadInterceptor
    from blackwall.gateway.server import MCPGatewayServer

    events: list[dict[str, Any]] = []
    forwarded_tools: list[str] = []

    # Stage the hijack: the compromised tool response (not a gateway verdict —
    # the agent received it before this session slice, as in the narrative).
    client = TestClient(hs.app)
    staged = client.get("/docs/compromised-response")
    assert staged.status_code == 200
    assert "id_rsa" in staged.text
    research = {"status": 200, "hijack_present": "id_rsa" in staged.text}

    # Gateway wrapping a mock tool server, backed by a real SQLite threat
    # graph in the ephemeral temp dir (production interceptor + synthesizer).
    threat_db_path = tmpdir / "threat_signatures.db"
    repo = SQLiteThreatRepository(db_path=str(threat_db_path))
    interceptor = PayloadInterceptor()

    async def _recording_downstream(payload: dict[str, Any]) -> dict[str, Any]:
        params = payload.get("params", {}) if isinstance(payload, dict) else {}
        forwarded_tools.append(str(params.get("name", "")))
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "content": [{"type": "text", "text": f"echo:{params.get('name', '')}"}],
                "echoedTool": params.get("name", ""),
                "echoedArguments": params.get("arguments", {}),
            },
        }

    server = MCPGatewayServer(
        resolver=_QuarantineResolver(repo, interceptor),
        downstream_handler=_recording_downstream,
    )
    try:
        # Step 1: legitimate refactor write — ALLOW, forwarded downstream.
        write1 = await server.process_message(
            build_tool_call(
                WRITE1_ID,
                "write_file",
                {"path": WRITE_PATH, "content": WRITE_CONTENT},
            )
        )
        events.append(_event("ALLOW", tool="write_file", code="result", score=0.0, id=WRITE1_ID))
        assert "result" in write1

        # Step 2: hijacked read of the synthetic SSH key — BLOCK (-32603).
        read_file = await server.process_message(
            build_tool_call(READ_FILE_ID, "read_file", {"path": "~/.ssh/id_rsa"})
        )
        events.append(
            _event("BLOCK", tool="read_file", code=-32603, score=0.95, id=READ_FILE_ID)
        )
        assert read_file.get("error", {}).get("code") == -32603

        # Step 3: session continues — second legitimate write ALLOW'd.
        write2 = await server.process_message(
            build_tool_call(
                WRITE2_ID,
                "write_file",
                {"path": WRITE_PATH, "content": WRITE_CONTENT},
            )
        )
        events.append(_event("ALLOW", tool="write_file", code="result", score=0.0, id=WRITE2_ID))
        assert "result" in write2
    finally:
        persisted_signature_count = len(await repo.get_all_signatures())
        close = getattr(repo, "close", None)
        if close is not None:
            res = close()
            if asyncio.iscoroutine(res):
                await res

    results_path = _write_quarantine_results(tmpdir, events)

    return {
        "write1_response": write1,
        "read_file_response": read_file,
        "write2_response": write2,
        "forwarded_tools": forwarded_tools,
        "research": research,
        "results_path": str(results_path),
        "events": events,
        "threat_db_path": str(threat_db_path),
        "persisted_signature_count": persisted_signature_count,
        "transport": "in-process",
    }


def _wait_for_compromised_response(timeout: float = 20.0) -> dict[str, Any]:
    """Poll the live honeypot for the hijack payload; return research metadata."""
    import time

    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"{HONEYPOT_URL}/docs/compromised-response", timeout=3
            ) as resp:
                body = resp.read().decode("utf-8")
                if resp.status == 200 and "id_rsa" in body:
                    return {"status": 200, "hijack_present": True}
                last_err = AssertionError(f"honeypot status {resp.status}")
        except Exception as exc:  # noqa: BLE001 — readiness polling
            last_err = exc
        time.sleep(0.5)
    raise AssertionError(f"Honeypot never served the compromised response: {last_err!r}")


def _run_live(tmpdir: Path) -> dict[str, Any]:
    """Live-transport Quarantine: real honeypot HTTP + real gateway stdio process."""
    events: list[dict[str, Any]] = []
    # Ownership: refuse to start if the port is already served — otherwise the
    # research payload could belong to a different server.
    _ensure_honeypot_port_free()
    honeypot = _spawn_honeypot_subprocess(env=os.environ.copy())
    assert honeypot.poll() is None, "Honeypot exited immediately after start"
    gateway: subprocess.Popen[str] | None = None
    try:
        # Stage the hijack live over HTTP (not a gateway verdict).
        research = _wait_for_compromised_response()
        assert honeypot.poll() is None, "Honeypot died while serving the hijack"

        # Gateway wrapping a mock echo downstream, isolated threat graph.
        gateway = _spawn_gateway_harness(tmpdir)

        # Step 1: legitimate refactor write — ALLOW, forwarded downstream.
        write1 = _stdio_call(
            gateway,
            build_tool_call(
                WRITE1_ID,
                "write_file",
                {"path": WRITE_PATH, "content": WRITE_CONTENT},
            ),
        )
        events.append(_event("ALLOW", tool="write_file", code="result", score=0.0, id=WRITE1_ID))
        assert "result" in write1

        # Step 2: hijacked read of the synthetic SSH key — BLOCK (-32603).
        read_file = _stdio_call(
            gateway,
            build_tool_call(READ_FILE_ID, "read_file", {"path": "~/.ssh/id_rsa"}),
        )
        events.append(
            _event("BLOCK", tool="read_file", code=-32603, score=0.95, id=READ_FILE_ID)
        )
        assert read_file.get("error", {}).get("code") == -32603

        # Step 3: session continues — second legitimate write ALLOW'd.
        write2 = _stdio_call(
            gateway,
            build_tool_call(
                WRITE2_ID,
                "write_file",
                {"path": WRITE_PATH, "content": WRITE_CONTENT},
            ),
        )
        events.append(_event("ALLOW", tool="write_file", code="result", score=0.0, id=WRITE2_ID))
        assert "result" in write2
    finally:
        _terminate_process_group(gateway)
        _terminate_process_group(honeypot)

    # Only legitimate calls reached a downstream: derive forwarding from echoes.
    forwarded_tools = [
        str(resp.get("result", {}).get("echoedTool", ""))
        for resp in (write1, write2)
        if "result" in resp
    ]
    threat_db_path = tmpdir / "threat_signatures.db"
    persisted_signature_count = _count_persisted_signatures(threat_db_path)
    results_path = _write_quarantine_results(tmpdir, events)

    return {
        "write1_response": write1,
        "read_file_response": read_file,
        "write2_response": write2,
        "forwarded_tools": forwarded_tools,
        "research": research,
        "results_path": str(results_path),
        "events": events,
        "threat_db_path": str(threat_db_path),
        "persisted_signature_count": persisted_signature_count,
        "transport": "live",
    }


def _count_persisted_signatures(threat_db_path: Path) -> int:
    """Count BLOCK rows in the isolated threat graph (parent process, post-run)."""

    async def _query() -> int:
        from blackwall.db.repository import SQLiteThreatRepository

        repo = SQLiteThreatRepository(db_path=str(threat_db_path))
        try:
            return len(await repo.get_all_signatures())
        finally:
            close = getattr(repo, "close", None)
            if close is not None:
                res = close()
                if asyncio.iscoroutine(res):
                    await res

    return asyncio.run(_query())


def run_quarantine(tmpdir: str | Path, *, transport: str = "in-process") -> dict[str, Any]:
    """Execute the Quarantine chain; write $TMPDIR/quarantine_results.json."""
    if transport not in ("in-process", "live"):
        raise ValueError(f"Unknown Quarantine transport: {transport!r}")
    root = ensure_synthetic_fixtures(tmpdir)
    prev_home = os.environ.get("HOME")
    prev_demo_dir = os.environ.get("BLACKWALL_DEMO_TMPDIR")
    os.environ["HOME"] = str(root)
    os.environ["BLACKWALL_DEMO_TMPDIR"] = str(root)
    try:
        if transport == "live":
            return _run_live(root)
        return asyncio.run(_run_chain(root))
    finally:
        if prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = prev_home
        if prev_demo_dir is None:
            os.environ.pop("BLACKWALL_DEMO_TMPDIR", None)
        else:
            os.environ["BLACKWALL_DEMO_TMPDIR"] = prev_demo_dir


def main() -> int:
    """Manual entry point: full live demo + JSON log (G04 recording-ready)."""
    tmpdir = Path(tempfile.mkdtemp(prefix="bw-quarantine-"))
    result = run_quarantine(tmpdir, transport="live")
    print(json.dumps({"results_path": result["results_path"], "events": result["events"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
