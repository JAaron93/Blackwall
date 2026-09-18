"""Resource profiling on Intel MacBook baseline (TASK-D04).

Verifies Blackwall Core gateway budgets on the 2019 Intel MacBook Pro baseline:
- Idle RAM target <= 60MB, Active RAM target <= 150MB.
- Idle CPU ~0% (event-driven, no polling).
- Per-call CPU burst < 5% single core (via per-call wall time).
- Startup time < 2s.

Methodology:
- RSS and %CPU are measured on an isolated harness subprocess
  (``tests/gateway_harness.py``) via portable ``ps`` so pytest framework
  overhead is excluded (Rule 1 warmup applied).
- Cold startup is measured in a fresh interpreter (imports + server init).
- All budgets are strictly enforced; violations fail explicitly (TASK-D04 AC6).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from blackwall.gateway.server import MCPGatewayServer
from blackwall.models import Verdict, VerdictDecision

REPO_ROOT = Path(__file__).resolve().parents[3]
HARNESS = REPO_ROOT / "tests" / "gateway_harness.py"

IDLE_TARGET_MB = 60.0
ACTIVE_TARGET_MB = 150.0
STARTUP_TARGET_S = 2.0
PER_CALL_TARGET_MS = 10.0


def _harness_rss_mb(pid: int) -> float:
    """Returns RSS in MB for a pid via portable ``ps``."""
    out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
    kb = float(out.strip().split()[0])
    return kb / 1024.0


def _harness_cpu_pct(pid: int) -> float:
    raise AssertionError("Use _harness_idle_cpu_pct for interval-based sampling.")


def _cputime_seconds(pid: int) -> float:
    """Returns cumulative CPU time in seconds for a pid via portable ``ps``."""
    out = subprocess.check_output(["ps", "-o", "time=", "-p", str(pid)], text=True).strip()
    # Format: [[dd-]hh:]mm:ss (macOS/Linux portable subset)
    days = 0
    if "-" in out:
        day_part, out = out.split("-", 1)
        days = int(day_part.strip())
    parts = out.strip().split(":")
    seconds = float(parts[-1]) if len(parts) >= 1 else 0.0
    minutes = int(parts[-2]) if len(parts) >= 2 else 0
    hours = int(parts[-3]) if len(parts) >= 3 else 0
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _harness_idle_cpu_pct(pid: int, interval: float = 2.0) -> float:
    """Samples %CPU over an idle interval (delta cputime / wall)."""
    c0 = _cputime_seconds(pid)
    t0 = time.monotonic()
    time.sleep(interval)
    c1 = _cputime_seconds(pid)
    wall = time.monotonic() - t0
    return ((c1 - c0) / wall * 100.0) if wall > 0 else 0.0


def _launch_stdio_harness(db_path: Path) -> subprocess.Popen[str]:
    cmd = [sys.executable, str(HARNESS), "--transport", "stdio", "--db-path", str(db_path)]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    preexec = os.setsid if hasattr(os, "setsid") else None
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
        preexec_fn=preexec,
    )


def _terminate(proc: subprocess.Popen[str]) -> None:
    try:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=5)
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass


def _fast_resolver() -> Any:
    resolver = MagicMock()
    verdict = Verdict(decision=VerdictDecision.ALLOW, reasoning="Profile ALLOW.", confidence_score=0.0)

    async def _eval(ctx: Any) -> Verdict:
        return verdict

    resolver.evaluate = _eval
    return resolver


async def _fast_downstream(payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"status": "ok"}}


class TestGatewayResourceProfile:
    """TASK-D04: Intel MacBook baseline resource budgets."""

    def test_gateway_startup_time_under_2s(self) -> None:
        # Cold start measured in a fresh interpreter (imports + server init),
        # not in-process after imports have completed.
        cmd = [
            sys.executable,
            "-c",
            "from blackwall.gateway.server import MCPGatewayServer; "
            "s = MCPGatewayServer(); s.create_app(); print('READY')",
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        elapsed = time.perf_counter() - t0
        print(f"\n[D04] gateway cold startup: {elapsed:.3f}s (budget <{STARTUP_TARGET_S:.1f}s)")
        assert proc.returncode == 0, f"Cold-start probe failed: {proc.stderr[-500:]}"
        assert elapsed < STARTUP_TARGET_S, f"Startup budget violated: {elapsed:.3f}s >= {STARTUP_TARGET_S}s"

    def test_gateway_idle_and_active_ram_budgets(self, tmp_path: Path) -> None:
        db = tmp_path / "profile.db"
        proc = _launch_stdio_harness(db)
        try:
            time.sleep(2.0)  # allow interpreter + imports to settle
            assert proc.poll() is None, "Harness exited prematurely"
            idle_mb = _harness_rss_mb(proc.pid)
            print(f"\n[D04] idle RSS (isolated daemon): {idle_mb:.1f}MB (budget <={IDLE_TARGET_MB:.0f}MB)")
            assert idle_mb <= IDLE_TARGET_MB, f"Idle RAM budget violated: {idle_mb:.1f}MB > {IDLE_TARGET_MB:.0f}MB"

            # Idle CPU sampled on the live daemon while it sleeps on stdio
            # (delta cputime over a 2s idle window; event loop sleeping ~0%).
            cpu_pct = _harness_idle_cpu_pct(proc.pid, interval=2.0)
            print(f"[D04] idle CPU (sampled daemon): {cpu_pct:.2f}% (budget ~0%)")
            assert cpu_pct < 2.0, f"Idle CPU budget violated: {cpu_pct:.2f}% >= 2%"

            # Drive active evaluation through the stdio pipe (warmup + measured).
            assert proc.stdin is not None and proc.stdout is not None
            for i in range(3):
                payload = {
                    "jsonrpc": "2.0",
                    "id": f"warmup-{i}",
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
                }
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()
                proc.stdout.readline()
            for i in range(20):
                payload = {
                    "jsonrpc": "2.0",
                    "id": f"active-{i}",
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
                }
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()
                proc.stdout.readline()
            active_mb = _harness_rss_mb(proc.pid)
            print(f"[D04] active RSS (during evaluation): {active_mb:.1f}MB (budget <={ACTIVE_TARGET_MB:.0f}MB)")
            assert active_mb <= ACTIVE_TARGET_MB, f"Active RAM budget violated: {active_mb:.1f}MB > {ACTIVE_TARGET_MB:.0f}MB"
        finally:
            _terminate(proc)

    def test_gateway_active_ram_during_sync_resolver_evaluation(self) -> None:
        """D04 AC2: active RAM measured during real SyncResolver evaluation.

        Runs genuine ``SyncResolver.evaluate()`` calls (mocked Gemini client,
        no network) in an isolated subprocess and asserts its RSS stays within
        the active budget — the harness echo path alone does not exercise the
        resolver pipeline.
        """
        child_lines = [
            "import asyncio, resource, sys",
            "from unittest.mock import MagicMock",
            "from blackwall.models import ToolCallContext",
            "from blackwall.sync_resolver import SyncResolver",
            "mock_client = MagicMock()",
            "mock_resp = MagicMock(); mock_resp.text = 'benign pattern'",
            "mock_client.models.generate_content.return_value = mock_resp",
            "resolver = SyncResolver(client=mock_client, threat_intel=None, cbm_client=None, repo=None, demo_mode=False)",
            "async def main():",
            "    allows = 0",
            "    for i in range(23):",
            "        ctx = ToolCallContext(tool_name='read_file', arguments={'path': '/safe/data/sample.txt'})",
            "        verdict = await resolver.evaluate(ctx)",
            "        if i >= 3 and verdict.decision.value == 'ALLOW': allows += 1",
            "    usage = resource.getrusage(resource.RUSAGE_SELF)",
            "    rss = usage.ru_maxrss / (1024 * 1024) if sys.platform == 'darwin' else usage.ru_maxrss / 1024",
            "    print(f'RSS_MB={rss:.1f} ALLOW={allows}')",
            "asyncio.run(main())",
        ]
        child = "\n".join(child_lines)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", child],
            capture_output=True, text=True, timeout=60, env=env,
        )
        assert proc.returncode == 0, f"SyncResolver probe failed: {proc.stderr[-500:]}"
        rss_mb = allows = None
        for line in proc.stdout.splitlines():
            if line.startswith("RSS_MB="):
                parts = dict(p.split("=") for p in line.split())
                rss_mb, allows = float(parts["RSS_MB"]), int(parts["ALLOW"])
        assert rss_mb is not None, f"No RSS report from probe: {proc.stdout[-300:]!r}"
        print(f"\n[D04] active RSS (SyncResolver eval x20): {rss_mb:.1f}MB (budget <={ACTIVE_TARGET_MB:.0f}MB)")
        assert allows == 20, f"Expected 20 ALLOW verdicts, got {allows}"
        assert rss_mb <= ACTIVE_TARGET_MB, f"SyncResolver active RAM violated: {rss_mb:.1f}MB"

    @pytest.mark.asyncio
    async def test_gateway_per_call_cpu_burst(self) -> None:
        server = MCPGatewayServer(resolver=_fast_resolver(), downstream_handler=_fast_downstream)
        payload = {
            "jsonrpc": "2.0",
            "id": "cpu-0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/safe/data/sample.txt"}},
        }
        for i in range(5):
            payload["id"] = f"warmup-{i}"
            await server.process_message(dict(payload))

        iterations = 50
        t_start = time.perf_counter()
        for i in range(iterations):
            payload["id"] = f"cpu-{i}"
            await server.process_message(dict(payload))
        wall = time.perf_counter() - t_start
        per_call_ms = (wall / iterations) * 1000.0
        # Burst as fraction of a 1s single-core window: 0.21ms -> ~0.02%.
        burst_pct = per_call_ms / 10.0
        print(
            f"\n[D04] per-call wall: {per_call_ms:.2f}ms "
            f"(budget <{PER_CALL_TARGET_MS:.0f}ms), burst ~{burst_pct:.3f}% of single core (budget <5%)"
        )
        assert per_call_ms < PER_CALL_TARGET_MS, f"Per-call overhead violated: {per_call_ms:.2f}ms"
        assert burst_pct < 5.0, f"CPU burst violated: {burst_pct:.2f}% >= 5%"

    def test_gateway_idle_cpu_no_polling(self) -> None:
        import inspect

        import blackwall.gateway.server as server_mod

        src = inspect.getsource(server_mod)
        assert "time.sleep" not in src, "Gateway server must not use blocking time.sleep (event-driven invariant)"
        print("\n[D04] idle CPU: event-driven, no blocking sleep (~0% idle by construction)")
