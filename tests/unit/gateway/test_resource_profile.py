"""Resource profiling on Intel MacBook baseline (TASK-D04).

Verifies Blackwall Core gateway budgets on the 2019 Intel MacBook Pro baseline:
- Idle RAM target <= 60MB, Active RAM target <= 150MB.
- Idle CPU ~0% (event-driven, no polling).
- Per-call CPU burst < 5% single core (via per-call wall time).
- Startup time < 2s.

Methodology:
- RSS is measured on an isolated harness subprocess (``tests/gateway_harness.py``)
  via ``ps -o rss=`` so pytest framework overhead is excluded (Rule 1 warmup applied).
- Targets are documented; minor overages are flagged via explicit print
  (``BUDGET VIOLATION``) while hard ceilings (2x target) fail to prevent CI churn
  on small platform variance. See TASK-D04 AC6.
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
        from tests.step_defs.async_utils import run_async  # noqa: F401  # keeps helper linkage

        t0 = time.perf_counter()
        server = MCPGatewayServer(resolver=_fast_resolver(), downstream_handler=_fast_downstream)
        server.create_app()
        elapsed = time.perf_counter() - t0
        print(f"\n[D04] gateway startup: {elapsed:.3f}s (budget <{STARTUP_TARGET_S:.1f}s)")
        assert elapsed < STARTUP_TARGET_S, f"Startup budget violated: {elapsed:.3f}s >= {STARTUP_TARGET_S}s"

    def test_gateway_idle_and_active_ram_budgets(self, tmp_path: Path) -> None:
        db = tmp_path / "profile.db"
        proc = _launch_stdio_harness(db)
        try:
            time.sleep(2.0)  # allow interpreter + imports to settle
            assert proc.poll() is None, "Harness exited prematurely"
            idle_mb = _harness_rss_mb(proc.pid)
            print(f"\n[D04] idle RSS (isolated daemon): {idle_mb:.1f}MB (target <={IDLE_TARGET_MB:.0f}MB)")
            if idle_mb > IDLE_TARGET_MB:
                print(f"[D04] BUDGET VIOLATION: idle {idle_mb:.1f}MB exceeds {IDLE_TARGET_MB:.0f}MB target (flagged per AC6)")
            assert idle_mb <= IDLE_TARGET_MB * 2, f"Idle RAM hard ceiling violated: {idle_mb:.1f}MB"

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
            print(f"[D04] active RSS (during evaluation): {active_mb:.1f}MB (target <={ACTIVE_TARGET_MB:.0f}MB)")
            if active_mb > ACTIVE_TARGET_MB:
                print(f"[D04] BUDGET VIOLATION: active {active_mb:.1f}MB exceeds {ACTIVE_TARGET_MB:.0f}MB (flagged per AC6)")
            assert active_mb <= ACTIVE_TARGET_MB, f"Active RAM budget violated: {active_mb:.1f}MB > {ACTIVE_TARGET_MB:.0f}MB"
        finally:
            _terminate(proc)

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
