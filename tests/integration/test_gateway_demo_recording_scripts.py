"""Integration coverage for the TASK-G06 demo orchestration shell scripts.

A stub runner injected through ``BW_DEMO_SCENARIO_RUNNER`` makes these real
end-to-end shell invocations fast, hermetic and free of live network calls.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "scripts" / "gateway_demo" / "run_gateway_demo.sh"
RECORD_SCRIPT = REPO_ROOT / "scripts" / "gateway_demo" / "record_demo.sh"
KEYS = ("honeypot", "heist", "quarantine", "poisoned_package", "bouncer")


@pytest.fixture()
def stub_runner(tmp_path: Path) -> Path:
    """Executable that records its scenario key and prints deterministic verdicts."""
    path = tmp_path / "stub_runner.sh"
    path.write_text(
        """#!/usr/bin/env bash
set -u
printf "%s\\n" "$1" >> "${BW_DEMO_TEST_LOG:?}"
if [[ "${BW_DEMO_TEST_SLEEP:-0}" == "1" ]]; then
  echo $$ > "${BW_DEMO_TEST_PIDFILE:?}"
  if [[ "${BW_DEMO_TEST_NESTED:-0}" == "1" ]]; then
    python3 -c 'import os, socket, sys, time; os.setsid(); s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 9231)); s.listen(); open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(60)' "${BW_DEMO_TEST_NESTED_PIDFILE:?}"
  fi
  sleep 60
fi
echo "[demo] scenario=$1"
echo "ALLOW read_url for $1"
echo "BLOCK read_file (-32603) threat_score=0.95"
if [[ "${BW_DEMO_TEST_FAIL_KEY:-}" == "$1" ]]; then exit 1; fi
exit 0
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.fixture()
def fake_live_tools(tmp_path: Path) -> tuple[Path, Path]:
    """asciinema/tmux stand-ins: real CLI shape, no terminal dependency.

    The fake asciinema deliberately writes an unredacted path/token into the
    cast; the recorder must sanitize it before keeping the take. The fake tmux
    writes the scenario status/done markers that the real panes produce.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "live_tools.log"
    asciinema = bin_dir / "asciinema"
    asciinema.write_text(
        """#!/usr/bin/env bash
echo "asciinema $*" >> "__MARKER__"
cast=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "rec" ]]; then cast="$arg"; fi
  prev="$arg"
done
if [[ -n "$cast" ]]; then
  cat > "$cast" <<'CAST'
{"version": 2, "width": 120, "height": 30}
[0.1, "o", "traceback /Users/real-operator/project token=supersecretvalue123\\r\\n"]
CAST
fi
exit 0
""".replace("__MARKER__", str(marker)),
        encoding="utf-8",
    )
    asciinema.chmod(0o755)
    tmux = bin_dir / "tmux"
    tmux.write_text(
        """#!/usr/bin/env bash
echo "tmux $*" >> "__MARKER__"
status="${BW_DEMO_TEST_LIVE_STATUS:-0}"
if [[ -n "${BW_DEMO_TEST_FAIL_KEY:-}" ]] && printf '%s\\n' "$*" | grep -q -- "${BW_DEMO_TEST_FAIL_KEY}"; then
  status=1
fi
for spec in $(printf '%s\\n' "$@" | grep -oE '[^"[:space:]]+\\.status' || true); do
  printf '%s' "$status" > "$spec"
done
for spec in $(printf '%s\\n' "$@" | grep -oE '[^"[:space:]]+\\.done' || true); do
  : > "$spec"
done
exit 0
""".replace("__MARKER__", str(marker)),
        encoding="utf-8",
    )
    tmux.chmod(0o755)
    return bin_dir, marker


def _env(tmp_path: Path, runner: Path, **extra: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "BW_DEMO_SCENARIO_RUNNER": str(runner),
            "BW_DEMO_TEST_LOG": str(tmp_path / "calls.log"),
            "BW_DEMO_LIVE_RECORD": "0",
            "BW_DEMO_PYTHON": "python3",
        }
    )
    env.update(extra)
    return env


def _call_log(tmp_path: Path) -> list[str]:
    return (tmp_path / "calls.log").read_text().splitlines()


def test_run_script_executes_all_five_scenarios_in_order(tmp_path: Path, stub_runner: Path):
    proc = subprocess.run(
        ["bash", str(RUN_SCRIPT)],
        cwd=REPO_ROOT,
        env=_env(tmp_path, stub_runner),
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert _call_log(tmp_path) == list(KEYS)


def test_run_script_aggregates_failures_but_runs_every_scenario(
    tmp_path: Path, stub_runner: Path
):
    proc = subprocess.run(
        ["bash", str(RUN_SCRIPT)],
        cwd=REPO_ROOT,
        env=_env(tmp_path, stub_runner, BW_DEMO_TEST_FAIL_KEY="heist"),
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert _call_log(tmp_path) == list(KEYS)
    assert "heist" in proc.stderr.lower()


def test_record_script_produces_cast_and_thumbnails(tmp_path: Path, stub_runner: Path):
    recordings = tmp_path / "recordings"
    proc = subprocess.run(
        ["bash", str(RECORD_SCRIPT)],
        cwd=REPO_ROOT,
        env=_env(
            tmp_path,
            stub_runner,
            BW_DEMO_RECORDINGS_DIR=str(recordings),
        ),
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    for key in KEYS:
        cast = recordings / f"{key}.cast"
        svg = recordings / f"{key}.svg"
        assert cast.is_file(), f"missing {cast}"
        assert svg.is_file(), f"missing {svg}"
        header = json.loads(cast.read_text().splitlines()[0])
        assert header["version"] == 2
        assert f"scenario={key}" in cast.read_text()
        assert svg.read_text().lstrip().startswith("<svg")
    assert _call_log(tmp_path) == list(KEYS)


def test_record_script_uses_asciinema_and_tmux_and_sanitizes_cast(
    tmp_path: Path, stub_runner: Path, fake_live_tools: tuple[Path, Path]
):
    """The live split-pane path is exercised with tool stubs (no real install)."""
    bin_dir, marker = fake_live_tools
    env = _env(
        tmp_path,
        stub_runner,
        BW_DEMO_RECORDINGS_DIR=str(tmp_path / "live-recordings"),
        BW_DEMO_LIVE_RECORD="1",
    )
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["HOME"] = "/Users/real-operator"
    proc = subprocess.run(
        ["bash", str(RECORD_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    tool_calls = marker.read_text()
    assert "asciinema rec" in tool_calls
    assert "tmux new-session" in tool_calls
    assert "tmux split-window" in tool_calls
    for key in KEYS:
        cast_path = tmp_path / "live-recordings" / f"{key}.cast"
        assert cast_path.is_file()
        assert (tmp_path / "live-recordings" / f"{key}.svg").is_file()
        # Live casts are sanitized before being kept as recording assets.
        cast_text = cast_path.read_text()
        assert "/Users/real-operator" not in cast_text
        assert "supersecretvalue123" not in cast_text


def test_record_script_propagates_failed_live_scenario(
    tmp_path: Path, stub_runner: Path, fake_live_tools: tuple[Path, Path]
):
    """A failed demo must not be reported as a successful recording."""
    bin_dir, _ = fake_live_tools
    env = _env(
        tmp_path,
        stub_runner,
        BW_DEMO_RECORDINGS_DIR=str(tmp_path / "failed-recordings"),
        BW_DEMO_LIVE_RECORD="1",
        BW_DEMO_TEST_FAIL_KEY="heist",
    )
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    proc = subprocess.run(
        ["bash", str(RECORD_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    assert proc.returncode != 0
    assert "heist" in proc.stderr.lower()


def test_scripts_install_signal_cleanup_traps():
    for script in (RUN_SCRIPT, RECORD_SCRIPT):
        text = script.read_text()
        assert "trap cleanup EXIT INT TERM" in text
        assert "kill -TERM" in text


def test_run_script_terminates_runner_and_detached_child_on_sigterm(
    tmp_path: Path, stub_runner: Path
):
    pidfile = tmp_path / "child.pid"
    nested_pidfile = tmp_path / "nested.pid"
    env = _env(
        tmp_path,
        stub_runner,
        BW_DEMO_TEST_SLEEP="1",
        BW_DEMO_TEST_PIDFILE=str(pidfile),
        BW_DEMO_TEST_NESTED="1",
        BW_DEMO_TEST_NESTED_PIDFILE=str(nested_pidfile),
    )
    proc = subprocess.Popen(
        ["bash", str(RUN_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    launched_pids: list[int] = []
    try:
        deadline = time.monotonic() + 10
        while not (pidfile.exists() and nested_pidfile.exists()) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pidfile.exists(), "stub runner never started"
        assert nested_pidfile.exists(), "detached grandchild never started"
        child_pid = int(pidfile.read_text())
        nested_pid = int(nested_pidfile.read_text())
        launched_pids = [child_pid, nested_pid]
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)

        deadline = time.monotonic() + 10
        for pid in launched_pids:
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                pytest.fail(f"process {pid} survived parent SIGTERM")
    finally:
        # The test itself must clean up process groups even on failure: a
        # launcher-only kill would orphan the detached demo children.
        for pid in launched_pids:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                proc.kill()
            proc.wait(timeout=10)
