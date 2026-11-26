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


def test_record_script_uses_asciinema_and_tmux_when_available(
    tmp_path: Path, stub_runner: Path
):
    """The live split-pane path is exercised with tool stubs (no real install)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "live_tools.log"
    asciinema = bin_dir / "asciinema"
    asciinema.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "asciinema $*" >> "{marker}"\n'
        'cast=""\n'
        'prev=""\n'
        'for arg in "$@"; do\n'
        '  if [[ "$prev" == "rec" ]]; then cast="$arg"; fi\n'
        '  prev="$arg"\n'
        "done\n"
        'if [[ -n "$cast" ]]; then\n'
        '  printf \'{"version": 2, "width": 120, "height": 30}\\n\' > "$cast"\n'
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    asciinema.chmod(0o755)
    tmux = bin_dir / "tmux"
    tmux.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "tmux $*" >> "{marker}"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    tmux.chmod(0o755)
    env = _env(
        tmp_path,
        stub_runner,
        BW_DEMO_RECORDINGS_DIR=str(tmp_path / "live-recordings"),
        BW_DEMO_LIVE_RECORD="1",
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
    assert proc.returncode == 0, proc.stderr
    tool_calls = marker.read_text()
    assert "asciinema rec" in tool_calls
    assert "tmux new-session" in tool_calls
    assert "tmux split-window" in tool_calls
    for key in KEYS:
        assert (tmp_path / "live-recordings" / f"{key}.cast").is_file()
        assert (tmp_path / "live-recordings" / f"{key}.svg").is_file()


def test_scripts_install_signal_cleanup_traps():
    for script in (RUN_SCRIPT, RECORD_SCRIPT):
        text = script.read_text()
        assert "trap cleanup EXIT INT TERM" in text
        assert "kill -TERM" in text


def test_run_script_terminates_active_child_on_sigterm(tmp_path: Path, stub_runner: Path):
    pidfile = tmp_path / "child.pid"
    env = _env(
        tmp_path,
        stub_runner,
        BW_DEMO_TEST_SLEEP="1",
        BW_DEMO_TEST_PIDFILE=str(pidfile),
    )
    proc = subprocess.Popen(
        ["bash", str(RUN_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pidfile.exists(), "stub runner never started"
        child_pid = int(pidfile.read_text())
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"stub runner {child_pid} survived parent SIGTERM")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
