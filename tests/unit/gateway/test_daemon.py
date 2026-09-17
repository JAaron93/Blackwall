"""
Unit tests for daemon and PID management utilities (Rule 10 compliant).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from blackwall.gateway.daemon import (
    is_blackwall_process,
    is_process_alive,
    read_pid_file,
    remove_pid_file,
    stop_daemon,
    write_pid_file,
)


def test_pid_file_lifecycle(tmp_path: Path) -> None:
    """write_pid_file, read_pid_file, and remove_pid_file operate atomically."""
    pid_file = tmp_path / "test.pid"
    assert read_pid_file(pid_file) is None

    write_pid_file(pid_file, 12345)
    assert pid_file.exists()
    assert read_pid_file(pid_file) == 12345

    remove_pid_file(pid_file)
    assert not pid_file.exists()
    assert read_pid_file(pid_file) is None


def test_is_process_alive() -> None:
    """is_process_alive correctly checks current process and invalid PIDs."""
    assert is_process_alive(os.getpid()) is True
    assert is_process_alive(0) is False
    assert is_process_alive(-1) is False
    # Extremely large PID that should not exist
    assert is_process_alive(9999999) is False


def test_is_blackwall_process_recognizes_identity() -> None:
    """is_blackwall_process identifies blackwall processes and rejects unrelated ones."""
    assert is_blackwall_process(0) is False
    assert is_blackwall_process(-1) is False
    assert is_blackwall_process(9999999) is False

    # 1. Unrelated process
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        preexec_fn=os.setsid,
    )
    try:
        assert is_blackwall_process(unrelated.pid) is False
    finally:
        try:
            os.killpg(os.getpgid(unrelated.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        if unrelated.poll() is None:
            unrelated.kill()

    # 2. Blackwall process
    bw_proc = subprocess.Popen(
        [sys.executable, "-c", "# blackwall daemon process\nimport time; time.sleep(60)"],
        preexec_fn=os.setsid,
    )
    try:
        assert is_blackwall_process(bw_proc.pid) is True
    finally:
        try:
            os.killpg(os.getpgid(bw_proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        if bw_proc.poll() is None:
            bw_proc.kill()


def test_stop_daemon_stale_pid_unrelated_process_not_killed(tmp_path: Path) -> None:
    """stop_daemon does not kill unrelated process on stale PID, and removes PID file."""
    pid_file = tmp_path / "stale.pid"
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        preexec_fn=os.setsid,
    )
    try:
        write_pid_file(pid_file, unrelated.pid)
        assert is_process_alive(unrelated.pid) is True

        # Attempt to stop daemon using stale PID
        result = stop_daemon(pid_file)
        assert result is True

        # Unrelated process must still be running
        assert is_process_alive(unrelated.pid) is True
        # Stale PID file must have been cleaned up
        assert not pid_file.exists()
    finally:
        try:
            os.killpg(os.getpgid(unrelated.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        if unrelated.poll() is None:
            unrelated.kill()


def test_stop_daemon_terminates_blackwall_process(tmp_path: Path) -> None:
    """stop_daemon terminates valid Blackwall process and cleans up PID file."""
    pid_file = tmp_path / "valid.pid"
    bw_proc = subprocess.Popen(
        [sys.executable, "-c", "# blackwall daemon\nimport time; time.sleep(60)"],
        preexec_fn=os.setsid,
    )
    try:
        write_pid_file(pid_file, bw_proc.pid)
        assert is_process_alive(bw_proc.pid) is True

        result = stop_daemon(pid_file, timeout=2.0)
        assert result is True
        assert not is_process_alive(bw_proc.pid)
        assert not pid_file.exists()
    finally:
        try:
            os.killpg(os.getpgid(bw_proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        if bw_proc.poll() is None:
            bw_proc.kill()
