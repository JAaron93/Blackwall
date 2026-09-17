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
from unittest.mock import MagicMock, patch

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


def test_read_pid_file_invalid_negative_or_zero(tmp_path: Path) -> None:
    """read_pid_file returns None for non-positive or non-numeric values."""
    pid_file = tmp_path / "corrupt.pid"

    for invalid in ["0", "-1", "-12345", "not_a_number", "   ", ""]:
        pid_file.write_text(invalid)
        assert read_pid_file(pid_file) is None


def test_is_blackwall_process_linux_proc_cmdline() -> None:
    """is_blackwall_process correctly parses Linux /proc/<pid>/cmdline entries."""
    fake_pid = 42424

    # 1. Valid blackwall daemon invocation
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.read_bytes",
        return_value=b"python3\x00-m\x00blackwall.cli\x00serve\x00--daemon\x00",
    ):
        assert is_blackwall_process(fake_pid) is True

    # 2. Direct blackwall executable
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.read_bytes",
        return_value=b"/usr/local/bin/blackwall\x00serve\x00",
    ):
        assert is_blackwall_process(fake_pid) is True

    # 3. Unrelated Python process
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.read_bytes",
        return_value=b"python3\x00script.py\x00--arg\x00",
    ):
        assert is_blackwall_process(fake_pid) is False

    # 4. Defunct or kernel thread process (empty cmdline bytes)
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.read_bytes",
        return_value=b"",
    ):
        assert is_blackwall_process(fake_pid) is False

    # 5. PermissionError on /proc/<pid>/cmdline falls back to POSIX ps
    mock_res = MagicMock(returncode=0, stdout="python3 -m blackwall.cli serve\n")
    with patch("pathlib.Path.exists", return_value=True), patch(
        "pathlib.Path.read_bytes", side_effect=PermissionError("Access denied")
    ), patch("subprocess.run", return_value=mock_res):
        assert is_blackwall_process(fake_pid) is True


def test_is_blackwall_process_rejects_unrelated_substring_match() -> None:
    """is_blackwall_process rejects unrelated commands that merely contain 'blackwall' in arguments."""
    fake_pid = 42424

    # grep searching for blackwall
    mock_grep = MagicMock(returncode=0, stdout="grep -rn blackwall /var/log/\n")
    with patch("pathlib.Path.exists", return_value=False), patch("subprocess.run", return_value=mock_grep):
        assert is_blackwall_process(fake_pid) is False

    # text editor opening blackwall source
    mock_vim = MagicMock(returncode=0, stdout="vim src/blackwall/cli.py\n")
    with patch("pathlib.Path.exists", return_value=False), patch("subprocess.run", return_value=mock_vim):
        assert is_blackwall_process(fake_pid) is False


def test_stop_daemon_skips_sigkill_if_pid_reused_during_timeout(tmp_path: Path) -> None:
    """stop_daemon does not send SIGKILL if process identity changes during timeout."""
    pid_file = tmp_path / "test_reused.pid"
    write_pid_file(pid_file, 55555)

    # Initially Blackwall (for SIGTERM), then PID reused by unrelated process (before SIGKILL)
    identity_sequence = [True, False]

    def _mock_identity(pid: int) -> bool:
        return identity_sequence.pop(0) if identity_sequence else False

    with patch("blackwall.gateway.daemon.is_process_alive", return_value=True), patch(
        "blackwall.gateway.daemon.is_blackwall_process", side_effect=_mock_identity
    ), patch("os.kill") as mock_kill, patch("time.sleep"):
        result = stop_daemon(pid_file, timeout=0.1)
        assert result is True
        # Must have sent SIGTERM initially, but not SIGKILL
        mock_kill.assert_called_once_with(55555, signal.SIGTERM)
        # PID file must be removed
        assert not pid_file.exists()
