"""
Daemonization and PID management utilities for Blackwall MCP Gateway.

Provides:
- PID file read/write/remove with atomic filesystem checks.
- Process liveness checking via signal probing.
- Graceful daemon shutdown (SIGTERM with SIGKILL escalation).
- UNIX double-fork daemonization with standard stream redirection.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def write_pid_file(pid_path: Path | str, pid: int | None = None) -> None:
    """Writes the process ID to the specified file path."""
    path = Path(pid_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    target_pid = pid if pid is not None else os.getpid()
    path.write_text(f"{target_pid}\n", encoding="utf-8")
    logger.debug("Wrote PID %d to %s", target_pid, path)


def read_pid_file(pid_path: Path | str) -> int | None:
    """Reads and returns the PID from the specified file path, or None if invalid/absent."""
    path = Path(pid_path).resolve()
    if not path.exists():
        return None

    try:
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return None
        return int(content)
    except (ValueError, OSError) as exc:
        logger.warning("Failed reading PID file '%s': %s", path, exc)
        return None


def remove_pid_file(pid_path: Path | str) -> None:
    """Safely removes the PID file if it exists."""
    path = Path(pid_path).resolve()
    try:
        if path.exists():
            path.unlink()
            logger.debug("Removed PID file %s", path)
    except OSError as exc:
        logger.warning("Failed removing PID file '%s': %s", path, exc)


def is_process_alive(pid: int) -> bool:
    """Checks whether a process with the given PID is currently running."""
    if pid <= 0:
        return False

    # If it is a direct child process, reap/check status via waitpid to avoid zombie false-positives
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return False
        if wpid == 0:
            return True
    except ChildProcessError:
        pass

    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # Process exists but belongs to another user
        return True
    except (ProcessLookupError, OSError):
        return False


def is_blackwall_process(pid: int) -> bool:
    """
    Verifies process command-line identity before sending signals.

    Checks /proc/<pid>/cmdline on Linux or 'ps -p <pid> -o command=' on POSIX
    to confirm the process is Blackwall or Python running Blackwall.
    """
    if pid <= 0:
        return False

    cmdline: str | None = None

    # 1. Linux /proc/<pid>/cmdline check
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    try:
        if proc_cmdline.exists():
            raw_bytes = proc_cmdline.read_bytes()
            cmdline = raw_bytes.decode(errors="replace").replace("\x00", " ")
    except (OSError, PermissionError):
        cmdline = None

    # 2. POSIX 'ps' fallback (macOS, BSD, or if /proc unavailable)
    if not cmdline:
        try:
            res = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                cmdline = res.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            cmdline = None

    if not cmdline:
        return False

    return "blackwall" in cmdline.lower()


def stop_daemon(pid_path: Path | str, timeout: float = 5.0) -> bool:
    """
    Sends SIGTERM to the daemon PID, waits for termination, and escalates to SIGKILL if necessary.

    Returns True if the daemon was stopped or was not running.
    """
    path = Path(pid_path).resolve()
    pid = read_pid_file(path)

    if pid is None:
        remove_pid_file(path)
        return True

    if not is_process_alive(pid):
        remove_pid_file(path)
        return True

    if not is_blackwall_process(pid):
        logger.warning(
            "Stale PID file '%s' detected (PID %d is alive but is not a Blackwall process). "
            "Removing stale PID file without signaling unrelated process.",
            path,
            pid,
        )
        remove_pid_file(path)
        return True

    logger.info("Sending SIGTERM to Blackwall daemon (PID %d)...", pid)
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        remove_pid_file(path)
        return True

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_process_alive(pid):
            remove_pid_file(path)
            logger.info("Blackwall daemon (PID %d) terminated cleanly.", pid)
            return True
        time.sleep(0.1)

    # Force kill if still running after timeout
    logger.warning("Daemon PID %d did not terminate in %ss; sending SIGKILL...", pid, timeout)
    try:
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.2)
    except (ProcessLookupError, OSError):
        pass

    remove_pid_file(path)
    return not is_process_alive(pid)


def daemonize(pid_path: Path | str, logfile_path: Path | str) -> None:
    """
    Performs standard UNIX double-fork daemonization.

    Detaches from controlling terminal, sets session leader, umask,
    redirects stdin to /dev/null, and redirects stdout/stderr to logfile_path.
    """
    pid_file = Path(pid_path).resolve()
    log_file = Path(logfile_path).resolve()

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        raise RuntimeError(f"First fork failed: {exc}") from exc

    # 2. Decouple from parent environment
    os.setsid()
    os.umask(0o022)

    # 3. Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        raise RuntimeError(f"Second fork failed: {exc}") from exc

    # 4. Flush standard streams
    sys.stdout.flush()
    sys.stderr.flush()

    # 5. Redirect file descriptors
    devnull = open(os.devnull, "r")
    log_fd = open(log_file, "a+", encoding="utf-8")

    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())

    # 6. Write PID of active daemon process
    write_pid_file(pid_file)
