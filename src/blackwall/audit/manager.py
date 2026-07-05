import sys
import os
import sqlite3
import threading
import traceback
import time
import uuid
import structlog
from typing import Optional, List, Tuple, Any

logger = structlog.get_logger(__name__)

# Global registry of active hook managers to allow dynamic enable/disable during tests
_active_managers: List["AuditHookManager"] = []
_hook_registered = False


def _global_audit_hook(event: str, args: Tuple[Any, ...]) -> None:
    # Use a copy of the list to avoid modification during iteration
    for manager in list(_active_managers):
        if manager.enabled:
            manager.handle_event(event, args)


def _register_global_hook() -> None:
    global _hook_registered
    if not _hook_registered:
        sys.addaudithook(_global_audit_hook)
        _hook_registered = True


class AuditHookManager:
    """Manages system audit hooks for low-level OS interception using sys.addaudithook."""

    def __init__(self, db_path: str = "./blackwall.db"):
        self.db_path = db_path
        self.enabled = False
        self._local = threading.local()

    def start(self) -> None:
        """Enables monitoring and registers with the global hook."""
        self.enabled = True
        _register_global_hook()
        if self not in _active_managers:
            _active_managers.append(self)

    def stop(self) -> None:
        """Disables monitoring and removes from active managers list."""
        self.enabled = False
        if self in _active_managers:
            _active_managers.remove(self)

    def _is_handling(self) -> bool:
        return bool(getattr(self._local, "handling", False))

    def _set_handling(self, val: bool) -> None:
        self._local.handling = val

    def _get_conn(self) -> sqlite3.Connection:
        current_pid = os.getpid()
        if (
            not hasattr(self._local, "conn")
            or getattr(self._local, "pid", None) != current_pid
        ):
            if hasattr(self._local, "conn"):
                try:
                    self._local.conn.close()
                except Exception:
                    pass
                delattr(self._local, "conn")

            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn.execute("PRAGMA busy_timeout=5000;")

            # Ensure tables exist synchronously
            self._local.conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_type TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    stack_trace TEXT
                );
            """)
            self._local.conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_executables (
                    executable TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );
            """)
            self._local.conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_iocs (
                    ioc TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
            """)
            self._local.conn.commit()
            self._local.pid = current_pid

        conn = self._local.conn
        assert isinstance(conn, sqlite3.Connection)
        return conn

    def handle_event(self, event: str, args: Tuple[Any, ...]) -> None:
        if not self.enabled:
            return
        if self._is_handling():
            return

        self._set_handling(True)
        start_time = time.perf_counter()
        try:
            self._evaluate_event(event, args)
        except PermissionError:
            raise
        except Exception as e:
            logger.error(
                "Audit hook evaluation failed", audit_event=event, error=str(e)
            )
            raise PermissionError(f"Audit hook evaluation failed: {e}") from e
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if duration_ms > 1.0:
                logger.warn(
                    "Audit hook callback execution exceeded 1ms limit",
                    duration_ms=duration_ms,
                )
            self._set_handling(False)

    def _evaluate_event(self, event: str, args: Tuple[Any, ...]) -> None:
        if event == "subprocess.Popen":
            self._validate_subprocess(args)
        elif event == "os.exec":
            self._validate_exec(args)
        elif event == "os.system":
            self._validate_system(args)
        elif event == "socket.connect":
            self._validate_socket(args)
        elif event == "open":
            self._validate_open(args)

    def _is_executable_blocked(self, executable: str) -> bool:
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT 1 FROM blocked_executables WHERE executable = ?", (executable,)
            )
            return cursor.fetchone() is not None
        except sqlite3.OperationalError as e:
            raise PermissionError(f"Database lookup failed, failing closed: {e}") from e

    def _is_ioc_blocked(self, ip: str, port: Optional[int]) -> bool:
        conn = self._get_conn()
        try:
            # Check exact IP match
            cursor = conn.execute("SELECT 1 FROM blocked_iocs WHERE ioc = ?", (ip,))
            if cursor.fetchone():
                return True

            # Check IP:port match
            if port is not None:
                ip_port = f"{ip}:{port}"
                cursor = conn.execute(
                    "SELECT 1 FROM blocked_iocs WHERE ioc = ?", (ip_port,)
                )
                if cursor.fetchone():
                    return True
            return False
        except sqlite3.OperationalError as e:
            raise PermissionError(f"Database lookup failed, failing closed: {e}") from e

    def _validate_subprocess(self, args: Tuple[Any, ...]) -> None:
        if len(args) < 2:
            return
        executable = args[0]
        cmd_args = args[1]

        exec_path = None
        if isinstance(executable, (str, bytes)):
            exec_path = (
                executable
                if isinstance(executable, str)
                else executable.decode("utf-8", errors="ignore")
            )
        elif isinstance(cmd_args, list) and len(cmd_args) > 0:
            item = cmd_args[0]
            if isinstance(item, (str, bytes)):
                exec_path = (
                    item
                    if isinstance(item, str)
                    else item.decode("utf-8", errors="ignore")
                )

        if exec_path:
            exec_name = os.path.basename(exec_path)
            if self._is_executable_blocked(exec_path) or self._is_executable_blocked(
                exec_name
            ):
                self._report_violation(
                    incident_type="SUBPROCESS_EXECUTION",
                    details=f"Unauthorized subprocess execution blocked: {exec_path}",
                    error_msg="PermissionError: Subprocess execution denied",
                )

    def _validate_exec(self, args: Tuple[Any, ...]) -> None:
        if len(args) < 1:
            return
        path = args[0]
        exec_path = None
        if isinstance(path, (str, bytes)):
            exec_path = (
                path if isinstance(path, str) else path.decode("utf-8", errors="ignore")
            )

        if exec_path:
            exec_name = os.path.basename(exec_path)
            is_shell = exec_name in ("sh", "bash", "zsh", "ksh", "csh", "dash", "ash")

            if (
                is_shell
                or self._is_executable_blocked(exec_path)
                or self._is_executable_blocked(exec_name)
            ):
                self._report_violation(
                    incident_type="DIRECT_EXEC_BYPASS",
                    details=f"Direct shell or unauthorized execution via os.exec blocked: {exec_path}",
                    error_msg="PermissionError: Direct shell execution denied",
                )

    def _validate_system(self, args: Tuple[Any, ...]) -> None:
        if len(args) < 1:
            return
        command = args[0]
        cmd_str = None
        if isinstance(command, (str, bytes)):
            cmd_str = (
                command
                if isinstance(command, str)
                else command.decode("utf-8", errors="ignore")
            )

        if cmd_str:
            tokens = cmd_str.split()
            if tokens:
                exec_path = tokens[0]
                exec_name = os.path.basename(exec_path)
                is_shell = exec_name in (
                    "sh",
                    "bash",
                    "zsh",
                    "ksh",
                    "csh",
                    "dash",
                    "ash",
                )
                if (
                    is_shell
                    or self._is_executable_blocked(exec_path)
                    or self._is_executable_blocked(exec_name)
                ):
                    self._report_violation(
                        incident_type="SYSTEM_COMMAND_EXECUTION",
                        details=f"Unauthorized system command execution blocked: {cmd_str}",
                        error_msg="PermissionError: System command execution denied",
                    )

    def _validate_socket(self, args: Tuple[Any, ...]) -> None:
        if len(args) < 2:
            return
        address = args[1]

        ip = None
        port = None
        if isinstance(address, tuple) and len(address) >= 2:
            ip = str(address[0])
            port = int(address[1])
        elif isinstance(address, (str, bytes)):
            ip = (
                address
                if isinstance(address, str)
                else address.decode("utf-8", errors="ignore")
            )

        if ip:
            if self._is_ioc_blocked(ip, port):
                target = f"{ip}:{port}" if port is not None else ip
                self._report_violation(
                    incident_type="MALICIOUS_IOC_CONNECTION",
                    details=f"Outbound connection to malicious IOC blocked: {target}",
                    error_msg="PermissionError: Connection to malicious IOC blocked",
                )

    def _validate_open(self, args: Tuple[Any, ...]) -> None:
        if len(args) < 1:
            return
        path = args[0]
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else None

        file_path = None
        if isinstance(path, (str, bytes)):
            file_path = (
                path if isinstance(path, str) else path.decode("utf-8", errors="ignore")
            )
        elif isinstance(path, int):
            return

        if not file_path:
            return

        is_write = False
        if mode is not None:
            if isinstance(mode, (str, bytes)):
                mode_str = (
                    mode
                    if isinstance(mode, str)
                    else mode.decode("utf-8", errors="ignore")
                )
                is_write = any(c in mode_str for c in ("w", "a", "+", "x"))
        elif flags is not None:
            is_write = (flags & 3) in (os.O_WRONLY, os.O_RDWR)

        if is_write:
            # Resolve symlinks recursively to prevent symlink write bypasses to critical paths
            abs_path = os.path.realpath(file_path)

            is_critical = False
            etc_real = os.path.realpath("/etc")
            root_real = os.path.realpath("/root")

            if (
                abs_path.startswith("/etc/")
                or abs_path == "/etc"
                or abs_path.startswith(etc_real + "/")
                or abs_path == etc_real
            ):
                is_critical = True
            elif (
                abs_path.startswith("/root/")
                or abs_path == "/root"
                or abs_path.startswith(root_real + "/")
                or abs_path == root_real
            ):
                is_critical = True
            elif abs_path.endswith(".bashrc"):
                is_critical = True
            elif "/.ssh/" in abs_path or abs_path.endswith("/.ssh"):
                is_critical = True

            if is_critical:
                self._report_violation(
                    incident_type="CRITICAL_FILE_WRITE",
                    details=f"Unauthorized write access to critical file blocked: {file_path} (target: {abs_path})",
                    error_msg="PermissionError: File write access denied",
                )

    def _report_violation(
        self, incident_type: str, details: str, error_msg: str
    ) -> None:
        conn = self._get_conn()
        incident_id = str(uuid.uuid4())
        timestamp = int(time.time())
        stack_trace = "".join(traceback.format_stack())

        try:
            conn.execute(
                "INSERT INTO audit_incidents (incident_id, incident_type, timestamp, details, stack_trace) VALUES (?, ?, ?, ?, ?)",
                (incident_id, incident_type, timestamp, details, stack_trace),
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.error("Failed to write audit incident to DB", error=str(e))

        logger.warn(
            "Security violation blocked by audit hook",
            incident_id=incident_id,
            incident_type=incident_type,
            details=details,
            stack_trace=stack_trace,
        )

        raise PermissionError(error_msg)
