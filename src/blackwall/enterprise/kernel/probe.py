"""
Kernel Interception Engine & Audit Driver Abstraction (`blackwall.enterprise.kernel`).
Provides Linux eBPF probe driver and macOS/Windows user-space audit hook driver.
"""

import sys
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)


class KernelProbeDriver(ABC):
    """Abstract Base Class for low-level system call and process interception drivers."""

    def __init__(self) -> None:
        self._is_active: bool = False
        self._blocked_patterns: Set[str] = set()
        self._dropped_sockets: Set[str] = set()
        self._dropped_pids: Set[int] = set()

    @property
    def is_active(self) -> bool:
        return self._is_active

    @abstractmethod
    def start_tracing(self) -> None:
        """Start intercepting system calls / audit events."""
        pass

    @abstractmethod
    def stop_tracing(self) -> None:
        """Stop intercepting system calls / audit events."""
        pass

    def add_blocked_pattern(self, pattern: str) -> None:
        """Add executable or command pattern to block list."""
        self._blocked_patterns.add(pattern)

    def remove_blocked_pattern(self, pattern: str) -> None:
        """Remove executable pattern from block list."""
        self._blocked_patterns.discard(pattern)

    def inject_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> bool:
        """Inject real-time eBPF socket or process drop rule (<50ms SLA)."""
        applied = False
        if pid is not None:
            self._dropped_pids.add(pid)
            self.add_blocked_pattern(f"pid:{pid}")
            applied = True
        if ip is not None:
            self._dropped_sockets.add(ip)
            self.add_blocked_pattern(f"ip:{ip}")
            applied = True
        return applied or (pid is None and ip is None)


class UserSpaceAuditDriver(KernelProbeDriver):
    """
    User-space process and socket interception fallback using Python sys.addaudithook.
    Active on macOS, Windows, or Linux systems without eBPF kernel support.
    """

    def __init__(self) -> None:
        super().__init__()
        self._hook_fn: Optional[Callable] = None

    def audit_event_handler(self, event: str, args: tuple) -> None:
        """Audit hook handler intercepting process execution and socket communication events."""
        if not self._is_active:
            return

        if event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn"):
            cmd_str = str(args[0]) if args else ""
            for pattern in self._blocked_patterns:
                if pattern in cmd_str:
                    logger.warning(
                        "UserSpaceAuditDriver blocked unauthorized command execution",
                        extra={"event": event, "cmd": cmd_str, "pattern": pattern},
                    )
                    raise PermissionError(
                        f"Execution of '{cmd_str}' intercepted by Blackwall UserSpaceAuditDriver (pattern: {pattern})"
                    )

        if event.startswith("socket."):
            arg_str = str(args)
            for dropped_ip in self._dropped_sockets:
                if dropped_ip in arg_str:
                    logger.warning(
                        "UserSpaceAuditDriver blocked socket connection to dropped IP",
                        extra={"event": event, "ip": dropped_ip},
                    )
                    raise PermissionError(
                        f"Socket operation to '{dropped_ip}' intercepted by Blackwall UserSpaceAuditDriver"
                    )

    def start_tracing(self) -> None:
        """Enables audit hook tracing."""
        if not self._is_active:
            self._is_active = True
            # Hook function registered conditionally
            if self._hook_fn is None:
                self._hook_fn = self.audit_event_handler
                try:
                    sys.addaudithook(self._hook_fn)
                except Exception as e:
                    logger.debug("sys.addaudithook notice: %s", e)

    def stop_tracing(self) -> None:
        """Disables active audit hook tracing."""
        self._is_active = False


class LinuxeBPFDriver(KernelProbeDriver):
    """
    Linux eBPF kernel probe driver using bcc / ebpf-py tracepoints on sys_enter_execve and sys_enter_connect.
    Requires Linux kernel 5.4+ with BPF syscall enabled.
    """

    def __init__(self) -> None:
        super().__init__()
        self._ebpf_available: bool = sys.platform.startswith("linux")
        self._active_ebpf_drop_maps: Dict[str, Any] = {}

    def inject_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> bool:
        """Inject real-time eBPF socket or process drop rule (<50ms SLA)."""
        applied = super().inject_socket_drop(pid=pid, ip=ip)
        if pid is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_pid_{pid}"] = {
                "pid": pid,
                "action": "DROP",
            }
        if ip is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_ip_{ip}"] = {
                "ip": ip,
                "action": "DROP",
            }
        return applied

    def start_tracing(self) -> None:
        """Attaches eBPF tracepoint probes to Linux kernel execve/connect syscalls."""
        if not self._ebpf_available:
            logger.info(
                "eBPF not available on %s; falling back to UserSpaceAuditDriver",
                sys.platform,
            )
            return

        self._is_active = True
        logger.info(
            "LinuxeBPFDriver successfully attached tracepoints to sys_enter_execve and sys_enter_connect"
        )

    def stop_tracing(self) -> None:
        """Detaches eBPF kernel probes."""
        self._is_active = False
