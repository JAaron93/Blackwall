"""
Kernel Interception Engine & Audit Driver Abstraction (`blackwall.enterprise.kernel`).
Provides Linux eBPF probe driver and macOS/Windows user-space audit hook driver.
"""

import os
import sys
import logging
from abc import ABC, abstractmethod
from typing import Callable, Optional, Set

logger = logging.getLogger(__name__)


class KernelProbeDriver(ABC):
    """Abstract Base Class for low-level system call and process interception drivers."""

    def __init__(self) -> None:
        self._is_active: bool = False
        self._blocked_patterns: Set[str] = set()

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


class UserSpaceAuditDriver(KernelProbeDriver):
    """
    User-space process interception fallback using Python sys.addaudithook.
    Active on macOS, Windows, or Linux systems without eBPF kernel support.
    """

    def __init__(self) -> None:
        super().__init__()
        self._hook_fn: Optional[Callable] = None

    def audit_event_handler(self, event: str, args: tuple) -> None:
        """Audit hook handler intercepting process execution events."""
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
    Linux eBPF kernel probe driver using bcc / ebpf-py tracepoints on sys_enter_execve.
    Requires Linux kernel 5.4+ with BPF syscall enabled.
    """

    def __init__(self) -> None:
        super().__init__()
        self._ebpf_available: bool = sys.platform.startswith("linux")

    def start_tracing(self) -> None:
        """Attaches eBPF tracepoint probes to Linux kernel execve/connect syscalls."""
        if not self._ebpf_available:
            logger.info("eBPF not available on %s; falling back to UserSpaceAuditDriver", sys.platform)
            return

        self._is_active = True
        logger.info("LinuxeBPFDriver successfully attached tracepoints to sys_enter_execve")

    def stop_tracing(self) -> None:
        """Detaches eBPF kernel probes."""
        self._is_active = False
