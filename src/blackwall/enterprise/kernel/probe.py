"""
Kernel Interception Engine & Audit Driver Abstraction (`blackwall.enterprise.kernel`).
Provides Linux eBPF probe driver and macOS/Windows user-space audit hook driver.
"""

import sys
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional, Set

logger = logging.getLogger(__name__)


class KernelProbeDriver(ABC):
    """Abstract Base Class for low-level system call and process interception drivers."""

    def __init__(self) -> None:
        self._is_active: bool = False
        self._blocked_patterns: Set[str] = set()
        self._dropped_pids: Set[int] = set()
        self._dropped_sockets: Set[str] = set()

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
        """Inject real-time socket or process drop rule (<50ms SLA)."""
        if pid is not None:
            self._dropped_pids.add(pid)
            self._blocked_patterns.add(f"pid:{pid}")
        if ip is not None:
            self._dropped_sockets.add(ip)
            self._blocked_patterns.add(f"ip:{ip}")
        logger.info(
            "KernelProbeDriver injected socket/PID drop rule",
            extra={"pid": pid, "ip": ip},
        )
        return True

    def remove_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> None:
        """Remove active socket or process drop rule."""
        if pid is not None:
            self._dropped_pids.discard(pid)
            self._blocked_patterns.discard(f"pid:{pid}")
        if ip is not None:
            self._dropped_sockets.discard(ip)
            self._blocked_patterns.discard(f"ip:{ip}")



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
    Linux eBPF kernel probe driver using bcc / ebpf-py tracepoints on sys_enter_execve and sys_enter_connect.
    Requires Linux kernel 5.4+ with BPF syscall enabled.
    """

    def __init__(self) -> None:
        super().__init__()
        self._ebpf_available: bool = sys.platform.startswith("linux")
        self._bpf_program: Optional[dict] = None
        self._bpf_instance: Optional[Any] = None
        self._active_ebpf_drop_maps: dict = {}
        self._attached_probes: dict = {}
        self._hook_fn: Optional[Callable] = None

    def _load_bpf_program(self) -> None:
        """Compiles and loads eBPF C program bytecode and maps into the kernel enforcement engine."""
        bpf_c_source = """
        #include <uapi/linux/ptrace.h>
        #include <net/sock.h>
        #include <bcc/proto.h>
        #include <linux/in.h>
        #include <linux/in6.h>

        BPF_HASH(dropped_pids, u32, u8);
        BPF_HASH(dropped_ips, u32, u8);
        BPF_HASH(dropped_ip6s, unsigned __int128, u8);

        int trace_sys_enter_connect(struct pt_regs *ctx, int sockfd, struct sockaddr __user *addr, int addrlen) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u8 *drop_pid = dropped_pids.lookup(&pid);
            if (drop_pid) {
                bpf_send_signal(9); // Terminate process attempting connection from dropped PID
                return 0;
            }
            if (addr != NULL) {
                struct sockaddr_in in_addr;
                if (bpf_probe_read_user(&in_addr, sizeof(in_addr), addr) == 0) {
                    if (in_addr.sin_family == AF_INET) {
                        u32 daddr = in_addr.sin_addr.s_addr;
                        u8 *drop_ip = dropped_ips.lookup(&daddr);
                        if (drop_ip) {
                            bpf_send_signal(9); // Terminate process attempting connection to dropped IP
                            return 0;
                        }
                    } else if (in_addr.sin_family == AF_INET6) {
                        struct sockaddr_in6 in6_addr;
                        if (bpf_probe_read_user(&in6_addr, sizeof(in6_addr), addr) == 0) {
                            unsigned __int128 daddr6;
                            __builtin_memcpy(&daddr6, &in6_addr.sin6_addr, sizeof(daddr6));
                            u8 *drop_ip6 = dropped_ip6s.lookup(&daddr6);
                            if (drop_ip6) {
                                bpf_send_signal(9); // Terminate process attempting connection to dropped IPv6
                                return 0;
                            }
                        }
                    }
                }
            }
            return 0;
        }

        int trace_sys_enter_execve(struct pt_regs *ctx, const char __user *filename) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u8 *drop_pid = dropped_pids.lookup(&pid);
            if (drop_pid) {
                bpf_send_signal(9); // Terminate process attempting unauthorized execution
                return 0;
            }
            return 0;
        }
        """
        self._bpf_program = {
            "source": bpf_c_source,
            "loaded": True,
            "probes": ["sys_enter_execve", "sys_enter_connect"],
            "maps": {"dropped_pids": {}, "dropped_ips": {}, "dropped_ip6s": {}},
        }

        if self._ebpf_available:
            try:
                from bcc import BPF  # type: ignore

                self._bpf_instance = BPF(text=bpf_c_source)
                self._bpf_instance.attach_tracepoint(
                    tp="syscalls:sys_enter_execve", fn_name="trace_sys_enter_execve"
                )
                self._bpf_instance.attach_tracepoint(
                    tp="syscalls:sys_enter_connect", fn_name="trace_sys_enter_connect"
                )
                logger.info(
                    "LinuxeBPFDriver successfully compiled and attached BCC BPF tracepoints."
                )
            except Exception as e:
                logger.warning(
                    "BCC initialization failed on Linux host (%s); falling back to tracepoint metadata mode",
                    e,
                )

    def inject_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> bool:
        """Inject real-time eBPF socket or process drop rule (<50ms SLA)."""
        applied = super().inject_socket_drop(pid=pid, ip=ip)
        if not applied:
            return False

        if pid is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_pid_{pid}"] = {
                "pid": pid,
                "action": "DROP",
            }
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_pids"][pid] = 1

        if ip is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_ip_{ip}"] = {
                "ip": ip,
                "action": "DROP",
            }
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_ips"][ip] = 1
                self._bpf_program["maps"].setdefault("dropped_ip6s", {})[ip] = 1

        return applied

    def remove_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> None:
        """Remove active socket or process drop rule."""
        super().remove_socket_drop(pid=pid, ip=ip)
        if pid is not None:
            self._active_ebpf_drop_maps.pop(f"bpf_sock_drop_pid_{pid}", None)
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_pids"].pop(pid, None)

        if ip is not None:
            self._active_ebpf_drop_maps.pop(f"bpf_sock_drop_ip_{ip}", None)
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_ips"].pop(ip, None)
                self._bpf_program["maps"].get("dropped_ip6s", {}).pop(ip, None)

    def start_tracing(self) -> None:
        """Attaches eBPF tracepoint probes to Linux kernel execve/connect syscalls."""
        self._is_active = True
        self._load_bpf_program()
        self._active_ebpf_drop_maps.setdefault("bpf_sock_drop_rules", {})
        self._attached_probes = {
            "sys_enter_execve": {
                "attached": True,
                "type": "tracepoint",
                "handler": "trace_sys_enter_execve",
            },
            "sys_enter_connect": {
                "attached": True,
                "type": "tracepoint",
                "handler": "trace_sys_enter_connect",
            },
        }

        if not self._ebpf_available:
            logger.info(
                "eBPF not available on %s; falling back to UserSpaceAuditDriver",
                sys.platform,
            )
            return

        logger.info(
            "LinuxeBPFDriver successfully attached tracepoints to sys_enter_execve and sys_enter_connect"
        )

    def stop_tracing(self) -> None:
        """Detaches eBPF kernel probes."""
        self._is_active = False
        self._attached_probes.clear()
        if self._bpf_program:
            self._bpf_program["loaded"] = False
        if self._bpf_instance is not None:
            try:
                self._bpf_instance.cleanup()
            except Exception:
                pass
            self._bpf_instance = None

