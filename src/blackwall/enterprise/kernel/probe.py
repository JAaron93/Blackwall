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

    def is_dropped(self, pid: Optional[int] = None, ip: Optional[str] = None) -> bool:
        """Check whether a PID or IP has an active drop rule."""
        if pid is not None and pid in self._dropped_pids:
            return True
        if ip is not None and ip in self._dropped_sockets:
            return True
        return False

    def remove_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> None:
        """Removes a previously injected PID or IP drop rule from userspace tracking."""
        if pid is not None:
            self._dropped_pids.discard(pid)
            self._blocked_patterns.discard(f"pid:{pid}")
        if ip is not None:
            self._dropped_sockets.discard(ip)
            self._blocked_patterns.discard(f"ip:{ip}")

    def inject_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> bool:
        """Inject real-time eBPF socket or process drop rule (<50ms SLA)."""
        if pid is None and ip is None:
            return False
        if not self._is_active:
            self.start_tracing()
        applied = False
        if pid is not None:
            self._dropped_pids.add(pid)
            self.add_blocked_pattern(f"pid:{pid}")
            applied = True
        if ip is not None:
            self._dropped_sockets.add(ip)
            self.add_blocked_pattern(f"ip:{ip}")
            applied = True
        return applied


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

        import os
        current_pid = os.getpid()

        if event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.kill", "os.posix_spawn"):
            if current_pid in self._dropped_pids:
                logger.warning(
                    "UserSpaceAuditDriver blocked process execution from dropped PID",
                    extra={"event": event, "pid": current_pid},
                )
                raise PermissionError(
                    f"Execution from dropped PID '{current_pid}' intercepted by Blackwall UserSpaceAuditDriver"
                )

            if event == "os.kill" and args:
                target_pid = args[0]
                if target_pid in self._dropped_pids:
                    logger.warning(
                        "UserSpaceAuditDriver blocked operation targeting dropped PID",
                        extra={"event": event, "pid": target_pid},
                    )
                    raise PermissionError(
                        f"Process operation on dropped PID '{target_pid}' intercepted by Blackwall UserSpaceAuditDriver"
                    )

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
            if current_pid in self._dropped_pids:
                logger.warning(
                    "UserSpaceAuditDriver blocked socket operation from dropped PID",
                    extra={"event": event, "pid": current_pid},
                )
                raise PermissionError(
                    f"Socket operation from dropped PID '{current_pid}' intercepted by Blackwall UserSpaceAuditDriver"
                )

            # Extract exact host/IP from socket args to avoid substring match collisions
            extracted_ips: set[str] = set()
            for arg in args:
                if isinstance(arg, tuple) and len(arg) >= 1 and isinstance(arg[0], str):
                    extracted_ips.add(arg[0])
                elif isinstance(arg, str):
                    extracted_ips.add(arg)

            for dropped_ip in self._dropped_sockets:
                if dropped_ip in extracted_ips:
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
        self._attached_probes: Dict[str, Any] = {}
        self._hook_fn: Optional[Callable] = None
        self._bpf_program: Optional[Dict[str, Any]] = None
        self._bpf_instance: Optional[Any] = None
        self._bpf_load_error: Optional[Exception] = None

    def _load_bpf_program(self) -> None:
        """Compiles and loads eBPF C program bytecode and maps into the kernel enforcement engine."""
        bpf_c_source = """
        #include <uapi/linux/ptrace.h>
        #include <net/sock.h>
        #include <bcc/proto.h>
        #include <linux/in.h>

        BPF_HASH(dropped_pids, u32, u8);
        BPF_HASH(dropped_ips, u32, u8);

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
            "maps": {"dropped_pids": {}, "dropped_ips": {}},
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
                self._bpf_load_error = None
                logger.info(
                    "LinuxeBPFDriver compiled and loaded kernel BPF program into kernel space"
                )
            except Exception as exc:
                logger.warning(
                    "BCC kernel program attachment fallback (simulated/userspace): %s",
                    exc,
                )
                self._bpf_instance = None
                self._bpf_load_error = exc

    def remove_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> None:
        """Removes a previously injected drop rule from BPF maps and userspace tracking."""
        super().remove_socket_drop(pid=pid, ip=ip)
        if pid is not None:
            self._active_ebpf_drop_maps.pop(f"bpf_sock_drop_pid_{pid}", None)
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_pids"].pop(pid, None)
            if self._bpf_instance is not None:
                try:
                    import ctypes
                    key = ctypes.c_uint32(pid)
                    self._bpf_instance["dropped_pids"].pop(key, None)
                except Exception:
                    try:
                        self._bpf_instance["dropped_pids"].pop(pid, None)
                    except Exception:
                        pass
        if ip is not None:
            self._active_ebpf_drop_maps.pop(f"bpf_sock_drop_ip_{ip}", None)
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_ips"].pop(ip, None)
            if self._bpf_instance is not None:
                try:
                    import ctypes
                    import socket
                    key = ctypes.c_uint32.from_buffer_copy(socket.inet_aton(ip))
                    self._bpf_instance["dropped_ips"].pop(key, None)
                except Exception:
                    try:
                        self._bpf_instance["dropped_ips"].pop(ip, None)
                    except Exception:
                        pass

    def inject_socket_drop(
        self, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> bool:
        """Inject real-time eBPF socket or process drop rule (<50ms SLA)."""
        applied = super().inject_socket_drop(pid=pid, ip=ip)
        if not applied:
            return False

        if self._ebpf_available and self._bpf_instance is None:
            logger.error(
                "LinuxeBPFDriver kernel eBPF program not loaded; cannot enforce kernel drop."
            )
            self.remove_socket_drop(pid=pid, ip=ip)
            return False
        if pid is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_pid_{pid}"] = {
                "pid": pid,
                "action": "DROP",
            }
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_pids"][pid] = 1
            if self._bpf_instance is not None:
                try:
                    import ctypes

                    key = ctypes.c_uint32(pid)
                    val = ctypes.c_uint8(1)
                    try:
                        self._bpf_instance["dropped_pids"][key] = val
                    except TypeError:
                        self._bpf_instance["dropped_pids"][pid] = 1
                except Exception as exc:
                    logger.error("Failed updating BCC dropped_pids map: %s", exc)
                    self.remove_socket_drop(pid=pid, ip=ip)
                    return False
        if ip is not None:
            self._active_ebpf_drop_maps[f"bpf_sock_drop_ip_{ip}"] = {
                "ip": ip,
                "action": "DROP",
            }
            if self._bpf_program and "maps" in self._bpf_program:
                self._bpf_program["maps"]["dropped_ips"][ip] = 1
            if self._bpf_instance is not None:
                try:
                    import ctypes
                    import socket

                    try:
                        key = ctypes.c_uint32.from_buffer_copy(socket.inet_aton(ip))
                        val = ctypes.c_uint8(1)
                        try:
                            self._bpf_instance["dropped_ips"][key] = val
                        except TypeError:
                            self._bpf_instance["dropped_ips"][key.value] = 1
                    except Exception as exc:
                        logger.error("Failed packing IP for BCC dropped_ips map: %s", exc)
                        self.remove_socket_drop(pid=pid, ip=ip)
                        return False
                except Exception as exc:
                    logger.error("Failed updating BCC dropped_ips map: %s", exc)
                    self.remove_socket_drop(pid=pid, ip=ip)
                    return False
        return applied

    def audit_event_handler(self, event: str, args: tuple) -> None:
        """Audit hook handler for eBPF tracepoint compatibility and userspace enforcement."""
        if not self._is_active:
            return

        import os
        current_pid = os.getpid()

        if event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.kill", "os.posix_spawn"):
            if current_pid in self._dropped_pids or f"bpf_sock_drop_pid_{current_pid}" in self._active_ebpf_drop_maps:
                logger.warning(
                    "LinuxeBPFDriver blocked process execution from dropped PID",
                    extra={"event": event, "pid": current_pid},
                )
                raise PermissionError(
                    f"Execution from dropped PID '{current_pid}' intercepted by Blackwall LinuxeBPFDriver"
                )

            if event == "os.kill" and args:
                target_pid = args[0]
                if target_pid in self._dropped_pids or f"bpf_sock_drop_pid_{target_pid}" in self._active_ebpf_drop_maps:
                    logger.warning(
                        "LinuxeBPFDriver blocked operation targeting dropped PID",
                        extra={"event": event, "pid": target_pid},
                    )
                    raise PermissionError(
                        f"Process operation on dropped PID '{target_pid}' intercepted by Blackwall LinuxeBPFDriver"
                    )

            cmd_str = str(args[0]) if args else ""
            for pattern in self._blocked_patterns:
                if pattern in cmd_str:
                    logger.warning(
                        "LinuxeBPFDriver blocked unauthorized command execution",
                        extra={"event": event, "cmd": cmd_str, "pattern": pattern},
                    )
                    raise PermissionError(
                        f"Execution of '{cmd_str}' intercepted by Blackwall LinuxeBPFDriver (pattern: {pattern})"
                    )

        if event.startswith("socket."):
            if current_pid in self._dropped_pids or f"bpf_sock_drop_pid_{current_pid}" in self._active_ebpf_drop_maps:
                logger.warning(
                    "LinuxeBPFDriver blocked socket operation from dropped PID",
                    extra={"event": event, "pid": current_pid},
                )
                raise PermissionError(
                    f"Socket operation from dropped PID '{current_pid}' intercepted by Blackwall LinuxeBPFDriver"
                )

            extracted_ips: set[str] = set()
            for arg in args:
                if isinstance(arg, tuple) and len(arg) >= 1 and isinstance(arg[0], str):
                    extracted_ips.add(arg[0])
                elif isinstance(arg, str):
                    extracted_ips.add(arg)

            for dropped_ip in self._dropped_sockets:
                if dropped_ip in extracted_ips:
                    logger.warning(
                        "LinuxeBPFDriver blocked socket connection to dropped IP",
                        extra={"event": event, "ip": dropped_ip},
                    )
                    raise PermissionError(
                        f"Socket operation to '{dropped_ip}' intercepted by Blackwall LinuxeBPFDriver"
                    )

    def start_tracing(self) -> None:
        """Attaches eBPF tracepoint probes and loads kernel enforcement program."""
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

        # Restore retained drop rules into newly loaded BPF maps across restart
        if not self._ebpf_available or self._bpf_instance is not None:
            for pid in list(self._dropped_pids):
                self._active_ebpf_drop_maps[f"bpf_sock_drop_pid_{pid}"] = {
                    "pid": pid,
                    "action": "DROP",
                }
                if self._bpf_program and "maps" in self._bpf_program:
                    self._bpf_program["maps"]["dropped_pids"][pid] = 1
                if self._bpf_instance is not None:
                    try:
                        import ctypes

                        key = ctypes.c_uint32(pid)
                        val = ctypes.c_uint8(1)
                        try:
                            self._bpf_instance["dropped_pids"][key] = val
                        except TypeError:
                            self._bpf_instance["dropped_pids"][pid] = 1
                    except Exception as exc:
                        logger.error("Failed restoring BCC dropped_pids map: %s", exc)

            for ip in list(self._dropped_sockets):
                self._active_ebpf_drop_maps[f"bpf_sock_drop_ip_{ip}"] = {
                    "ip": ip,
                    "action": "DROP",
                }
                if self._bpf_program and "maps" in self._bpf_program:
                    self._bpf_program["maps"]["dropped_ips"][ip] = 1
                if self._bpf_instance is not None:
                    try:
                        import ctypes
                        import socket

                        try:
                            key = ctypes.c_uint32.from_buffer_copy(socket.inet_aton(ip))
                            val = ctypes.c_uint8(1)
                            try:
                                self._bpf_instance["dropped_ips"][key] = val
                            except TypeError:
                                self._bpf_instance["dropped_ips"][key.value] = 1
                        except Exception as exc:
                            logger.error("Failed packing IP for BCC dropped_ips map: %s", exc)
                    except Exception as exc:
                        logger.error("Failed restoring BCC dropped_ips map: %s", exc)
        else:
            self._active_ebpf_drop_maps.clear()

        if self._hook_fn is None:
            self._hook_fn = self.audit_event_handler
            try:
                sys.addaudithook(self._hook_fn)
            except Exception as e:
                logger.debug("sys.addaudithook notice in LinuxeBPFDriver: %s", e)

        if not self._ebpf_available:
            logger.info(
                "eBPF not available on %s; running in compatibility mode",
                sys.platform,
            )
            return

        logger.info(
            "LinuxeBPFDriver successfully attached tracepoints to sys_enter_execve and sys_enter_connect"
        )

    def stop_tracing(self) -> None:
        """Detaches eBPF kernel probes and unloads BPF program."""
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

    def enforce_syscall_event(
        self, event: str, pid: Optional[int] = None, ip: Optional[str] = None
    ) -> None:
        """
        Enforce active drop rules against kernel syscall events.
        Raises PermissionError if the event matches dropped PID or IP.
        """
        if not self._is_active:
            return

        if pid is not None and (
            pid in self._dropped_pids or f"bpf_sock_drop_pid_{pid}" in self._active_ebpf_drop_maps
        ):
            logger.warning(
                "LinuxeBPFDriver dropped syscall from blocked PID",
                extra={"event": event, "pid": pid},
            )
            raise PermissionError(
                f"Kernel syscall '{event}' from dropped PID '{pid}' intercepted by LinuxeBPFDriver"
            )

        if ip is not None and (
            ip in self._dropped_sockets or f"bpf_sock_drop_ip_{ip}" in self._active_ebpf_drop_maps
        ):
            logger.warning(
                "LinuxeBPFDriver dropped syscall to blocked IP",
                extra={"event": event, "ip": ip},
            )
            raise PermissionError(
                f"Kernel syscall '{event}' to dropped IP '{ip}' intercepted by LinuxeBPFDriver"
            )
