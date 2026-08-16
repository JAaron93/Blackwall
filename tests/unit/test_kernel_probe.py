"""
Unit tests for Task K01: Kernel Probe Interface & macOS Fallback Audit Driver.
"""

import pytest


def test_kernel_probe_driver_interface_instantiation():
    """Verify KernelProbeDriver interface cannot be instantiated directly."""
    from blackwall.enterprise.kernel.probe import KernelProbeDriver

    with pytest.raises(TypeError):
        KernelProbeDriver()


def test_user_space_audit_driver_interception():
    """
    Verify UserSpaceAuditDriver installs Python audit hook and intercepts subprocess execution.
    Note: Audit hook imports are deferred inside test scope per isolation rules.
    """
    from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver

    driver = UserSpaceAuditDriver()
    assert driver.is_active is False

    driver.start_tracing()
    assert driver.is_active is True

    # Blocked executable pattern check
    driver.add_blocked_pattern("unauthorized_kernel_tool")

    with pytest.raises(PermissionError) as exc_info:
        driver.audit_event_handler("subprocess.Popen", ("unauthorized_kernel_tool",))
    assert "intercepted by Blackwall" in str(exc_info.value)

    driver.stop_tracing()
    assert driver.is_active is False


def test_user_space_audit_driver_socket_drop_interception():
    """Verify UserSpaceAuditDriver injects socket drop and blocks exact socket operations without prefix collisions."""
    from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver

    driver = UserSpaceAuditDriver()
    driver.start_tracing()

    # Inject drop for IP 10.0.0.5
    applied = driver.inject_socket_drop(ip="10.0.0.5")
    assert applied is True
    assert "ip:10.0.0.5" in driver._blocked_patterns
    assert "10.0.0.5" in driver._dropped_sockets

    # Verify socket operation to exact dropped IP is intercepted
    with pytest.raises(PermissionError) as exc_info:
        driver.audit_event_handler("socket.connect", ("<socket>", ("10.0.0.5", 8080)))
    assert "Socket operation to '10.0.0.5' intercepted" in str(exc_info.value)

    # Verify connection to prefix-sharing IP 10.0.0.50 is NOT intercepted
    driver.audit_event_handler("socket.connect", ("<socket>", ("10.0.0.50", 8080)))

    driver.stop_tracing()


def test_targetless_socket_drop_returns_false():
    """Verify that inject_socket_drop without PID and IP returns False."""
    from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver, LinuxeBPFDriver

    user_driver = UserSpaceAuditDriver()
    assert user_driver.inject_socket_drop(pid=None, ip=None) is False
    assert len(user_driver._blocked_patterns) == 0

    linux_driver = LinuxeBPFDriver()
    assert linux_driver.inject_socket_drop(pid=None, ip=None) is False
    assert len(linux_driver._active_ebpf_drop_maps) == 0


def test_user_space_audit_driver_pid_drop_interception():
    """Verify UserSpaceAuditDriver intercepts execution and socket operations from dropped PIDs."""
    import os
    from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver

    driver = UserSpaceAuditDriver()
    driver.start_tracing()

    curr_pid = os.getpid()
    applied = driver.inject_socket_drop(pid=curr_pid)
    assert applied is True
    assert driver.is_dropped(pid=curr_pid) is True

    # Intercepts subprocess/exec
    with pytest.raises(PermissionError) as exc_info:
        driver.audit_event_handler("subprocess.Popen", ("ls",))
    assert "Execution from dropped PID" in str(exc_info.value)

    # Intercepts socket ops
    with pytest.raises(PermissionError) as exc_info:
        driver.audit_event_handler("socket.connect", ("<socket>", ("1.1.1.1", 80)))
    assert "Socket operation from dropped PID" in str(exc_info.value)

    driver.stop_tracing()


def test_linux_ebpf_driver_socket_drop_and_tracing():
    """Verify LinuxeBPFDriver records drop maps and manages tracing lifecycle."""
    from blackwall.enterprise.kernel.probe import LinuxeBPFDriver

    driver = LinuxeBPFDriver()
    driver.start_tracing()

    applied = driver.inject_socket_drop(pid=5432, ip="10.10.10.10")
    assert applied is True
    assert "bpf_sock_drop_pid_5432" in driver._active_ebpf_drop_maps
    assert "bpf_sock_drop_ip_10.10.10.10" in driver._active_ebpf_drop_maps
    assert "pid:5432" in driver._blocked_patterns
    assert "ip:10.10.10.10" in driver._blocked_patterns

    driver.stop_tracing()
    assert driver.is_active is False
