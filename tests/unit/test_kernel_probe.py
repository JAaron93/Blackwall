"""
Unit tests for Task K01: Kernel Probe Interface & macOS Fallback Audit Driver.
"""

from unittest.mock import MagicMock
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


def test_linux_ebpf_driver_kernel_map_population():
    """Verify LinuxeBPFDriver populates kernel BPF maps on socket/PID drop."""
    from blackwall.enterprise.kernel.probe import LinuxeBPFDriver

    driver = LinuxeBPFDriver()
    mock_pids_map = {}
    mock_ips_map = {}
    mock_ip6s_map = {}
    driver._bpf_instance = {
        "dropped_pids": mock_pids_map,
        "dropped_ips": mock_ips_map,
        "dropped_ip6s": mock_ip6s_map,
    }

    # Inject PID drop
    success_pid = driver.inject_socket_drop(pid=9876)
    assert success_pid is True
    assert len(mock_pids_map) == 1

    # Inject IPv4 drop
    success_ip4 = driver.inject_socket_drop(ip="192.168.1.100")
    assert success_ip4 is True
    assert len(mock_ips_map) == 1

    # Inject IPv6 drop
    success_ip6 = driver.inject_socket_drop(ip="2001:db8::1")
    assert success_ip6 is True
    assert len(mock_ip6s_map) == 1

    # Verify removal
    driver.remove_socket_drop(pid=9876)
    assert len(mock_pids_map) == 0

    driver.remove_socket_drop(ip="192.168.1.100")
    assert len(mock_ips_map) == 0

    driver.remove_socket_drop(ip="2001:db8::1")
    assert len(mock_ip6s_map) == 0


def test_linux_ebpf_driver_atomic_rollback_on_failure():
    """Verify LinuxeBPFDriver atomically rolls back userspace tracking if kernel map insertion fails."""
    from blackwall.enterprise.kernel.probe import LinuxeBPFDriver

    driver = LinuxeBPFDriver()
    failing_map = MagicMock()
    failing_map.__setitem__.side_effect = RuntimeError("BPF map full")

    driver._bpf_instance = {
        "dropped_pids": failing_map,
        "dropped_ips": {},
        "dropped_ip6s": {},
    }

    res = driver.inject_socket_drop(pid=5555)
    assert res is False
    assert 5555 not in driver._dropped_pids
    assert "bpf_sock_drop_pid_5555" not in driver._active_ebpf_drop_maps
