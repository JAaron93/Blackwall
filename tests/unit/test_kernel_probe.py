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
    """Verify UserSpaceAuditDriver injects socket drop and blocks socket operations."""
    from blackwall.enterprise.kernel.probe import UserSpaceAuditDriver

    driver = UserSpaceAuditDriver()
    driver.start_tracing()

    # Inject drop for IP
    applied = driver.inject_socket_drop(ip="198.51.100.25")
    assert applied is True
    assert "ip:198.51.100.25" in driver._blocked_patterns
    assert "198.51.100.25" in driver._dropped_sockets

    # Verify socket operation is intercepted
    with pytest.raises(PermissionError) as exc_info:
        driver.audit_event_handler("socket.connect", ("<socket>", ("198.51.100.25", 8080)))
    assert "Socket operation to '198.51.100.25' intercepted" in str(exc_info.value)

    driver.stop_tracing()
