"""
Unit tests for Task T01: Core vs Enterprise Tier Packaging & Isolation.
Verifies that Blackwall Core remains a zero-dependency single-host daemon
and blackwall.enterprise is cleanly modularized.
"""

import sys
import pytest


def test_core_package_imports_cleanly():
    """Verify Blackwall Core imports without requiring enterprise subpackages."""
    import blackwall
    from blackwall.models import ToolCallContext, Verdict
    from blackwall.sync_resolver import SyncResolver

    assert hasattr(blackwall, "__version__")
    assert ToolCallContext is not None
    assert Verdict is not None
    assert SyncResolver is not None


def test_enterprise_package_structure():
    """Verify blackwall.enterprise package exists and provides conditional exports."""
    import blackwall.enterprise

    assert hasattr(blackwall.enterprise, "__version__")
    assert hasattr(blackwall.enterprise, "ENTERPRISE_ENABLED")
    assert blackwall.enterprise.ENTERPRISE_ENABLED is True
