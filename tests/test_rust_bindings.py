"""Unit tests for Blackwall Rust extension bindings and fallback verification."""

import pytest


def test_rust_module_import():
    """Verify that the compiled Rust extension _core_rs is importable and exposes version."""
    import _core_rs
    import blackwall

    assert hasattr(_core_rs, "__version__")
    assert _core_rs.__version__ == "0.1.0"
    assert blackwall._core_rs is not None
    assert blackwall._core_rs.__version__ == "0.1.0"


def test_fallback_when_core_rs_unavailable(monkeypatch):
    """Verify that modules handle missing _core_rs gracefully without crashing."""
    import sys
    import importlib

    # Temporarily hide _core_rs
    with monkeypatch.context() as m:
        m.setitem(sys.modules, "_core_rs", None)
        # Verify blackwall imports cleanly
        import blackwall
        assert blackwall.__version__ == "1.0.0"


