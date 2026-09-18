"""
Blackwall Agentic Firewall

Top-level exports are resolved lazily (PEP 562) so importing lightweight
subpackages (e.g. ``blackwall.gateway.server``) does not pay the cost of
heavy optional dependencies (``google-genai``, audit hooks, analytics) at
import time. This enforces the NFR-06 startup budget (<2s) via lazy module
initialization; heavy modules load on first attribute access instead.
"""

from __future__ import annotations

from typing import Any

__version__ = "2.0.0"

_LAZY_EXPORTS: dict[str, str] = {
    "Settings": "blackwall.config",
    "configure_provider_env": "blackwall.config",
    "get_genai_client": "blackwall.config",
    "AuditHookManager": "blackwall.audit.manager",
    "BatchResolutionError": "blackwall.interception",
    "InterceptionQueue": "blackwall.interception",
    "QueueEmptyException": "blackwall.interception",
    "QueueOverloadError": "blackwall.interception",
    "AgentBehavioralAnalytics": "blackwall.analytics",
    "ADKIntegration": "blackwall.adk_integration",
}


def __getattr__(name: str) -> Any:
    """Lazily resolve top-level exports on first access (PEP 562)."""
    if name in _LAZY_EXPORTS:
        import importlib

        module = importlib.import_module(_LAZY_EXPORTS[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

try:
    from blackwall import _core_rs  # type: ignore[attr-defined]
except ImportError:
    try:
        import _core_rs
    except ImportError:
        _core_rs = None  # type: ignore[assignment]


__all__ = [
    "Settings",
    "configure_provider_env",
    "get_genai_client",
    "AuditHookManager",
    "InterceptionQueue",
    "QueueEmptyException",
    "BatchResolutionError",
    "QueueOverloadError",
    "AgentBehavioralAnalytics",
    "ADKIntegration",
    "_core_rs",
]

