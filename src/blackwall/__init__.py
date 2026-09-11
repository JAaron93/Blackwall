"""
Blackwall Agentic Firewall
"""

__version__ = "1.0.0"

from blackwall.config import Settings, configure_provider_env, get_genai_client
from blackwall.audit.manager import AuditHookManager
from blackwall.interception import (
    BatchResolutionError,
    InterceptionQueue,
    QueueEmptyException,
    QueueOverloadError,
)
from blackwall.analytics import AgentBehavioralAnalytics
from blackwall.adk_integration import ADKIntegration

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

