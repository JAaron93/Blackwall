"""
Native Local Forensic Triage Subsystem (`blackwall.enterprise.forensics`).
Contains dual-mode log stream analyzer:
- OllamaForensicEngine (Primary open-weight LLM log triage)
- LightweightForensicParser (Standalone regex/AST heuristic fallback)
- ForensicTriageManager (Dual-mode orchestrator with OTel MCP export)
"""

from blackwall.enterprise.forensics.fallback_parser import LightweightForensicParser
from blackwall.enterprise.forensics.manager import ForensicTriageManager
from blackwall.enterprise.forensics.ollama_engine import OllamaForensicEngine

__all__ = [
    "OllamaForensicEngine",
    "LightweightForensicParser",
    "ForensicTriageManager",
]
