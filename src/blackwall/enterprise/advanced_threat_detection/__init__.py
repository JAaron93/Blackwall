"""Blackwall Advanced Threat Detection (Pillar 6).

Provides temporal graph analysis, agent swarm detection, zero-day exploit chain recognition,
and AI-Induced Lateral Movement (AILM) tracking.
"""

import logging

from blackwall.enterprise.advanced_threat_detection.enums import (
    EventSource,
    ExploitCategory,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    AILMEvidence,
    AttackNode,
    AttackPath,
    C2Evidence,
    ExploitChainEvidence,
    K8sThreatEvidence,
    NormalizedEvent,
    RegistryThreatEvidence,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection")

__all__ = [
    "EventSource",
    "ExploitCategory",
    "NormalizedEvent",
    "AttackNode",
    "AttackPath",
    "SwarmEvidence",
    "ExploitChainEvidence",
    "AILMEvidence",
    "C2Evidence",
    "K8sThreatEvidence",
    "RegistryThreatEvidence",
    "AttackGraphStore",
    "logger",
]

