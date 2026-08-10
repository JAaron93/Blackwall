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
    PermissionGrant,
    RegistryThreatEvidence,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.exploit import ExploitChainAnalyzer
from blackwall.enterprise.advanced_threat_detection.store import AttackGraphStore
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection")

__all__ = [
    "EventSource",
    "ExploitCategory",
    "NormalizedEvent",
    "AttackNode",
    "AttackPath",
    "SwarmEvidence",
    "ExploitChainEvidence",
    "PermissionGrant",
    "AILMEvidence",
    "C2Evidence",
    "K8sThreatEvidence",
    "RegistryThreatEvidence",
    "AttackGraphStore",
    "EventStreamCollector",
    "PathCorrelator",
    "AgentSwarmDetector",
    "ExploitChainAnalyzer",
    "AILMTracker",
    "logger",
]
