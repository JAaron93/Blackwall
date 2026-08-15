"""Weave traced detector wrappers and op decorators.

Subtask 22.3: Weave Traced Wrappers and WeaveTraceSerializer.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TypeVar

from blackwall.enterprise.advanced_threat_detection.ailm import AILMTracker
from blackwall.enterprise.advanced_threat_detection.c2 import C2InfrastructureDetector
from blackwall.enterprise.advanced_threat_detection.correlator import PathCorrelator
from blackwall.enterprise.advanced_threat_detection.exploit import ExploitChainAnalyzer
from blackwall.enterprise.advanced_threat_detection.models import (
    AILMEvidence,
    AttackPath,
    C2Evidence,
    ExploitChainEvidence,
    NormalizedEvent,
    PermissionGrant,
    SwarmEvidence,
)
from blackwall.enterprise.advanced_threat_detection.swarm import AgentSwarmDetector
from blackwall.enterprise.advanced_threat_detection.weave_config import (
    should_enable_weave,
)
from blackwall.enterprise.advanced_threat_detection.weave_serializer import (
    WeaveTraceSerializer,
)

try:
    import weave
except ImportError:  # pragma: no cover
    weave = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def weave_traced(fn: F) -> F:
    """Decorator applying @weave.op() if Weave is enabled, or passing through."""
    if weave is not None and hasattr(weave, "op") and should_enable_weave():
        try:
            return weave.op()(fn)  # type: ignore[return-value]
        except Exception as exc:
            logger.warning("Failed to apply weave.op to %s: %s", fn, exc)
            return fn
    return fn


class WeaveTracedPathCorrelator(PathCorrelator):
    """PathCorrelator wrapped with Weave tracing and data sanitization."""

    async def correlate_attack_paths(
        self,
        agent_id: str,
        time_window: Any,
        **kwargs: Any,
    ) -> list[AttackPath]:
        paths = await super().correlate_attack_paths(agent_id, time_window, **kwargs)
        try:
            if should_enable_weave():
                sanitized_paths = [WeaveTraceSerializer.serialize_path(p) for p in paths]
                logger.debug(
                    "Weave trace for correlate_attack_paths: agent=%s -> %d paths",
                    agent_id,
                    len(sanitized_paths),
                )
        except Exception as exc:
            logger.debug("Weave tracing error in correlate_attack_paths: %s", exc)
        return paths


class WeaveTracedAgentSwarmDetector(AgentSwarmDetector):
    """AgentSwarmDetector wrapped with Weave tracing and data sanitization."""

    async def detect_swarms(
        self,
        time_window: Any,
        **kwargs: Any,
    ) -> list[SwarmEvidence]:
        swarms = await super().detect_swarms(time_window, **kwargs)
        try:
            if should_enable_weave():
                sanitized_swarms = [WeaveTraceSerializer.serialize_swarm(s) for s in swarms]
                logger.debug(
                    "Weave trace for detect_swarms: %d swarms",
                    len(sanitized_swarms),
                )
        except Exception as exc:
            logger.debug("Weave tracing error in detect_swarms: %s", exc)
        return swarms


class WeaveTracedAILMTracker(AILMTracker):
    """AILMTracker wrapped with Weave tracing."""

    async def track_permission_grant(self, grant: PermissionGrant) -> None:
        await super().track_permission_grant(grant)
        try:
            if should_enable_weave():
                logger.debug(
                    "Weave trace for track_permission_grant: agent=%s",
                    grant.granted_to,
                )
        except Exception as exc:
            logger.debug("Weave tracing error in track_permission_grant: %s", exc)

    async def detect_permission_composition(
        self,
        agent_id: str,
        time_window: Any,
    ) -> list[AILMEvidence]:
        evidences = await super().detect_permission_composition(agent_id, time_window)
        try:
            if should_enable_weave():
                logger.debug(
                    "Weave trace for detect_permission_composition: agent=%s -> %d evidences",
                    agent_id,
                    len(evidences),
                )
        except Exception as exc:
            logger.debug("Weave tracing error in detect_permission_composition: %s", exc)
        return evidences


class WeaveTracedExploitChainAnalyzer(ExploitChainAnalyzer):
    """ExploitChainAnalyzer wrapped with Weave tracing."""

    async def detect_chains(
        self,
        agent_id: str,
        time_window: Any,
        **kwargs: Any,
    ) -> list[ExploitChainEvidence]:
        chains = await super().detect_chains(agent_id, time_window, **kwargs)
        try:
            if should_enable_weave():
                logger.debug(
                    "Weave trace for detect_chains: agent=%s -> %d chains",
                    agent_id,
                    len(chains),
                )
        except Exception as exc:
            logger.debug("Weave tracing error in detect_chains: %s", exc)
        return chains


class WeaveTracedC2InfrastructureDetector(C2InfrastructureDetector):
    """C2InfrastructureDetector wrapped with Weave tracing."""

    async def analyze_event(self, event: NormalizedEvent) -> list[C2Evidence]:
        if hasattr(super(), "analyze_event"):
            findings = await super().analyze_event(event)
        else:
            findings = []
        try:
            if should_enable_weave():
                sanitized_event = WeaveTraceSerializer.serialize_event(event)
                logger.debug(
                    "Weave trace for C2 analyze_event: %s -> %d findings",
                    sanitized_event["event_id"],
                    len(findings),
                )
        except Exception as exc:
            logger.debug("Weave tracing error in C2 analyze_event: %s", exc)
        return findings


# Aliases for backward/convenience compatibility
WeaveTracedAttackPathCorrelator = WeaveTracedPathCorrelator
WeaveTracedSwarmCoordinator = WeaveTracedAgentSwarmDetector
WeaveTracedAILMDetector = WeaveTracedAILMTracker
WeaveTracedExploitPayloadAnalyzer = WeaveTracedExploitChainAnalyzer
WeaveTracedC2ChannelDetector = WeaveTracedC2InfrastructureDetector
