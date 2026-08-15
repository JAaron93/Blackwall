"""Weave traced detector wrappers and sanitized op decorators.

Subtask 22.3: Weave Traced Wrappers and WeaveTraceSerializer.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from datetime import datetime
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


def _sanitize_value(val: Any) -> Any:
    """Sanitize any domain object or data structure before exposing to Weave."""
    if isinstance(val, NormalizedEvent):
        return WeaveTraceSerializer.serialize_event(val)
    if isinstance(val, AttackPath):
        return WeaveTraceSerializer.serialize_path(val)
    if isinstance(val, SwarmEvidence):
        return WeaveTraceSerializer.serialize_swarm(val)
    if isinstance(val, PermissionGrant):
        return {
            "permission": str(val.permission),
            "granted_to": str(val.granted_to),
            "granted_by": str(val.granted_by),
            "scope": str(val.scope),
        }
    if isinstance(val, (AILMEvidence, ExploitChainEvidence, C2Evidence)):
        return val.model_dump(mode="json") if hasattr(val, "model_dump") else str(val)
    if isinstance(val, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in val.items():
            k_lower = str(k).lower()
            if any(pat in k_lower for pat in WeaveTraceSerializer.SENSITIVE_KEY_PATTERNS):
                sanitized_dict[str(k)] = "**REDACTED**"
            else:
                sanitized_dict[str(k)] = _sanitize_value(v)
        return sanitized_dict
    if isinstance(val, (list, tuple, set)):
        sanitized = [_sanitize_value(item) for item in val]
        return type(val)(sanitized) if not isinstance(val, set) else sanitized
    if hasattr(val, "__class__") and not isinstance(val, (int, float, str, bool, type(None))):
        return val.__class__.__name__
    return val


def _wrap_op(fn: F) -> F:
    """Helper to apply weave.op() if available."""
    if weave is not None and hasattr(weave, "op"):
        try:
            return weave.op()(fn)  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to apply weave.op to %s: %s", getattr(fn, "__name__", str(fn)), exc)
            return fn
    return fn


# Dedicated Weave operations accepting strictly pre-sanitized payloads
@_wrap_op
def op_correlate_attack_paths(agent_id: str, count: int, paths: list[dict[str, Any]]) -> dict[str, Any]:
    return {"agent_id": agent_id, "count": count, "paths": paths}


@_wrap_op
def op_detect_swarms(count: int, swarms: list[dict[str, Any]]) -> dict[str, Any]:
    return {"count": count, "swarms": swarms}


@_wrap_op
def op_track_permission_grant(permission: str, granted_to: str, granted_by: str, scope: str) -> dict[str, Any]:
    return {"permission": permission, "granted_to": granted_to, "granted_by": granted_by, "scope": scope}


@_wrap_op
def op_detect_permission_composition(agent_id: str, evidences_count: int) -> dict[str, Any]:
    return {"agent_id": agent_id, "evidences_count": evidences_count}


@_wrap_op
def op_detect_chains(agent_id: str, chains_count: int) -> dict[str, Any]:
    return {"agent_id": agent_id, "chains_count": chains_count}


@_wrap_op
def op_analyze_c2_event(sanitized_event: dict[str, Any], findings_count: int) -> dict[str, Any]:
    return {"event": sanitized_event, "findings_count": findings_count}


@_wrap_op
def op_generic_trace(op_name: str, inputs: dict[str, Any], outputs: Any) -> dict[str, Any]:
    return {"op": op_name, "inputs": inputs, "outputs": outputs}


def _emit_sanitized_weave_op(
    op_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    result: Any,
) -> None:
    """Emit sanitized Weave operation without leaking raw NormalizedEvents or credentials."""
    call_args = (
        args[1:]
        if len(args) > 0 and hasattr(args[0], "__class__") and not isinstance(args[0], (int, float, str, bool, dict, list, tuple, set))
        else args
    )
    sanitized_args = [_sanitize_value(a) for a in call_args]
    sanitized_kwargs = {k: _sanitize_value(v) for k, v in kwargs.items()}
    sanitized_result = _sanitize_value(result)

    op_generic_trace(
        op_name,
        {"args": sanitized_args, "kwargs": sanitized_kwargs},
        sanitized_result,
    )


def weave_traced(fn: F) -> F:
    """Decorator ensuring Weave operations receive only sanitized inputs/outputs."""
    op_name = getattr(fn, "__name__", "traced_operation")

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = await fn(*args, **kwargs)
            if should_enable_weave():
                try:
                    _emit_sanitized_weave_op(op_name, args, kwargs, result)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Weave tracing error in %s: %s", op_name, exc)
            return result

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        result = fn(*args, **kwargs)
        if should_enable_weave():
            try:
                _emit_sanitized_weave_op(op_name, args, kwargs, result)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Weave tracing error in %s: %s", op_name, exc)
        return result

    return sync_wrapper  # type: ignore[return-value]


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
                op_correlate_attack_paths(str(agent_id), len(sanitized_paths), sanitized_paths)
                logger.debug(
                    "Weave trace for correlate_attack_paths: agent=%s -> %d paths",
                    agent_id,
                    len(sanitized_paths),
                )
        except Exception as exc:  # noqa: BLE001
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
                op_detect_swarms(len(sanitized_swarms), sanitized_swarms)
                logger.debug(
                    "Weave trace for detect_swarms: %d swarms",
                    len(sanitized_swarms),
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Weave tracing error in detect_swarms: %s", exc)
        return swarms


class WeaveTracedAILMTracker(AILMTracker):
    """AILMTracker wrapped with Weave tracing."""

    async def track_permission_grant(self, grant: PermissionGrant) -> None:
        await super().track_permission_grant(grant)
        try:
            if should_enable_weave():
                op_track_permission_grant(
                    str(grant.permission),
                    str(grant.granted_to),
                    str(grant.granted_by),
                    str(grant.scope),
                )
                logger.debug(
                    "Weave trace for track_permission_grant: agent=%s",
                    grant.granted_to,
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Weave tracing error in track_permission_grant: %s", exc)

    async def detect_permission_composition(
        self,
        agent_id: str,
        time_window: Any,
    ) -> list[AILMEvidence]:
        evidences = await super().detect_permission_composition(agent_id, time_window)
        try:
            if should_enable_weave():
                op_detect_permission_composition(str(agent_id), len(evidences))
                logger.debug(
                    "Weave trace for detect_permission_composition: agent=%s -> %d evidences",
                    agent_id,
                    len(evidences),
                )
        except Exception as exc:  # noqa: BLE001
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
                op_detect_chains(str(agent_id), len(chains))
                logger.debug(
                    "Weave trace for detect_chains: agent=%s -> %d chains",
                    agent_id,
                    len(chains),
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Weave tracing error in detect_chains: %s", exc)
        return chains


class WeaveTracedC2InfrastructureDetector(C2InfrastructureDetector):
    """C2InfrastructureDetector wrapped with Weave tracing."""

    async def detect_c2_establishment(
        self,
        agent_id: str,
        time_window: tuple[datetime, datetime],
        beaconing_threshold: float = 0.25,
    ) -> list[C2Evidence]:
        evidences = await super().detect_c2_establishment(
            agent_id, time_window, beaconing_threshold=beaconing_threshold
        )
        try:
            if should_enable_weave():
                op_analyze_c2_event({"agent_id": str(agent_id)}, len(evidences))
                logger.debug(
                    "Weave trace for detect_c2_establishment: agent=%s -> %d evidences",
                    agent_id,
                    len(evidences),
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Weave tracing error in detect_c2_establishment: %s", exc)
        return evidences

    async def analyze_event(self, event: NormalizedEvent) -> list[C2Evidence]:
        self.record_event(event)
        if hasattr(super(), "analyze_event"):
            findings = await super().analyze_event(event)
        else:
            agent_key = str(event.agent_id)
            agent_events = self._events_by_agent.get(agent_key, [])
            if agent_events:
                min_time = min(e.timestamp for e in agent_events)
                max_time = max(e.timestamp for e in agent_events)
                findings = await super().detect_c2_establishment(
                    agent_key,
                    (min_time, max_time),
                )
            else:
                findings = []
        try:
            if should_enable_weave():
                sanitized_event = WeaveTraceSerializer.serialize_event(event)
                op_analyze_c2_event(sanitized_event, len(findings))
                logger.debug(
                    "Weave trace for C2 analyze_event: %s -> %d findings",
                    sanitized_event.get("event_id", ""),
                    len(findings),
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Weave tracing error in C2 analyze_event: %s", exc)
        return findings


# Aliases for backward/convenience compatibility
WeaveTracedAttackPathCorrelator = WeaveTracedPathCorrelator
WeaveTracedSwarmCoordinator = WeaveTracedAgentSwarmDetector
WeaveTracedAILMDetector = WeaveTracedAILMTracker
WeaveTracedExploitPayloadAnalyzer = WeaveTracedExploitChainAnalyzer
WeaveTracedC2ChannelDetector = WeaveTracedC2InfrastructureDetector
WeaveTracedC2Detector = WeaveTracedC2InfrastructureDetector
