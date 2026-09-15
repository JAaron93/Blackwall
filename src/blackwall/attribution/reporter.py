"""
src/blackwall/attribution/reporter.py — Incident Report Generator.

Builds ``IncidentReport`` instances from attribution data and provides
serialization helpers. All tool arguments are sanitized through
``ContextResolver`` pattern-based redaction before embedding in the report (FR-6).

Design Constraints (per design.md §4):
  - Non-blocking: synchronous sanitization using inline regex (NFR-1, <5ms)
  - Fail-closed: sanitization failures leave a safe fallback (NFR-2)
  - Zero C-dependencies: delegates to blackwall.validators (stdlib re/json only)
  - Privacy-safe: secrets are redacted BEFORE embedding in IncidentReport (FR-6)
"""

from __future__ import annotations

from typing import Any, Dict
from uuid import UUID

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IncidentReport,
    SwarmContextSummary,
    ToolCallContext,
    VerdictDecision,
)
from blackwall.validators import (
    REDACTION_PATTERNS,
    SENSITIVE_KEY_PATTERNS,
    sanitize_dict_payload,
)

# ---------------------------------------------------------------------------
# Secret sanitization: canonical helpers live in blackwall.validators.
# This module keeps private aliases so existing imports keep working while
# the single implementation in validators.py remains the source of truth.
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS = REDACTION_PATTERNS
_SENSITIVE_KEY_PATTERNS = SENSITIVE_KEY_PATTERNS


def _sanitize_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize tool call arguments by redacting secrets via a two-pass strategy.

    Delegates to the canonical :func:`blackwall.validators.sanitize_dict_payload`
    (key-name inspection pre-serialization, then regex scan of the serialized
    payload; fail-closed). Kept as a thin wrapper so existing imports keep working.
    """
    return sanitize_dict_payload(arguments)


class IncidentReportGenerator:
    """
    Builds ``IncidentReport`` instances for ``BLOCK`` and ``QUARANTINE`` verdicts.

    Applies inline secret redaction to tool arguments before embedding them
    in the report (FR-6). All generated reports include a UTC-aware timestamp
    and a valid UUID ``report_id``.

    Usage::

        generator = IncidentReportGenerator()
        report = generator.build(
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            identity=identity,
            profile=profile,
            tool_context=context,
            technique="Command Injection",
            mitigation="Operation blocked",
            recommended_action="Revoke agent token",
            confidence=0.95,
        )
        print(report.to_markdown())
        print(report.to_json())
    """

    def build(
        self,
        event_id: UUID,
        verdict: VerdictDecision,
        identity: AttackerIdentity,
        profile: AttackerProfile,
        tool_context: ToolCallContext,
        technique: str,
        mitigation: str,
        recommended_action: str,
        confidence: float,
        swarm_context: SwarmContextSummary | None = None,
    ) -> IncidentReport:
        """
        Construct a fully-populated ``IncidentReport`` for an attacker attribution event.

        Args:
            event_id:           UUID of the originating security event.
            verdict:            The enforcement verdict (``BLOCK`` or ``QUARANTINE``).
            identity:           Extracted ``AttackerIdentity`` instance.
            profile:            Historical ``AttackerProfile`` for this fingerprint.
            tool_context:       Sanitized ``ToolCallContext`` from the interception pipeline.
            technique:          Human-readable attack technique label.
            mitigation:         Description of the mitigation action taken.
            recommended_action: Operator-facing remediation guidance.
            confidence:         Attribution confidence score (0.0–1.0).
            swarm_context:      Optional resolved swarm lineage (FR-6). When
                provided, the report is marked collective and carries the
                swarm ID, confidence, and suspected covert channels.

        Returns:
            A complete ``IncidentReport`` Pydantic model with redacted arguments.
        """
        # FR-6: Sanitize arguments before embedding in report
        sanitized_args = _sanitize_arguments(tool_context.arguments)

        swarm_id = None
        is_collective = False
        suspected_channels: list[str] = []
        collective_confidence = 0.0
        collective_summary = None
        if swarm_context is not None:
            swarm_id = swarm_context.swarm_id
            is_collective = bool(swarm_context.is_collective)
            suspected_channels = list(swarm_context.suspected_covert_channels)
            collective_confidence = swarm_context.collective_confidence
            if is_collective:
                agent_label = (
                    identity.agent_name or identity.agent_id or "Unknown agent"
                )
                swarm_label = swarm_context.collective_name or (
                    str(swarm_context.swarm_id)
                    if swarm_context.swarm_id
                    else "Unknown swarm"
                )
                channel_label = (
                    ", ".join(suspected_channels)
                    if suspected_channels
                    else "no confirmed channel"
                )
                collective_summary = (
                    f"Blocked action by {agent_label} (Part of Coordinated "
                    f"Swarm {swarm_label} communicating via {channel_label})"
                )

        return IncidentReport(
            event_id=event_id,
            verdict=verdict,
            attacker_identity=identity,
            attacker_profile=profile,
            exploited_tool=tool_context.tool_name,
            sanitized_arguments=sanitized_args,
            attack_technique=technique,
            mitigation_action=mitigation,
            recommended_user_action=recommended_action,
            attribution_confidence=confidence,
            swarm_id=swarm_id,
            is_collective=is_collective,
            suspected_covert_channels=suspected_channels,
            collective_confidence=collective_confidence,
            collective_attribution_summary=collective_summary,
        )
