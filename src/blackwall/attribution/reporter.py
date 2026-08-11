"""
src/blackwall/attribution/reporter.py — Incident Report Generator.

Builds ``IncidentReport`` instances from attribution data and provides
serialization helpers. All tool arguments are sanitized through
``ContextResolver`` pattern-based redaction before embedding in the report (FR-6).

Design Constraints (per design.md §4):
  - Non-blocking: synchronous sanitization using inline regex (NFR-1, <5ms)
  - Fail-closed: sanitization failures leave a safe fallback (NFR-2)
  - Zero C-dependencies: uses only re, json, hashlib, pydantic (NFR-3)
  - Privacy-safe: secrets are redacted BEFORE embedding in IncidentReport (FR-6)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional
from uuid import UUID

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    IncidentReport,
    ToolCallContext,
    VerdictDecision,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Inline sanitization patterns (synchronous subset of ContextHygiene patterns)
# Used to avoid spawning the async KillableRegexWorker during fast-path reports.
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "API_KEY",
        re.compile(r"(?i)(api[_-]?key|apikey|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})"),
        "[[API_KEY]]",
    ),
    (
        "OPENAI_KEY",
        # Matches: sk-abc123, sk-proj-abc-def123, sk-or-v1-abc, sk-ant-abc etc.
        # The pattern allows hyphens within segments to catch project-scoped keys.
        re.compile(r"sk-(?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]{8,}"),
        "[[OPENAI_API_KEY]]",
    ),
    (
        "GOOGLE_KEY",
        re.compile(r"AIza[a-zA-Z0-9_\-]{10,}"),
        "[[GOOGLE_API_KEY]]",
    ),
    (
        "SECRET_VALUE",
        re.compile(r"(?i)(secret|api_key|apikey)[\s:\"']*:[\s\"']*[a-zA-Z0-9_\-]{8,}"),
        "[[SECRET_VALUE]]",
    ),
    (
        "KEY_VALUE_PAIR",
        # Catches dict key names that look like API key env vars followed by their values.
        # e.g. "OPENAI_API_KEY": "sk-...", "ANTHROPIC_API_KEY": "sk-ant-..."
        re.compile(r'(?i)(["\']?(?:openai|anthropic|google|huggingface|cohere|azure|aws)[_-]?(?:api[_-]?)?key[_-]?(?:id|secret)?["\']?\s*:\s*["\']?)([a-zA-Z0-9_\-]{10,})'),
        "[[API_KEY_VALUE]]",
    ),
    (
        "PASSWORD",
        re.compile(r"(?i)(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]+)"),
        "[[PASSWORD]]",
    ),
    (
        "URL",
        re.compile(r"https?://[^\s\"']+"),
        "[[URL]]",
    ),
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "[[IP_ADDRESS]]",
    ),
    (
        "EMAIL",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "[[EMAIL]]",
    ),
    (
        "FILE_PATH",
        re.compile(r"(?:/[^/\\\s\"']+)+/?"),
        "[[FILE_PATH]]",
    ),
]


def _sanitize_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize tool call arguments by redacting secrets in both keys and values.

    Applies the same redaction patterns as ``ContextHygiene`` but synchronously,
    using a value-by-value pass over the arguments dict (FR-6, NFR-1).

    Returns:
        A new dict with secrets replaced by ``[[PLACEHOLDER]]`` tokens.
    """
    try:
        # Serialize to JSON string to handle nested structures uniformly
        serialized = json.dumps(arguments)
        redacted = serialized
        for _name, pattern, placeholder in _REDACTION_PATTERNS:
            try:
                redacted = pattern.sub(placeholder, redacted)
            except re.error as exc:
                logger.warning("Sanitization pattern failed: %s", exc)
                continue

        return json.loads(redacted)
    except Exception as exc:  # noqa: BLE001
        # Never let sanitization block report generation; fall back to safe empty dict
        logger.error("IncidentReportGenerator: argument sanitization failed: %s", exc)
        return {"sanitization_error": "[REDACTED DUE TO SANITIZATION FAILURE]"}


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

        Returns:
            A complete ``IncidentReport`` Pydantic model with redacted arguments.
        """
        # FR-6: Sanitize arguments before embedding in report
        sanitized_args = _sanitize_arguments(tool_context.arguments)

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
        )


# ---------------------------------------------------------------------------
# Module-level convenience helpers (re-export for ergonomic access)
# ---------------------------------------------------------------------------

def to_markdown(report: IncidentReport) -> str:
    """Format an ``IncidentReport`` as a Markdown summary string."""
    return report.to_markdown()


def to_json(report: IncidentReport) -> str:
    """Serialize an ``IncidentReport`` to a JSON string."""
    return report.to_json()
