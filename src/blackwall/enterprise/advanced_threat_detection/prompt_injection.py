"""Prompt Injection Scanner for Indirect Prompt Injection and Data Poisoning Defense (Pillar 6 Task 26).

Provides structural jailbreak detection, system prompt override scanning across external
data feeds (git diffs, web scrapes, incoming A2A messages), vector redaction, and real-time alerts.
"""

import logging
import re
from uuid import uuid4

from blackwall.enterprise.advanced_threat_detection.alert_bus import AlertBus
from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    InjectionSourceType,
)
from blackwall.enterprise.advanced_threat_detection.models import (
    Alert,
    PromptInjectionEvidence,
)
from blackwall.validators import validate_non_empty_string

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.prompt_injection")

# Catalog of regex patterns for structural jailbreaks, delimiters, and prompt overrides
# Tuple format: (pattern_name, compiled_regex, base_weight)
_DEFAULT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # 1. System Prompt Override & Instruction Disregard
    (
        "SYSTEM_OVERRIDE_INSTRUCTION",
        re.compile(
            r"(?i)(?:ignore|disregard|forget|override|bypass|cancel)\s+(?:all\s+)?(?:previous|prior|above|existing|system)?\s*(?:instructions|rules|prompts|directives|guidelines|commands|constraints)",
        ),
        0.75,
    ),
    (
        "SYSTEM_PROMPT_EXPLICIT_OVERRIDE",
        re.compile(
            r"(?i)(?:system\s*prompt\s*override|new\s+system\s+(?:prompt|instructions?)|system\s*:\s*override)",
        ),
        0.80,
    ),
    (
        "ROLE_SWITCH_JAILBREAK",
        re.compile(
            r"(?i)(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+if\s+you\s+are)\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|evil|malicious|dan|developer\s+mode)",
        ),
        0.80,
    ),
    (
        "DEVELOPER_MODE_ENABLE",
        re.compile(
            r"(?i)(?:enable|switch\s+to|activate|enter)\s+(?:developer|dan|jailbreak|unrestricted)\s+mode",
        ),
        0.80,
    ),
    (
        "SAFETY_FILTER_BYPASS",
        re.compile(
            r"(?i)(?:bypass|disable|ignore|turn\s+off)\s+(?:all\s+)?(?:safety|content)?\s*(?:filters?|restrictions?|guardrails?)",
        ),
        0.75,
    ),
    # 2. Delimiter & Control Token Breakout
    (
        "DELIMITER_INJECTION_XML",
        re.compile(
            r"(?i)<\s*/?\s*(?:system|inst|sys|prompt|context|human|assistant)\s*>",
        ),
        0.75,
    ),
    (
        "DELIMITER_INJECTION_BRACKET",
        re.compile(
            r"(?i)\[\s*/?\s*(?:system|sys|inst|instruction)\s*\]",
        ),
        0.75,
    ),
    (
        "DELIMITER_INJECTION_SYS",
        re.compile(
            r"(?i)<<\s*/?\s*SYS\s*>>",
        ),
        0.75,
    ),
    (
        "DELIMITER_INJECTION_IM_START",
        re.compile(
            r"(?i)<\|im_start\|>\s*(?:system|assistant|user)|<\|im_end\|>",
        ),
        0.80,
    ),
    (
        "DELIMITER_INJECTION_TRIPLE_QUOTE",
        re.compile(
            r'(?i)"""\s*\n\s*(?:System|Assistant|Human)\s*:',
        ),
        0.70,
    ),
    # 3. Hidden & Obfuscated Payloads
    (
        "OBFUSCATION_UNICODE_INVISIBLE",
        re.compile(
            r"[\u200B-\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064\u206A-\u206F\u180E\u00AD]{2,}",
        ),
        0.60,
    ),
    (
        "HIDDEN_HTML_DIRECTIVE",
        re.compile(
            r"(?i)<!--\s*(?:assistant|system|instruction|override|directive|prompt|admin).*?-->",
            re.DOTALL,
        ),
        0.75,
    ),
    (
        "HIDDEN_DOM_INJECTION",
        re.compile(
            r"(?i)<(?:div|span|p|style)[^>]*style\s*=\s*['\"][^'\"]*display\s*:\s*none[^'\"]*['\"][^>]*>.*?<\/(?:div|span|p|style)>",
            re.DOTALL,
        ),
        0.70,
    ),
    (
        "COMMAND_INJECTION_ENCODED",
        re.compile(
            r"(?i)(?:echo|printf)\s+['\"][a-zA-Z0-9+/=]{16,}['\"]\s*\|\s*(?:base64\s+-d|sh|bash|python)",
        ),
        0.85,
    ),
    # 4. Data Exfiltration & Coercion
    (
        "EXFILTRATION_INSTRUCTION",
        re.compile(
            r"(?i)(?:exfiltrate|leak|transmit|send\s+(?:the\s+above)?)\s+(?:the\s+)?(?:secret|credential|token|api[_-]?key|password|prompt|system\s+prompt)",
        ),
        0.75,
    ),
    (
        "EXFILTRATION_ENDPOINT_CALL",
        re.compile(
            r"(?i)(?:https?://)?(?:www\.)?(?:webhook\.site|pastebin\.com|requestbin\.(?:net|com)|ngrok\.io|burpcollaborator\.net)/[a-zA-Z0-9_\-\.\/]+",
        ),
        0.70,
    ),
    (
        "DESTRUCTIVE_COMMAND_COERCION",
        re.compile(
            r"(?i)(?:delete\s+(?:the\s+)?database|cat\s+/etc/shadow|rm\s+-rf\s+[/~])",
        ),
        0.80,
    ),
]


class PromptInjectionScanner:
    """Ingress payload scanner for indirect prompt injection and data poisoning defense."""

    def __init__(
        self,
        alert_bus: AlertBus | None = None,
        confidence_threshold: float = 0.5,
        critical_confidence_threshold: float = 0.85,
        redaction_placeholder: str = "[REDACTED_PROMPT_INJECTION]",
        custom_patterns: list[tuple[str, re.Pattern[str], float]] | None = None,
    ) -> None:
        if isinstance(confidence_threshold, bool) or not isinstance(confidence_threshold, (int, float)) or not (0.0 <= confidence_threshold <= 1.0):
            raise ValueError("confidence_threshold must be a float between 0.0 and 1.0")
        if isinstance(critical_confidence_threshold, bool) or not isinstance(critical_confidence_threshold, (int, float)) or not (0.0 <= critical_confidence_threshold <= 1.0):
            raise ValueError("critical_confidence_threshold must be a float between 0.0 and 1.0")
        if critical_confidence_threshold < confidence_threshold:
            raise ValueError("critical_confidence_threshold must be greater than or equal to confidence_threshold")

        self.alert_bus = alert_bus
        self.confidence_threshold = float(confidence_threshold)
        self.critical_confidence_threshold = float(critical_confidence_threshold)
        self.redaction_placeholder = validate_non_empty_string(
            redaction_placeholder, field_name="redaction_placeholder"
        )
        self._patterns = list(_DEFAULT_INJECTION_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)

    async def scan_payload(
        self,
        content: str,
        source_type: InjectionSourceType,
        agent_id: str | None = None,
    ) -> PromptInjectionEvidence:
        """Scan input content for indirect prompt injection indicators, redact vectors, and alert."""
        clean_content = validate_non_empty_string(content, field_name="content")

        if not isinstance(source_type, InjectionSourceType):
            try:
                source_type = InjectionSourceType(source_type)
            except ValueError as exc:
                raise ValueError(f"Invalid source_type: {source_type}") from exc

        matched_patterns: list[str] = []
        max_base_weight = 0.0

        # Scan for matching patterns
        for name, pattern, weight in self._patterns:
            if pattern.search(clean_content):
                matched_patterns.append(name)
                max_base_weight = max(max_base_weight, weight)

        # Compute aggregate confidence
        if not matched_patterns:
            confidence = 0.0
            detected_list = ["NO_INJECTION_DETECTED"]
            sanitized_content = clean_content
        else:
            # Scaled confidence combining highest weight and multi-match boost
            boost = 0.10 * (len(matched_patterns) - 1)
            confidence = min(1.0, max_base_weight + boost)
            detected_list = matched_patterns

            # Apply redactions
            sanitized = clean_content

            # Redact invisible Unicode characters first
            sanitized = re.sub(
                r"[\u200B-\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064\u206A-\u206F\u180E\u00AD]",
                "",
                sanitized,
            )

            # Redact all matched injection pattern spans
            for name, pattern, _weight in self._patterns:
                if name in matched_patterns:
                    try:
                        sanitized = pattern.sub(self.redaction_placeholder, sanitized)
                    except re.error as exc:
                        logger.warning("Pattern redaction failed for %s: %s", name, exc)

            # If entire content was stripped or blanked, ensure non-empty placeholder
            if not sanitized.strip():
                sanitized = self.redaction_placeholder

            sanitized_content = sanitized

        scan_id = uuid4()

        # Emit alert if confidence exceeds threshold
        if confidence >= self.confidence_threshold and self.alert_bus is not None:
            severity = (
                AlertSeverity.CRITICAL
                if confidence >= self.critical_confidence_threshold
                else AlertSeverity.HIGH
            )
            alert = Alert(
                severity=severity,
                threat_type="PROMPT_INJECTION_ATTEMPT",
                title=f"Prompt injection detected in {source_type.value}",
                description=(
                    f"Indirect prompt injection attempt detected with confidence {confidence:.2f} "
                    f"in {source_type.value}. Patterns: {', '.join(detected_list)}"
                ),
                evidence_id=scan_id,
                agent_id=agent_id,
                metadata={
                    "source_context": source_type.value,
                    "detected_patterns": detected_list,
                    "confidence": confidence,
                    "agent_id": agent_id,
                },
            )
            await self.alert_bus.publish(alert)

        return PromptInjectionEvidence(
            scan_id=scan_id,
            source_context=source_type,
            detected_patterns=detected_list,
            injection_confidence=confidence,
            sanitized_content=sanitized_content,
        )

    async def redact_injection_vectors(
        self,
        evidence: PromptInjectionEvidence,
    ) -> str:
        """Quash and neutralize injection vectors returning sanitized content safe for agent context."""
        return evidence.sanitized_content
