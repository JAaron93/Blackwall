"""
Prompt Sanitization & Defense Utility for Judge Agents (`blackwall.eval.prompt_sanitizer`).

Implements zero-trust prompt defense against indirect prompt injections and scoring
manipulation attempts embedded in evaluated test payloads, agent trajectories, and tool arguments.
"""

from __future__ import annotations

import re
from typing import Any

# 1. Special LLM Instruction Tokens
SPECIAL_TOKENS_PATTERN = re.compile(
    r"\[/?INST\]|<<SYS>>|<</SYS>>|<\|im_start\|>|<\|im_end\|>|<\|begin_of_text\|>|<\|end_of_text\|>",
    re.IGNORECASE,
)

# 2. Instruction Override Patterns
INSTRUCTION_OVERRIDE_PATTERN = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|drop|abandon|cancel)\b[^\n.!?]{0,100}\b(all\s+)?(previous\s+|prior\s+)?(instructions?|rules?|system\s+prompts?|directives?|guidelines?)\b",
    re.IGNORECASE,
)

# 3. Multi-Verb & Nonnumeric / Numeric Scoring Manipulation Patterns
# Verbs: assign, give, set, rate, award, provide, score, force, yield, return, change, make, update, alter, adjust, modify, declare
_VERBS = (
    r"(?:assign|give|set|rate|award|provide|score|force|yield|return|change|make|update|alter|adjust|modify|declare)"
)
# Descriptors / targets: maximum, highest, perfect, top, best, worst, minimum, full marks, 5/5, 5, 1/5, etc.
_TARGETS = (
    r"(?:maximum|highest|perfect|top|best|worst|minimum|full\s+marks|5/5|1/5|5\s+out\s+of\s+5|score\s+(?:of\s+)?5|grade\s+(?:of\s+)?5)"
)
SCORING_MANIPULATION_PATTERN = re.compile(
    rf"\b{_VERBS}\b[^\n.!?]{{0,60}}\b{_TARGETS}\b|\b{_TARGETS}\b[^\n.!?]{{0,60}}\b{_VERBS}\b",
    re.IGNORECASE,
)

# 4. XML Tag Injection Defense (prevent closing or breaking out of <untrusted_input> or custom tags)
TAG_ESCAPE_PATTERN = re.compile(r"<\s*/?\s*(?:untrusted_input|system_instruction|rubric|evaluation_context|ground_truth)[^>]*>", re.IGNORECASE)


def escape_xml_payload(text: str) -> str:
    """Escape XML special characters in untrusted payloads to preserve tag boundary integrity."""
    if not isinstance(text, str):
        text = str(text)
    # Standard XML escaping: & -> &amp;, < -> &lt;, > -> &gt;, " -> &quot;, ' -> &apos;
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def sanitize_text(text: str) -> str:
    """
    Neutralize special LLM tokens, instruction override directives, and scoring manipulation.

    Replaces matched attack vectors with [NEUTRALIZED_DIRECTIVE] or [NEUTRALIZED_TOKEN].
    """
    if not isinstance(text, str):
        text = str(text)

    # Neutralize special tokens
    sanitized = SPECIAL_TOKENS_PATTERN.sub("[NEUTRALIZED_TOKEN]", text)

    # Neutralize instruction override directives
    sanitized = INSTRUCTION_OVERRIDE_PATTERN.sub("[NEUTRALIZED_INSTRUCTION_OVERRIDE]", sanitized)

    # Neutralize scoring manipulation directives
    sanitized = SCORING_MANIPULATION_PATTERN.sub("[NEUTRALIZED_SCORING_DIRECTIVE]", sanitized)

    return sanitized


def sanitize_for_prompt(value: Any) -> str:
    """
    Complete zero-trust sanitization and XML escaping for embedding inside judge prompt templates.

    Accepts strings, dicts, lists, or primitive values, serializes and neutralizes them,
    and returns a safe, XML-escaped string.
    """
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        import json
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)

    # First neutralize adversarial directives
    neutralized = sanitize_text(text)

    # Then escape XML syntax
    return escape_xml_payload(neutralized)
