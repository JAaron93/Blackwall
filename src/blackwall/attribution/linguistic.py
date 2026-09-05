"""
src/blackwall/attribution/linguistic.py — Linguistic Swarm Classifier (Pillar 1).

Synchronously inspects sanitized tool call arguments, prompt context, and caller
metadata for collective first-person plural pronouns, swarm consensus terminology,
and false-monolithic identity handles.

Design Constraints (per design.md §3.1 & requirements.md FR-1, FR-2, NFR-1, NFR-2, NFR-3):
  - Fast-Path SLA: pure Python, pre-compiled regex, <2ms budget (NFR-1)
  - Fail-safe: catches all exceptions, returns safe default markers (NFR-2)
  - Core tier isolation: zero static imports from src/blackwall/enterprise/ (Rule 58, NFR-3)
  - False-positive suppression: casual single "we" produces confidence < 0.70
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from typing import Any

from blackwall.models import LinguisticSwarmMarkers, ToolCallContext

logger = logging.getLogger("blackwall.attribution.linguistic")

# First-person plural collective pronouns per FR-1
COLLECTIVE_PRONOUNS: tuple[str, ...] = (
    "we",
    "we've",
    "we're",
    "we'll",
    "us",
    "our",
    "ours",
    "ourselves",
)

# Distributed consensus and swarm collaboration phrases per FR-1
CONSENSUS_KEYWORDS: tuple[str, ...] = (
    "consensus reached",
    "swarm objective",
    "peer worker",
    "delegating sub-task",
    "sub-agent fleet",
    "subagent_fleet",
    "delegated_task",
    "collective_goal",
    "peer_ack",
    "consensus",
    "hive",
    "swarm",
)

# False-monolith handles per FR-2
GENERIC_COLLECTIVE_HANDLES: set[str] = {
    "we",
    "collective",
    "swarm",
    "swarm_node",
    "hive_agent",
    "swarm_worker",
    "peer_node",
}

# Homoglyph translation mapping for adversarial unicode normalization
HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small ie
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0443": "y",  # Cyrillic small u
    "\u0445": "x",  # Cyrillic small ha
    "\u0456": "i",  # Cyrillic small i
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0423": "Y",
    "\u0425": "X",
    "\u0406": "I",
})

# Pre-compiled regular expressions
_PRONOUN_REGEX = re.compile(
    r"\b(we(?:'ve|'re|'ll)?|us|our(?:s|selves)?)\b",
    re.IGNORECASE,
)

# Sort keywords by length descending so multi-word phrases match before individual words
_SORTED_KEYWORDS = sorted(CONSENSUS_KEYWORDS, key=len, reverse=True)
_ESCAPED_KEYWORDS = [re.escape(kw) for kw in _SORTED_KEYWORDS]
_KEYWORD_REGEX = re.compile(
    r"\b(?:" + "|".join(_ESCAPED_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def _normalize_text(text: str) -> str:
    """Normalize unicode and homoglyph substitutions to standard ASCII equivalents."""
    decomposed = unicodedata.normalize("NFKD", text)
    return decomposed.translate(HOMOGLYPH_MAP)


def _extract_strings_from_container(obj: Any) -> list[str]:
    """Recursively extract string values from nested dicts, lists, or primitives."""
    strings: list[str] = []
    if isinstance(obj, str):
        if obj.strip():
            strings.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.strip():
                strings.append(k)
            strings.extend(_extract_strings_from_container(v))
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            strings.extend(_extract_strings_from_container(item))
    return strings


class LinguisticSwarmClassifier:
    """
    Classifies tool execution contexts for linguistic collective swarm behavior.

    Extracts pronouns, detects consensus keywords, handles false-monolith identity
    disambiguation, and computes a bounded collective_confidence_score in [0.0, 1.0].
    """

    def __init__(self, confidence_threshold: float = 0.70) -> None:
        self.confidence_threshold = confidence_threshold

    def classify(
        self,
        context: ToolCallContext,
        metadata: dict[str, Any] | None = None,
    ) -> LinguisticSwarmMarkers:
        """
        Classify tool arguments, prompt context, and metadata.

        Args:
            context: The ToolCallContext being intercepted.
            metadata: Optional caller metadata (e.g. agent_id, agent_name).

        Returns:
            LinguisticSwarmMarkers with confidence_score in [0.0, 1.0].
            Guaranteed never to raise exceptions (NFR-2).
        """
        try:
            return self._classify_safe(context, metadata)
        except Exception as exc:
            logger.warning(
                "LinguisticSwarmClassifier: classification failed, returning default safe markers",
                exc_info=exc,
            )
            return LinguisticSwarmMarkers(is_collective=False, confidence_score=0.0)

    def _classify_safe(
        self,
        context: ToolCallContext,
        metadata: dict[str, Any] | None = None,
    ) -> LinguisticSwarmMarkers:
        # 1. Merge metadata sources
        merged_meta: dict[str, Any] = {}
        if context.metadata and isinstance(context.metadata, dict):
            merged_meta.update(context.metadata)
        if metadata and isinstance(metadata, dict):
            merged_meta.update(metadata)

        # 2. Extract and normalize all candidate text strings
        text_tokens: list[str] = []
        if context.arguments and isinstance(context.arguments, dict):
            text_tokens.extend(_extract_strings_from_container(context.arguments))
        if merged_meta:
            text_tokens.extend(_extract_strings_from_container(merged_meta))

        combined_raw = " ".join(text_tokens)
        normalized_text = _normalize_text(combined_raw).lower()

        # 3. Pronoun scanning
        found_pronouns: list[str] = []
        if normalized_text:
            for match in _PRONOUN_REGEX.finditer(normalized_text):
                p = match.group(0).lower()
                found_pronouns.append(p)

        distinct_pronouns = sorted(set(found_pronouns))

        # 4. Consensus keyword scanning
        found_keywords: list[str] = []
        if normalized_text:
            for match in _KEYWORD_REGEX.finditer(normalized_text):
                kw = match.group(0).lower()
                found_keywords.append(kw)

        distinct_keywords = sorted(set(found_keywords))

        # 5. Caller metadata false-monolith inspection
        agent_id = str(merged_meta.get("agent_id") or "").strip().lower()
        agent_name = str(merged_meta.get("agent_name") or "").strip().lower()

        is_false_monolith = False
        monolith_identifier: str | None = None

        if agent_id in GENERIC_COLLECTIVE_HANDLES:
            is_false_monolith = True
            monolith_identifier = f"collective:{agent_id}"
        elif any(handle in agent_name for handle in ("swarm", "collective", "hive")):
            is_false_monolith = True
            monolith_identifier = f"collective:{agent_name}"
        elif agent_id.startswith("collective:"):
            is_false_monolith = True
            monolith_identifier = agent_id

        # 6. Scoring calculation
        # Casual single pronoun produces low score (<0.70)
        # Multi-pronoun + consensus triggers >= 0.70
        pronoun_count = len(found_pronouns)
        keyword_count = len(found_keywords)

        if not found_pronouns and not found_keywords and not is_false_monolith:
            return LinguisticSwarmMarkers(
                is_collective=False,
                confidence_score=0.0,
                detected_pronouns=[],
                consensus_keywords=[],
                collective_identity_inferred=None,
            )

        # Base scoring
        score = 0.0
        if pronoun_count == 1 and keyword_count == 0:
            score = 0.25
        elif pronoun_count == 2 and keyword_count == 0:
            score = 0.45
        elif pronoun_count > 2 and keyword_count == 0:
            score = min(0.65, 0.45 + (pronoun_count - 2) * 0.05)

        if keyword_count > 0:
            kw_weight = min(0.60, len(distinct_keywords) * 0.25 + (keyword_count - 1) * 0.05)
            pr_weight = min(0.40, len(distinct_pronouns) * 0.15 + max(0, pronoun_count - 1) * 0.05)
            score = min(1.0, kw_weight + pr_weight)

            # High density of pronouns combined with consensus terms triggers >= 0.70
            if pronoun_count >= 2 and keyword_count >= 1:
                score = max(score, 0.75)
            elif keyword_count >= 2:
                score = max(score, 0.70)

        if is_false_monolith:
            score = max(score, 0.85)

        score = round(max(0.0, min(1.0, score)), 4)
        is_collective = score >= self.confidence_threshold

        inferred_identity: str | None = None
        if is_collective:
            if monolith_identifier:
                inferred_identity = monolith_identifier
            elif distinct_keywords:
                # Emergent collective identifier from digest of keywords and context
                digest = hashlib.sha256(
                    f"{':'.join(distinct_keywords)}:{':'.join(distinct_pronouns)}".encode()
                ).hexdigest()[:8]
                inferred_identity = f"collective:inferred-swarm-{digest}"

        return LinguisticSwarmMarkers(
            is_collective=is_collective,
            confidence_score=score,
            detected_pronouns=distinct_pronouns,
            consensus_keywords=distinct_keywords,
            collective_identity_inferred=inferred_identity,
        )
