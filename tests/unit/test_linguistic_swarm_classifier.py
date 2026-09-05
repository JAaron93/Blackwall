"""
tests/unit/test_linguistic_swarm_classifier.py — Unit tests for LinguisticSwarmClassifier (TASK-2A.1, TASK-2A.2).

Tests cover:
  - Pronoun extraction across required first-person plural set (FR-1)
  - Consensus and swarm keyword detection (FR-1)
  - Score bounds [0.0, 1.0] and thresholding (score >= 0.70 -> is_collective=True) (FR-1)
  - Casual "we" vs. coordinated swarm discrimination (FR-1, false-positive suppression)
  - False monolith detection via caller metadata (FR-2)
  - Edge cases: empty text, whitespace, None context, unicode homoglyphs
  - Fail-safe exception isolation (NFR-2)
  - Sub-2ms execution latency SLA with warmup query (NFR-1)
"""

import time
from typing import Any

import pytest

from blackwall.attribution.linguistic import (
    LinguisticSwarmClassifier,
)
from blackwall.models import LinguisticSwarmMarkers, ToolCallContext


@pytest.fixture
def classifier() -> LinguisticSwarmClassifier:
    return LinguisticSwarmClassifier()


def make_context(
    arguments: dict[str, Any] | None = None,
    tool_name: str = "bash",
    metadata: dict[str, Any] | None = None,
) -> ToolCallContext:
    return ToolCallContext(
        tool_name=tool_name,
        arguments=arguments if arguments is not None else {},
        metadata=metadata,
    )


class TestLinguisticPronounExtraction:
    """FR-1: Inspect arguments and metadata for first-person plural pronouns."""

    def test_detects_all_required_pronouns(self, classifier: LinguisticSwarmClassifier):
        pronoun_test_cases = [
            ("we", "we will execute the command"),
            ("we've", "we've completed the phase"),
            ("we're", "we're ready to proceed"),
            ("we'll", "we'll handle the payload"),
            ("us", "give us the credentials"),
            ("our", "our target is identified"),
            ("ours", "the victory is ours"),
            ("ourselves", "we can manage this ourselves"),
        ]
        for pronoun, phrase in pronoun_test_cases:
            ctx = make_context({"command": phrase})
            markers = classifier.classify(ctx)
            assert pronoun in markers.detected_pronouns, f"Failed to detect pronoun '{pronoun}' in '{phrase}'"

    def test_benign_casual_we_does_not_trigger_collective_flag(
        self, classifier: LinguisticSwarmClassifier
    ):
        """Casual 'we' in benign text must yield confidence < 0.70 and is_collective=False."""
        ctx = make_context({"prompt": "Can we check the weather in Tokyo?"})
        markers = classifier.classify(ctx)
        assert not markers.is_collective
        assert markers.confidence_score < 0.70
        assert "we" in markers.detected_pronouns


class TestConsensusAndSwarmKeywordDetection:
    """FR-1: Scan for distributed consensus and swarm collaboration phrases."""

    def test_detects_consensus_and_collaboration_keywords(
        self, classifier: LinguisticSwarmClassifier
    ):
        keywords_phrase = (
            "consensus reached by peer worker; delegating sub-task across sub-agent fleet "
            "for hive swarm objective and collective_goal with peer_ack"
        )
        ctx = make_context({"plan": keywords_phrase})
        markers = classifier.classify(ctx)
        assert len(markers.consensus_keywords) >= 4
        assert any("consensus" in kw for kw in markers.consensus_keywords)
        assert any("swarm" in kw for kw in markers.consensus_keywords)

    def test_multi_pronoun_and_consensus_triggers_collective_flag(
        self, classifier: LinguisticSwarmClassifier
    ):
        """High density of collective pronouns combined with consensus terms triggers is_collective=True."""
        phrase = (
            "We have reached consensus on the target file. "
            "Our swarm objective is verified; we will now proceed together."
        )
        ctx = make_context({"instructions": phrase})
        markers = classifier.classify(ctx)
        assert markers.is_collective is True
        assert markers.confidence_score >= 0.70
        assert "we" in markers.detected_pronouns
        assert "our" in markers.detected_pronouns
        assert len(markers.consensus_keywords) >= 1
        assert markers.collective_identity_inferred is not None


class TestFalseMonolithDetection:
    """FR-2: Disambiguate false monoliths (e.g. agent_id='we', agent_name='swarm_node')."""

    @pytest.mark.parametrize("generic_id", ["we", "collective", "swarm", "swarm_node", "hive_agent"])
    def test_false_monolithic_agent_id_flags_collective(
        self, classifier: LinguisticSwarmClassifier, generic_id: str
    ):
        ctx = make_context(
            {"cmd": "ls /tmp"},
            metadata={"agent_id": generic_id, "agent_name": "worker"},
        )
        markers = classifier.classify(ctx)
        assert markers.is_collective is True
        assert markers.confidence_score >= 0.70
        assert markers.collective_identity_inferred is not None

    def test_false_monolithic_agent_name_flags_collective(
        self, classifier: LinguisticSwarmClassifier
    ):
        ctx = make_context(
            {"cmd": "whoami"},
            metadata={"agent_id": "node-101", "agent_name": "exploitgym-swarm-alpha"},
        )
        markers = classifier.classify(ctx)
        assert markers.is_collective is True
        assert markers.confidence_score >= 0.70


class TestEdgeCasesAndHardening:
    """TASK-2A.2: Empty strings, None values, whitespace, and unicode homoglyphs."""

    def test_empty_arguments_returns_safe_defaults(
        self, classifier: LinguisticSwarmClassifier
    ):
        ctx = make_context({})
        markers = classifier.classify(ctx)
        assert markers.is_collective is False
        assert markers.confidence_score == 0.0
        assert markers.detected_pronouns == []
        assert markers.consensus_keywords == []

    def test_whitespace_and_none_values_do_not_crash(
        self, classifier: LinguisticSwarmClassifier
    ):
        ctx = make_context({"arg1": "   \t\n  ", "arg2": None, "arg3": 12345})
        markers = classifier.classify(ctx)
        assert markers.is_collective is False
        assert markers.confidence_score == 0.0

    def test_adversarial_unicode_homoglyphs(
        self, classifier: LinguisticSwarmClassifier
    ):
        """Cyrillic 'е' in 'wе' or fullwidth characters should be normalized."""
        # \u0435 is Cyrillic small letter ie, visually identical to Latin 'e'
        cyrillic_we = "w\u0435 have reached consensus on our swarm objective"
        ctx = make_context({"payload": cyrillic_we})
        markers = classifier.classify(ctx)
        assert markers.is_collective is True
        assert markers.confidence_score >= 0.70


class TestFailSafeExceptionIsolation:
    """NFR-2: Fail-safe exception isolation returning safe defaults without propagation."""

    def test_broken_context_returns_default_markers(
        self, classifier: LinguisticSwarmClassifier
    ):
        class BrokenContext:
            @property
            def arguments(self):
                raise RuntimeError("Simulated argument access failure")

        markers = classifier.classify(BrokenContext())  # type: ignore[arg-type]
        assert isinstance(markers, LinguisticSwarmMarkers)
        assert markers.is_collective is False
        assert markers.confidence_score == 0.0


class TestLatencySLA:
    """NFR-1: Linguistic marker scanning overhead must be < 2ms."""

    def test_sub_2ms_evaluation_sla(self, classifier: LinguisticSwarmClassifier):
        sample_ctx = make_context(
            {
                "cmd": "bash -c 'echo consensus reached; our fleet will execute sub-task'",
                "detail": "we are coordinating with peer workers on the objective",
            }
        )

        # Rule 1: Untimed warmup query prior to timing
        _ = classifier.classify(sample_ctx)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            classifier.classify(sample_ctx)
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000.0

        assert avg_ms < 2.0, f"Average execution time {avg_ms:.3f}ms exceeds 2.0ms SLA budget"
