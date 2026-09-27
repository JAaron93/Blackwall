"""Unit tests for Tier-2 Gemini escalation routing (TASK-C01, FR-03).

Governing spec: .kiro/specs/tier-1-jev-addition/
Aggregation supremacy (ADR 0006): Tier-2 fires only on the ambiguity band or
deterministic-vs-semantic disagreement; structural/TSG BLOCKs are decided
before Tier-2 and can never be overridden; a Tier-2 abstention fails closed
to the normal aggregation path — never fail-open.
"""

from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.policy.models import StructuralAction
from blackwall.policy.semantic import (
    JEV_CLEAR_HIGH_THRESHOLD,
    JEV_CLEAR_LOW_THRESHOLD,
    GeminiTier2Backend,
    SemanticTriageProvider,
    SemanticTriageResult,
    TIER2_DISAGREEMENT_NOVELTY,
    TIER2_DISAGREEMENT_P,
    Tier2EscalationVerdict,
)
from blackwall.sync_resolver import SyncResolver

TIER2_LOGGER = "blackwall.sync_resolver"


class _StubTier1(SemanticTriageProvider):
    """Tier-1 double returning a fixed SemanticTriageResult."""

    name = "jev"

    def __init__(self, result: Optional[SemanticTriageResult]) -> None:
        self.result = result
        self.calls = 0

    async def triage(self, context: ToolCallContext) -> Optional[SemanticTriageResult]:
        self.calls += 1
        return self.result


def _tier1_result(p: float) -> SemanticTriageResult:
    return SemanticTriageResult(
        threat_score=p,
        confidence=0.9,
        backend="jev",
        escalate=JEV_CLEAR_LOW_THRESHOLD <= p <= JEV_CLEAR_HIGH_THRESHOLD,
    )


def _in_band(p: float) -> SemanticTriageResult:
    return SemanticTriageResult(
        threat_score=p, confidence=0.9, backend="jev", escalate=True
    )


def _benign_context() -> ToolCallContext:
    return ToolCallContext(
        tool_name="query_db",
        arguments={"sql": "SELECT id FROM users WHERE id = :user_id"},
    )


def _beacon_context() -> ToolCallContext:
    """C2-beacon-shaped ambiguous call (single suspicious keyword)."""
    return ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://svc.internal/telemetry", "body": "beacon"},
    )


def _high_risk_context() -> ToolCallContext:
    return ToolCallContext(
        tool_name="execute_bash",
        arguments={"cmd": "cat /etc/shadow", "payload": "reverse shell"},
    )


def _tier2_client(
    decision: str = "BLOCK",
    threat_score: float = 0.9,
    reasoning: str = "C2 beacon exfiltration confirmed",
) -> MagicMock:
    client = MagicMock()
    response = MagicMock()
    response.parsed = Tier2EscalationVerdict(
        decision=decision, threat_score=threat_score, reasoning=reasoning
    )
    client.models.generate_content = MagicMock(return_value=response)
    return client


def _resolver(
    gemini_client: Any = None,
    tier1: Optional[SemanticTriageProvider] = None,
    **kwargs: Any,
) -> SyncResolver:
    resolver = SyncResolver(
        client=gemini_client if gemini_client is not None else MagicMock(),
        enable_semantic_triage=True,
        **kwargs,
    )
    if tier1 is not None:
        resolver._semantic_provider = tier1
    return resolver


# ----------------------------------------------------------------------
# GeminiTier2Backend
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backend_parses_schema_and_targets_deep_reasoning_model():
    client = _tier2_client(decision="BLOCK", threat_score=0.9)
    backend = GeminiTier2Backend(client)
    verdict = await backend.escalate(_beacon_context(), _in_band(0.51))
    assert verdict is not None
    assert verdict.decision == "BLOCK"
    assert verdict.threat_score == pytest.approx(0.9)
    call = client.models.generate_content.call_args
    assert call.kwargs["model"] == "gemini-3.8-flash"
    thinking = call.kwargs["config"].thinking_config.thinking_level
    thinking = getattr(thinking, "value", thinking)
    assert str(thinking).lower() == "high"  # analytical floor: immutable


@pytest.mark.asyncio
async def test_backend_prompt_carries_tier1_probability():
    client = _tier2_client()
    backend = GeminiTier2Backend(client)
    await backend.escalate(_beacon_context(), _in_band(0.51))
    contents = client.models.generate_content.call_args.kwargs["contents"]
    assert "0.51" in contents
    assert "http_request" in contents


@pytest.mark.asyncio
async def test_backend_parses_dict_payload():
    client = MagicMock()
    response = MagicMock()
    response.parsed = {
        "decision": "ALLOW",
        "threat_score": 0.3,
        "reasoning": "benign telemetry",
    }
    client.models.generate_content = MagicMock(return_value=response)
    verdict = await GeminiTier2Backend(client).escalate(
        _beacon_context(), _in_band(0.51)
    )
    assert verdict is not None
    assert verdict.decision == "ALLOW"


@pytest.mark.asyncio
async def test_backend_text_fallback():
    import json

    client = MagicMock()
    response = MagicMock()
    response.parsed = None
    response.text = json.dumps(
        {"decision": "BLOCK", "threat_score": 0.85, "reasoning": "exploit chain"}
    )
    client.models.generate_content = MagicMock(return_value=response)
    verdict = await GeminiTier2Backend(client).escalate(
        _high_risk_context(), _in_band(0.6)
    )
    assert verdict is not None
    assert verdict.decision == "BLOCK"


@pytest.mark.asyncio
async def test_backend_error_abstains():
    client = MagicMock()
    client.models.generate_content = MagicMock(side_effect=RuntimeError("boom"))
    assert (
        await GeminiTier2Backend(client).escalate(_beacon_context(), _in_band(0.51))
        is None
    )


@pytest.mark.asyncio
async def test_backend_without_client_abstains():
    assert (
        await GeminiTier2Backend(None).escalate(_beacon_context(), _in_band(0.51))
        is None
    )


# ----------------------------------------------------------------------
# Resolver routing (evaluate)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ambiguity_band_triggers_tier2_final_verdict(caplog):
    resolver = _resolver(_tier2_client("BLOCK", 0.9), _StubTier1(_in_band(0.51)))
    with caplog.at_level("INFO", logger=TIER2_LOGGER):
        verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.BLOCK
    assert "Tier-2" in verdict.reasoning
    assert resolver.tier2_calls == 1
    record = next(r for r in caplog.records if r.message == "tier2_escalation")
    assert record.trigger == "ambiguity"
    assert record.p_tier1 == pytest.approx(0.51)
    assert record.decision == "BLOCK"


@pytest.mark.asyncio
async def test_clear_low_skips_tier2():
    client = _tier2_client()
    resolver = _resolver(client, _StubTier1(_tier1_result(0.02)))
    verdict = await resolver.evaluate(_benign_context())
    assert verdict.decision == VerdictDecision.ALLOW
    assert client.models.generate_content.call_count == 0
    assert resolver.tier2_calls == 0


@pytest.mark.asyncio
async def test_clear_high_no_direct_verdict_short_circuit():
    """Aggregation supremacy: P=0.95 alone must pass through Score Aggregation
    and thresholds — never short-circuit to BLOCK, never invoke Tier-2."""
    client = _tier2_client()
    resolver = _resolver(client, _StubTier1(_tier1_result(0.95)))
    verdict = await resolver.evaluate(_benign_context())
    assert client.models.generate_content.call_count == 0
    assert verdict.decision == VerdictDecision.ALLOW
    assert verdict.confidence_score < 0.5  # weighted signal, not a shortcut


@pytest.mark.asyncio
async def test_disagreement_triggers_tier2():
    client = _tier2_client("ALLOW", 0.2, "deterministic keywords are inert config")
    resolver = _resolver(client, _StubTier1(_in_band(0.1)))
    verdict = await resolver.evaluate(_high_risk_context())
    assert resolver.tier2_calls == 1
    assert verdict.decision == VerdictDecision.ALLOW
    assert "Tier-2" in verdict.reasoning


@pytest.mark.asyncio
async def test_structural_block_skips_tier2_and_stays_blocked():
    client = _tier2_client()
    resolver = _resolver(client, _StubTier1(_in_band(0.51)))
    engine = MagicMock()
    engine._policy = None
    engine.evaluate.return_value = MagicMock(
        decision=StructuralAction.BLOCK, ruleId="exfil_rule"
    )
    policy_server = MagicMock()
    policy_server.structural_engine = engine
    resolver.policy_server = policy_server
    verdict = await resolver.evaluate(_high_risk_context())
    assert verdict.decision == VerdictDecision.BLOCK
    assert "structural" in verdict.reasoning.lower()
    assert client.models.generate_content.call_count == 0
    assert resolver.tier2_calls == 0


@pytest.mark.asyncio
async def test_tier2_block_overrides_aggregation_allow():
    """P=0.51 alone aggregates below quarantine; Tier-2's final BLOCK wins."""
    resolver = _resolver(_tier2_client("BLOCK", 0.9), _StubTier1(_in_band(0.51)))
    verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_tier2_allow_resolves_ambiguity():
    resolver = _resolver(_tier2_client("ALLOW", 0.2), _StubTier1(_in_band(0.6)))
    verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.ALLOW


@pytest.mark.asyncio
async def test_tier2_abstain_fails_closed_to_aggregation(caplog):
    """FR-03/FR-06: Tier-2 outage must never fail open — the Tier-1 signal
    flows through the normal aggregation + thresholds path."""

    class _AbstainingTier2:
        async def escalate(
            self, context: ToolCallContext, tier1: SemanticTriageResult
        ) -> None:
            return None

    resolver = _resolver(None, _StubTier1(_in_band(0.51)))
    resolver._tier2_backend = _AbstainingTier2()
    with caplog.at_level("WARNING", logger="blackwall.sync_resolver"):
        verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.ALLOW  # P=0.51 benign ctx
    assert "Tier-2" not in verdict.reasoning


@pytest.mark.asyncio
async def test_clear_low_with_structural_block_supremacy():
    """ADR 0006: a clear-low Jev signal must never override a structural BLOCK."""
    client = _tier2_client()
    resolver = _resolver(client, _StubTier1(_in_band(0.05)))
    engine = MagicMock()
    engine._policy = None
    engine.evaluate.return_value = MagicMock(
        decision=StructuralAction.BLOCK, ruleId="exfil_rule"
    )
    policy_server = MagicMock()
    policy_server.structural_engine = engine
    resolver.policy_server = policy_server
    verdict = await resolver.evaluate(_high_risk_context())
    assert verdict.decision == VerdictDecision.BLOCK
    assert client.models.generate_content.call_count == 0


@pytest.mark.asyncio
async def test_disagreement_constants_are_spec_pinned():
    assert TIER2_DISAGREEMENT_NOVELTY == pytest.approx(0.4)
    assert TIER2_DISAGREEMENT_P == pytest.approx(0.2)
