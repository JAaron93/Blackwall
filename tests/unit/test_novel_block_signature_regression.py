"""Regression tests for the async signature path under the Jev pipeline
(TASK-C02, FR-04).

Governing spec: .kiro/specs/tier-1-jev-addition/
Every novel BLOCK (no TSG signature match — whether sourced from Tier-1,
Tier-2, or structural policy) must still yield a ThreatSignaturePayload
appended to the SQLite TSG off the hot path. Blocks served by an existing
TSG match return immediately and must invoke ZERO generation calls.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from blackwall.models import ToolCallContext, VerdictDecision
from blackwall.policy.models import StructuralAction
from blackwall.policy.semantic import SemanticTriageProvider, SemanticTriageResult
from blackwall.sync_resolver import SyncResolver, ThreatSignaturePayload

from tests.unit.test_tier2_escalation import (  # reuse doubles
    _beacon_context,
    _high_risk_context,
    _in_band,
    _tier2_client,
    _StubTier1,
)


def _mock_repo(match: dict | None = None) -> MagicMock:
    repo = MagicMock()
    repo.find_matching_signature = AsyncMock(return_value=match)
    repo.writeSignature = AsyncMock()
    return repo


def _signature_client() -> MagicMock:
    client = MagicMock()
    response = MagicMock()
    response.parsed = ThreatSignaturePayload(
        attacker_intent="Credential exfiltration via shadow read",
        payload_pattern="cat /etc/shadow; reverse shell",
        target_sink="execute_bash",
        mitigation_action="BLOCK",
    )
    client.models.generate_content = MagicMock(return_value=response)
    return client


def _resolver(
    client: MagicMock, repo: MagicMock, tier1: SemanticTriageProvider | None = None
) -> SyncResolver:
    resolver = SyncResolver(
        client=client,
        repo=repo,
        aba=None,  # force the repo persistence path — aba must not mask it
        enable_semantic_triage=True,
    )
    if tier1 is not None:
        resolver._semantic_provider = tier1
    return resolver


@pytest.mark.asyncio
async def test_novel_tier2_block_triggers_async_signature_generation():
    """A novel BLOCK arriving through the Jev→Tier-2 path must still produce
    a ThreatSignaturePayload write, off the hot path."""
    repo = _mock_repo(match=None)
    tier2_response = MagicMock()
    tier2_response.parsed = None
    tier2_response.text = (
        '{"decision": "BLOCK", "threat_score": 0.9, "reasoning": "beacon"}'
    )
    client = _signature_client()
    client.models.generate_content = MagicMock(
        side_effect=[tier2_response, client.models.generate_content.return_value]
    )
    resolver = _resolver(client, repo, _StubTier1(_in_band(0.51)))
    verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.BLOCK
    await resolver.flush_background_tasks()
    assert resolver._inline_signatures_generated == 1
    repo.writeSignature.assert_awaited_once()
    signature = repo.writeSignature.await_args.args[0]
    # aba=None exercises the real AgentBehavioralAnalytics → repo path, so
    # these fields are the actual persisted TSG signature, not a mock echo.
    assert signature["attackerIntent"] == "Credential exfiltration via shadow read"
    assert signature["payloadPattern"] == "cat /etc/shadow; reverse shell"
    assert signature["targetTool"] == "http_request"
    assert signature["mitigationAction"] == "BLOCK"
    assert signature["similarityVector"] is not None  # 768-dim TSG embedding


@pytest.mark.asyncio
async def test_novel_structural_block_still_generates_signature():
    """Structural BLOCKs are novel (no TSG match) — the signature path is
    untouched by the Jev wiring."""
    repo = _mock_repo(match=None)
    resolver = _resolver(_signature_client(), repo)
    engine = MagicMock()
    engine._policy = None
    engine.evaluate.return_value = MagicMock(
        decision=StructuralAction.BLOCK, ruleId="exfil_rule"
    )
    policy_server = MagicMock()
    policy_server.structural_engine = engine
    resolver.policy_server = policy_server
    await resolver.evaluate(_high_risk_context())
    await resolver.flush_background_tasks()
    assert resolver._inline_signatures_generated == 1
    repo.writeSignature.assert_awaited_once()


@pytest.mark.asyncio
async def test_tsg_matched_block_returns_immediately_with_zero_generation():
    """FR-04: the signature already exists — regenerating per repeat would
    add Gemini cost and graph churn."""
    repo = _mock_repo(match={"attackerIntent": "prior exfil", "matchCount": 3})
    client = _signature_client()
    resolver = _resolver(client, repo, _StubTier1(_in_band(0.51)))
    verdict = await resolver.evaluate(_high_risk_context())
    assert verdict.decision == VerdictDecision.BLOCK
    assert "signature match" in verdict.reasoning
    assert client.models.generate_content.call_count == 0
    assert resolver._inline_signatures_generated == 0
    repo.writeSignature.assert_not_awaited()


@pytest.mark.asyncio
async def test_repeated_tsg_match_never_regenerates():
    repo = _mock_repo(match={"attackerIntent": "prior exfil"})
    client = _signature_client()
    resolver = _resolver(client, repo, _StubTier1(_in_band(0.51)))
    for _ in range(3):
        verdict = await resolver.evaluate(_high_risk_context())
        assert verdict.decision == VerdictDecision.BLOCK
    await resolver.flush_background_tasks()
    assert client.models.generate_content.call_count == 0
    assert resolver._inline_signatures_generated == 0
