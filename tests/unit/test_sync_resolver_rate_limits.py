"""SyncResolver rate limits after the Jev-only Tier-1 (ADR 0009).

Two buckets, each sized to the service it protects:

* the front bucket guards every evaluation and matches Jev's organization limit
  (80 req/s, ADR 0008);
* the Tier-2 bucket guards only the Vertex AI call (300 RPM, 5 tokens/s).

An empty Tier-2 bucket QUARANTINEs the call, exactly as the single 300 RPM
bucket did before. It is not a Tier-2 abstention: an abstention reaches Score
Aggregation, which allows a lone band signal at production thresholds (ADR 0008,
Open Item 9), so draining the bucket would become a bypass.
"""

import pytest
from unittest.mock import MagicMock

from blackwall.models import VerdictDecision
from blackwall.resolver import TokenBucketRateLimiter
from blackwall import sync_resolver
from blackwall.sync_resolver import SyncResolver
from tests.unit.test_tier2_escalation import (
    _StubTier1,
    _beacon_context,
    _benign_context,
    _in_band,
    _tier1_result,
    _tier2_client,
)


def _resolver(tier1, client=None) -> SyncResolver:
    resolver = SyncResolver(
        client=client if client is not None else MagicMock(),
        enable_semantic_triage=True,
    )
    resolver._semantic_provider = tier1
    return resolver


def test_front_bucket_matches_the_jev_org_limit():
    assert sync_resolver.FRONT_RATE_LIMIT_CAPACITY == 80.0
    assert sync_resolver.FRONT_RATE_LIMIT_REFILL_PER_S == 80.0
    resolver = SyncResolver(client=None)
    assert resolver._rate_limiter.capacity == 80.0
    assert resolver._rate_limiter.refill_rate == 80.0


def test_tier2_bucket_matches_the_vertex_limit():
    assert sync_resolver.TIER2_RATE_LIMIT_CAPACITY == 300.0
    assert sync_resolver.TIER2_RATE_LIMIT_REFILL_PER_S == 5.0
    resolver = SyncResolver(client=None)
    assert resolver._tier2_rate_limiter.capacity == 300.0
    assert resolver._tier2_rate_limiter.refill_rate == 5.0
    assert resolver._tier2_rate_limiter is not resolver._rate_limiter


@pytest.mark.asyncio
async def test_front_exhaustion_quarantines_and_names_the_jev_limit():
    resolver = _resolver(_StubTier1(_tier1_result(0.02)))
    resolver._rate_limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
    first = await resolver.evaluate(_benign_context())
    second = await resolver.evaluate(_benign_context())
    assert first.decision != VerdictDecision.QUARANTINE
    assert second.decision == VerdictDecision.QUARANTINE
    assert "80 req/s" in second.reasoning
    assert "300 RPM" not in second.reasoning


@pytest.mark.asyncio
async def test_clear_signals_never_spend_tier2_tokens():
    resolver = _resolver(_StubTier1(_tier1_result(0.02)))
    before = resolver._tier2_rate_limiter.tokens
    await resolver.evaluate(_benign_context())
    assert resolver.tier2_calls == 0
    assert resolver._tier2_rate_limiter.tokens == pytest.approx(before, abs=0.5)


@pytest.mark.asyncio
async def test_escalation_spends_exactly_one_tier2_token():
    client = _tier2_client(decision="BLOCK", threat_score=0.9)
    resolver = _resolver(_StubTier1(_in_band(0.51)), client)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=0.0)
    verdict = await resolver.evaluate(_beacon_context())
    assert resolver.tier2_calls == 1
    assert resolver._tier2_rate_limiter.tokens == pytest.approx(4.0)
    assert verdict.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_empty_tier2_bucket_quarantines_and_skips_the_vertex_call():
    client = _tier2_client(decision="ALLOW", threat_score=0.0)
    resolver = _resolver(_StubTier1(_in_band(0.51)), client)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
    await resolver.evaluate(_beacon_context())
    calls_after_first = client.models.generate_content.call_count
    verdict = await resolver.evaluate(_beacon_context())
    assert client.models.generate_content.call_count == calls_after_first
    assert resolver.tier2_calls == 1  # only calls that reached Vertex count
    assert resolver.tier2_rate_limit_hits == 1
    assert verdict.decision == VerdictDecision.QUARANTINE
    assert "Tier-2" in verdict.reasoning and "300 RPM" in verdict.reasoning


@pytest.mark.asyncio
async def test_draining_the_tier2_bucket_never_yields_allow_for_a_band_call():
    """The bypass this guards: aim calls at the band, drain Tier-2, get ALLOW."""
    client = _tier2_client(decision="ALLOW", threat_score=0.0)
    resolver = _resolver(_StubTier1(_in_band(0.51)), client)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(capacity=0.0, refill_rate=0.0)
    for _ in range(5):
        verdict = await resolver.evaluate(_beacon_context())
        assert verdict.decision == VerdictDecision.QUARANTINE
    assert client.models.generate_content.call_count == 0


@pytest.mark.asyncio
async def test_structural_block_is_not_downgraded_by_an_empty_tier2_bucket():
    from blackwall.policy.models import StructuralAction

    resolver = _resolver(_StubTier1(_in_band(0.51)))
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(capacity=0.0, refill_rate=0.0)
    engine = MagicMock()
    engine._policy = None
    engine.evaluate.return_value = MagicMock(
        decision=StructuralAction.BLOCK, ruleId="rule"
    )
    server = MagicMock()
    server.structural_engine = engine
    resolver.policy_server = server
    verdict = await resolver.evaluate(_beacon_context())
    assert verdict.decision == VerdictDecision.BLOCK  # aggregation supremacy


@pytest.mark.asyncio
async def test_tier2_exhaustion_does_not_quarantine_unrelated_calls():
    resolver = _resolver(_StubTier1(_tier1_result(0.02)))
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(capacity=0.0, refill_rate=0.0)
    verdict = await resolver.evaluate(_benign_context())
    assert verdict.decision != VerdictDecision.QUARANTINE
