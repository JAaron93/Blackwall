"""Tier-2 Vertex quota reservation by rate-partition (TASK-F03, ADR 0009 OI2).

The 300 RPM Vertex quota is split into a reserved rate share for Tier-2 and the
remainder for signature synthesis / ABA refactoring. Separate refills sum to the
provider quota, so neither caller can over-commit the provider's per-minute window
(a shared token floor could: burst + refill > quota — Greptile P1). These tests pin
the partition and that synthesis/refactoring yield when their share is exhausted
without touching Tier-2's share.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from blackwall import sync_resolver
from blackwall.resolver import TokenBucketRateLimiter
from blackwall.sync_resolver import SyncResolver


def test_rate_shares_sum_to_the_provider_quota():
    assert sync_resolver.VERTEX_QUOTA_RPM == 300.0
    assert sync_resolver.TIER2_RESERVED_RPM == 60.0
    total_refill = (
        sync_resolver.TIER2_RATE_LIMIT_REFILL_PER_S
        + sync_resolver.SYNTHESIS_RATE_LIMIT_REFILL_PER_S
    )
    assert total_refill == pytest.approx(sync_resolver.VERTEX_QUOTA_RPM / 60.0)
    assert sync_resolver.TIER2_RATE_LIMIT_REFILL_PER_S == pytest.approx(1.0)
    assert sync_resolver.SYNTHESIS_RATE_LIMIT_REFILL_PER_S == pytest.approx(4.0)


def test_resolver_builds_separate_tier2_and_synthesis_buckets():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    assert resolver._tier2_rate_limiter is not resolver._synthesis_rate_limiter
    assert resolver._tier2_rate_limiter.refill_rate == pytest.approx(1.0)
    assert resolver._synthesis_rate_limiter.refill_rate == pytest.approx(4.0)
    assert resolver._tier2_rate_limiter is not resolver._rate_limiter


@pytest.mark.asyncio
async def test_synthesis_burst_cannot_drain_tier2_share():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    # Exhaust the synthesis share completely.
    while await resolver._synthesis_rate_limiter.consume(1.0):
        pass
    # Tier-2's reserved share is untouched and still serves a call.
    assert resolver._tier2_rate_limiter.tokens > 0
    assert await resolver._tier2_rate_limiter.consume(1.0)


@pytest.mark.asyncio
async def test_tier2_burst_cannot_drain_synthesis_share():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    while await resolver._tier2_rate_limiter.consume(1.0):
        pass
    assert resolver._synthesis_rate_limiter.tokens > 0
    assert await resolver._synthesis_rate_limiter.consume(1.0)


@pytest.mark.asyncio
async def test_inline_signature_skips_when_synthesis_share_exhausted():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    resolver._synthesis_rate_limiter = TokenBucketRateLimiter(
        capacity=0.0, refill_rate=0.0
    )
    client = MagicMock()
    resolver.client = client
    from blackwall.models import ToolCallContext, Verdict, VerdictDecision

    ctx = ToolCallContext(tool_name="execute_bash", arguments={"cmd": "x"})
    verdict = Verdict(
        decision=VerdictDecision.BLOCK, reasoning="r", confidence_score=0.9
    )
    await resolver._inline_generate_signature(ctx, verdict)
    client.models.generate_content.assert_not_called()
    if hasattr(client, "aio"):
        client.aio.models.generate_content.assert_not_called()


@pytest.mark.asyncio
async def test_quarantine_refactoring_skips_when_synthesis_share_exhausted():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    resolver._synthesis_rate_limiter = TokenBucketRateLimiter(
        capacity=0.0, refill_rate=0.0
    )
    aba = MagicMock()
    aba.triggerRefactoring = AsyncMock()
    resolver.aba = aba
    from blackwall.models import ToolCallContext, Verdict, VerdictDecision

    ctx = ToolCallContext(tool_name="execute_bash", arguments={"cmd": "x"})
    verdict = Verdict(
        decision=VerdictDecision.QUARANTINE, reasoning="r", confidence_score=0.6
    )
    result = await resolver._handle_quarantine_refactoring(ctx, verdict)
    assert result is None
    aba.triggerRefactoring.assert_not_called()