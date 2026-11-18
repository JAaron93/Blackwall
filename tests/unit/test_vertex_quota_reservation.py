"""Tier-2 Vertex quota reservation (TASK-F03, ADR 0009 Open Item 2).

The 300 RPM Vertex quota is shared by Tier-2, signature synthesis and ABA. A
reserved token floor protects Tier-2: non-priority callers (synthesis/ABA) cannot
drain the bucket below the reserve, while Tier-2 (priority) may use any token.
Empirical basis: a live burst test showed the uncoordinated path gave Tier-2 a 30%
429 rate under synthesis bursts, while a reservation kept Tier-2 reliable and improved
synthesis throughput (ADR 0009 OI2). These tests pin the mechanism deterministically.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from blackwall.resolver import TokenBucketRateLimiter
from blackwall.sync_resolver import SyncResolver


@pytest.mark.asyncio
async def test_non_priority_cannot_drain_below_reserve():
    bucket = TokenBucketRateLimiter(capacity=10.0, refill_rate=0.0, reserve=3.0)
    for _ in range(7):  # 10 -> 3
        assert await bucket.consume(1.0, priority=False)
    assert not await bucket.consume(1.0, priority=False)  # blocked at the reserve
    assert bucket.tokens == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_priority_may_use_tokens_below_the_reserve():
    bucket = TokenBucketRateLimiter(capacity=10.0, refill_rate=0.0, reserve=3.0)
    for _ in range(7):
        assert await bucket.consume(1.0, priority=False)
    # Tier-2 (priority) can spend the reserved tokens and below.
    for _ in range(3):
        assert await bucket.consume(1.0, priority=True)
    assert bucket.tokens == pytest.approx(0.0)
    assert not await bucket.consume(1.0, priority=True)


@pytest.mark.asyncio
async def test_priority_ignores_reserve_entirely():
    bucket = TokenBucketRateLimiter(capacity=5.0, refill_rate=0.0, reserve=5.0)
    assert not await bucket.consume(1.0, priority=False)  # floor == capacity
    assert await bucket.consume(1.0, priority=True)
    assert bucket.tokens == pytest.approx(4.0)


@pytest.mark.asyncio
async def test_default_reserve_zero_preserves_legacy_behavior():
    bucket = TokenBucketRateLimiter(capacity=5.0, refill_rate=0.0)
    assert bucket.reserve == 0.0
    for _ in range(5):
        assert await bucket.consume(1.0)  # default non-priority, floor 0
    assert not await bucket.consume(1.0)


@pytest.mark.asyncio
async def test_synthesis_cannot_starve_tier2():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(
        capacity=5.0, refill_rate=0.0, reserve=3.0
    )
    # Synthesis drains to the reserve.
    assert await resolver._tier2_rate_limiter.consume(1.0, priority=False)
    assert await resolver._tier2_rate_limiter.consume(1.0, priority=False)
    # Tier-2 still gets a token (priority); synthesis is now blocked.
    assert await resolver._tier2_rate_limiter.consume(1.0, priority=True)
    assert not await resolver._tier2_rate_limiter.consume(1.0, priority=False)


@pytest.mark.asyncio
async def test_inline_signature_skips_when_quota_is_reserved_for_tier2():
    """When the shared Vertex quota is drained to the Tier-2 reserve, signature
    synthesis yields (no Gemini call) rather than starving Tier-2."""
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(
        capacity=3.0, refill_rate=0.0, reserve=3.0
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
async def test_quarantine_refactoring_skips_when_quota_is_reserved_for_tier2():
    resolver = SyncResolver(client=MagicMock(), enable_semantic_triage=True)
    resolver._tier2_rate_limiter = TokenBucketRateLimiter(
        capacity=3.0, refill_rate=0.0, reserve=3.0
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