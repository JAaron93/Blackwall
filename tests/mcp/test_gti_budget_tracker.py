import asyncio
import pytest
from blackwall.mcp.gti_budget_tracker import GTIQueryBudgetTracker

@pytest.mark.asyncio
async def test_initializes_with_four_tokens():
    tracker = GTIQueryBudgetTracker()
    assert tracker.getAvailableTokens() == 4
    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 0
    assert metrics.queries_executed == 0
    assert metrics.queries_deferred == 0
    assert metrics.cache_hits == 0
    assert metrics.budget_exhaustion_count == 0

@pytest.mark.asyncio
async def test_try_acquire_consumes_token():
    tracker = GTIQueryBudgetTracker()
    assert tracker.tryAcquire() is True
    assert tracker.getAvailableTokens() == 3
    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 1
    assert metrics.queries_executed == 1
    assert metrics.queries_deferred == 0

@pytest.mark.asyncio
async def test_try_acquire_returns_false_when_exhausted():
    tracker = GTIQueryBudgetTracker()
    # Consume all 4 tokens
    for _ in range(4):
        assert tracker.tryAcquire() is True
    
    # 5th attempt should fail
    assert tracker.tryAcquire() is False
    assert tracker.getAvailableTokens() == 0
    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 5
    assert metrics.queries_executed == 4
    assert metrics.queries_deferred == 1
    assert metrics.budget_exhaustion_count == 1

@pytest.mark.asyncio
async def test_token_replenishment_timing():
    # Use a small replenishment interval for testing to avoid waiting 15s
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.1)
    await tracker.start()
    
    try:
        # Drain all tokens
        for _ in range(4):
            tracker.tryAcquire()
        assert tracker.getAvailableTokens() == 0
        
        # Wait for 1 replenishment (0.1s + small margin)
        await asyncio.sleep(0.12)
        assert tracker.getAvailableTokens() == 1
        
        # Wait for another replenishment
        await asyncio.sleep(0.1)
        assert tracker.getAvailableTokens() == 2
    finally:
        await tracker.stop()

@pytest.mark.asyncio
async def test_hard_cap_enforcement():
    # Initial capacity is 4. Even with replenishment loop running, it should never exceed 4.
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.01)
    await tracker.start()
    try:
        await asyncio.sleep(0.05)
        assert tracker.getAvailableTokens() == 4
        
        # Try to acquire and let it replenish again
        assert tracker.tryAcquire() is True
        assert tracker.getAvailableTokens() == 3
        await asyncio.sleep(0.02)
        assert tracker.getAvailableTokens() == 4
        await asyncio.sleep(0.02)
        assert tracker.getAvailableTokens() == 4
    finally:
        await tracker.stop()

@pytest.mark.asyncio
async def test_sliding_window_four_queries_in_sixty_seconds():
    # In a 60-second window, we refill 1 token every 15 seconds.
    # Total tokens available = initial (4) + refills (4 in 60s) = 8 total.
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=1.0) # Scale down for testing
    await tracker.start()
    try:
        # Initial 4 queries
        for _ in range(4):
            assert tracker.tryAcquire() is True
        
        # 5th query should fail immediately
        assert tracker.tryAcquire() is False
        
        # After 1 interval (1s), we get 1 token back
        await asyncio.sleep(1.05)
        assert tracker.getAvailableTokens() == 1
        assert tracker.tryAcquire() is True
        assert tracker.tryAcquire() is False
    finally:
        await tracker.stop()

@pytest.mark.asyncio
async def test_concurrent_thread_safety():
    tracker = GTIQueryBudgetTracker(capacity=10)
    
    async def worker():
        # Call the async safe variant
        return await tracker.async_try_acquire()

    # Run 12 concurrent workers
    tasks = [worker() for _ in range(12)]
    results = await asyncio.gather(*tasks)
    
    successes = sum(1 for r in results if r is True)
    failures = sum(1 for r in results if r is False)
    
    assert successes == 10
    assert failures == 2
    assert tracker.getAvailableTokens() == 0
    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 12
    assert metrics.queries_executed == 10
    assert metrics.queries_deferred == 2

@pytest.mark.asyncio
async def test_cache_hits_metric():
    tracker = GTIQueryBudgetTracker()
    tracker.record_cache_hit()
    tracker.record_cache_hit()
    metrics = tracker.getMetrics()
    assert metrics.cache_hits == 2
    # Cache hits should not consume tokens
    assert tracker.getAvailableTokens() == 4

@pytest.mark.asyncio
async def test_reset():
    tracker = GTIQueryBudgetTracker()
    tracker.tryAcquire()
    tracker.record_cache_hit()
    tracker.reset()
    assert tracker.getAvailableTokens() == 4
    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 0
    assert metrics.queries_executed == 0
    assert metrics.queries_deferred == 0
    assert metrics.cache_hits == 0
    assert metrics.budget_exhaustion_count == 0

@pytest.mark.asyncio
async def test_budget_exhaustion_count_increments_only_on_transition_to_zero_sync():
    """Verify that budget_exhaustion_count only increments when bucket transitions to zero.

    Multiple failed acquire attempts while the bucket is already empty should NOT
    increment the counter further - only the transition from non-zero to zero counts.
    """
    tracker = GTIQueryBudgetTracker()

    # Consume all 4 tokens - the 4th consume should trigger exhaustion counter
    for i in range(4):
        assert tracker.tryAcquire() is True

    metrics = tracker.getMetrics()
    assert metrics.queries_executed == 4
    assert metrics.queries_deferred == 0
    assert metrics.budget_exhaustion_count == 1  # Incremented when last token was consumed

    # Now make multiple failed attempts while bucket is empty
    for i in range(5):
        assert tracker.tryAcquire() is False

    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 9  # 4 successful + 5 failed
    assert metrics.queries_executed == 4
    assert metrics.queries_deferred == 5
    assert metrics.budget_exhaustion_count == 1  # Still 1! Not incremented on failures

@pytest.mark.asyncio
async def test_budget_exhaustion_count_increments_only_on_transition_to_zero_async():
    """Verify that budget_exhaustion_count only increments on transition to zero (async variant).

    Tests the same behavior as the sync test but using async_try_acquire().
    """
    tracker = GTIQueryBudgetTracker()

    # Consume all 4 tokens - the 4th consume should trigger exhaustion counter
    for i in range(4):
        assert await tracker.async_try_acquire() is True

    metrics = tracker.getMetrics()
    assert metrics.queries_executed == 4
    assert metrics.queries_deferred == 0
    assert metrics.budget_exhaustion_count == 1  # Incremented when last token was consumed

    # Now make multiple failed attempts while bucket is empty
    for i in range(5):
        assert await tracker.async_try_acquire() is False

    metrics = tracker.getMetrics()
    assert metrics.queries_attempted == 9  # 4 successful + 5 failed
    assert metrics.queries_executed == 4
    assert metrics.queries_deferred == 5
    assert metrics.budget_exhaustion_count == 1  # Still 1! Not incremented on failures

@pytest.mark.asyncio
async def test_budget_exhaustion_count_multiple_cycles():
    """Verify exhaustion counter increments correctly across multiple exhaust-refill cycles."""
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.05)
    await tracker.start()

    try:
        # First cycle: exhaust the bucket
        for _ in range(4):
            assert tracker.tryAcquire() is True
        metrics = tracker.getMetrics()
        assert metrics.budget_exhaustion_count == 1

        # Multiple failed attempts should not increment
        assert tracker.tryAcquire() is False
        assert tracker.tryAcquire() is False
        metrics = tracker.getMetrics()
        assert metrics.budget_exhaustion_count == 1  # Still 1

        # Wait for replenishment
        await asyncio.sleep(0.1)
        assert tracker.getAvailableTokens() >= 1

        # Second cycle: exhaust again
        while tracker.tryAcquire():
            pass

        metrics = tracker.getMetrics()
        assert metrics.budget_exhaustion_count == 2  # Now 2 (second transition)

        # More failed attempts should not increment
        assert tracker.tryAcquire() is False
        assert tracker.tryAcquire() is False
        metrics = tracker.getMetrics()
        assert metrics.budget_exhaustion_count == 2  # Still 2

    finally:
        await tracker.stop()
