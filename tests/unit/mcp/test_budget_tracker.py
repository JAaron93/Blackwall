import asyncio
import gc
import pytest
from blackwall.mcp.gti_client import GTIQueryBudgetTracker

@pytest.mark.asyncio
async def test_budget_tracker_initialization():
    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        assert await tracker.get_available_tokens() == 4
        metrics = await tracker.get_metrics()
        assert metrics.queries_attempted == 0
        assert metrics.queries_executed == 0
        assert metrics.queries_deferred == 0
        assert metrics.cache_hits == 0
        assert metrics.cache_hit_rate == 0.0
    finally:
        tracker.close()

@pytest.mark.asyncio
async def test_budget_tracker_try_acquire():
    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        # Acquire 4 tokens
        for _ in range(4):
            assert await tracker.try_acquire() is True
        
        # 5th attempt should fail
        assert await tracker.try_acquire() is False
        
        assert await tracker.get_available_tokens() == 0
        metrics = await tracker.get_metrics()
        assert metrics.queries_attempted == 5
        assert metrics.queries_executed == 4
        assert metrics.queries_deferred == 1
    finally:
        tracker.close()

@pytest.mark.asyncio
async def test_budget_tracker_replenishment():
    # Set replenishment interval to very small for fast testing
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.01)
    try:
        # Drain all tokens
        for _ in range(4):
            await tracker.try_acquire()
        
        assert await tracker.get_available_tokens() == 0
        
        # Wait for replenishment (1 token every 0.01s, wait 0.025s for 2 tokens)
        await asyncio.sleep(0.025)
        
        tokens = await tracker.get_available_tokens()
        assert tokens >= 1
    finally:
        tracker.close()

@pytest.mark.asyncio
async def test_budget_tracker_hard_cap():
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.001)
    try:
        # Let it run a bit
        await asyncio.sleep(0.01)
        # Should not exceed capacity
        assert await tracker.get_available_tokens() == 4
    finally:
        tracker.close()

@pytest.mark.asyncio
async def test_budget_tracker_cache_hits():
    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        await tracker.record_cache_hit()
        await tracker.record_cache_hit()
        assert await tracker.try_acquire() is True
        
        metrics = await tracker.get_metrics()
        assert metrics.queries_attempted == 3
        assert metrics.queries_executed == 1
        assert metrics.cache_hits == 2
        assert metrics.cache_hit_rate == 2.0 / 3.0
    finally:
        tracker.close()

@pytest.mark.asyncio
async def test_budget_tracker_concurrent_access():
    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        # Trigger multiple acquires concurrently
        async def acquire_task():
            return await tracker.try_acquire()

        tasks = [acquire_task() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        assert results.count(True) == 4
        assert results.count(False) == 6
        
        metrics = await tracker.get_metrics()
        assert metrics.queries_attempted == 10
        assert metrics.queries_executed == 4
        assert metrics.queries_deferred == 6
    finally:
        tracker.close()


def test_budget_tracker_sync_instantiation_no_running_loop(recwarn):
    """Test that instantiating GTIQueryBudgetTracker outside an event loop does not emit unawaited coroutine RuntimeWarning."""
    # Explicitly verify there is no running event loop in this test context
    with pytest.raises(RuntimeError, match="no running event loop"):
        asyncio.get_running_loop()

    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        assert tracker.tokens == 4.0
        assert tracker._replenish_task is None
        # Force garbage collection to trigger warning if unawaited coroutine was instantiated
        gc.collect()
        runtime_warnings = [w for w in recwarn.list if issubclass(w.category, RuntimeWarning)]
        assert len(runtime_warnings) == 0, f"Expected 0 RuntimeWarnings, got: {runtime_warnings}"
    finally:
        tracker.close()
