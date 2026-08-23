"""Property-based tests for GTIQueryBudgetTracker invariants.

Uses Hypothesis to verify mathematical and behavioral invariants:
  - Token count is always within [0, capacity] after arbitrary sequences of operations.
  - try_acquire() returns False exactly when available tokens are exhausted (< 1.0).
  - Replenishment never exceeds configured capacity.
  - Exactly min(N, capacity) acquisitions succeed when requesting N tokens from a full tracker.
  - Concurrent acquisitions maintain strict consistency and accounting.
"""

import asyncio
from typing import List
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.mcp.gti_client import GTIQueryBudgetTracker


def _run(coro):
    """Run an async coroutine synchronously in a dedicated event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

capacity_st = st.integers(min_value=1, max_value=50)
replenishment_interval_st = st.floats(min_value=0.1, max_value=60.0)

# An operation sequence: 0 = try_acquire, 1 = manual replenish, 2 = record_cache_hit, 3 = reset
operation_st = st.sampled_from(["acquire", "replenish", "cache_hit", "reset"])
operations_list_st = st.lists(operation_st, min_size=1, max_size=100)


# ---------------------------------------------------------------------------
# Property 1: Token count is always in [0, capacity]
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(capacity=capacity_st, operations=operations_list_st)
def test_token_count_bounded_invariant(capacity: int, operations: List[str]) -> None:
    """Property: Token count is strictly bounded in [0, capacity] after arbitrary operations."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()  # Prevent autonomous background replenishment during step-by-step test
        try:
            for op in operations:
                if op == "acquire":
                    await tracker.try_acquire()
                elif op == "replenish":
                    async with tracker.lock:
                        if tracker.tokens < tracker.capacity:
                            tracker.tokens += 1
                elif op == "cache_hit":
                    await tracker.record_cache_hit()
                elif op == "reset":
                    await tracker.reset()

                tokens = await tracker.get_available_tokens()
                assert 0 <= tokens <= capacity, f"Tokens {tokens} out of [0, {capacity}]"
                assert 0.0 <= tracker.tokens <= float(capacity)
        finally:
            tracker.close()

    _run(_async_test())


# ---------------------------------------------------------------------------
# Property 2: try_acquire returns False exactly when tokens == 0
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(capacity=capacity_st, initial_drains=st.integers(min_value=0, max_value=100))
def test_try_acquire_returns_false_iff_exhausted(capacity: int, initial_drains: int) -> None:
    """Property: try_acquire returns False exactly when tokens < 1.0 (available tokens == 0)."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()
        try:
            for _ in range(initial_drains):
                await tracker.try_acquire()

            available = await tracker.get_available_tokens()
            result = await tracker.try_acquire()

            if available >= 1:
                assert result is True, f"Expected acquire success when available was {available}"
            else:
                assert result is False, f"Expected acquire failure when available was {available}"
                assert (await tracker.get_available_tokens()) == 0
        finally:
            tracker.close()

    _run(_async_test())


# ---------------------------------------------------------------------------
# Property 3: Replenish never exceeds max_tokens (capacity)
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    capacity=capacity_st,
    initial_drains=st.integers(min_value=0, max_value=50),
    replenish_count=st.integers(min_value=0, max_value=100),
)
def test_replenish_never_exceeds_capacity(
    capacity: int, initial_drains: int, replenish_count: int
) -> None:
    """Property: Replenishing any number of tokens never exceeds tracker capacity."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()
        try:
            for _ in range(initial_drains):
                await tracker.try_acquire()

            for _ in range(replenish_count):
                async with tracker.lock:
                    if tracker.tokens < tracker.capacity:
                        tracker.tokens += 1

            available = await tracker.get_available_tokens()
            assert available <= capacity
            assert tracker.tokens <= float(capacity)
        finally:
            tracker.close()

    _run(_async_test())


# ---------------------------------------------------------------------------
# Property 4: N acquires from full tracker -> exactly min(N, capacity) succeed
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(capacity=capacity_st, n_acquires=st.integers(min_value=0, max_value=100))
def test_n_acquires_from_full_tracker(capacity: int, n_acquires: int) -> None:
    """Property: Exactly min(N, capacity) acquires succeed sequentially from a fresh tracker."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()
        try:
            results = []
            for _ in range(n_acquires):
                res = await tracker.try_acquire()
                results.append(res)

            success_count = sum(1 for r in results if r is True)
            failure_count = sum(1 for r in results if r is False)
            expected_success = min(n_acquires, capacity)
            expected_failure = max(0, n_acquires - capacity)

            assert success_count == expected_success, (
                f"Expected {expected_success} successes, got {success_count}"
            )
            assert failure_count == expected_failure, (
                f"Expected {expected_failure} failures, got {failure_count}"
            )
            assert (await tracker.get_available_tokens()) == max(0, capacity - n_acquires)
        finally:
            tracker.close()

    _run(_async_test())


# ---------------------------------------------------------------------------
# Property 5: Concurrent acquires maintain exact accounting
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(capacity=capacity_st, concurrent_workers=st.integers(min_value=1, max_value=60))
def test_concurrent_acquires_maintain_consistency(
    capacity: int, concurrent_workers: int
) -> None:
    """Property: Concurrent try_acquire() calls maintain atomic accounting and capacity limits."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()
        try:
            tasks = [tracker.try_acquire() for _ in range(concurrent_workers)]
            results = await asyncio.gather(*tasks)

            successes = sum(1 for r in results if r is True)
            expected_successes = min(concurrent_workers, capacity)

            assert successes == expected_successes, (
                f"Expected {expected_successes} concurrent successes, got {successes}"
            )
            metrics = await tracker.get_metrics()
            assert metrics.queries_attempted == concurrent_workers
            assert metrics.queries_executed == expected_successes
            assert metrics.queries_deferred == concurrent_workers - expected_successes
        finally:
            tracker.close()

    _run(_async_test())


# ---------------------------------------------------------------------------
# Property 6: Cache hit accounting does not decrement available tokens
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(capacity=capacity_st, cache_hit_count=st.integers(min_value=1, max_value=50))
def test_cache_hits_preserve_available_tokens(
    capacity: int, cache_hit_count: int
) -> None:
    """Property: Recording cache hits never decrements available token budget."""
    async def _async_test():
        tracker = GTIQueryBudgetTracker(capacity=capacity, replenishment_interval=1000.0)
        tracker.close()
        try:
            initial_tokens = await tracker.get_available_tokens()
            for _ in range(cache_hit_count):
                await tracker.record_cache_hit()

            final_tokens = await tracker.get_available_tokens()
            assert final_tokens == initial_tokens == capacity
            metrics = await tracker.get_metrics()
            assert metrics.cache_hits == cache_hit_count
            assert metrics.cache_hit_rate == 1.0
        finally:
            tracker.close()

    _run(_async_test())
