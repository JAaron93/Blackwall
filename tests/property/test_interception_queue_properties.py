"""Property-based tests for InterceptionQueue using Hypothesis.

Tests core invariants of the FIFO interception queue:
1. FIFO ordering
2. Size consistency after enqueue/dequeue sequences
3. Flush empties the queue
4. getBatch never exceeds max_size
5. Correlation ID uniqueness after _assign_correlation_ids
6. dequeue on empty raises QueueEmptyException
"""

import asyncio
from typing import List, Optional
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.interception import InterceptionQueue, QueueEmptyException, QueueOverloadError
from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

non_empty_thread_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=32,
).filter(lambda s: bool(s.strip()))

tool_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_"),
    min_size=1,
    max_size=20,
).filter(lambda s: bool(s.strip()))


@st.composite
def callback_token_st(draw) -> CallbackToken:
    """Strategy to generate a valid CallbackToken with a unique thread_id."""
    thread_id = draw(non_empty_thread_id_st)
    return CallbackToken(thread_id=thread_id)


@st.composite
def tool_call_context_st(draw) -> ToolCallContext:
    """Strategy to generate a valid ToolCallContext."""
    tool_name = draw(tool_name_st)
    return ToolCallContext(tool_name=tool_name, arguments={})


def make_noop_resume() -> MagicMock:
    """Return a mock callable that accepts a Verdict."""
    return MagicMock(return_value=None)


def make_allow_verdict() -> Verdict:
    return Verdict(
        decision=VerdictDecision.ALLOW,
        reasoning="property test allow",
        confidence_score=1.0,
    )


def _run(coro):
    """Run an async coroutine synchronously in a fresh event loop.

    Used by synchronous Hypothesis @given tests to execute async queue operations.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Property 1: FIFO Ordering
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(st.lists(callback_token_st(), min_size=1, max_size=30))
def test_property_fifo_ordering(tokens: List[CallbackToken]) -> None:
    """Property 1: Enqueue N items, dequeue in same order (token_ids match).

    The queue must be strictly FIFO: the first item enqueued must be the first
    item dequeued, preserving insertion order across arbitrary token sequences.
    """
    async def _run_test() -> None:
        # Use a high emergency threshold so no overload is triggered
        queue = InterceptionQueue(emergency_threshold=len(tokens) + 10)

        for token in tokens:
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        dequeued_ids = []
        for _ in tokens:
            t = await queue.dequeue(timeout_ms=500)
            dequeued_ids.append(t.token_id)

        expected_ids = [t.token_id for t in tokens]
        assert dequeued_ids == expected_ids, (
            f"FIFO ordering violated: expected {expected_ids}, got {dequeued_ids}"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 2: Size Consistency
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(
    tokens=st.lists(callback_token_st(), min_size=1, max_size=40),
    dequeue_count=st.integers(min_value=0, max_value=40),
)
def test_property_size_consistency(
    tokens: List[CallbackToken], dequeue_count: int
) -> None:
    """Property 2: After N enqueues and M dequeues (M<=N), size() == N-M.

    The size reported by size() must always equal the number of items
    currently present: enqueues increment it, dequeues decrement it.
    """
    async def _run_test() -> None:
        n = len(tokens)
        m = min(dequeue_count, n)

        queue = InterceptionQueue(emergency_threshold=n + 10)

        for token in tokens:
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        assert queue.size() == n, f"Expected size {n} after {n} enqueues, got {queue.size()}"

        for _ in range(m):
            await queue.dequeue(timeout_ms=500)

        expected_size = n - m
        assert queue.size() == expected_size, (
            f"Expected size {expected_size} after {m} dequeues from {n}, got {queue.size()}"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 3: Flush Empties the Queue
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(st.lists(callback_token_st(), min_size=0, max_size=40))
def test_property_flush_empties_queue(tokens: List[CallbackToken]) -> None:
    """Property 3: After any number of enqueues, flush() results in size() == 0.

    flush() must atomically drain the queue regardless of how many tokens
    have been enqueued prior to calling it.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue(emergency_threshold=len(tokens) + 10)

        for token in tokens:
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        flushed = await queue.flush()

        assert queue.size() == 0, (
            f"Expected size 0 after flush, got {queue.size()}"
        )
        assert len(flushed) == len(tokens), (
            f"Expected flush to return {len(tokens)} items, got {len(flushed)}"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 4: getBatch Never Exceeds max_size
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(
    tokens=st.lists(callback_token_st(), min_size=1, max_size=30),
    max_size=st.integers(min_value=1, max_value=20),
)
def test_property_get_batch_never_exceeds_max_size(
    tokens: List[CallbackToken], max_size: int
) -> None:
    """Property 4: For any queue state, getBatch(max_size, t).items <= max_size.

    getBatch must never return more items than the requested max_size,
    regardless of how many tokens are currently in the queue.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue(emergency_threshold=len(tokens) + 10)

        for token in tokens:
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        # Use a short timeout to avoid waiting; queue already has items
        batch = await queue.getBatch(maxSize=max_size, maxWaitMs=50)

        assert len(batch) <= max_size, (
            f"getBatch returned {len(batch)} items, exceeding max_size={max_size}"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 5: Correlation ID Uniqueness
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(st.lists(callback_token_st(), min_size=1, max_size=50))
def test_property_correlation_id_uniqueness(tokens: List[CallbackToken]) -> None:
    """Property 5: After _assign_correlation_ids, all correlation_ids are unique.

    Each call to _assign_correlation_ids on a batch assigns a new batch UUID
    prefix, and each token within the batch receives a unique positional suffix.
    The resulting correlation_ids must be pairwise unique.
    """
    queue = InterceptionQueue()

    queue._assign_correlation_ids(tokens)

    assigned_ids = [t.correlation_id for t in tokens]

    # All must be assigned (non-None)
    assert all(cid is not None for cid in assigned_ids), (
        "Some tokens were not assigned a correlation_id"
    )

    # All must be unique
    assert len(assigned_ids) == len(set(assigned_ids)), (
        f"Duplicate correlation_ids found in batch of {len(tokens)}: {assigned_ids}"
    )

    # Each must end with its positional index
    for idx, cid in enumerate(assigned_ids):
        assert cid is not None
        assert cid.endswith(f"-{idx}"), (
            f"Token at index {idx} has correlation_id '{cid}', expected suffix '-{idx}'"
        )


# ---------------------------------------------------------------------------
# Property 5b: Correlation ID Uniqueness Across Multiple Batches
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    batch_a=st.lists(callback_token_st(), min_size=1, max_size=20),
    batch_b=st.lists(callback_token_st(), min_size=1, max_size=20),
)
def test_property_correlation_ids_unique_across_batches(
    batch_a: List[CallbackToken], batch_b: List[CallbackToken]
) -> None:
    """Property 5b: Two separate _assign_correlation_ids calls produce non-overlapping IDs.

    Each batch call generates a fresh UUID prefix so IDs from different batches
    must not collide, ensuring cross-batch traceability.
    """
    queue = InterceptionQueue()

    queue._assign_correlation_ids(batch_a)
    queue._assign_correlation_ids(batch_b)

    ids_a = set(t.correlation_id for t in batch_a)
    ids_b = set(t.correlation_id for t in batch_b)

    # Across different batches (different UUID prefix), no overlap is expected
    # (with astronomically high probability given UUID4 uniqueness)
    overlap = ids_a & ids_b
    assert len(overlap) == 0, (
        f"Unexpected correlation_id collision across two batches: {overlap}"
    )


# ---------------------------------------------------------------------------
# Property 6: dequeue on Empty Queue Raises QueueEmptyException
# ---------------------------------------------------------------------------

@settings(max_examples=100, deadline=None)
@given(st.integers(min_value=1, max_value=50))
def test_property_dequeue_empty_raises_exception(timeout_ms: int) -> None:
    """Property 6: dequeue on an empty queue raises QueueEmptyException.

    When the queue contains no items, dequeue must raise QueueEmptyException
    after the specified timeout elapses, regardless of the timeout value.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue()
        with pytest.raises(QueueEmptyException):
            await queue.dequeue(timeout_ms=timeout_ms)

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 6b: dequeue after full drain also raises QueueEmptyException
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(st.lists(callback_token_st(), min_size=1, max_size=15))
def test_property_dequeue_after_drain_raises_exception(
    tokens: List[CallbackToken],
) -> None:
    """Property 6b: After draining all items, further dequeue raises QueueEmptyException.

    Once every enqueued token has been dequeued, the queue is empty and any
    subsequent dequeue must raise QueueEmptyException.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue(emergency_threshold=len(tokens) + 10)

        for token in tokens:
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        # Drain all items
        for _ in tokens:
            await queue.dequeue(timeout_ms=500)

        assert queue.size() == 0

        # Next dequeue must raise
        with pytest.raises(QueueEmptyException):
            await queue.dequeue(timeout_ms=10)

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 7: getBatch Returns Empty List on Empty Queue
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(st.integers(min_value=1, max_value=10))
def test_property_get_batch_empty_queue_returns_empty_list(max_size: int) -> None:
    """Property 7: getBatch on an empty queue returns [] after timeout.

    When there are no items in the queue, getBatch must return an empty list
    rather than blocking indefinitely or raising an exception.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue()
        batch = await queue.getBatch(maxSize=max_size, maxWaitMs=20)
        assert isinstance(batch, list)
        assert len(batch) == 0, (
            f"Expected empty batch from empty queue, got {len(batch)} items"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 8: Size Monotonically Increases During Sequential Enqueues
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(st.lists(callback_token_st(), min_size=2, max_size=20))
def test_property_size_monotonically_increases_during_enqueue(
    tokens: List[CallbackToken],
) -> None:
    """Property 8: size() increases by exactly 1 after each successful enqueue.

    Each enqueue must increment the queue size by exactly 1, so sizes form
    the sequence 0, 1, 2, ..., N for N enqueued tokens.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue(emergency_threshold=len(tokens) + 10)

        for expected_size, token in enumerate(tokens, start=1):
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)
            assert queue.size() == expected_size, (
                f"After enqueue {expected_size}, expected size {expected_size}, "
                f"got {queue.size()}"
            )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 9: QueueOverloadError Raised When Threshold Exceeded
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(st.integers(min_value=1, max_value=10))
def test_property_overload_error_on_threshold_breach(threshold: int) -> None:
    """Property 9: Enqueuing beyond emergency_threshold raises QueueOverloadError.

    When the number of items already in the queue equals the emergency threshold,
    the next enqueue must raise QueueOverloadError and leave the queue empty
    (fail-closed emergency flush).
    """
    async def _run_test() -> None:
        queue = InterceptionQueue(emergency_threshold=threshold)

        # Fill to the threshold without triggering overload
        for i in range(threshold):
            token = CallbackToken(thread_id=f"thread-overload-{i}")
            ctx = ToolCallContext(tool_name="tool", arguments={})
            resume = make_noop_resume()
            await queue.enqueue(token, ctx, resume)

        assert queue.size() == threshold

        # The (threshold+1)th enqueue must trigger the overload
        overflow_token = CallbackToken(thread_id="thread-overflow")
        ctx = ToolCallContext(tool_name="tool", arguments={})
        resume = make_noop_resume()

        with pytest.raises(QueueOverloadError):
            await queue.enqueue(overflow_token, ctx, resume)

        # After emergency flush, queue must be empty
        assert queue.size() == 0, (
            f"Expected empty queue after overload flush, got {queue.size()}"
        )

    _run(_run_test())


# ---------------------------------------------------------------------------
# Property 10: flush() on Empty Queue Returns Empty List and Keeps Size 0
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(st.none())
def test_property_flush_empty_queue_is_idempotent(_: None) -> None:
    """Property 10: flush() on an already-empty queue returns [] and size stays 0.

    Calling flush on an empty queue must be a safe, idempotent no-op.
    """
    async def _run_test() -> None:
        queue = InterceptionQueue()
        assert queue.size() == 0

        flushed = await queue.flush()
        assert flushed == [], f"Expected empty list, got {flushed}"
        assert queue.size() == 0

    _run(_run_test())
