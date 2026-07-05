import asyncio
import pytest
from typing import List, Optional
from hypothesis import given, settings, strategies as st

from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision
from blackwall.interception import (
    InterceptionQueue,
    QueueEmptyException,
    BatchResolutionError,
    QueueOverloadError,
)


class MockResume:
    """Mock callback to track invocations and received verdicts."""

    def __init__(self) -> None:
        self.called_with: Optional[Verdict] = None
        self.call_count: int = 0

    def __call__(self, verdict: Verdict) -> None:
        self.call_count += 1
        self.called_with = verdict


@pytest.mark.asyncio
async def test_enqueue_dequeue_asyncio() -> None:
    """Test standard enqueue and dequeue operations."""
    queue = InterceptionQueue()
    token = CallbackToken(thread_id="thread-1")
    context = ToolCallContext(tool_name="test_tool", arguments={"foo": "bar"})
    resume = MockResume()

    await queue.enqueue(token, context, resume)
    assert queue.size() == 1

    dequeued = await queue.dequeue(timeout_ms=10)
    assert dequeued.token_id == token.token_id
    assert dequeued.tool_context is not None
    assert dequeued.tool_context.tool_name == "test_tool"
    assert dequeued.resumeCallback == resume
    assert queue.size() == 0


@pytest.mark.asyncio
async def test_dequeue_timeout() -> None:
    """Test that dequeue raises QueueEmptyException when timeout expires."""
    queue = InterceptionQueue()
    with pytest.raises(QueueEmptyException):
        await queue.dequeue(timeout_ms=10)


@pytest.mark.asyncio
async def test_batch_accumulation_max_size() -> None:
    """Test that getBatch flushes immediately when maxSize is reached."""
    queue = InterceptionQueue()
    tokens = []
    resumes = []

    for i in range(5):
        token = CallbackToken(thread_id=f"thread-{i}")
        context = ToolCallContext(tool_name=f"tool_{i}", arguments={})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)
        resumes.append(resume)

    batch = await queue.getBatch(maxSize=5, maxWaitMs=5000)
    assert len(batch) == 5
    for i in range(5):
        assert batch[i].token_id == tokens[i].token_id
        correlation_id = batch[i].correlation_id
        assert correlation_id is not None
        # Ensure all correlation IDs share the same batch UUID prefix but unique suffix/index
        assert correlation_id.endswith(f"-{i}")


@pytest.mark.asyncio
async def test_timeout_flushing_partial_batch() -> None:
    """Test that partial batches are flushed when maxWaitMs timeout is reached."""
    queue = InterceptionQueue()
    tokens = []

    for i in range(3):
        token = CallbackToken(thread_id=f"thread-{i}")
        context = ToolCallContext(tool_name=f"tool_{i}", arguments={})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)

    # We wait for maxSize=5, but only 3 are in the queue.
    # It should timeout after maxWaitMs=100 and return the 3 items.
    start_time = asyncio.get_event_loop().time()
    batch = await queue.getBatch(maxSize=5, maxWaitMs=100)
    duration = (asyncio.get_event_loop().time() - start_time) * 1000

    assert len(batch) == 3
    assert duration >= 80  # should be around 100ms
    assert [b.token_id for b in batch] == [t.token_id for t in tokens]


@pytest.mark.asyncio
async def test_verdict_array_mapping_correctness() -> None:
    """Test index-based verdict array mapping correctness."""
    queue = InterceptionQueue()
    tokens = []
    resumes = []

    for i in range(3):
        token = CallbackToken(thread_id=f"thread-{i}")
        context = ToolCallContext(tool_name=f"tool_{i}", arguments={})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)
        resumes.append(resume)

    batch = await queue.getBatch(maxSize=3)
    assert len(batch) == 3

    verdicts = [
        Verdict(
            decision=VerdictDecision.ALLOW, reasoning="Reason 0", confidence_score=0.9
        ),
        Verdict(
            decision=VerdictDecision.BLOCK, reasoning="Reason 1", confidence_score=0.8
        ),
        Verdict(
            decision=VerdictDecision.QUARANTINE,
            reasoning="Reason 2",
            confidence_score=0.7,
        ),
    ]

    await queue.resolveCallbacks(verdicts, batch)

    for i in range(3):
        assert resumes[i].call_count == 1
        called_with = resumes[i].called_with
        assert called_with is not None
        assert called_with.decision == verdicts[i].decision
        assert called_with.reasoning == verdicts[i].reasoning


@pytest.mark.asyncio
async def test_emergency_flushing_exceeds_threshold() -> None:
    """Test emergency flushing triggers fail-closed BLOCK for all enqueued items when threshold is exceeded."""
    # Set threshold to 5 (6th element triggers emergency flush)
    queue = InterceptionQueue(emergency_threshold=5)
    tokens = []
    resumes = []

    for i in range(5):
        token = CallbackToken(thread_id=f"thread-{i}")
        context = ToolCallContext(tool_name=f"tool_{i}", arguments={})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)
        resumes.append(resume)

    assert queue.size() == 5

    # Enqueuing the 6th item should exceed threshold (5) and trigger emergency flush
    sixth_token = CallbackToken(thread_id="thread-5")
    sixth_context = ToolCallContext(tool_name="tool_5", arguments={})
    sixth_resume = MockResume()

    with pytest.raises(QueueOverloadError):
        await queue.enqueue(sixth_token, sixth_context, sixth_resume)

    # Verify queue is now empty
    assert queue.size() == 0

    # Verify all 6 callbacks resolved to BLOCK (fail-closed)
    for resume in resumes:
        assert resume.call_count == 1
        called_with = resume.called_with
        assert called_with is not None
        assert called_with.decision == VerdictDecision.BLOCK
        assert "emergency queue flush" in called_with.reasoning.lower()

    assert sixth_resume.call_count == 1
    sixth_called_with = sixth_resume.called_with
    assert sixth_called_with is not None
    assert sixth_called_with.decision == VerdictDecision.BLOCK


@pytest.mark.asyncio
async def test_array_size_mismatch_rejection() -> None:
    """Test that array size mismatch triggers batch rejection and fail-closed BLOCK."""
    queue = InterceptionQueue()
    tokens = []
    resumes = []

    for i in range(3):
        token = CallbackToken(thread_id=f"thread-{i}")
        context = ToolCallContext(tool_name=f"tool_{i}", arguments={})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)
        resumes.append(resume)

    batch = await queue.getBatch(maxSize=3)

    # We resolve with 2 verdicts instead of 3
    verdicts = [
        Verdict(
            decision=VerdictDecision.ALLOW, reasoning="Reason 0", confidence_score=0.9
        ),
        Verdict(
            decision=VerdictDecision.ALLOW, reasoning="Reason 1", confidence_score=0.9
        ),
    ]

    with pytest.raises(BatchResolutionError):
        await queue.resolveCallbacks(verdicts, batch)

    # Verify all enqueued callbacks in the batch failed closed (BLOCK)
    for resume in resumes:
        assert resume.call_count == 1
        called_with = resume.called_with
        assert called_with is not None
        assert called_with.decision == VerdictDecision.BLOCK
        assert "size mismatch" in called_with.reasoning.lower()


# Property 1: Callback Resolution Completeness using Hypothesis
@given(st.lists(st.text(min_size=1, max_size=10), min_size=1, max_size=100))
@settings(max_examples=30, deadline=None)
@pytest.mark.asyncio
async def test_callback_resolution_completeness_property(thread_ids: List[str]) -> None:
    """Hypothesis test verifying that every enqueued callback is resolved exactly once."""
    queue = InterceptionQueue(emergency_threshold=200)  # prevent emergency flush
    tokens = []
    resumes = []

    for idx, thread_id in enumerate(thread_ids):
        token = CallbackToken(thread_id=thread_id)
        context = ToolCallContext(tool_name=f"tool_{idx}", arguments={"idx": idx})
        resume = MockResume()
        await queue.enqueue(token, context, resume)
        tokens.append(token)
        resumes.append(resume)

    assert queue.size() == len(thread_ids)

    # Process all batches
    while queue.size() > 0:
        batch = await queue.getBatch(maxSize=5, maxWaitMs=10)
        if not batch:
            break

        verdicts = [
            Verdict(
                decision=VerdictDecision.ALLOW,
                reasoning="Batch allow",
                confidence_score=0.9,
            )
            for _ in batch
        ]
        await queue.resolveCallbacks(verdicts, batch)

    # Verify completeness property
    for resume in resumes:
        assert resume.call_count == 1
        called_with = resume.called_with
        assert called_with is not None
        assert called_with.decision == VerdictDecision.ALLOW

    assert queue.size() == 0
