import asyncio
import logging
from typing import Any, Callable, List, Optional, Set
from uuid import UUID, uuid4

from blackwall.models import CallbackToken, ToolCallContext, Verdict, VerdictDecision

logger = logging.getLogger("blackwall.interception")


class QueueEmptyException(Exception):
    """Raised when attempting to dequeue from an empty queue or on timeout."""

    pass


class BatchResolutionError(Exception):
    """Raised when there is an error resolving a batch, such as size mismatch."""

    pass


class QueueOverloadError(Exception):
    """Raised when the queue exceeds its maximum capacity (emergency threshold)."""

    pass


class InterceptionQueue:
    """Thread-safe FIFO queue that holds suspended ADK tool callbacks during batch accumulation."""

    def __init__(self, emergency_threshold: int = 50) -> None:
        self._queue: asyncio.Queue[CallbackToken] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._emergency_threshold = emergency_threshold
        self._resolved_tokens: Set[UUID] = set()

    async def enqueue(
        self,
        token: CallbackToken,
        context: ToolCallContext,
        resume_func: Callable[[Verdict], Any],
    ) -> None:
        """Suspends the execution flow by enqueuing the CallbackToken and its context."""
        from blackwall.telemetry import get_metric
        interceptions_metric = get_metric("interceptions_total")
        if interceptions_metric:
            interceptions_metric.add(1)

        # Set context and resume callback on the token
        token.tool_context = context
        token.resumeCallback = resume_func

        callbacks_to_invoke = []
        async with self._lock:
            # Check if queue size exceeds emergency threshold
            if self._queue.qsize() >= self._emergency_threshold:
                logger.warning(
                    "Queue size exceeds emergency threshold. Triggering fail-closed emergency flush.",
                    extra={
                        "qsize": self._queue.qsize(),
                        "threshold": self._emergency_threshold,
                    },
                )
                # Flush the queue
                flushed_tokens = await self._flush_internal()

                # Fail-closed: reject all flushed callbacks
                block_verdict = Verdict(
                    decision=VerdictDecision.BLOCK,
                    reasoning="Emergency queue flush due to queue size limit exceeded",
                    confidence_score=1.0,
                )

                for ft in flushed_tokens:
                    callback = self._resolve_single_under_lock(ft, block_verdict)
                    if callback:
                        callbacks_to_invoke.append(
                            (callback, block_verdict, ft.token_id)
                        )

                # Reject the current token too
                callback = self._resolve_single_under_lock(token, block_verdict)
                if callback:
                    callbacks_to_invoke.append(
                        (callback, block_verdict, token.token_id)
                    )

        # Release lock before invoking callbacks
        if callbacks_to_invoke:
            for callback, verdict, token_id in callbacks_to_invoke:
                try:
                    callback(verdict)
                except Exception:
                    logger.error(
                        "Error invoking resume callback for token",
                        exc_info=True,
                        extra={"token_id": token_id},
                    )
            raise QueueOverloadError("Queue overloaded; emergency flush triggered.")

        await self._queue.put(token)
        logger.debug(
            "Enqueued callback token",
            extra={"token_id": token.token_id, "qsize": self._queue.qsize()},
        )

    async def dequeue(self, timeout_ms: float) -> CallbackToken:
        """Retrieves a single CallbackToken from the queue, waiting up to timeout_ms."""
        try:
            timeout_sec = timeout_ms / 1000.0
            # We do NOT hold self._lock while waiting, to prevent deadlocking enqueues
            token = await asyncio.wait_for(self._queue.get(), timeout=timeout_sec)
            self._queue.task_done()
            return token
        except asyncio.TimeoutError:
            raise QueueEmptyException("Queue is empty (timeout)")

    async def getBatch(
        self, maxSize: int = 5, maxWaitMs: float = 100
    ) -> List[CallbackToken]:
        """Accumulates up to maxSize items or waits at most maxWaitMs (partial batch)."""
        # Block until at least one item is available, respecting maxWaitMs
        try:
            timeout_sec = maxWaitMs / 1000.0
            first_token = await asyncio.wait_for(self._queue.get(), timeout=timeout_sec)
            self._queue.task_done()
        except asyncio.TimeoutError:
            return []
        except Exception as e:
            logger.error(f"Error waiting for first queue item: {e}")
            return []

        batch = [first_token]

        if len(batch) >= maxSize:
            self._assign_correlation_ids(batch)
            return batch

        # Define the timeout task
        async def wait_timeout() -> None:
            await asyncio.sleep(maxWaitMs / 1000.0)

        timeout_task = asyncio.create_task(wait_timeout())

        try:
            while len(batch) < maxSize and not timeout_task.done():
                try:
                    # Non-blocking check if queue has items
                    async with self._lock:
                        if self._queue.empty():
                            is_empty = True
                        else:
                            is_empty = False

                    if is_empty:
                        # Wait for next item or timeout
                        get_task = asyncio.create_task(self._queue.get())
                        done, pending = await asyncio.wait(
                            {get_task, timeout_task},
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if get_task in done:
                            token = get_task.result()
                            batch.append(token)
                            self._queue.task_done()
                        else:
                            get_task.cancel()
                            break
                    else:
                        # Immediately get without waiting
                        token = self._queue.get_nowait()
                        batch.append(token)
                        self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in getBatch loop: {e}")
                    break
        finally:
            if not timeout_task.done():
                timeout_task.cancel()
                try:
                    await timeout_task
                except asyncio.CancelledError:
                    pass

        self._assign_correlation_ids(batch)
        return batch

    def _assign_correlation_ids(self, batch: List[CallbackToken]) -> None:
        """Assigns correlation IDs to all tokens in the batch linking to their batch position."""
        batch_id = uuid4()
        for idx, token in enumerate(batch):
            token.correlation_id = f"{batch_id}-{idx}"

    async def flush(self) -> List[CallbackToken]:
        """Manually triggers emergency flushing, pulling all items from the queue."""
        async with self._lock:
            return await self._flush_internal()

    async def _flush_internal(self) -> List[CallbackToken]:
        """Internal helper to flush all items. Must be called under lock."""
        flushed = []
        while not self._queue.empty():
            try:
                token = self._queue.get_nowait()
                flushed.append(token)
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break
        return flushed

    async def resolveCallbacks(
        self, verdicts: List[Verdict], batch: List[CallbackToken]
    ) -> None:
        """Resolves enqueued callbacks by mapping the verdict array to the batch by index."""
        callbacks_to_invoke = []
        error_to_raise = None
        
        from blackwall.telemetry import get_metric
        verdicts_metric = get_metric("verdicts_total")

        async with self._lock:
            if len(verdicts) != len(batch):
                logger.error(
                    "Verdict array size mismatch during batch resolution. Rejecting batch.",
                    extra={"verdicts_size": len(verdicts), "batch_size": len(batch)},
                )
                # Fail-closed: resolve all batch items with BLOCK
                block_verdict = Verdict(
                    decision=VerdictDecision.BLOCK,
                    reasoning="Batch resolution rejected due to size mismatch",
                    confidence_score=1.0,
                )
                for token in batch:
                    callback = self._resolve_single_under_lock(token, block_verdict)
                    if callback:
                        callbacks_to_invoke.append(
                            (callback, block_verdict, token.token_id)
                        )
                error_to_raise = BatchResolutionError(
                    "Verdict array size does not match batch size."
                )
            else:
                for token, verdict in zip(batch, verdicts):
                    callback = self._resolve_single_under_lock(token, verdict)
                    if callback:
                        callbacks_to_invoke.append((callback, verdict, token.token_id))

        # Invoke callbacks outside the lock
        for callback, verdict, token_id in callbacks_to_invoke:
            if verdicts_metric:
                verdicts_metric.add(1, {"decision": verdict.decision.value})
            
            try:
                callback(verdict)
            except Exception:
                logger.error(
                    "Error invoking resume callback for token",
                    exc_info=True,
                    extra={"token_id": token_id},
                )

        if error_to_raise:
            raise error_to_raise

    def _resolve_single_under_lock(
        self, token: CallbackToken, verdict: Verdict
    ) -> Optional[Callable[[Verdict], Any]]:
        """Marks a single CallbackToken as resolved and returns the callback to invoke outside the lock."""
        if token.token_id in self._resolved_tokens:
            logger.debug(
                "Token already resolved, skipping duplicate resolution",
                extra={"token_id": token.token_id},
            )
            return None

        self._resolved_tokens.add(token.token_id)
        return token.resumeCallback

    def size(self) -> int:
        """Returns the current size of the queue."""
        return self._queue.qsize()
