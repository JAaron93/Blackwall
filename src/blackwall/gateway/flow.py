"""
Flow Control and In-Flight Request Tracking for Blackwall MCP Gateway.

Manages paused tool requests awaiting verdict resolution, enforces concurrent
request isolation by JSON-RPC ID, queue bounds, and deterministic timeouts.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from blackwall.gateway.exceptions import (
    DuplicateRequestIdError,
    QueueOverflowError,
)
from blackwall.gateway.synthesizer import ResponseSynthesizer

logger = logging.getLogger(__name__)


@dataclass
class InFlightRequest:
    """Represents a paused or in-flight JSON-RPC request."""

    request_id: Any
    method: str
    params: dict[str, Any]
    created_at: float
    future: asyncio.Future[dict[str, Any]]


class FlowController:
    """
    Flow controller and request tracker for MCP protocol streams.

    Invariants:
    - In-flight requests are tracked deterministically by their JSON-RPC `id`.
    - Max queue size is strictly enforced to prevent memory exhaustion (QueueOverflowError).
    - Request timeouts synthesize standard JSON-RPC -32000 error responses.
    - Non-tool methods (initialize, tools/list, notifications/*) are passed through without holding.
    - Abandoned requests are cleaned up deterministically.
    """

    PASSTHROUGH_METHODS = frozenset(
        {
            "initialize",
            "tools/list",
            "ping",
            "prompts/list",
            "resources/list",
            "resources/templates/list",
        }
    )

    def __init__(
        self,
        max_queue_size: int = 1000,
        request_timeout: float = 30.0,
        synthesizer: ResponseSynthesizer | None = None,
    ) -> None:
        self.max_queue_size = max_queue_size
        self.request_timeout = request_timeout
        self.synthesizer = synthesizer or ResponseSynthesizer()
        self._in_flight: dict[Any, InFlightRequest] = {}

    @property
    def active_count(self) -> int:
        """Returns the number of currently in-flight requests."""
        return len(self._in_flight)

    def has_in_flight(self, request_id: Any) -> bool:
        """Checks whether a request ID is currently tracked in-flight."""
        return request_id in self._in_flight

    def is_tool_call(self, method: str) -> bool:
        """Determines if a method invocation targets tool execution."""
        return method == "tools/call"

    def is_passthrough(self, method: str) -> bool:
        """
        Determines if a method is a non-tool protocol method that should pass
        through immediately without queuing or security gating.
        """
        if method in self.PASSTHROUGH_METHODS:
            return True
        if method.startswith("notifications/"):
            return True
        return False

    async def hold_request(
        self,
        request_id: Any,
        method: str,
        params: dict[str, Any],
    ) -> asyncio.Future[dict[str, Any]]:
        """
        Pauses an incoming tools/call request by allocating an in-flight future.

        Args:
            request_id: JSON-RPC request identifier.
            method: JSON-RPC method name.
            params: Parameters dictionary.

        Returns:
            An asyncio.Future resolving to the JSON-RPC response dictionary.

        Raises:
            QueueOverflowError: When max_queue_size is exceeded.
        """
        if len(self._in_flight) >= self.max_queue_size:
            logger.warning(
                "FlowController queue overflow: %d >= %d. Rejecting request_id=%s",
                len(self._in_flight),
                self.max_queue_size,
                request_id,
            )
            raise QueueOverflowError(
                f"Server queue overflow: active in-flight requests ({len(self._in_flight)}) "
                f"exceed max capacity ({self.max_queue_size})"
            )

        if request_id in self._in_flight:
            existing = self._in_flight[request_id]
            if not existing.future.done():
                logger.warning(
                    "FlowController duplicate request ID rejected: %s is already in flight",
                    request_id,
                )
                raise DuplicateRequestIdError(
                    f"Duplicate request id already in flight: {request_id}"
                )

        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()

        record = InFlightRequest(
            request_id=request_id,
            method=method,
            params=params,
            created_at=time.monotonic(),
            future=future,
        )
        self._in_flight[request_id] = record

        logger.debug(
            "Held request_id=%s (%s), active_in_flight=%d",
            request_id,
            method,
            len(self._in_flight),
        )
        return future

    async def wait_for_verdict(
        self,
        request_id: Any,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """
        Awaits verdict resolution for a held request with timeout and cancellation protection.

        Args:
            request_id: JSON-RPC request identifier.
            timeout: Optional override for request timeout in seconds.

        Returns:
            JSON-RPC response dictionary.
        """
        record = self._in_flight.get(request_id)
        if not record:
            return self.synthesizer.synthesize_error(
                code=-32603,
                message=f"Request {request_id} not found in in-flight queue",
                request_id=request_id,
            )

        effective_timeout = timeout if timeout is not None else self.request_timeout

        try:
            return await asyncio.wait_for(
                asyncio.shield(record.future),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Request_id=%s timed out after %.2fs awaiting security verdict",
                request_id,
                effective_timeout,
            )
            if not record.future.done():
                record.future.cancel()
            return self.synthesizer.synthesize_error(
                code=-32000,
                message=f"Request {request_id} timed out awaiting security verdict",
                request_id=request_id,
            )
        except asyncio.CancelledError:
            logger.info("Request_id=%s was cancelled by client", request_id)
            return self.synthesizer.synthesize_error(
                code=-32000,
                message=f"Request {request_id} was cancelled",
                request_id=request_id,
            )
        finally:
            self._in_flight.pop(request_id, None)

    def resolve_request(
        self,
        request_id: Any,
        response: dict[str, Any],
    ) -> bool:
        """
        Resolves a held request with the provided JSON-RPC response.

        Args:
            request_id: Identifier of the request to resolve.
            response: Full JSON-RPC response dictionary to deliver.

        Returns:
            True if request was found and resolved; False otherwise.
        """
        record = self._in_flight.get(request_id)
        if not record:
            logger.debug("Attempted to resolve untracked request_id=%s", request_id)
            return False

        if not record.future.done():
            record.future.set_result(response)
            logger.debug("Resolved request_id=%s", request_id)
            return True
        return False

    def cancel_request(
        self,
        request_id: Any,
        reason: str = "Request cancelled",
    ) -> bool:
        """
        Cancels a held request, delivering a synthesized cancellation error.

        Args:
            request_id: Identifier of the request to cancel.
            reason: Cancellation explanation message.

        Returns:
            True if cancelled; False if request was not found.
        """
        record = self._in_flight.get(request_id)
        if not record:
            return False

        if not record.future.done():
            error_response = self.synthesizer.synthesize_error(
                code=-32000,
                message=f"Request {request_id} was cancelled: {reason}",
                request_id=request_id,
            )
            record.future.set_result(error_response)
            return True
        return False

    def cleanup_abandoned(
        self,
        max_age_seconds: float | None = None,
    ) -> int:
        """
        Deterministically cleans up abandoned or stale in-flight requests.

        Args:
            max_age_seconds: Maximum age before a request is declared abandoned.
                             Defaults to 2x request_timeout.

        Returns:
            Count of cleaned-up requests.
        """
        limit = max_age_seconds if max_age_seconds is not None else (self.request_timeout * 2.0)
        now = time.monotonic()
        to_clean = [
            req_id
            for req_id, req in self._in_flight.items()
            if (now - req.created_at) > limit
        ]

        for req_id in to_clean:
            logger.warning("Cleaning up abandoned request_id=%s", req_id)
            record = self._in_flight.pop(req_id, None)
            if record and not record.future.done():
                error_response = self.synthesizer.synthesize_error(
                    code=-32000,
                    message=f"Request {req_id} was abandoned and cleaned up",
                    request_id=req_id,
                )
                record.future.set_result(error_response)

        return len(to_clean)
