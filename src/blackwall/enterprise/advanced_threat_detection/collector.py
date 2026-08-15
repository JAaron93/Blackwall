"""EventStreamCollector component for Blackwall Advanced Threat Detection (Pillar 6)."""

import asyncio
import inspect
import logging
from collections.abc import AsyncIterable, AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent
from blackwall.validators import ensure_uuid_v4, utc_now

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.collector")


class EventStreamCollector:
    """Collector component normalizing heterogeneous event streams from all five Blackwall pillars."""

    def __init__(
        self,
        reconnect_max_attempts: int = 5,
        reconnect_backoff_base: float = 0.1,
    ) -> None:
        self.reconnect_max_attempts = reconnect_max_attempts
        self.reconnect_backoff_base = reconnect_backoff_base
        self.stream_subscriptions: dict[
            EventSource, Callable[[], AsyncIterator[dict[str, Any]]]
        ] = {}

    def normalize_event(
        self, source: EventSource, raw_event: dict[str, Any]
    ) -> NormalizedEvent:
        """Normalize heterogeneous raw event into standard NormalizedEvent.

        Enriches event with temporal context, UUID v4 ID, agent metadata, and initial risk score.
        """
        if not isinstance(raw_event, dict):
            raise ValueError(
                f"Discarding malformed event payload: expected dict, got {type(raw_event)}"
            )

        # Event ID validation or generation using centralized helper
        event_id = ensure_uuid_v4(raw_event.get("event_id"))

        # Timestamp validation or generation
        raw_ts = raw_event.get("timestamp")
        timestamp: datetime
        if isinstance(raw_ts, datetime):
            if raw_ts.tzinfo is None:
                logger.warning(
                    "Naive datetime %r provided for source %s; falling back to current UTC time",
                    raw_ts,
                    source,
                )
                timestamp = utc_now()
            else:
                timestamp = raw_ts.astimezone(UTC)
        elif isinstance(raw_ts, str):
            clean_ts = raw_ts.strip().replace("Z", "+00:00")
            try:
                parsed_dt = datetime.fromisoformat(clean_ts)
                if parsed_dt.tzinfo is None:
                    logger.warning(
                        "Timezone-less ISO string timestamp %r provided for source %s; falling back to current UTC time",
                        raw_ts,
                        source,
                    )
                    timestamp = utc_now()
                else:
                    timestamp = parsed_dt.astimezone(UTC)
            except Exception as parse_err:
                logger.warning(
                    "Failed to parse string timestamp %r for source %s (%s); falling back to current UTC time",
                    raw_ts,
                    source,
                    parse_err,
                )
                timestamp = utc_now()
        elif isinstance(raw_ts, (int, float)):
            timestamp = datetime.fromtimestamp(raw_ts, tz=UTC)
        else:
            timestamp = utc_now()

        # Agent ID extraction (explicit None check to preserve falsy non-empty IDs like 0)
        raw_agent_id = raw_event.get("agent_id")
        if raw_agent_id is None:
            raw_agent_id = raw_event.get("agent")
        if raw_agent_id is None:
            raw_agent_id = ""
        agent_id = str(raw_agent_id).strip()
        if not agent_id:
            raise ValueError("agent_id must not be empty")

        # Action & Target extraction
        action = str(
            raw_event.get("action")
            or raw_event.get("event_type")
            or raw_event.get("syscall")
            or raw_event.get("tool_name")
            or "unknown_action"
        ).strip()

        target = str(
            raw_event.get("target")
            or raw_event.get("resource")
            or raw_event.get("path")
            or raw_event.get("endpoint")
            or "unknown_target"
        ).strip()

        # Metadata enrichment
        raw_metadata = raw_event.get("metadata")
        metadata: dict[str, Any] = (
            dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        )
        metadata["ingested_at"] = datetime.now(UTC).isoformat()
        metadata["pillar_source"] = source.value
        if isinstance(raw_ts, (str, datetime)) and "raw_timestamp" not in metadata:
            metadata.setdefault("raw_timestamp", str(raw_ts))

        # Initial risk score calculation
        if "risk_score" in raw_event and isinstance(
            raw_event["risk_score"], (int, float)
        ):
            risk_score = float(raw_event["risk_score"])
            risk_score = max(0.0, min(1.0, risk_score))
        else:
            risk_score = self._compute_initial_risk_score(source, action)

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            agent_id=agent_id,
            action=action,
            target=target,
            metadata=metadata,
            risk_score=risk_score,
        )

    def _compute_initial_risk_score(self, source: EventSource, action: str) -> float:
        """Compute heuristic initial risk score in [0.0, 1.0]."""
        act_lower = action.lower()
        if source == EventSource.FORENSIC_ALERT:
            return 0.8
        elif source == EventSource.KERNEL_SYSCALL:
            if any(
                k in act_lower for k in ("exec", "socket", "connect", "ptrace", "chmod")
            ):
                return 0.6
            return 0.3
        elif source == EventSource.TOOL_CALL:
            if any(k in act_lower for k in ("exec", "shell", "cmd", "delete", "write")):
                return 0.5
            return 0.2
        elif source == EventSource.IDENTITY_ACCESS:
            if any(
                k in act_lower
                for k in ("token", "secret", "grant", "sudo", "privilege")
            ):
                return 0.7
            return 0.3
        elif source == EventSource.PIPELINE_EXECUTION:
            return 0.4
        return 0.2

    async def _process_stream(
        self,
        source: EventSource,
        source_stream: AsyncIterable[dict[str, Any]] | None,
    ) -> AsyncIterator[NormalizedEvent]:
        """Internal helper to iterate and normalize raw events from stream."""
        if source_stream is None:
            return

        async for raw_item in source_stream:
            if not isinstance(raw_item, dict):
                logger.warning(
                    "Discarding malformed event payload for source %s: expected dict, got %s",
                    source,
                    type(raw_item),
                )
                continue
            try:
                normalized = self.normalize_event(source, raw_item)
                yield normalized
            except (ValueError, ValidationError) as exc:
                logger.warning(
                    "Validation error normalizing event from %s: %s",
                    source,
                    exc,
                )
                continue

    async def collect_with_reconnect(
        self,
        source: EventSource,
        stream_factory: Callable[[], Any],
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events with exponential backoff reconnection on failure."""
        if not callable(stream_factory):
            raise ValueError(
                "stream_factory must be a callable returning a fresh AsyncIterable to support reconnection"
            )

        attempt = 0
        while attempt <= self.reconnect_max_attempts:
            try:
                stream = stream_factory()
                if inspect.iscoroutine(stream):
                    stream = await stream
                if not hasattr(stream, "__aiter__"):
                    raise TypeError(
                        f"stream_factory returned non-AsyncIterable object of type {type(stream).__name__}"
                    )
                async for normalized in self._process_stream(source, stream):
                    yield normalized
                break  # Completed stream successfully
            except (TypeError, ValueError):
                # Fail fast on deterministic programming/configuration errors
                raise
            except Exception as exc:
                attempt += 1
                if attempt > self.reconnect_max_attempts:
                    logger.error(
                        "Pillar stream %s failed after %d attempts: %s",
                        source,
                        attempt,
                        exc,
                    )
                    raise
                backoff = self.reconnect_backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    "Pillar stream %s lost (%s). Retrying attempt %d/%d in %.2fs...",
                    source,
                    exc,
                    attempt,
                    self.reconnect_max_attempts,
                    backoff,
                )
                await asyncio.sleep(backoff)

    async def collect_all_streams(
        self,
        stream_factories: dict[EventSource, Callable[[], Any]],
    ) -> AsyncIterator[NormalizedEvent]:
        """Collect events concurrently from multiple pillar streams with fault isolation.

        If any individual pillar stream fails or disconnects permanently, logging diagnostics
        are emitted and collection continues uninterrupted for all surviving pillars.
        """
        if not stream_factories:
            return

        queue: asyncio.Queue[NormalizedEvent | object] = asyncio.Queue()
        sentinel = object()
        active_streams = len(stream_factories)

        async def _stream_worker(src: EventSource, factory: Callable[[], Any]) -> None:
            nonlocal active_streams
            try:
                async for event in self.collect_with_reconnect(src, factory):
                    await queue.put(event)
            except Exception as exc:
                logger.error(
                    "Pillar stream %s terminated with unrecoverable error: %s",
                    src,
                    exc,
                )
            finally:
                active_streams -= 1
                if active_streams == 0:
                    await queue.put(sentinel)

        tasks = [
            asyncio.create_task(_stream_worker(src, factory))
            for src, factory in stream_factories.items()
        ]

        try:
            while True:
                item = await queue.get()
                if item is sentinel:
                    break
                if isinstance(item, NormalizedEvent):
                    yield item
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    def process_event_batch(
        self, source: EventSource, raw_events: list[dict[str, Any]]
    ) -> list[NormalizedEvent]:
        """Normalize a batch of heterogeneous raw events synchronously for high throughput.

        Args:
            source: EventSource indicating the pillar source.
            raw_events: List of raw event dictionary payloads.

        Returns:
            List of successfully normalized NormalizedEvent instances.
        """
        normalized_events: list[NormalizedEvent] = []
        for raw_item in raw_events:
            if not isinstance(raw_item, dict):
                logger.warning(
                    "Discarding malformed event payload in batch for source %s: expected dict, got %s",
                    source,
                    type(raw_item),
                )
                continue
            try:
                normalized = self.normalize_event(source, raw_item)
                normalized_events.append(normalized)
            except (ValueError, ValidationError) as exc:
                logger.warning(
                    "Validation error normalizing event in batch from %s: %s",
                    source,
                    exc,
                )
                continue
        return normalized_events

    async def collect_and_store_batch(
        self,
        store: Any,
        source: EventSource,
        raw_events: list[dict[str, Any]],
    ) -> list[Any]:
        """Normalize a batch of events and persist them into AttackGraphStore using batch insertion."""
        normalized = self.process_event_batch(source, raw_events)
        if hasattr(store, "insert_events_batch"):
            return await store.insert_events_batch(normalized)
        nodes = []
        for ev in normalized:
            node = await store.insert_event(ev)
            nodes.append(node)
        return nodes

    async def collect_from_kernel(
        self, source_stream: AsyncIterable[dict[str, Any]] | None = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 1: Kernel eBPF/Audit hooks."""
        async for ev in self._process_stream(EventSource.KERNEL_SYSCALL, source_stream):
            yield ev

    async def collect_from_tool_intercepts(
        self, source_stream: AsyncIterable[dict[str, Any]] | None = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from ADK tool call interceptions."""
        async for ev in self._process_stream(EventSource.TOOL_CALL, source_stream):
            yield ev

    async def collect_from_identity(
        self, source_stream: AsyncIterable[dict[str, Any]] | None = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 3: Identity Sidecar."""
        async for ev in self._process_stream(
            EventSource.IDENTITY_ACCESS, source_stream
        ):
            yield ev

    async def collect_from_pipeline(
        self, source_stream: AsyncIterable[dict[str, Any]] | None = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 4: Pipeline Wrappers."""
        async for ev in self._process_stream(
            EventSource.PIPELINE_EXECUTION, source_stream
        ):
            yield ev

    async def collect_from_forensics(
        self, source_stream: AsyncIterable[dict[str, Any]] | None = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 5: Forensic Triage Engine."""
        async for ev in self._process_stream(EventSource.FORENSIC_ALERT, source_stream):
            yield ev

