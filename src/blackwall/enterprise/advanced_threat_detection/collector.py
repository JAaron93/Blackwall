"""EventStreamCollector component for Blackwall Advanced Threat Detection (Pillar 6)."""

import asyncio
from datetime import datetime, timezone
import inspect
import logging
from typing import Any, AsyncIterable, AsyncIterator, Callable, Dict, Optional
import uuid

from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent

logger = logging.getLogger("blackwall.enterprise.advanced_threat_detection.collector")



class EventStreamCollector:
    """Unified ingestion collector normalizing telemetry across all five Blackwall pillars."""

    def __init__(
        self,
        reconnect_max_attempts: int = 5,
        reconnect_backoff_base: float = 0.1,
    ) -> None:
        self.reconnect_max_attempts = reconnect_max_attempts
        self.reconnect_backoff_base = reconnect_backoff_base

    def normalize_event(
        self, source: EventSource, raw_event: Dict[str, Any]
    ) -> NormalizedEvent:
        """Normalize heterogeneous raw event into standard NormalizedEvent.

        Enriches event with temporal context, UUID v4 ID, agent metadata, and initial risk score.
        """
        if not isinstance(raw_event, dict):
            raise ValueError(f"Discarding malformed event payload: expected dict, got {type(raw_event)}")

        # Event ID validation or generation
        event_id = raw_event.get("event_id")
        if event_id:
            try:
                parsed = uuid.UUID(str(event_id))
                if parsed.version != 4:
                    event_id = str(uuid.uuid4())
                else:
                    event_id = str(event_id)
            except Exception:
                event_id = str(uuid.uuid4())
        else:
            event_id = str(uuid.uuid4())

        # Timestamp validation or generation
        raw_ts = raw_event.get("timestamp")
        timestamp: datetime
        if isinstance(raw_ts, datetime):
            if raw_ts.tzinfo is None:
                timestamp = raw_ts.replace(tzinfo=timezone.utc)
            else:
                timestamp = raw_ts.astimezone(timezone.utc)
        elif isinstance(raw_ts, str):
            clean_ts = raw_ts.strip().replace("Z", "+00:00")
            try:
                parsed_dt = datetime.fromisoformat(clean_ts)
                if parsed_dt.tzinfo is None:
                    timestamp = parsed_dt.replace(tzinfo=timezone.utc)
                else:
                    timestamp = parsed_dt.astimezone(timezone.utc)
            except Exception as parse_err:
                logger.warning(
                    "Failed to parse string timestamp %r for source %s (%s); falling back to current UTC time",
                    raw_ts,
                    source,
                    parse_err,
                )
                timestamp = datetime.now(timezone.utc)
        elif isinstance(raw_ts, (int, float)):
            timestamp = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

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
        metadata: Dict[str, Any] = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        metadata["ingested_at"] = datetime.now(timezone.utc).isoformat()
        metadata["pillar_source"] = source.value
        if isinstance(raw_ts, str) and "raw_timestamp" not in metadata:
            metadata.setdefault("raw_timestamp", raw_ts)

        # Initial risk score calculation
        if "risk_score" in raw_event and isinstance(raw_event["risk_score"], (int, float)):
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
            if any(k in act_lower for k in ("exec", "socket", "connect", "ptrace", "chmod")):
                return 0.6
            return 0.3
        elif source == EventSource.TOOL_CALL:
            if any(k in act_lower for k in ("exec", "shell", "cmd", "delete", "write")):
                return 0.5
            return 0.2
        elif source == EventSource.IDENTITY_ACCESS:
            if any(k in act_lower for k in ("token", "secret", "grant", "sudo", "privilege")):
                return 0.7
            return 0.3
        elif source == EventSource.PIPELINE_EXECUTION:
            return 0.4
        return 0.2

    async def _process_stream(
        self, source: EventSource, source_stream: Optional[AsyncIterable[Dict[str, Any]]]
    ) -> AsyncIterator[NormalizedEvent]:
        """Internal helper to iterate and normalize raw events from stream."""
        if source_stream is None:
            return

        async for raw_item in source_stream:
            if not isinstance(raw_item, dict):
                logger.warning(f"Discarding malformed event payload: expected dict, got {type(raw_item)}")
                continue
            try:
                normalized = self.normalize_event(source, raw_item)
                yield normalized
            except (ValueError, ValidationError) as exc:
                logger.warning(f"Validation error normalizing event from {source}: {exc}")
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
                        f"Pillar stream {source} failed after {attempt} attempts: {exc}"
                    )
                    raise
                backoff = self.reconnect_backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    f"Pillar stream {source} lost ({exc}). Retrying attempt {attempt}/{self.reconnect_max_attempts} in {backoff:.2f}s..."
                )
                await asyncio.sleep(backoff)



    async def collect_from_kernel(
        self, source_stream: Optional[AsyncIterable[Dict[str, Any]]] = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 1: Kernel eBPF/Audit hooks."""
        async for ev in self._process_stream(EventSource.KERNEL_SYSCALL, source_stream):
            yield ev

    async def collect_from_tool_intercepts(
        self, source_stream: Optional[AsyncIterable[Dict[str, Any]]] = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from ADK tool call interceptions."""
        async for ev in self._process_stream(EventSource.TOOL_CALL, source_stream):
            yield ev

    async def collect_from_identity(
        self, source_stream: Optional[AsyncIterable[Dict[str, Any]]] = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 3: Identity Sidecar."""
        async for ev in self._process_stream(EventSource.IDENTITY_ACCESS, source_stream):
            yield ev

    async def collect_from_pipeline(
        self, source_stream: Optional[AsyncIterable[Dict[str, Any]]] = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 4: Pipeline Wrappers."""
        async for ev in self._process_stream(EventSource.PIPELINE_EXECUTION, source_stream):
            yield ev

    async def collect_from_forensics(
        self, source_stream: Optional[AsyncIterable[Dict[str, Any]]] = None
    ) -> AsyncIterator[NormalizedEvent]:
        """Stream events from Pillar 5: Forensic Triage Engine."""
        async for ev in self._process_stream(EventSource.FORENSIC_ALERT, source_stream):
            yield ev
