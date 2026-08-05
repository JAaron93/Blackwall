"""Unit tests for EventStreamCollector (Task 4)."""

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from typing import Any

import pytest

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent


async def sample_stream(events: list[dict[str, Any]]) -> AsyncIterator[dict[str, Any]]:
    for event in events:
        yield event


@pytest.mark.asyncio
async def test_pillar_subscriptions():
    """Requirement 1.1 - 1.5, 12.1 - 12.6: Test subscribing to all 5 pillar event sources."""
    collector = EventStreamCollector()

    raw_kernel = [{"action": "execve", "target": "/bin/bash", "agent_id": "agent-k1"}]
    raw_tool = [{"action": "call_tool", "target": "shell_exec", "agent_id": "agent-t1"}]
    raw_identity = [
        {"action": "access_token", "target": "vault_secret", "agent_id": "agent-i1"}
    ]
    raw_pipeline = [
        {"action": "pipeline_run", "target": "eval_dataset", "agent_id": "agent-p1"}
    ]
    raw_forensic = [
        {"action": "anomaly_alert", "target": "log_stream", "agent_id": "agent-f1"}
    ]

    kernel_events = [
        ev async for ev in collector.collect_from_kernel(sample_stream(raw_kernel))
    ]
    assert len(kernel_events) == 1
    assert kernel_events[0].source == EventSource.KERNEL_SYSCALL
    assert kernel_events[0].agent_id == "agent-k1"

    tool_events = [
        ev
        async for ev in collector.collect_from_tool_intercepts(sample_stream(raw_tool))
    ]
    assert len(tool_events) == 1
    assert tool_events[0].source == EventSource.TOOL_CALL
    assert tool_events[0].agent_id == "agent-t1"

    identity_events = [
        ev async for ev in collector.collect_from_identity(sample_stream(raw_identity))
    ]
    assert len(identity_events) == 1
    assert identity_events[0].source == EventSource.IDENTITY_ACCESS
    assert identity_events[0].agent_id == "agent-i1"

    pipeline_events = [
        ev async for ev in collector.collect_from_pipeline(sample_stream(raw_pipeline))
    ]
    assert len(pipeline_events) == 1
    assert pipeline_events[0].source == EventSource.PIPELINE_EXECUTION
    assert pipeline_events[0].agent_id == "agent-p1"

    forensic_events = [
        ev async for ev in collector.collect_from_forensics(sample_stream(raw_forensic))
    ]
    assert len(forensic_events) == 1
    assert forensic_events[0].source == EventSource.FORENSIC_ALERT
    assert forensic_events[0].agent_id == "agent-f1"


@pytest.mark.asyncio
async def test_normalization():
    """Requirement 1.6 - 1.9: Test normalization, enrichment, UUID v4, UTC timestamp, risk score."""
    collector = EventStreamCollector()

    raw_event = {
        "agent_id": "agent-norm-01",
        "action": "network_connect",
        "target": "192.168.1.100:8080",
        "metadata": {"protocol": "tcp", "bytes": 1024},
    }

    norm = collector.normalize_event(EventSource.KERNEL_SYSCALL, raw_event)

    assert isinstance(norm, NormalizedEvent)

    # UUID v4 check
    parsed_uuid = uuid.UUID(norm.event_id)
    assert parsed_uuid.version == 4

    # UTC timestamp check
    assert norm.timestamp.tzinfo is not None
    assert norm.timestamp.utcoffset() == UTC.utcoffset(norm.timestamp)

    # Metadata enrichment check
    assert norm.agent_id == "agent-norm-01"
    assert norm.action == "network_connect"
    assert norm.target == "192.168.1.100:8080"
    assert norm.metadata["protocol"] == "tcp"
    assert "ingested_at" in norm.metadata

    # Risk score check [0.0, 1.0]
    assert 0.0 <= norm.risk_score <= 1.0


@pytest.mark.asyncio
async def test_error_handling(caplog):
    """Error Handling: Malformed events, schema failures logged & skipped, reconnection with backoff."""
    collector = EventStreamCollector(
        reconnect_max_attempts=2, reconnect_backoff_base=0.01
    )

    raw_events = [
        {"agent_id": "agent-valid-1", "action": "read", "target": "/etc/hosts"},
        "not_a_dict_malformed",  # Malformed event
        {
            "agent_id": "",
            "action": "write",
            "target": "/tmp/test",
        },  # Invalid empty agent_id
        {"agent_id": "agent-valid-2", "action": "write", "target": "/etc/passwd"},
    ]

    with caplog.at_level(logging.WARNING):
        events = [
            ev async for ev in collector.collect_from_kernel(sample_stream(raw_events))
        ]

    # Malformed & schema invalid events should be skipped without halting
    assert len(events) == 2
    assert events[0].agent_id == "agent-valid-1"
    assert events[1].agent_id == "agent-valid-2"

    # Warnings should be logged
    assert any(
        "Discarding malformed event payload" in rec.message
        or "Validation error" in rec.message
        for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_reconnection_backoff():
    """Error Handling: Reconnection logic with exponential backoff on stream failure."""
    collector = EventStreamCollector(
        reconnect_max_attempts=2, reconnect_backoff_base=0.01
    )

    attempts = 0

    async def flaky_stream_factory():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            yield {"agent_id": "agent-before", "action": "act1", "target": "t1"}
            raise ConnectionError("Stream dropped")
        else:
            yield {"agent_id": "agent-after", "action": "act2", "target": "t2"}

    events = [
        ev
        async for ev in collector.collect_with_reconnect(
            EventSource.TOOL_CALL, flaky_stream_factory
        )
    ]

    assert len(events) == 2
    assert events[0].agent_id == "agent-before"
    assert events[1].agent_id == "agent-after"
    assert attempts == 2


@pytest.mark.asyncio
async def test_falsy_agent_id():
    """Bug fix: Falsy agent_id like 0 should be preserved as '0' rather than dropped as empty."""
    collector = EventStreamCollector()
    raw = {"agent_id": 0, "action": "read", "target": "/etc/hosts"}
    norm = collector.normalize_event(EventSource.KERNEL_SYSCALL, raw)
    assert norm.agent_id == "0"


@pytest.mark.asyncio
async def test_invalid_string_timestamp_logging(caplog):
    """Bug fix: Invalid string timestamp should log warning and record raw_timestamp in metadata."""
    collector = EventStreamCollector()
    raw = {
        "agent_id": "agent-ts-1",
        "action": "read",
        "target": "/etc/hosts",
        "timestamp": "invalid-iso-format",
    }
    with caplog.at_level(logging.WARNING):
        norm = collector.normalize_event(EventSource.KERNEL_SYSCALL, raw)

    assert norm.metadata.get("raw_timestamp") == "invalid-iso-format"
    assert "Failed to parse string timestamp" in caplog.text


@pytest.mark.asyncio
async def test_naive_datetime_timestamp_logging(caplog):
    """Naive datetime timestamps log a warning, preserve raw_timestamp, and fallback to UTC now."""
    collector = EventStreamCollector()
    naive_dt = datetime.now()
    raw = {
        "agent_id": "agent-naive-dt",
        "action": "execve",
        "target": "/bin/bash",
        "timestamp": naive_dt,
    }
    with caplog.at_level(logging.WARNING):
        norm = collector.normalize_event(EventSource.KERNEL_SYSCALL, raw)

    assert norm.metadata.get("raw_timestamp") == str(naive_dt)
    assert norm.timestamp.tzinfo is not None
    assert "Naive datetime" in caplog.text


@pytest.mark.asyncio
async def test_timezoneless_iso_string_timestamp_logging(caplog):
    """Timezone-less ISO string timestamps log a warning, preserve raw_timestamp, and fallback to UTC now."""
    collector = EventStreamCollector()
    raw = {
        "agent_id": "agent-tzless-iso",
        "action": "execve",
        "target": "/bin/bash",
        "timestamp": "2026-08-05T12:00:00",
    }
    with caplog.at_level(logging.WARNING):
        norm = collector.normalize_event(EventSource.KERNEL_SYSCALL, raw)

    assert norm.metadata.get("raw_timestamp") == "2026-08-05T12:00:00"
    assert norm.timestamp.tzinfo is not None
    assert "Timezone-less ISO string timestamp" in caplog.text


@pytest.mark.asyncio
async def test_reconnect_non_callable_error():
    """Bug fix: collect_with_reconnect must raise ValueError if stream_factory is not callable."""
    collector = EventStreamCollector()
    stream = sample_stream([{"agent_id": "a1", "action": "act", "target": "t"}])
    with pytest.raises(ValueError, match="stream_factory must be a callable"):
        async for _ in collector.collect_with_reconnect(EventSource.TOOL_CALL, stream):
            pass


@pytest.mark.asyncio
async def test_reconnect_async_def_factory():
    """Support async def stream_factory returning a coroutine that resolves to an AsyncIterable."""
    collector = EventStreamCollector()

    async def async_factory():
        return sample_stream(
            [{"agent_id": "a-coro", "action": "read", "target": "/etc/shadow"}]
        )

    events = [
        ev
        async for ev in collector.collect_with_reconnect(
            EventSource.KERNEL_SYSCALL, async_factory
        )
    ]
    assert len(events) == 1
    assert events[0].agent_id == "a-coro"


@pytest.mark.asyncio
async def test_reconnect_non_async_iterable_raises_type_error():
    """Fail fast with TypeError if stream_factory returns a non-AsyncIterable object."""
    collector = EventStreamCollector()

    def bad_factory():
        return 12345  # Not an AsyncIterable

    with pytest.raises(
        TypeError, match="stream_factory returned non-AsyncIterable object"
    ):
        async for _ in collector.collect_with_reconnect(
            EventSource.TOOL_CALL, bad_factory
        ):
            pass


@pytest.mark.asyncio
async def test_reconnect_programming_error_fails_fast():
    """Fail fast without backoff retries when stream_factory raises TypeError or ValueError."""
    collector = EventStreamCollector(
        reconnect_max_attempts=3, reconnect_backoff_base=10.0
    )

    attempts = 0

    def error_factory():
        nonlocal attempts
        attempts += 1
        raise TypeError("Programming error in factory")

    with pytest.raises(TypeError, match="Programming error in factory"):
        async for _ in collector.collect_with_reconnect(
            EventSource.TOOL_CALL, error_factory
        ):
            pass

    assert attempts == 1  # No retries occurred
