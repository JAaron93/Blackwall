"""Unit tests for SyncResolver integration with ThreatIntelOrchestrator (TASK-G02)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest

from blackwall.models import (
    ToolCallContext,
    VerdictDecision,
)
from blackwall.sync_resolver import SyncResolver
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator


@pytest.fixture
def mock_genai_client():
    client = MagicMock()
    client.models = MagicMock()
    return client


@pytest.fixture
def mock_threat_intel():
    orchestrator = MagicMock(spec=ThreatIntelOrchestrator)
    orchestrator.lookup = AsyncMock()
    return orchestrator


@pytest.mark.asyncio
async def test_sync_resolver_initializes_with_threat_intel(mock_genai_client, mock_threat_intel):
    """SyncResolver should accept threat_intel orchestrator and expose it."""
    resolver = SyncResolver(client=mock_genai_client, threat_intel=mock_threat_intel)
    assert resolver.threat_intel is mock_threat_intel
    assert resolver.gti_client is mock_threat_intel


@pytest.mark.asyncio
async def test_sync_resolver_malicious_detection_triggers_block(mock_genai_client, mock_threat_intel):
    """Malicious threat intel detections escalate composite score and trigger BLOCK verdict."""
    mock_threat_intel.lookup.return_value = ThreatIntelResponse(
        indicator="198.51.100.25",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=True,
        risk_score=0.92,
        detection_count=15,
        total_engines=20,
        provider_name="AlienVault OTX",
        pulse_count=4,
    )

    resolver = SyncResolver(client=mock_genai_client, threat_intel=mock_threat_intel, demo_mode=False)

    # Tool call containing malicious IP
    context = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://198.51.100.25/payload.sh"},
    )

    verdict = await resolver.evaluate(context)

    assert verdict.decision == VerdictDecision.BLOCK
    assert verdict.confidence_score >= 0.75
    assert "AlienVault OTX" in verdict.reasoning or "ThreatIntel" in verdict.reasoning
    mock_threat_intel.lookup.assert_awaited_once()


@pytest.mark.asyncio
async def test_sync_resolver_benign_threat_intel_allows(mock_genai_client, mock_threat_intel):
    """Benign threat intel response allows tool call when other signals are low."""
    mock_threat_intel.lookup.return_value = ThreatIntelResponse(
        indicator="198.51.100.1",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        risk_score=0.0,
        provider_name="AlienVault OTX",
    )

    resolver = SyncResolver(client=mock_genai_client, threat_intel=mock_threat_intel, demo_mode=False)

    context = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://198.51.100.1/data.json"},
    )

    verdict = await resolver.evaluate(context)

    assert verdict.decision == VerdictDecision.ALLOW
    assert verdict.confidence_score < 0.50


@pytest.mark.asyncio
async def test_sync_resolver_high_burst_no_throttling(mock_genai_client, mock_threat_intel):
    """SyncResolver comfortably evaluates 20 consecutive calls without budget exhaustion."""
    mock_threat_intel.lookup.return_value = ThreatIntelResponse(
        indicator="198.51.100.2",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        risk_score=0.05,
        provider_name="AlienVault OTX",
    )

    resolver = SyncResolver(client=mock_genai_client, threat_intel=mock_threat_intel, demo_mode=False)

    for i in range(20):
        context = ToolCallContext(
            tool_name="http_request",
            arguments={"url": f"http://198.51.100.{i + 1}/test"},
        )
        verdict = await resolver.evaluate(context)
        assert verdict.decision in (VerdictDecision.ALLOW, VerdictDecision.QUARANTINE, VerdictDecision.BLOCK)

    metrics = resolver.get_metrics()
    assert metrics["total_evaluations"] == 20
    assert metrics["rate_limit_hits"] == 0


@pytest.mark.asyncio
async def test_sync_resolver_async_budget_tracker_enforced(mock_genai_client, mock_threat_intel):
    """SyncResolver awaits async budget tracker and defers lookup when budget is exhausted."""
    async_tracker = MagicMock()
    async_tracker.try_acquire = AsyncMock(return_value=False)

    resolver = SyncResolver(
        client=mock_genai_client,
        threat_intel=mock_threat_intel,
        gti_budget_tracker=async_tracker,
        demo_mode=False,
    )

    context = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://198.51.100.1/test"},
    )
    await resolver.evaluate(context)

    async_tracker.try_acquire.assert_awaited_once()
    mock_threat_intel.lookup.assert_not_called()
    assert resolver._threat_intel_queries_deferred == 1


@pytest.mark.asyncio
async def test_sync_resolver_async_budget_tracker_allowed(mock_genai_client, mock_threat_intel):
    """SyncResolver awaits async budget tracker and proceeds with lookup when allowed."""
    async_tracker = MagicMock()
    async_tracker.try_acquire = AsyncMock(return_value=True)

    mock_threat_intel.lookup.return_value = ThreatIntelResponse(
        indicator="198.51.100.1",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        risk_score=0.1,
        provider_name="AlienVault OTX",
    )

    resolver = SyncResolver(
        client=mock_genai_client,
        threat_intel=mock_threat_intel,
        gti_budget_tracker=async_tracker,
        demo_mode=False,
    )

    context = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://198.51.100.1/test"},
    )
    await resolver.evaluate(context)

    async_tracker.try_acquire.assert_awaited_once()
    mock_threat_intel.lookup.assert_called_once()
    assert resolver._threat_intel_queries_deferred == 0


@pytest.mark.asyncio
async def test_sync_resolver_budget_tracker_fails_closed_on_error(mock_genai_client, mock_threat_intel):
    """SyncResolver fails closed and defers lookup if budget tracker raises an exception."""
    faulty_tracker = MagicMock()
    faulty_tracker.try_acquire = AsyncMock(side_effect=RuntimeError("Tracker connection failed"))

    resolver = SyncResolver(
        client=mock_genai_client,
        threat_intel=mock_threat_intel,
        gti_budget_tracker=faulty_tracker,
        demo_mode=False,
    )

    context = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://198.51.100.1/test"},
    )
    await resolver.evaluate(context)

    mock_threat_intel.lookup.assert_not_called()
    assert resolver._threat_intel_queries_deferred == 1
