import asyncio
import inspect
import json
import time
import hmac
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from blackwall.analytics import AgentBehavioralAnalytics
# Wait, webhook_listener imports Agent_Behavioral_Analytics (with underscores)
from blackwall.analytics import Agent_Behavioral_Analytics
from blackwall.analytics.BackgroundTaskSubmitter import AgentBehavioralAnalytics as BackgroundSubmitterAnalytics
from blackwall.api.webhook_listener import WebhookListener
from blackwall.models import SecurityEvent, Verdict, VerdictDecision, ToolCallContext

pytestmark = pytest.mark.asyncio

def test_generateSignature_no_sleep():
    """Asserts AgentBehavioralAnalytics.generateSignature carries no internal asyncio.sleep or time.sleep calls."""
    source = inspect.getsource(AgentBehavioralAnalytics.generateSignature)
    assert "asyncio.sleep" not in source, "Polling pattern 'asyncio.sleep' found in generateSignature!"
    assert "time.sleep" not in source, "Polling pattern 'time.sleep' found in generateSignature!"

def test_WebhookListener_no_sleep():
    """Asserts WebhookListener has no asyncio.sleep in its request handler path."""
    source_handle = inspect.getsource(WebhookListener.handle_webhook)
    source_process = inspect.getsource(WebhookListener._process_payload)
    assert "asyncio.sleep" not in source_handle, "Polling pattern found in handle_webhook!"
    assert "time.sleep" not in source_handle, "Polling pattern found in handle_webhook!"
    assert "asyncio.sleep" not in source_process, "Polling pattern found in _process_payload!"
    assert "time.sleep" not in source_process, "Polling pattern found in _process_payload!"

async def test_submitBackgroundAnalysis_non_blocking(safe_sla_limit):
    """Asserts submitBackgroundAnalysis returns without blocking (completes in <10ms) using aio path.
    
    The default 10ms threshold may be overridden using the BLACKWALL_SUBMIT_SLA_LIMIT_MS
    environment variable.
    """
    mock_repo = AsyncMock()
    # Create a mock with aio attribute to test the async client.aio path
    mock_client = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.id = "test-task-123"

    # Explicitly set up the aio path
    mock_client.aio.interactions.create = AsyncMock(return_value=mock_interaction)

    analytics = BackgroundSubmitterAnalytics(repo=mock_repo, client=mock_client)

    event = SecurityEvent(
        event_type="INTERCEPTION",
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Test", confidence_score=1.0),
        agent_id="agent-1"
    )

    # Warmup call
    await analytics.submitBackgroundAnalysis(event)

    start_time = time.monotonic()
    task_id = await analytics.submitBackgroundAnalysis(event)
    end_time = time.monotonic()
    latency_ms = (end_time - start_time) * 1000

    limit = safe_sla_limit("BLACKWALL_SUBMIT_SLA_LIMIT_MS", 10.0)
    assert task_id == "test-task-123"
    assert latency_ms < limit, f"submitBackgroundAnalysis blocked for {latency_ms}ms! Must be <{limit}ms."

async def test_submitBackgroundAnalysis_to_thread_fallback(safe_sla_limit):
    """Asserts submitBackgroundAnalysis uses asyncio.to_thread fallback when client lacks aio attribute (completes in <10ms).
    
    The default 10ms threshold may be overridden using the BLACKWALL_SUBMIT_SLA_LIMIT_MS
    environment variable.
    """
    mock_repo = AsyncMock()
    # Create a spec-limited mock without aio attribute to force asyncio.to_thread path
    mock_client = MagicMock(spec=['interactions'])
    mock_interaction = MagicMock()
    mock_interaction.id = "test-task-456"

    # Mock the sync interactions.create method (used via to_thread)
    mock_client.interactions.create.return_value = mock_interaction

    analytics = BackgroundSubmitterAnalytics(repo=mock_repo, client=mock_client)

    event = SecurityEvent(
        event_type="INTERCEPTION",
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Test", confidence_score=1.0),
        agent_id="agent-1"
    )

    # Warmup call (warms up the executor thread pool)
    await analytics.submitBackgroundAnalysis(event)

    start_time = time.monotonic()
    task_id = await analytics.submitBackgroundAnalysis(event)
    end_time = time.monotonic()
    latency_ms = (end_time - start_time) * 1000

    limit = safe_sla_limit("BLACKWALL_SUBMIT_SLA_LIMIT_MS", 10.0)
    assert task_id == "test-task-456"
    assert latency_ms < limit, f"submitBackgroundAnalysis blocked for {latency_ms}ms! Must be <{limit}ms."

async def test_webhook_integration_end_to_end(safe_sla_limit):
    """
    Delivers a synthetic webhook payload and asserts generateSignature is called exactly once 
    per candidate with no timer-based delay, and end-to-end processing completes within 250ms.
    
    The default 250ms threshold may be overridden using the BLACKWALL_WEBHOOK_SLA_LIMIT_MS
    environment variable.
    """
    mock_repo = AsyncMock()
    mock_repo.is_task_valid.return_value = True

    mock_gemini = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.task_id = "test-task-123"
    mock_interaction.threat_signature_candidates = [
        {"candidate": "1"},
        {"candidate": "2"}
    ]
    mock_gemini.interactions.get = AsyncMock(return_value=mock_interaction)

    listener = WebhookListener(db_repository=mock_repo, gemini_client=mock_gemini, audience="test-audience")
    
    # Create synthetic payload
    payload_dict = {
        "type": "interaction.completed",
        "version": "1",
        "timestamp": "2026-07-06T00:00:00Z",
        "data": {"id": "test-interaction-123"}
    }
    payload_bytes = json.dumps(payload_dict).encode("utf-8")

    mock_request = AsyncMock(spec=web.Request)
    mock_request.headers = {
        "Webhook-Signature": "mock-token",
        "webhook-timestamp": str(time.time()),
        "webhook-id": "mock-webhook-id"
    }
    mock_request.read.return_value = payload_bytes

    # Mock the target generateSignature method
    with patch.object(Agent_Behavioral_Analytics, "generateSignature", new_callable=AsyncMock) as mock_gen_sig, \
         patch("blackwall.api.webhook_listener.jwt.get_unverified_header") as mock_jwt_header, \
         patch("blackwall.api.webhook_listener.jwt.decode") as mock_jwt_decode, \
         patch.object(listener, "_get_public_key", new_callable=AsyncMock) as mock_get_pubkey:

        mock_jwt_header.return_value = {"kid": "test-kid"}
        mock_jwt_decode.return_value = {"sub": "test-interaction-123"}
        mock_get_pubkey.return_value = "mock-key"
        mock_gen_sig.return_value = {"sig": "test"}

        # Warmup call with a distinct webhook-id to bypass deduplication check
        mock_request.headers["webhook-id"] = "mock-webhook-id-warmup"
        warmup_response = await listener.handle_webhook(mock_request)
        assert warmup_response.status == 200
        if listener.background_tasks:
            await asyncio.gather(*listener.background_tasks)

        # Reset generateSignature mock call count
        mock_gen_sig.reset_mock()

        # Timed test call
        mock_request.headers["webhook-id"] = "mock-webhook-id-timed"
        start_time = time.time()
        
        # 1. Trigger the webhook
        response = await listener.handle_webhook(mock_request)
        assert response.status == 200
        
        # 2. Wait for background tasks spawned by WebhookListener to complete
        if listener.background_tasks:
            await asyncio.gather(*listener.background_tasks)
            
        end_time = time.time()
        
        limit = safe_sla_limit("BLACKWALL_WEBHOOK_SLA_LIMIT_MS", 250.0)
        latency_ms = (end_time - start_time) * 1000
        
        # Verify generateSignature called exactly once per candidate
        assert mock_gen_sig.call_count == 2
        mock_gen_sig.assert_any_call({"candidate": "1"})
        mock_gen_sig.assert_any_call({"candidate": "2"})
        
        assert latency_ms < limit, f"Webhook integration end-to-end blocked for {latency_ms}ms! Must be <{limit}ms."
