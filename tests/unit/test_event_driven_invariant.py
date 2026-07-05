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

async def test_submitBackgroundAnalysis_non_blocking():
    """Asserts submitBackgroundAnalysis returns without blocking (completes in <10ms)."""
    mock_repo = AsyncMock()
    mock_client = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.id = "test-task-123"
    
    # Mock the sync interactions.create method (used via to_thread) or async aio
    if hasattr(mock_client, 'aio'):
        mock_client.aio.interactions.create = AsyncMock(return_value=mock_interaction)
    else:
        mock_client.interactions.create.return_value = mock_interaction

    analytics = BackgroundSubmitterAnalytics(repo=mock_repo, client=mock_client)

    event = SecurityEvent(
        event_type="INTERCEPTION",
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Test", confidence_score=1.0),
        agent_id="agent-1"
    )

    start_time = time.time()
    task_id = await analytics.submitBackgroundAnalysis(event)
    end_time = time.time()
    
    latency_ms = (end_time - start_time) * 1000
    assert task_id == "test-task-123"
    assert latency_ms < 10.0, f"submitBackgroundAnalysis blocked for {latency_ms}ms! Must be <10ms."

async def test_webhook_integration_end_to_end():
    """
    Delivers a synthetic webhook payload and asserts generateSignature is called exactly once 
    per candidate with no timer-based delay, and end-to-end processing completes within 100ms.
    """
    mock_repo = AsyncMock()
    mock_repo.is_task_valid.return_value = True

    listener = WebhookListener(db_repository=mock_repo, secret_key="test-secret")
    
    # Create synthetic payload
    payload_dict = {
        "event_id": "evt-1",
        "task_id": "test-task-123",
        "threat_signature_candidates": [
            {"candidate": "1"},
            {"candidate": "2"}
        ]
    }
    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    
    # Calculate signature
    signature = hmac.new(
        b"test-secret",
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    mock_request = AsyncMock(spec=web.Request)
    mock_request.headers = {"X-Webhook-Signature": signature}
    mock_request.read.return_value = payload_bytes

    # Mock the target generateSignature method
    with patch.object(Agent_Behavioral_Analytics, "generateSignature", new_callable=AsyncMock) as mock_gen_sig:
        mock_gen_sig.return_value = {"sig": "test"}

        start_time = time.time()
        
        # 1. Trigger the webhook
        response = await listener.handle_webhook(mock_request)
        assert response.status == 202
        
        # 2. Wait for background tasks spawned by WebhookListener to complete
        if listener.background_tasks:
            await asyncio.gather(*listener.background_tasks)
            
        end_time = time.time()
        
        latency_ms = (end_time - start_time) * 1000
        
        # Verify generateSignature called exactly once per candidate
        assert mock_gen_sig.call_count == 2
        mock_gen_sig.assert_any_call({"candidate": "1"})
        mock_gen_sig.assert_any_call({"candidate": "2"})
        
        assert latency_ms < 100.0, f"Webhook integration end-to-end blocked for {latency_ms}ms! Must be <100ms."
