import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone
from uuid import uuid4

from blackwall.models import (
    SecurityEvent, EventType, ToolCallContext, Verdict, VerdictDecision,
    BehaviorScore, SinkType, CBMResponse, GTIResponse
)
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.analytics.BackgroundTaskSubmitter import AgentBehavioralAnalytics


@pytest.fixture
def mock_repo():
    repo = MagicMock(spec=SQLiteThreatRepository)
    repo.add_background_task = AsyncMock()
    return repo


@pytest.fixture
def mock_client():
    client = MagicMock()
    # Support both sync and async interactions.create mocks
    client.interactions = MagicMock()
    client.interactions.create = MagicMock()
    client.aio = MagicMock()
    client.aio.interactions = MagicMock()
    client.aio.interactions.create = AsyncMock()
    return client


@pytest.fixture
def security_event():
    return SecurityEvent(
        event_id=uuid4(),
        event_type=EventType.BLOCK,
        timestamp=datetime.now(timezone.utc),
        tool_context=ToolCallContext(tool_name="test_tool", arguments={"arg1": "val1"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Test reason", confidence_score=0.9),
        cbm_response=CBMResponse(blast_radius=3, critical_sinks=[SinkType.FILE_SYSTEM]),
        gti_response=GTIResponse(indicator="192.168.1.1", is_malicious=True),
        related_signatures=[uuid4()]
    )


@pytest.mark.asyncio
async def test_submitBackgroundAnalysis_success(mock_repo, mock_client, security_event):
    # Setup
    mock_interaction = MagicMock()
    mock_interaction.id = "task-12345"
    mock_client.aio.interactions.create.return_value = mock_interaction
    
    analytics = AgentBehavioralAnalytics(repo=mock_repo, client=mock_client)
    
    # Execute
    task_id = await analytics.submitBackgroundAnalysis(security_event)
    
    # Assert
    assert task_id == "task-12345"
    mock_client.aio.interactions.create.assert_called_once()
    
    call_kwargs = mock_client.aio.interactions.create.call_args.kwargs
    assert call_kwargs["model"] == "gemini-3.1-pro-preview"
    assert call_kwargs["background"] is True
    assert call_kwargs["webhook_config"] == {"uris": ["http://localhost:8090/webhook/analysis_complete"]}
    
    # Verify JSON structure presence in prompt
    prompt = call_kwargs["input"]
    assert "Tool Context" in prompt
    assert "Verdict" in prompt
    assert security_event.tool_context.model_dump_json() in prompt
    
    mock_repo.add_background_task.assert_called_once_with("task-12345", "PENDING_WEBHOOK_CALLBACK")


@pytest.mark.asyncio
async def test_submitBackgroundAnalysis_not_blocked(mock_repo, mock_client, security_event):
    # Setup
    security_event.verdict.decision = VerdictDecision.ALLOW
    security_event.event_type = EventType.ALLOW
    
    analytics = AgentBehavioralAnalytics(repo=mock_repo, client=mock_client)
    
    # Execute
    task_id = await analytics.submitBackgroundAnalysis(security_event)
    
    # Assert
    assert task_id is None
    mock_client.aio.interactions.create.assert_not_called()
    mock_repo.add_background_task.assert_not_called()


@pytest.mark.asyncio
async def test_submitBackgroundAnalysis_api_failure_fail_closed(mock_repo, mock_client, security_event):
    # Setup
    mock_client.aio.interactions.create.side_effect = Exception("API Rate Limit")
    
    analytics = AgentBehavioralAnalytics(repo=mock_repo, client=mock_client)
    
    # Execute
    task_id = await analytics.submitBackgroundAnalysis(security_event)
    
    # Assert
    assert task_id is None
    mock_client.aio.interactions.create.assert_called_once()
    mock_repo.add_background_task.assert_not_called()
