import pytest
import asyncio
import os
import tempfile
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime, timezone
from uuid import uuid4

from blackwall.models import (
    SecurityEvent, EventType, ToolCallContext, Verdict, VerdictDecision,
    CBMResponse, GTIResponse, SinkType
)
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.analytics.BackgroundTaskSubmitter import AgentBehavioralAnalytics

@pytest.fixture
def temp_db_path():
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    os.unlink(path)

@pytest.mark.asyncio
async def test_integration_background_task_submission(temp_db_path):
    repo = SQLiteThreatRepository(db_path=temp_db_path)
    await repo.initialize()
    
    mock_client = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.id = "integration-task-999"
    
    mock_client.aio = MagicMock()
    mock_client.aio.interactions = MagicMock()
    mock_client.aio.interactions.create = AsyncMock(return_value=mock_interaction)

    analytics = AgentBehavioralAnalytics(repo=repo, client=mock_client)
    
    event = SecurityEvent(
        event_id=uuid4(),
        event_type=EventType.BLOCK,
        timestamp=datetime.now(timezone.utc),
        tool_context=ToolCallContext(tool_name="test_tool", arguments={"arg1": "val1"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Test reason", confidence_score=0.9),
        cbm_response=CBMResponse(blast_radius=3, critical_sinks=[SinkType.FILE_SYSTEM]),
        gti_response=GTIResponse(indicator="192.168.1.1", is_malicious=True),
        related_signatures=[]
    )
    
    task_id = await analytics.submitBackgroundAnalysis(event)
    
    assert task_id == "integration-task-999"
    
    # Verify database
    async with repo.pool.connection() as conn:
        cursor = await conn.execute("SELECT status FROM background_tasks WHERE task_id = ?", (task_id,))
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "PENDING_WEBHOOK_CALLBACK"
        
    await repo.close()
