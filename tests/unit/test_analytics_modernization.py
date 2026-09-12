"""Unit tests for modernized analytics with structured outputs and in-process task fallback."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import pytest

from blackwall.analytics import AgentBehavioralAnalytics
from blackwall.analytics.BackgroundTaskSubmitter import (
    AgentBehavioralAnalytics as BackgroundSubmitterAnalytics,
)
from blackwall.config import DEFAULT_RAPID_TRIAGE_MODEL
from blackwall.models import (
    BehaviorScore,
    EventType,
    RefactoringHint,
    SecurityEvent,
    SinkType,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)


@pytest.mark.asyncio
async def test_score_event_with_parsed_structured_output():
    """Test scoreEvent extracts score and risk_level directly from interaction.parsed."""
    mock_interaction = MagicMock()
    mock_interaction.parsed = {"score": 4.0, "risk_level": "CRITICAL"}
    mock_interaction.output_text = None

    mock_client = MagicMock()
    mock_client.interactions.create = AsyncMock(return_value=mock_interaction)

    analytics = AgentBehavioralAnalytics(client=mock_client)
    event = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="eval_exec", arguments={"code": "os.system('sh')"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Dangerous execution", confidence_score=0.9),
    )

    result = await analytics.scoreEvent(event)
    assert isinstance(result, BehaviorScore)
    assert result.score == 4.0 / 5.0
    assert result.risk_level == "CRITICAL"

    # Verify model used is DEFAULT_RAPID_TRIAGE_MODEL
    call_kwargs = mock_client.interactions.create.call_args.kwargs
    assert call_kwargs["model"] == DEFAULT_RAPID_TRIAGE_MODEL


@pytest.mark.asyncio
async def test_trigger_refactoring_with_parsed_structured_output():
    """Test triggerRefactoring extracts fields directly from interaction.parsed."""
    mock_interaction = MagicMock()
    mock_interaction.parsed = {
        "suggestion": "Avoid raw shell invocation",
        "confidence": 0.98,
        "vulnerability_type": "Command Injection",
        "suggested_fix": "Use shlex.split and execve",
    }
    mock_interaction.output_text = None

    mock_client = MagicMock()
    mock_client.interactions.create = AsyncMock(return_value=mock_interaction)

    analytics = AgentBehavioralAnalytics(client=mock_client)
    event = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="execute_command", arguments={"CommandLine": "bash -i"}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="Quarantined shell", confidence_score=0.8),
    )

    hint = await analytics.triggerRefactoring(event)
    assert isinstance(hint, RefactoringHint)
    assert hint.confidence == 0.98
    assert hint.vulnerability_type == "Command Injection"
    assert hint.suggested_fix == "Use shlex.split and execve"


@pytest.mark.asyncio
async def test_background_task_submitter_in_process_fallback():
    """Test BackgroundTaskSubmitter supports in-process execution when webhook is None."""
    mock_repo = MagicMock()
    mock_repo.add_background_task = AsyncMock()

    mock_client = MagicMock()
    # Mock client without aio
    delattr(mock_client, "aio") if hasattr(mock_client, "aio") else None
    mock_interaction = MagicMock()
    mock_interaction.id = "in-proc-task-999"
    mock_client.interactions.create = MagicMock(return_value=mock_interaction)

    submitter = BackgroundSubmitterAnalytics(
        repo=mock_repo, client=mock_client, in_process=True
    )

    event = SecurityEvent(
        event_id=uuid4(),
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="malicious_tool", arguments={"cmd": "sh"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Blocked", confidence_score=0.9),
    )

    task_id = await submitter.submitBackgroundAnalysis(event)
    assert task_id == "in-proc-task-999"
    mock_repo.add_background_task.assert_called_once_with(
        "in-proc-task-999", "COMPLETED"
    )
