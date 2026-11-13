"""Unit tests for google-genai client.aio direct async dispatch."""

from unittest.mock import AsyncMock, MagicMock
import pytest
from blackwall.models import ToolCallContext, Verdict, VerdictDecision
from blackwall.resolver import BatchResolver


@pytest.mark.asyncio
async def test_batch_resolver_uses_client_aio_for_interactions():
    """Verify BatchResolver directly awaits client.aio.interactions.create when available."""
    mock_client = MagicMock()
    mock_aio = MagicMock()
    mock_aio_interactions = MagicMock()

    mock_interaction = MagicMock()
    mock_interaction.id = "interaction-123"
    mock_interaction.parsed = [
        Verdict(
            decision=VerdictDecision.ALLOW,
            reasoning="Safe mock verdict",
            confidence_score=0.9,
        )
    ]
    mock_aio_interactions.create = AsyncMock(return_value=mock_interaction)
    mock_aio.interactions = mock_aio_interactions
    mock_client.aio = mock_aio

    resolver = BatchResolver(client=mock_client)
    contexts = [ToolCallContext(tool_name="test_tool", arguments={})]

    response = await resolver.submit_to_gemini_sync(contexts)
    assert len(response.verdicts) == 1
    assert response.verdicts[0].decision == VerdictDecision.ALLOW
    mock_aio_interactions.create.assert_awaited_once()
