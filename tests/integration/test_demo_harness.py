import os
import sys
import tempfile
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure PYTHONPATH is correct (must be before any blackwall imports)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import ToolCallContext, Verdict, VerdictDecision, CBMResponse

# Note: test_audit_hook_blocks_subprocess and test_rogue_agent_interception are now
# covered by the existing BDD scenarios in audit_hook_enforcement.feature and
# adk_interception.feature with corresponding step definitions in test_guardrails.py.
# See tests/features/audit_hook_enforcement.feature for subprocess blocking coverage.
# See tests/features/adk_interception.feature for tool interception coverage.

# 2. Test that the Blackwall agent daemon can be imported and runs (starts successfully)
@pytest.mark.asyncio
async def test_blackwall_daemon_starts() -> None:
    from agent import root_agent
    assert root_agent is not None
    assert root_agent.name == "blackwall_target_agent"
    assert len(root_agent.tools) == 4

# 4. Test attack sequences with real signature persistence
@pytest.mark.asyncio
async def test_attack_sequences() -> None:
    # Use a temporary SQLiteThreatRepository for real signature persistence
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db_path = temp_db.name
    temp_db.close()

    try:
        repo = SQLiteThreatRepository(db_path=temp_db_path)
        await repo.initialize()

        # Mock GTI and CBM clients to prevent external network calls
        mock_gti = MagicMock()
        mock_gti.query = AsyncMock(return_value=None)

        mock_cbm = MagicMock()
        mock_cbm.query = AsyncMock(return_value=CBMResponse(blast_radius=0, critical_sinks=[]))

        # Instantiate a clean SyncResolver in demo mode
        from blackwall.sync_resolver import SyncResolver
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "generalized SQL injection signature"
        mock_client.models.generate_content.return_value = mock_response

        resolver = SyncResolver(
            client=mock_client,
            repo=repo,
            gti_client=mock_gti,
            cbm_client=mock_cbm,
            demo_mode=True
        )

        # Attempt 1: SQL Injection (Novel Attack)
        ctx_1 = ToolCallContext(
            tool_name="http_request",
            arguments={"url": "http://127.0.0.1:8000/api/users?username=admin' UNION SELECT username, secret_token FROM users --"}
        )

        # Compute high threat score so it blocks
        # We patch _compute_threat_score to return 0.9 (BLOCK) to guarantee block
        with patch.object(resolver, "_compute_threat_score", AsyncMock(return_value=0.9)):
            verdict_1 = await resolver.evaluate(ctx_1)

        assert verdict_1.decision == VerdictDecision.BLOCK

        # Verify signature was written to the database
        stats = await repo.getStatistics()
        assert stats["totalSignatures"] >= 1, "Signature should be persisted after BLOCK"

        # Attempt 2: Modified SQL Injection (Evasion Attempt)
        # The second evaluation should perform actual FTS lookup
        ctx_2 = ToolCallContext(
            tool_name="http_request",
            arguments={"url": "http://127.0.0.1:8000/api/users?username=admin'%20UNION%20SELECT%20username,%20secret_token%20FROM%20users%20--"}
        )

        verdict_2 = await resolver.evaluate(ctx_2)
        assert verdict_2.decision == VerdictDecision.BLOCK
        assert "Blocked via signature match" in verdict_2.reasoning

        await repo.close()
    finally:
        # Clean up temporary database
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
