import os
import sys
import subprocess
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.models import ToolCallContext, Verdict, VerdictDecision, CBMResponse

# Ensure PYTHONPATH is correct
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

# 1. Test that the audit hook blocks raw subprocess calls
def test_audit_hook_blocks_subprocess() -> None:
    code = """
import sys
import os
import subprocess
from blackwall.audit.manager import AuditHookManager
from blackwall.db.repository import SQLiteThreatRepository
import asyncio

async def run_test():
    db_path = "test_smoke_audit.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        
    manager = AuditHookManager(db_path=db_path)
    manager.start()
    
    try:
        subprocess.Popen([sys.executable, "-c", "pass"])
        print("FAIL: Subprocess not blocked")
        sys.exit(1)
    except PermissionError as e:
        if "Subprocess execution denied" in str(e):
            print("PASS")
            sys.exit(0)
        else:
            print(f"FAIL: Unexpected error message: {e}")
            sys.exit(2)
    finally:
        manager.stop()
        if os.path.exists(db_path):
            os.remove(db_path)

asyncio.run(run_test())
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    assert result.returncode == 0, f"Audit hook test failed: {result.stdout} {result.stderr}"
    assert "PASS" in result.stdout

# 2. Test that the Blackwall agent daemon can be imported and runs (starts successfully)
@pytest.mark.asyncio
async def test_blackwall_daemon_starts() -> None:
    from agent import root_agent
    assert root_agent is not None
    assert root_agent.name == "blackwall_target_agent"
    assert len(root_agent.tools) == 4

# 3. Test that rogue agent tool calls are intercepted by before_tool_callback
@pytest.mark.asyncio
async def test_rogue_agent_interception() -> None:
    from agent import blackwall_before_tool_callback
    from google.adk.tools import FunctionTool
    from google.adk.tools.tool_context import ToolContext
    
    mock_verdict = Verdict(
        decision=VerdictDecision.BLOCK,
        confidence_score=0.9,
        reasoning="Blocked in unit smoke test"
    )
    
    def my_tool(x: str):
        return x
        
    tool = FunctionTool(func=my_tool)
    tool_context = MagicMock(spec=ToolContext)
    
    with patch("agent._resolver") as mock_resolver:
        mock_resolver.evaluate = AsyncMock(return_value=mock_verdict)
        
        with pytest.raises(PermissionError) as exc_info:
            await blackwall_before_tool_callback(tool, {"x": "val"}, tool_context)
            
        assert "[BLACKWALL BLOCK]" in str(exc_info.value)
        mock_resolver.evaluate.assert_called_once()

# 4. Test attack sequences (Attempt 1 blocked by semantic evaluation, Attempt 2 blocked by signature match)
@pytest.mark.asyncio
async def test_attack_sequences() -> None:
    # Use a mock repository to isolate database actions
    mock_repo = AsyncMock()
    mock_repo.find_matching_signature = AsyncMock(side_effect=[None, {"signature_id": "sig-123", "attacker_intent": "SQL Injection"}]) # First not match, second match
    mock_repo.writeSignature = AsyncMock(return_value="sig-123")
    
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
        repo=mock_repo,
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
    mock_repo.writeSignature.assert_called_once() # Signature written after block
    
    # Attempt 2: Modified SQL Injection (Evasion Attempt)
    ctx_2 = ToolCallContext(
        tool_name="http_request",
        arguments={"url": "http://127.0.0.1:8000/api/users?username=admin'%20UNION%20SELECT%20username,%20secret_token%20FROM%20users%20--"}
    )
    
    verdict_2 = await resolver.evaluate(ctx_2)
    assert verdict_2.decision == VerdictDecision.BLOCK
    assert "Blocked via signature match" in verdict_2.reasoning
