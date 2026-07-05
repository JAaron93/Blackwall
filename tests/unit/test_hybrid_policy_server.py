import asyncio
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from hypothesis import given, strategies as st, settings

from blackwall.models import ToolCallContext, Verdict, VerdictDecision, PolicyServerState
from blackwall.policy import HybridPolicyServer, StructuralGatingEngine, SemanticGatingEngine
from blackwall.policy.engine import StructuralGatingResult, StructuralAction
from blackwall.policy.models import GateResult, PolicyConfig
from blackwall.exceptions import APIRateLimitException

# Define strategies for generating ToolCallContext and Environment roles
tool_context_strategy = st.builds(
    ToolCallContext,
    tool_name=st.sampled_from(["run_command", "write_file", "read_file", "safe_tool"]),
    arguments=st.dictionaries(
        st.text(min_size=1, max_size=10),
        st.text(min_size=1, max_size=10)
    )
)

contexts_and_roles_strategy = st.lists(
    st.tuples(
        tool_context_strategy,
        st.sampled_from(["sandbox", "production"])
    ),
    min_size=10,
    max_size=50
)


@pytest.mark.asyncio
async def test_structural_block_fast_path():
    """
    Test that if Structural Gating returns BLOCK, semantic evaluation is skipped
    and a BLOCK verdict is returned immediately.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.BLOCK,
        requireSemanticReview=False,
        ruleId="block-rule-1"
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)

    server = HybridPolicyServer(mock_struct, mock_semantic)
    context = ToolCallContext(tool_name="run_command", arguments={"cmd": "sudo rm -rf"})
    
    verdict = await server.evaluate(context, "sandbox")
    
    assert verdict.decision == VerdictDecision.BLOCK
    assert verdict.reasoning == "BLOCKED_BY_STRUCTURAL_RULE"
    assert verdict.confidence_score == 1.0
    mock_semantic.evaluate.assert_not_called()


@pytest.mark.asyncio
async def test_structural_allow_fast_path():
    """
    Test that if Structural Gating returns ALLOW (without semantic review required),
    semantic evaluation is skipped and an ALLOW verdict is returned immediately.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ALLOW,
        requireSemanticReview=False,
        ruleId="allow-rule-1"
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)

    server = HybridPolicyServer(mock_struct, mock_semantic)
    context = ToolCallContext(tool_name="read_file", arguments={"path": "foo.txt"})
    
    verdict = await server.evaluate(context, "sandbox")
    
    assert verdict.decision == VerdictDecision.ALLOW
    assert verdict.reasoning == "ALLOWED_BY_STRUCTURAL_RULE"
    assert verdict.confidence_score == 0.0
    mock_semantic.evaluate.assert_not_called()


@pytest.mark.asyncio
async def test_structural_escalate_triggers_semantic():
    """
    Test that if Structural Gating returns ESCALATE_TO_SEMANTIC, or ALLOW with requireSemanticReview=True,
    it calls SemanticGatingEngine.evaluate.
    """
    # Case 1: ESCALATE_TO_SEMANTIC
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)
    mock_semantic.evaluate.return_value = GateResult(
        verdict=VerdictDecision.QUARANTINE,
        reason="Suspicious pattern matched semantically",
        threat_score=0.6
    )

    server = HybridPolicyServer(mock_struct, mock_semantic)
    context = ToolCallContext(tool_name="write_file", arguments={"path": "foo.txt"})
    
    verdict = await server.evaluate(context, "sandbox")
    
    assert verdict.decision == VerdictDecision.QUARANTINE
    assert verdict.reasoning == "Suspicious pattern matched semantically"
    assert verdict.confidence_score == 0.6
    mock_semantic.evaluate.assert_called_once_with(context, "sandbox")

    # Case 2: ALLOW but requireSemanticReview is True
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ALLOW,
        requireSemanticReview=True
    )
    mock_semantic.reset_mock()
    
    verdict2 = await server.evaluate(context, "sandbox")
    assert verdict2.decision == VerdictDecision.QUARANTINE
    mock_semantic.evaluate.assert_called_once_with(context, "sandbox")


@pytest.mark.asyncio
async def test_evaluate_batch_preserves_order():
    """
    Test that evaluateBatch returns verdicts in the exact same order as the input contexts.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    # Side effects returning different results for different inputs
    mock_struct.evaluate.side_effect = lambda context, role: (
        StructuralGatingResult(
            decision=StructuralAction.BLOCK if context.tool_name == "run_command" else StructuralAction.ALLOW,
            requireSemanticReview=(context.tool_name == "write_file"),
            ruleId="rule"
        )
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)
    mock_semantic.evaluate.return_value = GateResult(
        verdict=VerdictDecision.QUARANTINE,
        reason="Semantic Quarantine",
        threat_score=0.6
    )

    server = HybridPolicyServer(mock_struct, mock_semantic)
    
    contexts = [
        ToolCallContext(tool_name="run_command", arguments={}),  # Should be BLOCK (fast path)
        ToolCallContext(tool_name="read_file", arguments={}),    # Should be ALLOW (fast path)
        ToolCallContext(tool_name="write_file", arguments={}),   # Should be QUARANTINE (escalated)
    ]
    roles = ["production", "sandbox", "sandbox"]

    verdicts = await server.evaluateBatch(contexts, roles)

    assert len(verdicts) == 3
    assert verdicts[0].decision == VerdictDecision.BLOCK
    assert verdicts[0].reasoning == "BLOCKED_BY_STRUCTURAL_RULE"
    
    assert verdicts[1].decision == VerdictDecision.ALLOW
    assert verdicts[1].reasoning == "ALLOWED_BY_STRUCTURAL_RULE"
    
    assert verdicts[2].decision == VerdictDecision.QUARANTINE
    assert verdicts[2].reasoning == "Semantic Quarantine"


@settings(max_examples=50)
@given(contexts_and_roles_strategy)
@pytest.mark.asyncio
async def test_verdict_array_order_correspondence_property(contexts_and_roles):
    """
    Property-based test verifying that verdict array corresponds exactly to input context array.
    """
    contexts = [c for c, r in contexts_and_roles]
    roles = [r for c, r in contexts_and_roles]

    mock_struct = MagicMock(spec=StructuralGatingEngine)
    # Return a deterministic structural result based on tool name length to make it interesting
    def struct_eval(context, role):
        if len(context.tool_name) % 3 == 0:
            return StructuralGatingResult(StructuralAction.BLOCK, False, "r1")
        elif len(context.tool_name) % 3 == 1:
            return StructuralGatingResult(StructuralAction.ALLOW, False, "r2")
        else:
            return StructuralGatingResult(StructuralAction.ESCALATE_TO_SEMANTIC, True, "r3")
    mock_struct.evaluate.side_effect = struct_eval

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)
    mock_semantic.evaluate.return_value = GateResult(
        verdict=VerdictDecision.QUARANTINE,
        reason="Property check semantic result",
        threat_score=0.55
    )

    server = HybridPolicyServer(mock_struct, mock_semantic)
    verdicts = await server.evaluateBatch(contexts, roles)

    assert len(verdicts) == len(contexts)
    for i in range(len(contexts)):
        ctx = contexts[i]
        verdict = verdicts[i]
        
        # Check that the verdict corresponds correctly to structural vs semantic logic
        if len(ctx.tool_name) % 3 == 0:
            assert verdict.decision == VerdictDecision.BLOCK
            assert verdict.reasoning == "BLOCKED_BY_STRUCTURAL_RULE"
        elif len(ctx.tool_name) % 3 == 1:
            assert verdict.decision == VerdictDecision.ALLOW
            assert verdict.reasoning == "ALLOWED_BY_STRUCTURAL_RULE"
        else:
            assert verdict.decision == VerdictDecision.QUARANTINE
            assert verdict.reasoning == "Property check semantic result"


@pytest.mark.asyncio
async def test_fail_closed_on_rate_limit():
    """
    Test that evaluateBatch fails closed (returns QUARANTINE verdicts) on APIRateLimitException.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)
    mock_semantic.evaluate.side_effect = APIRateLimitException("Gemini API Rate Limit Exceeded")

    server = HybridPolicyServer(mock_struct, mock_semantic)
    contexts = [
        ToolCallContext(tool_name="write_file", arguments={}),
        ToolCallContext(tool_name="run_command", arguments={}),
    ]
    roles = ["sandbox", "sandbox"]

    verdicts = await server.evaluateBatch(contexts, roles)
    
    assert len(verdicts) == 2
    for v in verdicts:
        assert v.decision == VerdictDecision.QUARANTINE
        assert "Fail-closed" in v.reasoning
        assert v.confidence_score == 0.5


@pytest.mark.asyncio
async def test_fail_closed_on_timeout():
    """
    Test that evaluateBatch fails closed (returns QUARANTINE verdicts) on TimeoutError.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_struct.evaluate.return_value = StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True
    )

    mock_semantic = AsyncMock(spec=SemanticGatingEngine)
    mock_semantic.evaluate.side_effect = asyncio.TimeoutError("Timeout waiting for LLM")

    server = HybridPolicyServer(mock_struct, mock_semantic)
    contexts = [
        ToolCallContext(tool_name="write_file", arguments={}),
    ]
    roles = ["sandbox"]

    verdicts = await server.evaluateBatch(contexts, roles)
    
    assert len(verdicts) == 1
    assert verdicts[0].decision == VerdictDecision.QUARANTINE
    assert "Fail-closed" in verdicts[0].reasoning
    assert verdicts[0].confidence_score == 0.5


@pytest.mark.asyncio
async def test_getCurrentState_returns_valid_state():
    """
    Test that getCurrentState returns a PolicyServerState snapshot.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_policy = MagicMock(spec=PolicyConfig)
    mock_policy.version = "2.1.3"
    mock_struct._policy = mock_policy

    mock_repo = AsyncMock()
    mock_repo.getStatistics.return_value = {"totalSignatures": 42}

    mock_semantic = MagicMock(spec=SemanticGatingEngine)
    mock_semantic.repo = mock_repo

    server = HybridPolicyServer(mock_struct, mock_semantic)
    
    state = await server.getCurrentState()
    
    assert isinstance(state, PolicyServerState)
    assert state.version == "2.1.3"
    assert state.active_signatures == 42
    assert isinstance(state.last_updated, datetime)


def test_update_policy_triggers_reload():
    """
    Test that updatePolicy reloads the policy configuration in the structural engine.
    """
    mock_struct = MagicMock(spec=StructuralGatingEngine)
    mock_semantic = MagicMock(spec=SemanticGatingEngine)
    
    server = HybridPolicyServer(mock_struct, mock_semantic)
    
    t_before = server.last_updated
    server.updatePolicy("dummy_path.yaml")
    
    mock_struct.load_policy.assert_called_once_with("dummy_path.yaml")
    assert server.last_updated > t_before
