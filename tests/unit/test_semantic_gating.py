import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from hypothesis import given, strategies as st, settings

from blackwall.models import ToolCallContext, VerdictDecision, GTIResponse
from blackwall.policy.semantic import SemanticGatingEngine
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.mcp.gti_client import GTIMCPClient, GTIDegradedError
from blackwall.mcp.codebase_memory import CodebaseMemoryClient, DependencyChain, BlastRadiusReport, BlastRadiusIsolation, CriticalSink, CriticalSinkType

TEST_DB_PATH = "test_semantic_gating.db"


@pytest_asyncio.fixture
async def temp_repo():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    repo = SQLiteThreatRepository(db_path=TEST_DB_PATH)
    await repo.initialize()
    yield repo
    await repo.close()
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass


@pytest.mark.asyncio
async def test_signature_matching_returns_block(temp_repo):
    # Insert a signature
    sig_data = {
        "signatureId": "test-sig-123",
        "attackerIntent": "Unauthorized command execution",
        "payloadPattern": "eval(obfuscated)",
        "targetTool": "run_command",
        "mitigationAction": "BLOCK",
    }
    await temp_repo.writeSignature(sig_data)

    engine = SemanticGatingEngine(repo=temp_repo)
    context = ToolCallContext(
        tool_name="run_command",
        arguments={"cmd": "eval(obfuscated)"}
    )

    result = await engine.evaluate(context, "sandbox")
    assert result.verdict == VerdictDecision.BLOCK
    assert result.signature_id == "test-sig-123"
    assert "Unauthorized command" in result.reason
    assert result.threat_score == 1.0


@pytest.mark.asyncio
async def test_signature_match_count_increment(temp_repo):
    sig_data = {
        "signatureId": "test-sig-123",
        "attackerIntent": "Unauthorized command execution",
        "payloadPattern": "eval(obfuscated)",
        "targetTool": "run_command",
        "mitigationAction": "BLOCK",
    }
    await temp_repo.writeSignature(sig_data)

    engine = SemanticGatingEngine(repo=temp_repo)
    context = ToolCallContext(
        tool_name="run_command",
        arguments={"cmd": "eval(obfuscated)"}
    )

    # Evaluate multiple times
    await engine.evaluate(context, "sandbox")
    await engine.evaluate(context, "sandbox")

    # Verify match count in DB
    async with temp_repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT match_count FROM signatures WHERE signature_id = 'test-sig-123'"
        )
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == 2


@pytest.mark.asyncio
async def test_gti_malicious_ioc_increases_threat_score(temp_repo):
    # Setup mock GTI Client
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    
    # Mock malicious response
    mock_response = GTIResponse(
        indicator="1.2.3.4",
        is_malicious=True,
        threat_categories=["botnet"],
        detection_rate=80.0,
        confidence=0.9
    )
    mock_gti.queryIOC = AsyncMock(return_value=mock_response)

    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4"}
    )

    result = await engine.evaluate(context, "sandbox")
    
    # We expect a high threat score since GTI is malicious (score should be >= 0.5 or high)
    # Context score: tool_risk = 0.2, argument_novelty = 0.0, env_risk = 0.2 => context = 0.4 * 0.2 + 0.3*0 + 0.3*0.2 = 0.14
    # GTI score: is_malicious (0.5) + detection_rate (0.3 * 0.8 = 0.24) + categories (0.1) = 0.84
    # Weighted score: 0.4 * 0.84 + 0.6 * 0.14 = 0.336 + 0.084 = 0.42
    # Wait, the weights redistribution: CBM is unavailable (None), so GTI weight is 40 / 70 = 57.14%, Context is 30 / 70 = 42.86%.
    # Weighted score: 0.5714 * 0.84 + 0.4286 * 0.14 = 0.48 + 0.06 = 0.54
    assert result.threat_score >= 0.5
    assert result.verdict == VerdictDecision.QUARANTINE


@pytest.mark.asyncio
async def test_cbm_critical_sink_detection_increases_threat_score(temp_repo):
    # Setup mock CBM Client
    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.0
    
    # Mock CBM response
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="ProcessOrder",
        callChain=["ProcessOrder", "ExecuteSQL"],
        depth=2,
        hasCriticalSink=True,
        criticalSinks=["ExecuteSQL"]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="ProcessOrder",
        affectedModules=["src/db"],
        affectedFunctions=["ProcessOrder"],
        riskScore=0.8,
        isolation=BlastRadiusIsolation.MEDIUM
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[
        CriticalSink(
            sinkType=CriticalSinkType.SQL_QUERY,
            functionName="ExecuteSQL",
            modulePath="src/db.py",
            isUnsafe=True,
            mitigationHint="use parameterized queries"
        )
    ])
    mock_cbm.identifyUnsafeSinks = lambda sinks: [s for s in sinks if s.isUnsafe]

    engine = SemanticGatingEngine(repo=temp_repo, cbm_client=mock_cbm)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"targetFunction": "ProcessOrder"}
    )

    result = await engine.evaluate(context, "sandbox")
    
    # Context score: 0.14
    # CBM score: hasCriticalSink (0.4) + unsafe_sinks (0.3) + riskScore (0.3 * 0.8 = 0.24) = 0.94
    # GTI is unavailable (None), so CBM weight = 30 / 60 = 50%, Context weight = 30 / 60 = 50%.
    # Weighted score: 0.5 * 0.94 + 0.5 * 0.14 = 0.47 + 0.07 = 0.54
    assert result.threat_score >= 0.5
    assert result.verdict == VerdictDecision.QUARANTINE


@pytest.mark.asyncio
async def test_weighted_threat_score_aggregation_and_redistribution(temp_repo):
    # Setup mocks
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    mock_gti.queryIOC = AsyncMock(return_value=GTIResponse(
        indicator="1.2.3.4",
        is_malicious=True,
        threat_categories=["botnet"],
        detection_rate=80.0,
        confidence=0.9
    ))

    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.0
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="ProcessOrder",
        callChain=["ProcessOrder", "ExecuteSQL"],
        depth=2,
        hasCriticalSink=True,
        criticalSinks=["ExecuteSQL"]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="ProcessOrder",
        affectedModules=["src/db"],
        affectedFunctions=["ProcessOrder"],
        riskScore=0.8,
        isolation=BlastRadiusIsolation.MEDIUM
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[
        CriticalSink(
            sinkType=CriticalSinkType.SQL_QUERY,
            functionName="ExecuteSQL",
            modulePath="src/db.py",
            isUnsafe=True,
            mitigationHint="use parameterized queries"
        )
    ])
    mock_cbm.identifyUnsafeSinks = lambda sinks: [s for s in sinks if s.isUnsafe]

    # Test Case 1: All three signals available (GTI, CBM, Context)
    engine_all = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti, cbm_client=mock_cbm)
    context_all = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4", "targetFunction": "ProcessOrder"}
    )
    result_all = await engine_all.evaluate(context_all, "sandbox")
    
    # GTI: 0.84, CBM: 0.94, Context: 0.14
    # Weights: GTI (40%), CBM (30%), Context (30%)
    # Expected: 0.4 * 0.84 + 0.3 * 0.94 + 0.3 * 0.14 = 0.336 + 0.282 + 0.042 = 0.66
    assert abs(result_all.threat_score - 0.66) < 0.01
    assert result_all.verdict == VerdictDecision.QUARANTINE

    # Test Case 2: GTI unavailable (redistributed to CBM and Context)
    engine_no_gti = SemanticGatingEngine(repo=temp_repo, cbm_client=mock_cbm)
    result_no_gti = await engine_no_gti.evaluate(context_all, "sandbox")
    # CBM (50%), Context (50%)
    # Expected: 0.5 * 0.94 + 0.5 * 0.14 = 0.54
    assert abs(result_no_gti.threat_score - 0.54) < 0.01

    # Test Case 3: CBM unavailable (redistributed to GTI and Context)
    engine_no_cbm = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)
    result_no_cbm = await engine_no_cbm.evaluate(context_all, "sandbox")
    # GTI (57.14%), Context (42.86%)
    # Expected: (4/7) * 0.84 + (3/7) * 0.14 = 0.48 + 0.06 = 0.54
    assert abs(result_no_cbm.threat_score - 0.54) < 0.01

    # Test Case 4: Both GTI and CBM unavailable (Context gets 100%)
    engine_only_context = SemanticGatingEngine(repo=temp_repo)
    result_only_context = await engine_only_context.evaluate(context_all, "sandbox")
    # Expected: 0.14
    assert abs(result_only_context.threat_score - 0.14) < 0.01


@pytest.mark.asyncio
async def test_gti_degraded_penalty_applied(temp_repo):
    # Setup mock degraded GTI Client
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = True
    # queryIOC raises GTIDegradedError
    mock_gti.queryIOC = AsyncMock(side_effect=GTIDegradedError("Degraded"))

    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4"}
    )

    result = await engine.evaluate(context, "sandbox")
    # GTI is degraded, so it's treated as unavailable (redistributed), but gti_penalty=0.2 is applied.
    # Base score (context 100% since CBM is also unavailable) = 0.14
    # Final threat score = 0.14 + 0.2 = 0.34
    assert abs(result.threat_score - 0.34) < 0.01
    assert result.verdict == VerdictDecision.ALLOW


@pytest.mark.asyncio
async def test_deterministic_scoring(temp_repo):
    engine = SemanticGatingEngine(repo=temp_repo)
    context = ToolCallContext(
        tool_name="run_command",
        arguments={"cmd": "ls -l"}
    )
    
    res1 = await engine.evaluate(context, "sandbox")
    res2 = await engine.evaluate(context, "sandbox")
    assert res1.threat_score == res2.threat_score
    assert res1.verdict == res2.verdict


@pytest.mark.asyncio
async def test_verdict_thresholds(temp_repo):
    engine = SemanticGatingEngine(repo=temp_repo)
    
    # 1. ALLOW threshold (<0.5)
    # Context score: safe_tool (0.2) + no susp (0.0) + sandbox (0.2) => 0.14
    res_allow = await engine.evaluate(
        ToolCallContext(tool_name="safe_tool", arguments={}),
        "sandbox"
    )
    assert res_allow.threat_score < 0.5
    assert res_allow.verdict == VerdictDecision.ALLOW

    # 2. QUARANTINE threshold (>=0.5, <0.75)
    # Context score: run_command (1.0) + no susp (0.0) + sandbox (0.2) => 0.46
    # Add a CBM mock to push score into QUARANTINE
    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.0
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="f", callChain=[], depth=1, hasCriticalSink=True, criticalSinks=[]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="f", affectedModules=[], affectedFunctions=[], riskScore=0.5, isolation=BlastRadiusIsolation.HIGH
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[])
    mock_cbm.identifyUnsafeSinks = lambda sinks: []
    
    engine_q = SemanticGatingEngine(repo=temp_repo, cbm_client=mock_cbm)
    res_q = await engine_q.evaluate(
        ToolCallContext(tool_name="run_command", arguments={"targetFunction": "f"}),
        "sandbox"
    )
    # Context score: 0.4 * 1.0 + 0.3 * 0.0 + 0.3 * 0.2 = 0.46
    # CBM score: hasCriticalSink (0.4) + riskScore (0.3 * 0.5 = 0.15) = 0.55
    # Aggregated: 0.5 * 0.46 + 0.5 * 0.55 = 0.23 + 0.275 = 0.505
    assert 0.5 <= res_q.threat_score < 0.75
    assert res_q.verdict == VerdictDecision.QUARANTINE

    # 3. BLOCK threshold (>=0.75)
    # Context score: run_command (1.0) + suspicious (1.0) + production (1.0) => 1.0
    res_block = await engine.evaluate(
        ToolCallContext(tool_name="run_command", arguments={"cmd": "sudo rm -rf"}),
        "production"
    )
    assert res_block.threat_score >= 0.75
    assert res_block.verdict == VerdictDecision.BLOCK


# --- Property 3: Threat Score Bounded ---
@settings(max_examples=100)
@given(
    tool_name=st.sampled_from(["run_command", "write_to_file", "safe_tool"]),
    arguments=st.dictionaries(st.text(), st.text()),
    gti_is_malicious=st.booleans(),
    gti_detection_rate=st.floats(min_value=0.0, max_value=100.0),
    gti_categories=st.lists(st.sampled_from(["malware", "botnet", "c2"]), max_size=3),
    cbm_has_critical_sink=st.booleans(),
    cbm_unsafe=st.booleans(),
    cbm_blast_radius_risk=st.floats(min_value=0.0, max_value=1.0),
    environment_role=st.sampled_from(["sandbox", "production"]),
    gti_degraded=st.booleans(),
    cbm_stale=st.booleans()
)
@pytest.mark.asyncio
async def test_threat_score_bounded_property(
    tool_name, arguments, gti_is_malicious, gti_detection_rate, gti_categories,
    cbm_has_critical_sink, cbm_unsafe, cbm_blast_radius_risk, environment_role,
    gti_degraded, cbm_stale
):
    # Setup stubs manually to keep tests fast (no SQLite or real network)
    # We call evaluate with mock clients and verify bounds.
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = gti_degraded
    if gti_degraded:
        mock_gti.queryIOC = AsyncMock(side_effect=GTIDegradedError("Degraded"))
    else:
        mock_gti.queryIOC = AsyncMock(return_value=GTIResponse(
            indicator="test",
            is_malicious=gti_is_malicious,
            threat_categories=gti_categories,
            detection_rate=gti_detection_rate,
            confidence=0.5
        ))

    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.4 if cbm_stale else 0.0
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="f", callChain=[], depth=1, hasCriticalSink=cbm_has_critical_sink, criticalSinks=[]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="f", affectedModules=[], affectedFunctions=[], riskScore=cbm_blast_radius_risk, isolation=BlastRadiusIsolation.HIGH
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[])
    mock_cbm.identifyUnsafeSinks = lambda sinks: [MagicMock()] if cbm_unsafe else []

    engine = SemanticGatingEngine(repo=None, gti_client=mock_gti, cbm_client=mock_cbm)
    
    # Always include targetFunction to trigger CBM evaluation
    args = dict(arguments)
    args["targetFunction"] = "f"
    
    # Include an IP so we trigger GTI
    args["ip"] = "8.8.8.8"

    context = ToolCallContext(
        tool_name=tool_name,
        arguments=args
    )

    result = await engine.evaluate(context, environment_role)
    
    # Threat score must always be bounded [0.0, 1.0]
    assert 0.0 <= result.threat_score <= 1.0
    
    # Verdict correctness checks
    if result.threat_score >= 0.75:
        assert result.verdict == VerdictDecision.BLOCK
    elif result.threat_score >= 0.5:
        assert result.verdict == VerdictDecision.QUARANTINE
    else:
        assert result.verdict == VerdictDecision.ALLOW


@pytest.mark.asyncio
async def test_high_risk_event_classification(temp_repo):
    from blackwall.policy.engine import StructuralGatingResult, StructuralAction
    from blackwall.policy.semantic import extract_iocs
    
    engine = SemanticGatingEngine(repo=temp_repo)
    
    # Test case 1: Private IP -> Should NOT be high risk
    ctx_private_ip = ToolCallContext(
        tool_name="test_tool",
        arguments={"ip": "127.0.0.1"}
    )
    iocs_private = extract_iocs(ctx_private_ip)
    assert not await engine.is_high_risk(ctx_private_ip, iocs_private)
    
    # Test case 2: External IP (new) -> Should be high risk
    ctx_external_ip = ToolCallContext(
        tool_name="test_tool",
        arguments={"ip": "8.8.8.8"}
    )
    iocs_external = extract_iocs(ctx_external_ip)
    assert await engine.is_high_risk(ctx_external_ip, iocs_external)

    # Test case 3: Structural gating escalated -> Should be high risk
    ctx_escalated = ToolCallContext(
        tool_name="test_tool",
        arguments={}
    )
    struct_res = StructuralGatingResult(
        decision=StructuralAction.ESCALATE_TO_SEMANTIC,
        requireSemanticReview=True
    )
    assert await engine.is_high_risk(ctx_escalated, {}, structural_result=struct_res)


@pytest.mark.asyncio
async def test_suspicion_score_calculation(temp_repo):
    from blackwall.policy.engine import StructuralGatingResult, StructuralAction
    from blackwall.policy.semantic import extract_iocs
    
    engine = SemanticGatingEngine(repo=temp_repo)
    
    # Base/empty context
    ctx_empty = ToolCallContext(tool_name="test_tool", arguments={})
    score_empty = await engine.calculate_suspicion_score(ctx_empty, {})
    assert score_empty == 0.0
    
    # External IP from high-risk country
    ctx_hr_geo = ToolCallContext(
        tool_name="test_tool",
        arguments={"ip": "8.8.8.8"},
        metadata={"country": "RU"}
    )
    iocs_hr = extract_iocs(ctx_hr_geo)
    score_hr = await engine.calculate_suspicion_score(ctx_hr_geo, iocs_hr)
    # Novelty (0.3) + Geolocation (0.2) = 0.50
    assert abs(score_hr - 0.50) < 0.01

    # Suspicious TLD (.xyz)
    ctx_xyz = ToolCallContext(
        tool_name="test_tool",
        arguments={"domain": "malicious.xyz"}
    )
    iocs_xyz = extract_iocs(ctx_xyz)
    score_xyz = await engine.calculate_suspicion_score(ctx_xyz, iocs_xyz)
    # Novelty (0.3) + Reputation (0.2) = 0.5
    assert abs(score_xyz - 0.5) < 0.01

    # High entropy hash
    ctx_hash = ToolCallContext(
        tool_name="test_tool",
        arguments={"file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}
    )
    iocs_hash = extract_iocs(ctx_hash)
    score_hash = await engine.calculate_suspicion_score(ctx_hash, iocs_hash)
    # Novelty (0.3) + Entropy (0.15) = 0.45
    assert abs(score_hash - 0.45) < 0.01


@pytest.mark.asyncio
async def test_gti_query_budget_tracker_integration():
    from blackwall.mcp.gti_client import GTIQueryBudgetTracker
    import asyncio
    
    tracker = GTIQueryBudgetTracker(capacity=4, replenishment_interval=0.1)
    try:
        # 4 queries should succeed
        for _ in range(4):
            assert await tracker.tryAcquire() is True
            
        # 5th query should fail (budget exhausted)
        assert await tracker.tryAcquire() is False
        assert await tracker.getAvailableTokens() == 0
        
        metrics = await tracker.getMetrics()
        assert metrics["queriesAttempted"] == 5
        assert metrics["queriesExecuted"] == 4
        assert metrics["queriesDeferred"] == 1
        assert metrics["budgetExhaustionCount"] == 1
        
        # Wait for replenishment (0.1s replenishment interval)
        await asyncio.sleep(0.15)
        assert await tracker.tryAcquire() is True
    finally:
        tracker.close()


@pytest.mark.asyncio
async def test_gti_query_skipped_and_redistributed_on_budget_exhaustion(temp_repo):
    from blackwall.mcp.gti_client import GTIQueryBudgetTracker
    from blackwall.models import IndicatorType
    
    # Mock GTI and CBM
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    
    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.0
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="f", callChain=[], depth=1, hasCriticalSink=True, criticalSinks=[]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="f", affectedModules=[], affectedFunctions=[], riskScore=0.5, isolation=BlastRadiusIsolation.HIGH
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[])
    mock_cbm.identifyUnsafeSinks = lambda sinks: []

    # Exhaust budget tracker
    tracker = GTIQueryBudgetTracker(capacity=4)
    try:
        for _ in range(4):
            await tracker.tryAcquire()
        assert await tracker.getAvailableTokens() == 0

        engine = SemanticGatingEngine(
            repo=temp_repo,
            gti_client=mock_gti,
            cbm_client=mock_cbm,
            budget_tracker=tracker
        )
        
        context = ToolCallContext(
            tool_name="safe_tool",
            arguments={"ip": "8.8.8.8", "targetFunction": "f"}
        )
        
        result = await engine.evaluate(context, "sandbox")
        
        # GTI should not be queried
        mock_gti.queryIOC.assert_not_called()
        
        # GTI penalty (0.2) must be applied
        # Weights redistributed: CBM gets 50%, Context gets 50%
        # Context score: 0.14
        # CBM score: hasCriticalSink (0.4) + riskScore (0.3 * 0.5 = 0.15) = 0.55
        # Base score = 0.5 * 0.55 + 0.5 * 0.14 = 0.275 + 0.07 = 0.345
        # Total score = Base score (0.345) + Penalty (0.2) = 0.545
        assert abs(result.threat_score - 0.545) < 0.01
        assert result.verdict == VerdictDecision.QUARANTINE
    finally:
        tracker.close()


from blackwall.mcp.gti_client import GTIBudgetExhaustedError

@pytest.mark.asyncio
async def test_gti_budget_exhausted_penalty_applied(temp_repo):
    # Setup mock GTI Client that raises GTIBudgetExhaustedError
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    mock_gti.queryIOC = AsyncMock(side_effect=GTIBudgetExhaustedError("Budget exhausted"))

    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4"}
    )

    result = await engine.evaluate(context, "sandbox")
    # GTI is budget exhausted, treated as unavailable (redistributed), gti_penalty=0.2 is applied.
    # Base score (context 100% since CBM is also unavailable) = 0.14
    # Final threat score = 0.14 + 0.2 = 0.34
    assert abs(result.threat_score - 0.34) < 0.01
    assert result.verdict == VerdictDecision.ALLOW


@pytest.mark.asyncio
async def test_weight_redistribution_on_budget_exhaustion(temp_repo):
    # Setup mock GTI Client that raises GTIBudgetExhaustedError
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    mock_gti.queryIOC = AsyncMock(side_effect=GTIBudgetExhaustedError("Budget exhausted"))

    mock_cbm = MagicMock(spec=CodebaseMemoryClient)
    mock_cbm.get_threat_score_penalty.return_value = 0.0
    mock_cbm.queryDependencyChain = AsyncMock(return_value=DependencyChain(
        rootFunction="ProcessOrder",
        callChain=["ProcessOrder", "ExecuteSQL"],
        depth=2,
        hasCriticalSink=True,
        criticalSinks=["ExecuteSQL"]
    ))
    mock_cbm.getBlastRadius = AsyncMock(return_value=BlastRadiusReport(
        targetNode="ProcessOrder",
        affectedModules=["src/db"],
        affectedFunctions=["ProcessOrder"],
        riskScore=0.8,
        isolation=BlastRadiusIsolation.MEDIUM
    ))
    mock_cbm.identifyCriticalSinks = AsyncMock(return_value=[])
    mock_cbm.identifyUnsafeSinks = lambda sinks: []

    # CBM score: hasCriticalSink (0.4) + riskScore (0.3 * 0.8 = 0.24) = 0.64
    # Context score: 0.14
    # Since GTI is budget exhausted: CBM (50%), Context (50%) + penalty (0.2)
    # Expected: 0.5 * 0.64 + 0.5 * 0.14 + 0.2 = 0.32 + 0.07 + 0.2 = 0.59
    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti, cbm_client=mock_cbm)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4", "targetFunction": "ProcessOrder"}
    )
    result = await engine.evaluate(context, "sandbox")
    assert abs(result.threat_score - 0.59) < 0.01


@pytest.mark.asyncio
async def test_gti_partial_results_preserved_on_budget_exhaustion(temp_repo):
    """
    Regression test: When GTI budget is exhausted mid-evaluation after some IOCs
    have been queried successfully, the partial GTI results should be preserved
    and incorporated into the threat score, not discarded.
    """
    # Setup mock GTI Client: first call succeeds with malicious result, second call raises budget exhaustion
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False

    malicious_response = GTIResponse(
        indicator="1.2.3.4",
        is_malicious=True,
        threat_categories=["botnet", "c2"],
        detection_rate=85.0,
        confidence=0.9
    )

    # First queryIOC call succeeds, second raises budget exhausted
    mock_gti.queryIOC = AsyncMock(side_effect=[
        malicious_response,  # First IP query succeeds
        GTIBudgetExhaustedError("Budget exhausted")  # Second URL query fails
    ])

    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)

    # Context with two IOCs: IP and URL
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4", "url": "http://evil.example.com/malware"}
    )

    result = await engine.evaluate(context, "sandbox")

    # GTI score from first (successful) query:
    # is_malicious (0.5) + detection_rate (0.3 * 0.85 = 0.255) + categories (0.2) = 0.955, capped to 1.0
    # Since we have partial GTI results, GTI should NOT be treated as unavailable
    # Weights: GTI (40% / 70% = 57.14%), Context (30% / 70% = 42.86%)
    # Context score: 0.14
    # Base score: 0.5714 * 0.955 + 0.4286 * 0.14 = 0.5457 + 0.06 = 0.6057
    # With gti_penalty (0.2): 0.6057 + 0.2 = 0.8057
    # Expected threat score should be >= 0.75 (BLOCK threshold)

    assert result.threat_score >= 0.75, f"Expected threat score >= 0.75, got {result.threat_score}"
    assert result.verdict == VerdictDecision.BLOCK

    # Verify that queryIOC was called twice (once successfully, once with budget exhaustion)
    assert mock_gti.queryIOC.call_count == 2


@pytest.mark.asyncio
async def test_gti_budget_exhaustion_does_not_skip_cached_iocs(temp_repo):
    """
    Regression test for Issue 2: When GTI budget is exhausted on an early IOC lookup,
    subsequent IOC types (especially cached ones like domains/hashes) should still be
    queried and detected, not skipped due to the exception.
    """
    # Pre-cache a malicious domain in the repository
    malicious_domain_response = {
        "indicator": "evil.example.com",
        "is_malicious": True,
        "threat_categories": ["malware", "phishing"],
        "detection_rate": 90.0,
        "last_analysis_date": "2024-01-01T00:00:00Z",
        "related_campaigns": ["campaign-xyz"],
        "confidence": 0.95
    }
    await temp_repo.cache_gti_response(
        indicator="evil.example.com",
        indicator_type="domain",
        response=malicious_domain_response
    )

    # Setup mock GTI Client: first IP query raises budget exhaustion
    mock_gti = MagicMock(spec=GTIMCPClient)
    mock_gti.is_degraded.return_value = False
    mock_gti.repo = temp_repo

    # First queryIOC call (IP) raises budget exhaustion
    # Second queryIOC call (domain) should succeed from cache
    mock_gti.queryIOC = AsyncMock(side_effect=[
        GTIBudgetExhaustedError("Budget exhausted"),  # IP query fails
    ])

    # Override queryIOC to handle cache lookups properly for the domain
    async def mock_query_ioc(indicator, indicator_type, context=None, skip_budget_check=False):
        if indicator == "evil.example.com":
            # Simulate cache hit by returning the cached response
            return GTIResponse(
                indicator="evil.example.com",
                is_malicious=True,
                threat_categories=["malware", "phishing"],
                detection_rate=90.0,
                confidence=0.95
            )
        raise GTIBudgetExhaustedError("Budget exhausted")

    mock_gti.queryIOC = AsyncMock(side_effect=mock_query_ioc)

    engine = SemanticGatingEngine(repo=temp_repo, gti_client=mock_gti)

    # Context with IP (will fail) and domain (should succeed from cache)
    context = ToolCallContext(
        tool_name="safe_tool",
        arguments={"ip": "1.2.3.4", "domain": "evil.example.com"}
    )

    result = await engine.evaluate(context, "sandbox")

    # Despite budget exhaustion on IP, the cached domain should be detected
    # GTI score from domain: is_malicious (0.5) + detection_rate (0.3 * 0.9 = 0.27) + categories (0.2) = 0.97
    # Weights: GTI (57.14%), Context (42.86%)
    # Context score: 0.14
    # Base score: 0.5714 * 0.97 + 0.4286 * 0.14 = 0.5542 + 0.06 = 0.6142
    # With gti_penalty (0.2): 0.6142 + 0.2 = 0.8142
    # Expected threat score should be >= 0.75 (BLOCK threshold)

    assert result.threat_score >= 0.75, f"Expected threat score >= 0.75 for cached malicious domain, got {result.threat_score}"
    assert result.verdict == VerdictDecision.BLOCK

    # Verify that queryIOC was called for both IP and domain
    assert mock_gti.queryIOC.call_count == 2

