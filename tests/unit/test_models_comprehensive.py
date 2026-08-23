"""Comprehensive unit tests for core data models and enums in src/blackwall/models.py."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from blackwall.models import (
    AttackerIdentity,
    AttackerProfile,
    BatchPayload,
    BatchResponse,
    BehaviorScore,
    CallbackToken,
    CBMResponse,
    EventType,
    GTIResponse,
    GraphStatistics,
    GroundTruthLabel,
    IdentitySource,
    IncidentReport,
    IndicatorType,
    PolicyServerState,
    RefactoringHint,
    RelationshipType,
    ResolverMetrics,
    SecurityEvent,
    SecurityMetrics,
    SinkType,
    SyncResolverMetrics,
    TestResult,
    ThreatSignature,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)


# ==============================================================================
# 1. Enums Testing
# ==============================================================================


class TestCoreEnums:
    """Verify all enum memberships and string values."""

    def test_event_type_members(self):
        assert EventType.INTERCEPTION == "INTERCEPTION"
        assert EventType.BLOCK == "BLOCK"
        assert EventType.ALLOW == "ALLOW"
        assert EventType.QUARANTINE == "QUARANTINE"
        assert EventType.SIGNATURE_CREATED == "SIGNATURE_CREATED"
        assert len(EventType) == 5

    def test_verdict_decision_members(self):
        assert VerdictDecision.ALLOW == "ALLOW"
        assert VerdictDecision.BLOCK == "BLOCK"
        assert VerdictDecision.QUARANTINE == "QUARANTINE"
        assert len(VerdictDecision) == 3

    def test_sink_type_members(self):
        assert SinkType.FILE_SYSTEM == "FILE_SYSTEM"
        assert SinkType.NETWORK == "NETWORK"
        assert SinkType.DATABASE == "DATABASE"
        assert SinkType.PROCESS == "PROCESS"
        assert len(SinkType) == 4

    def test_relationship_type_members(self):
        assert RelationshipType.CALLS == "CALLS"
        assert RelationshipType.DEPENDS_ON == "DEPENDS_ON"
        assert RelationshipType.MODIFIES == "MODIFIES"
        assert RelationshipType.SIMILAR_TO == "SIMILAR_TO"
        assert RelationshipType.MITIGATED_BY == "MITIGATED_BY"
        assert len(RelationshipType) == 5

    def test_ground_truth_label_members(self):
        assert GroundTruthLabel.MALICIOUS == "MALICIOUS"
        assert GroundTruthLabel.BENIGN == "BENIGN"
        assert len(GroundTruthLabel) == 2

    def test_indicator_type_members(self):
        assert IndicatorType.IP_ADDRESS == "IP_ADDRESS"
        assert IndicatorType.DOMAIN == "DOMAIN"
        assert IndicatorType.URL == "URL"
        assert IndicatorType.FILE_HASH == "FILE_HASH"
        assert len(IndicatorType) == 4

    def test_identity_source_members(self):
        assert IdentitySource.ADK_METADATA == "ADK_METADATA"
        assert IdentitySource.SYSTEM_PROCESS == "SYSTEM_PROCESS"
        assert IdentitySource.EBPF_KERNEL == "EBPF_KERNEL"
        assert IdentitySource.CONTAINER == "CONTAINER"
        assert IdentitySource.NETWORK_IP == "NETWORK_IP"
        assert IdentitySource.VAULT_TOKEN == "VAULT_TOKEN"
        assert len(IdentitySource) == 6


# ==============================================================================
# 2. TestResult, Verdict, and ToolCallContext
# ==============================================================================


class TestVerdictAndContext:
    def test_test_result_valid(self):
        tr = TestResult(verdict_decision=VerdictDecision.ALLOW)
        assert tr.verdict_decision == VerdictDecision.ALLOW
        assert tr.model_dump() == {"verdict_decision": "ALLOW"}

    @pytest.mark.parametrize("score", [0.0, 0.5, 1.0])
    def test_verdict_valid_boundary_scores(self, score):
        v = Verdict(
            decision=VerdictDecision.BLOCK,
            reasoning="Suspicious tool parameter detected",
            confidence_score=score,
        )
        assert v.decision == VerdictDecision.BLOCK
        assert v.confidence_score == score

    @pytest.mark.parametrize("invalid_score", [-0.01, 1.01, -10.0, 5.0])
    def test_verdict_out_of_bounds_score(self, invalid_score):
        with pytest.raises(ValidationError):
            Verdict(
                decision=VerdictDecision.ALLOW,
                reasoning="Invalid score",
                confidence_score=invalid_score,
            )

    def test_verdict_serialization_round_trip(self):
        v = Verdict(
            decision=VerdictDecision.QUARANTINE,
            reasoning="Needs deeper analysis",
            confidence_score=0.85,
        )
        dumped = v.model_dump()
        restored = Verdict(**dumped)
        assert restored == v

    def test_tool_call_context_minimal_and_full(self):
        minimal = ToolCallContext(tool_name="bash", arguments={"command": "ls"})
        assert minimal.tool_name == "bash"
        assert minimal.arguments == {"command": "ls"}
        assert minimal.metadata is None

        full = ToolCallContext(
            tool_name="eval_python",
            arguments={"code": "import os; os.listdir()"},
            metadata={"session_id": "sess-123", "risk_hint": "high"},
        )
        assert full.metadata == {"session_id": "sess-123", "risk_hint": "high"}
        assert ToolCallContext(**full.model_dump()) == full


# ==============================================================================
# 3. CallbackToken and Batch Models
# ==============================================================================


class TestCallbackTokenAndBatch:
    def test_callback_token_defaults_and_fields(self):
        token = CallbackToken(thread_id="thread-abc-123")
        assert isinstance(token.token_id, UUID)
        assert token.timestamp.tzinfo is timezone.utc
        assert token.thread_id == "thread-abc-123"
        assert token.tool_context is None
        assert token.correlation_id is None
        assert token.telemetry_span_id is None

        # Unique token_id auto-generation
        token2 = CallbackToken(thread_id="thread-abc-123")
        assert token.token_id != token2.token_id

    def test_callback_token_resume_callback_exclusion(self):
        called = False

        def mock_cb(v: Verdict):
            nonlocal called
            called = True

        ctx = ToolCallContext(tool_name="fs_read", arguments={"path": "/etc/hosts"})
        token = CallbackToken(
            thread_id="t-1",
            tool_context=ctx,
            resumeCallback=mock_cb,
            correlation_id="corr-99",
            telemetry_span_id="span-88",
        )
        assert token.resumeCallback is not None
        token.resumeCallback(Verdict(decision=VerdictDecision.ALLOW, reasoning="ok", confidence_score=0.9))
        assert called is True

        # resumeCallback should be excluded from model_dump
        dumped = token.model_dump()
        assert "resumeCallback" not in dumped or dumped.get("resumeCallback") is None

    def test_batch_payload_empty_and_populated(self):
        empty_payload = BatchPayload(
            sanitized_contexts=[],
            policy_snapshot={"policy_version": "1.0.0"},
        )
        assert isinstance(empty_payload.batch_id, UUID)
        assert empty_payload.sanitized_contexts == []
        assert empty_payload.previous_interaction_id is None

        ctx = ToolCallContext(tool_name="sql_query", arguments={"query": "SELECT 1"})
        populated = BatchPayload(
            sanitized_contexts=[ctx],
            policy_snapshot={"rule_count": 5},
            previous_interaction_id="inter-42",
        )
        assert len(populated.sanitized_contexts) == 1
        assert populated.previous_interaction_id == "inter-42"
        assert BatchPayload(**populated.model_dump()) == populated

    def test_batch_response_construction(self):
        v = Verdict(decision=VerdictDecision.ALLOW, reasoning="ok", confidence_score=1.0)
        resp = BatchResponse(
            verdicts=[v],
            processing_time=12.5,
            tokens_consumed=150,
            cache_hit_count=3,
        )
        assert len(resp.verdicts) == 1
        assert resp.processing_time == 12.5
        assert resp.tokens_consumed == 150
        assert resp.cache_hit_count == 3
        assert BatchResponse(**resp.model_dump()) == resp


# ==============================================================================
# 4. ThreatSignature, BehaviorScore, RefactoringHint, and Responses
# ==============================================================================


class TestSignaturesAndScores:
    def test_threat_signature_construction(self):
        sig = ThreatSignature(
            pattern=r"(?i)rm\s+-rf\s+/",
            description="Destructive filesystem wipe command",
            sink_type=SinkType.FILE_SYSTEM,
        )
        assert isinstance(sig.signature_id, UUID)
        assert sig.created_at.tzinfo is timezone.utc
        assert sig.sink_type == SinkType.FILE_SYSTEM
        assert ThreatSignature(**sig.model_dump()) == sig

    @pytest.mark.parametrize("score", [0.0, 0.42, 1.0])
    def test_behavior_score_valid(self, score):
        bs = BehaviorScore(score=score, risk_level="MEDIUM")
        assert bs.score == score
        assert bs.risk_level == "MEDIUM"

    @pytest.mark.parametrize("invalid_score", [-0.1, 1.1])
    def test_behavior_score_invalid(self, invalid_score):
        with pytest.raises(ValidationError):
            BehaviorScore(score=invalid_score, risk_level="HIGH")

    def test_refactoring_hint_valid_and_bounds(self):
        hint = RefactoringHint(
            suggestion="Use subprocess.run with arguments list instead of shell=True",
            confidence=0.92,
            target_code="os.system('cmd')",
            vulnerability_type="Command Injection",
            suggested_fix="subprocess.run(['cmd'], check=True)",
        )
        assert isinstance(hint.hint_id, UUID)
        assert hint.confidence == 0.92
        assert RefactoringHint(**hint.model_dump()) == hint

        with pytest.raises(ValidationError):
            RefactoringHint(suggestion="Fix", confidence=1.5)

    def test_gti_response_valid_and_defaults(self):
        gti = GTIResponse(
            indicator="198.51.100.23",
            is_malicious=True,
            threat_categories=["c2", "botnet"],
            detection_rate=0.88,
            confidence=0.95,
        )
        assert gti.is_malicious is True
        assert gti.threat_categories == ["c2", "botnet"]
        assert gti.detection_rate == 0.88
        assert gti.confidence == 0.95
        assert gti.related_campaigns == []
        assert GTIResponse(**gti.model_dump()) == gti

        # Confidence boundary validation
        with pytest.raises(ValidationError):
            GTIResponse(indicator="1.2.3.4", is_malicious=False, confidence=-0.5)

    def test_cbm_response_construction(self):
        cbm = CBMResponse(
            blast_radius=4,
            critical_sinks=[SinkType.FILE_SYSTEM, SinkType.NETWORK],
        )
        assert cbm.blast_radius == 4
        assert len(cbm.critical_sinks) == 2
        assert CBMResponse(**cbm.model_dump()) == cbm


# ==============================================================================
# 5. Metrics Models
# ==============================================================================


class TestMetricsModels:
    def test_security_metrics_defaults(self):
        sm = SecurityMetrics()
        assert sm.false_refusal_rate == 0.0
        assert sm.evasion_rate == 0.0
        assert sm.accuracy == 0.0
        assert sm.precision == 0.0
        assert sm.recall == 0.0
        assert sm.f1_score == 0.0
        assert sm.quarantine_count == 0

        custom_sm = SecurityMetrics(
            accuracy=0.95,
            precision=0.94,
            recall=0.96,
            f1_score=0.95,
            quarantine_count=12,
        )
        assert custom_sm.accuracy == 0.95
        assert SecurityMetrics(**custom_sm.model_dump()) == custom_sm

    def test_graph_statistics_construction(self):
        gs = GraphStatistics(node_count=150, edge_count=420)
        assert gs.node_count == 150
        assert gs.edge_count == 420
        assert GraphStatistics(**gs.model_dump()) == gs

    def test_resolver_metrics_valid_and_bounds(self):
        rm = ResolverMetrics(
            total_batches=10,
            average_batch_size=4.5,
            average_latency_ms=120.0,
            rate_limit_hits=2,
            cache_hit_rate=0.75,
        )
        assert rm.cache_hit_rate == 0.75
        assert ResolverMetrics(**rm.model_dump()) == rm

        with pytest.raises(ValidationError):
            ResolverMetrics(
                total_batches=1,
                average_batch_size=1.0,
                average_latency_ms=10.0,
                rate_limit_hits=0,
                cache_hit_rate=1.5,
            )

    def test_sync_resolver_metrics_defaults(self):
        srm = SyncResolverMetrics()
        assert srm.total_evaluations == 0
        assert srm.average_latency_ms == 0.0
        assert srm.rate_limit_hits == 0
        assert srm.gti_queries_executed == 0
        assert srm.gti_queries_deferred == 0
        assert srm.inline_signatures_generated == 0
        assert srm.block_count == 0
        assert srm.quarantine_count == 0
        assert srm.allow_count == 0

        srm.total_evaluations = 50
        srm.block_count = 5
        assert SyncResolverMetrics(**srm.model_dump()).total_evaluations == 50


# ==============================================================================
# 6. PolicyServerState and Semver Validator
# ==============================================================================


class TestPolicyServerState:
    @pytest.mark.parametrize("valid_semver", ["1.0.0", "0.1.0", "12.34.56", "2.10.300"])
    def test_policy_server_state_valid_semver(self, valid_semver):
        state = PolicyServerState(
            version=valid_semver,
            last_updated=datetime.now(timezone.utc),
            active_signatures=42,
        )
        assert state.version == valid_semver
        assert state.active_signatures == 42

    @pytest.mark.parametrize("invalid_semver", ["1.0", "v1.0.0", "1.0.0-alpha", "latest", ""])
    def test_policy_server_state_invalid_semver(self, invalid_semver):
        with pytest.raises(ValidationError):
            PolicyServerState(
                version=invalid_semver,
                last_updated=datetime.now(timezone.utc),
                active_signatures=10,
            )


# ==============================================================================
# 7. SecurityEvent and Verdict Presence Validation
# ==============================================================================


class TestSecurityEvent:
    @pytest.fixture
    def valid_context(self):
        return ToolCallContext(tool_name="curl", arguments={"url": "https://example.com"})

    @pytest.fixture
    def valid_verdict(self):
        return Verdict(decision=VerdictDecision.ALLOW, reasoning="Safe URL", confidence_score=0.99)

    def test_security_event_valid_construction(self, valid_context, valid_verdict):
        event = SecurityEvent(
            event_type=EventType.ALLOW,
            tool_context=valid_context,
            verdict=valid_verdict,
            agent_id="agent-01",
            behavior_score=BehaviorScore(score=0.1, risk_level="LOW"),
            gti_response=GTIResponse(indicator="example.com", is_malicious=False),
            cbm_response=CBMResponse(blast_radius=1, critical_sinks=[]),
            related_signatures=[uuid4()],
            telemetry_span_id="span-1234",
        )
        assert isinstance(event.event_id, UUID)
        assert event.timestamp.tzinfo is timezone.utc
        assert event.agent_id == "agent-01"
        assert event.verdict == valid_verdict
        assert SecurityEvent(**event.model_dump()) == event

    def test_security_event_timestamp_within_5_seconds(self, valid_context, valid_verdict):
        now = datetime.now(timezone.utc)
        # Exactly now: valid
        event = SecurityEvent(
            event_type=EventType.ALLOW,
            timestamp=now,
            tool_context=valid_context,
            verdict=valid_verdict,
        )
        assert event.timestamp == now

        # Within 3 seconds: valid
        valid_past = now - timedelta(seconds=3)
        event_past = SecurityEvent(
            event_type=EventType.ALLOW,
            timestamp=valid_past,
            tool_context=valid_context,
            verdict=valid_verdict,
        )
        assert event_past.timestamp == valid_past

    def test_security_event_stale_timestamp_raises(self, valid_context, valid_verdict):
        now = datetime.now(timezone.utc)
        stale = now - timedelta(seconds=10)
        with pytest.raises(ValidationError, match="within 5 seconds"):
            SecurityEvent(
                event_type=EventType.ALLOW,
                timestamp=stale,
                tool_context=valid_context,
                verdict=valid_verdict,
            )

        future_stale = now + timedelta(seconds=10)
        with pytest.raises(ValidationError, match="within 5 seconds"):
            SecurityEvent(
                event_type=EventType.ALLOW,
                timestamp=future_stale,
                tool_context=valid_context,
                verdict=valid_verdict,
            )

    def test_security_event_naive_or_non_utc_timestamp_raises(self, valid_context, valid_verdict):
        naive_now = datetime.now()
        with pytest.raises(ValidationError, match="timezone-aware"):
            SecurityEvent(
                event_type=EventType.ALLOW,
                timestamp=naive_now,
                tool_context=valid_context,
                verdict=valid_verdict,
            )

        est = timezone(timedelta(hours=-5))
        est_now = datetime.now(est)
        with pytest.raises(ValidationError, match="timezone-aware"):
            SecurityEvent(
                event_type=EventType.ALLOW,
                timestamp=est_now,
                tool_context=valid_context,
                verdict=valid_verdict,
            )

    @pytest.mark.parametrize(
        "ev_type",
        [
            EventType.INTERCEPTION,
            EventType.BLOCK,
            EventType.ALLOW,
            EventType.QUARANTINE,
        ],
    )
    def test_security_event_verdict_required_for_enforcement_types(self, ev_type, valid_context):
        with pytest.raises(ValidationError, match=f"Verdict is required for event_type {ev_type.value}"):
            SecurityEvent(
                event_type=ev_type,
                tool_context=valid_context,
                verdict=None,
            )

    def test_security_event_verdict_optional_for_signature_created(self, valid_context):
        event = SecurityEvent(
            event_type=EventType.SIGNATURE_CREATED,
            tool_context=valid_context,
            verdict=None,
        )
        assert event.event_type == EventType.SIGNATURE_CREATED
        assert event.verdict is None


# ==============================================================================
# 8. AttackerIdentity and Fingerprint Computation
# ==============================================================================


class TestAttackerIdentity:
    def test_attacker_identity_fingerprint_auto_computation(self):
        identity = AttackerIdentity(
            agent_id="agent-xyz",
            agent_name="AutoTester",
            thread_id="t-001",
            process_uid=1000,
            source_ip="192.168.1.50",
            primary_source=IdentitySource.SYSTEM_PROCESS,
        )
        expected_raw = "agent-xyz:AutoTester:t-001:1000:192.168.1.50:SYSTEM_PROCESS"
        expected_fp = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
        assert identity.identity_fingerprint == expected_fp

    def test_attacker_identity_none_fields_computation(self):
        identity = AttackerIdentity(
            agent_id=None,
            agent_name=None,
            thread_id=None,
            process_uid=None,
            source_ip=None,
            primary_source=IdentitySource.ADK_METADATA,
        )
        expected_raw = ":::::ADK_METADATA"
        expected_fp = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
        assert identity.identity_fingerprint == expected_fp

    def test_attacker_identity_matching_pre_supplied_fingerprint(self):
        expected_raw = "ag-1:::::ADK_METADATA"
        expected_fp = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()

        identity = AttackerIdentity(
            agent_id="ag-1",
            identity_fingerprint=expected_fp,
        )
        assert identity.identity_fingerprint == expected_fp

    def test_attacker_identity_mismatched_fingerprint_raises(self):
        with pytest.raises(ValidationError, match="does not match computed identity fingerprint"):
            AttackerIdentity(
                agent_id="ag-1",
                identity_fingerprint="mismatched_sha256_hash",
            )


# ==============================================================================
# 9. AttackerProfile and Temporal Sequence Validation
# ==============================================================================


class TestAttackerProfile:
    def test_attacker_profile_valid(self):
        now = datetime.now(timezone.utc)
        profile = AttackerProfile(
            fingerprint="abc123sha",
            first_seen=now - timedelta(minutes=10),
            last_seen=now,
            total_attacks=5,
            threat_score=0.75,
            associated_signatures=["sig-1", "sig-2"],
            targeted_tools=["bash", "sql"],
            risk_category="CRITICAL",
        )
        assert profile.total_attacks == 5
        assert profile.threat_score == 0.75
        assert AttackerProfile(**profile.model_dump()) == profile

    def test_attacker_profile_temporal_sequence_violation(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError, match="last_seen must be greater than or equal to first_seen"):
            AttackerProfile(
                fingerprint="abc123sha",
                first_seen=now,
                last_seen=now - timedelta(seconds=1),
            )

    def test_attacker_profile_naive_or_non_utc_timestamps(self):
        now = datetime.now(timezone.utc)
        naive = datetime.now()
        with pytest.raises(ValidationError, match="UTC timezone-aware"):
            AttackerProfile(fingerprint="fp", first_seen=naive, last_seen=now)

        with pytest.raises(ValidationError, match="UTC timezone-aware"):
            AttackerProfile(fingerprint="fp", first_seen=now, last_seen=naive)

    def test_attacker_profile_bounds(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            AttackerProfile(fingerprint="fp", first_seen=now, last_seen=now, total_attacks=0)

        with pytest.raises(ValidationError):
            AttackerProfile(fingerprint="fp", first_seen=now, last_seen=now, threat_score=1.2)

        with pytest.raises(ValidationError):
            AttackerProfile(fingerprint="fp", first_seen=now, last_seen=now, threat_score=-0.1)


# ==============================================================================
# 10. IncidentReport, Serialization, JSON, and Markdown
# ==============================================================================


class TestIncidentReport:
    @pytest.fixture
    def sample_identity(self):
        return AttackerIdentity(agent_id="attacker-99", agent_name="RogueAgent")

    @pytest.fixture
    def sample_profile(self, sample_identity):
        now = datetime.now(timezone.utc)
        return AttackerProfile(
            fingerprint=sample_identity.identity_fingerprint,
            first_seen=now - timedelta(hours=1),
            last_seen=now,
            total_attacks=3,
            threat_score=0.9,
        )

    def test_incident_report_valid(self, sample_identity, sample_profile):
        now = datetime.now(timezone.utc)
        ev_id = uuid4()
        report = IncidentReport(
            timestamp=now,
            event_id=ev_id,
            verdict=VerdictDecision.BLOCK,
            attacker_identity=sample_identity,
            attacker_profile=sample_profile,
            exploited_tool="bash_executor",
            sanitized_arguments={"cmd": "cat [[REDACTED]]"},
            attack_technique="T1059.004",
            mitigation_action="Block tool execution and revoke token",
            recommended_user_action="Audit caller credentials",
            attribution_confidence=0.95,
        )
        assert isinstance(report.report_id, UUID)
        assert report.event_id == ev_id
        assert report.verdict == VerdictDecision.BLOCK
        assert report.attribution_confidence == 0.95
        assert IncidentReport(**report.model_dump()) == report

    def test_incident_report_naive_timestamp_rejected(self, sample_identity, sample_profile):
        with pytest.raises(ValidationError, match="UTC timezone-aware"):
            IncidentReport(
                timestamp=datetime.now(),
                event_id=uuid4(),
                verdict=VerdictDecision.BLOCK,
                attacker_identity=sample_identity,
                attacker_profile=sample_profile,
                exploited_tool="tool",
                attack_technique="tech",
                mitigation_action="mit",
                recommended_user_action="rec",
                attribution_confidence=0.8,
            )

    def test_incident_report_to_json_and_markdown(self, sample_identity, sample_profile):
        now = datetime.now(timezone.utc)
        report = IncidentReport(
            timestamp=now,
            event_id=uuid4(),
            verdict=VerdictDecision.BLOCK,
            attacker_identity=sample_identity,
            attacker_profile=sample_profile,
            exploited_tool="kernel_exec",
            attack_technique="Process Injection",
            mitigation_action="Isolate container",
            recommended_user_action="Investigate host",
            attribution_confidence=0.88,
        )

        json_str = report.to_json()
        parsed_json = json.loads(json_str)
        assert parsed_json["exploited_tool"] == "kernel_exec"
        assert parsed_json["verdict"] == "BLOCK"

        md_str = report.to_markdown()
        assert "# Blackwall Incident Attribution Report" in md_str
        assert str(report.report_id) in md_str
        assert "kernel_exec" in md_str
        assert "RogueAgent" in md_str
        assert "88.0%" in md_str
