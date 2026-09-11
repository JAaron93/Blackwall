"""Property-based tests for core Blackwall data models.

Uses Hypothesis to verify:
  - Construction soundness: valid inputs generated via custom strategies produce valid instances
  - Validation rejection: out-of-bounds score values, invalid semver, and bad enums raise ValidationError
  - Serialization round-trip: Model.model_validate(instance.model_dump()) == instance
  - UUID uniqueness: auto-generated UUID fields have zero collisions across 1,000 generations
  - Bound invariant: confidence_score and score fields are strictly within [0.0, 1.0]
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
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
    GraphStatistics,
    GTIResponse,
    IdentitySource,
    IncidentReport,
    PolicyServerState,
    RefactoringHint,
    ResolverMetrics,
    SecurityEvent,
    SecurityMetrics,
    SinkType,
    SyncResolverMetrics,
    ThreatSignature,
    ToolCallContext,
    Verdict,
    VerdictDecision,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

valid_uuid4_st = st.uuids(version=4)
utc_datetime_st = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 1, 1),
    timezones=st.just(timezone.utc),
)

non_empty_str_st = st.text(min_size=1, max_size=50).filter(lambda s: bool(s.strip()))
unit_interval_st = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
out_of_bounds_unit_st = st.one_of(
    st.floats(max_value=-0.0001, allow_nan=False, allow_infinity=False),
    st.floats(min_value=1.0001, allow_nan=False, allow_infinity=False),
)

semver_st = st.tuples(
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
).map(lambda parts: f"{parts[0]}.{parts[1]}.{parts[2]}")

invalid_semver_st = st.sampled_from(["invalid", "1.0", "1.2.3.4", "v1.0.0", "1.0.0-beta", "a.b.c", ""])

primitive_value_st = st.one_of(
    st.text(max_size=40),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
    st.booleans(),
    st.none(),
)

arguments_dict_st = st.dictionaries(
    keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=15),
    values=primitive_value_st,
    max_size=5,
)

# Model strategies
verdict_st = st.builds(
    Verdict,
    decision=st.sampled_from(list(VerdictDecision)),
    reasoning=st.text(max_size=100),
    confidence_score=unit_interval_st,
)

tool_call_context_st = st.builds(
    ToolCallContext,
    tool_name=non_empty_str_st,
    arguments=arguments_dict_st,
    metadata=st.one_of(st.none(), arguments_dict_st),
)

behavior_score_st = st.builds(
    BehaviorScore,
    score=unit_interval_st,
    risk_level=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
)

cbm_response_st = st.builds(
    CBMResponse,
    blast_radius=st.integers(min_value=0, max_value=100),
    critical_sinks=st.lists(st.sampled_from(list(SinkType)), max_size=4),
)

gti_response_st = st.builds(
    GTIResponse,
    indicator=non_empty_str_st,
    is_malicious=st.booleans(),
    threat_categories=st.lists(st.text(max_size=20), max_size=3),
    detection_rate=unit_interval_st,
    last_analysis_date=st.one_of(st.none(), st.text(max_size=20)),
    related_campaigns=st.lists(st.text(max_size=20), max_size=3),
    confidence=unit_interval_st,
)

threat_signature_st = st.builds(
    ThreatSignature,
    signature_id=valid_uuid4_st,
    pattern=non_empty_str_st,
    created_at=utc_datetime_st,
    description=st.text(max_size=100),
    sink_type=st.sampled_from(list(SinkType)),
)

refactoring_hint_st = st.builds(
    RefactoringHint,
    hint_id=valid_uuid4_st,
    suggestion=non_empty_str_st,
    confidence=unit_interval_st,
    target_code=st.one_of(st.none(), st.text(max_size=50)),
    vulnerability_type=st.one_of(st.none(), st.text(max_size=30)),
    suggested_fix=st.one_of(st.none(), st.text(max_size=50)),
)

security_metrics_st = st.builds(
    SecurityMetrics,
    false_refusal_rate=unit_interval_st,
    evasion_rate=unit_interval_st,
    accuracy=unit_interval_st,
    precision=unit_interval_st,
    recall=unit_interval_st,
    f1_score=unit_interval_st,
    quarantine_count=st.integers(min_value=0, max_value=1000),
)

resolver_metrics_st = st.builds(
    ResolverMetrics,
    total_batches=st.integers(min_value=0, max_value=1000),
    average_batch_size=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    average_latency_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
    rate_limit_hits=st.integers(min_value=0, max_value=500),
    cache_hit_rate=unit_interval_st,
)

sync_resolver_metrics_st = st.builds(
    SyncResolverMetrics,
    total_evaluations=st.integers(min_value=0, max_value=10000),
    average_latency_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
    rate_limit_hits=st.integers(min_value=0, max_value=1000),
    gti_queries_executed=st.integers(min_value=0, max_value=1000),
    gti_queries_deferred=st.integers(min_value=0, max_value=1000),
    inline_signatures_generated=st.integers(min_value=0, max_value=1000),
    block_count=st.integers(min_value=0, max_value=1000),
    quarantine_count=st.integers(min_value=0, max_value=1000),
    allow_count=st.integers(min_value=0, max_value=1000),
)

policy_server_state_st = st.builds(
    PolicyServerState,
    version=semver_st,
    last_updated=utc_datetime_st,
    active_signatures=st.integers(min_value=0, max_value=10000),
)

graph_statistics_st = st.builds(
    GraphStatistics,
    node_count=st.integers(min_value=0, max_value=100000),
    edge_count=st.integers(min_value=0, max_value=500000),
)

callback_token_st = st.builds(
    CallbackToken,
    token_id=valid_uuid4_st,
    thread_id=non_empty_str_st,
    timestamp=utc_datetime_st,
    tool_context=st.one_of(st.none(), tool_call_context_st),
    correlation_id=st.one_of(st.none(), non_empty_str_st),
    telemetry_span_id=st.one_of(st.none(), st.text(max_size=30)),
)

attacker_identity_st = st.builds(
    AttackerIdentity,
    identity_id=valid_uuid4_st,
    agent_id=st.one_of(st.none(), non_empty_str_st),
    agent_name=st.one_of(st.none(), non_empty_str_st),
    agent_model=st.one_of(st.none(), non_empty_str_st),
    thread_id=st.one_of(st.none(), non_empty_str_st),
    process_pid=st.one_of(st.none(), st.integers(min_value=1, max_value=65535)),
    process_uid=st.one_of(st.none(), st.integers(min_value=0, max_value=65535)),
    process_name=st.one_of(st.none(), non_empty_str_st),
    process_cmdline=st.one_of(st.none(), st.text(max_size=50)),
    container_id=st.one_of(st.none(), non_empty_str_st),
    source_ip=st.one_of(st.none(), st.sampled_from(["192.168.1.1", "10.0.0.1", "127.0.0.1"])),
    vault_token_accessor=st.one_of(st.none(), non_empty_str_st),
    primary_source=st.sampled_from(list(IdentitySource)),
)

@st.composite
def attacker_profile_strategy(draw):
    first = draw(utc_datetime_st)
    # Ensure last_seen >= first_seen and both bounds are UTC timezone-aware
    last = draw(st.datetimes(
        min_value=first,
        max_value=datetime(2030, 1, 1, tzinfo=timezone.utc),
        timezones=st.just(timezone.utc),
    ))
    return AttackerProfile(
        fingerprint=draw(non_empty_str_st),
        first_seen=first,
        last_seen=last,
        total_attacks=draw(st.integers(min_value=1, max_value=1000)),
        threat_score=draw(unit_interval_st),
        associated_signatures=draw(st.lists(non_empty_str_st, max_size=3)),
        targeted_tools=draw(st.lists(non_empty_str_st, max_size=3)),
        risk_category=draw(st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"])),
    )

@st.composite
def incident_report_strategy(draw):
    identity = draw(attacker_identity_st)
    profile = draw(attacker_profile_strategy())
    return IncidentReport(
        report_id=draw(valid_uuid4_st),
        timestamp=draw(utc_datetime_st),
        event_id=draw(valid_uuid4_st),
        verdict=draw(st.sampled_from(list(VerdictDecision))),
        attacker_identity=identity,
        attacker_profile=profile,
        exploited_tool=draw(non_empty_str_st),
        sanitized_arguments=draw(arguments_dict_st),
        attack_technique=draw(non_empty_str_st),
        mitigation_action=draw(non_empty_str_st),
        recommended_user_action=draw(non_empty_str_st),
        attribution_confidence=draw(unit_interval_st),
    )

@st.composite
def security_event_strategy(draw):
    event_type = draw(st.sampled_from(list(EventType)))
    verdict = draw(verdict_st) if event_type != EventType.SIGNATURE_CREATED else draw(st.one_of(st.none(), verdict_st))
    return SecurityEvent(
        event_id=draw(valid_uuid4_st),
        event_type=event_type,
        timestamp=datetime.now(timezone.utc),
        tool_context=draw(tool_call_context_st),
        verdict=verdict,
        behavior_score=draw(st.one_of(st.none(), behavior_score_st)),
        agent_id=draw(st.one_of(st.none(), non_empty_str_st)),
        gti_response=draw(st.one_of(st.none(), gti_response_st)),
        cbm_response=draw(st.one_of(st.none(), cbm_response_st)),
        related_signatures=draw(st.lists(valid_uuid4_st, max_size=3)),
        telemetry_span_id=draw(st.one_of(st.none(), st.text(max_size=30))),
    )

batch_payload_st = st.builds(
    BatchPayload,
    batch_id=valid_uuid4_st,
    timestamp=utc_datetime_st,
    sanitized_contexts=st.lists(tool_call_context_st, max_size=5),
    policy_snapshot=arguments_dict_st,
    previous_interaction_id=st.one_of(st.none(), non_empty_str_st),
)

batch_response_st = st.builds(
    BatchResponse,
    verdicts=st.lists(verdict_st, max_size=5),
    processing_time=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    tokens_consumed=st.integers(min_value=0, max_value=100000),
    cache_hit_count=st.integers(min_value=0, max_value=1000),
)


# ---------------------------------------------------------------------------
# Property 1: Construction soundness (all models accept valid input)
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(v=verdict_st)
def test_verdict_construction_soundness(v: Verdict) -> None:
    """Property: Verdict constructs successfully and confidence_score is bounded in [0.0, 1.0]."""
    assert isinstance(v, Verdict)
    assert 0.0 <= v.confidence_score <= 1.0
    assert isinstance(v.decision, VerdictDecision)


@settings(max_examples=200)
@given(bs=behavior_score_st)
def test_behavior_score_construction_soundness(bs: BehaviorScore) -> None:
    """Property: BehaviorScore constructs successfully and score is bounded in [0.0, 1.0]."""
    assert isinstance(bs, BehaviorScore)
    assert 0.0 <= bs.score <= 1.0


@settings(max_examples=200)
@given(rh=refactoring_hint_st)
def test_refactoring_hint_construction_soundness(rh: RefactoringHint) -> None:
    """Property: RefactoringHint constructs successfully and confidence is bounded in [0.0, 1.0]."""
    assert isinstance(rh, RefactoringHint)
    assert 0.0 <= rh.confidence <= 1.0


@settings(max_examples=200)
@given(gti=gti_response_st)
def test_gti_response_construction_soundness(gti: GTIResponse) -> None:
    """Property: GTIResponse constructs successfully and confidence is bounded in [0.0, 1.0]."""
    assert isinstance(gti, GTIResponse)
    assert 0.0 <= gti.confidence <= 1.0


@settings(max_examples=200)
@given(se=security_event_strategy())
def test_security_event_construction_soundness(se: SecurityEvent) -> None:
    """Property: SecurityEvent constructs successfully with all composite models."""
    assert isinstance(se, SecurityEvent)
    assert isinstance(se.event_id, uuid.UUID)
    assert isinstance(se.event_type, EventType)


@settings(max_examples=200)
@given(bp=batch_payload_st)
def test_batch_payload_construction_soundness(bp: BatchPayload) -> None:
    """Property: BatchPayload constructs successfully with sanitized contexts."""
    assert isinstance(bp, BatchPayload)
    assert isinstance(bp.batch_id, uuid.UUID)


@settings(max_examples=200)
@given(sm=security_metrics_st)
def test_security_metrics_construction_soundness(sm: SecurityMetrics) -> None:
    """Property: SecurityMetrics constructs successfully with all metric rates bounded in [0.0, 1.0]."""
    assert isinstance(sm, SecurityMetrics)
    assert 0.0 <= sm.accuracy <= 1.0
    assert 0.0 <= sm.precision <= 1.0
    assert 0.0 <= sm.recall <= 1.0
    assert 0.0 <= sm.f1_score <= 1.0
    assert sm.quarantine_count >= 0


@settings(max_examples=200)
@given(rm=resolver_metrics_st)
def test_resolver_metrics_construction_soundness(rm: ResolverMetrics) -> None:
    """Property: ResolverMetrics constructs successfully and cache_hit_rate is bounded in [0.0, 1.0]."""
    assert isinstance(rm, ResolverMetrics)
    assert 0.0 <= rm.cache_hit_rate <= 1.0
    assert rm.total_batches >= 0


@settings(max_examples=200)
@given(srm=sync_resolver_metrics_st)
def test_sync_resolver_metrics_construction_soundness(srm: SyncResolverMetrics) -> None:
    """Property: SyncResolverMetrics constructs successfully with non-negative counters."""
    assert isinstance(srm, SyncResolverMetrics)
    assert srm.total_evaluations >= 0
    assert srm.average_latency_ms >= 0.0
    assert srm.rate_limit_hits >= 0


@settings(max_examples=200)
@given(pss=policy_server_state_st)
def test_policy_server_state_construction_soundness(pss: PolicyServerState) -> None:
    """Property: PolicyServerState constructs successfully with validated semver."""
    assert isinstance(pss, PolicyServerState)
    assert len(pss.version.split(".")) == 3


@settings(max_examples=200)
@given(gs=graph_statistics_st)
def test_graph_statistics_construction_soundness(gs: GraphStatistics) -> None:
    """Property: GraphStatistics constructs successfully with non-negative counts."""
    assert isinstance(gs, GraphStatistics)
    assert gs.node_count >= 0
    assert gs.edge_count >= 0


@settings(max_examples=200)
@given(ct=callback_token_st)
def test_callback_token_construction_soundness(ct: CallbackToken) -> None:
    """Property: CallbackToken constructs successfully with UUID token_id."""
    assert isinstance(ct, CallbackToken)
    assert isinstance(ct.token_id, uuid.UUID)


@settings(max_examples=200)
@given(ai=attacker_identity_st)
def test_attacker_identity_construction_soundness(ai: AttackerIdentity) -> None:
    """Property: AttackerIdentity constructs successfully and computes sha256 fingerprint."""
    assert isinstance(ai, AttackerIdentity)
    assert len(ai.identity_fingerprint) == 64
    assert isinstance(ai.primary_source, IdentitySource)


@settings(max_examples=200)
@given(ap=attacker_profile_strategy())
def test_attacker_profile_construction_soundness(ap: AttackerProfile) -> None:
    """Property: AttackerProfile constructs successfully and enforces first_seen <= last_seen."""
    assert isinstance(ap, AttackerProfile)
    assert ap.first_seen <= ap.last_seen
    assert 0.0 <= ap.threat_score <= 1.0
    assert ap.total_attacks >= 1


@settings(max_examples=200)
@given(ir=incident_report_strategy())
def test_incident_report_construction_soundness(ir: IncidentReport) -> None:
    """Property: IncidentReport constructs successfully and generates non-empty report formats."""
    assert isinstance(ir, IncidentReport)
    assert 0.0 <= ir.attribution_confidence <= 1.0
    md = ir.to_markdown()
    assert "# Blackwall Incident Attribution Report" in md
    assert ir.verdict.value in md


# ---------------------------------------------------------------------------
# Property 2: Invalid inputs consistently produce ValidationError
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(bad_score=out_of_bounds_unit_st)
def test_verdict_invalid_confidence_score_raises(bad_score: float) -> None:
    """Property: Verdict confidence_score out of [0.0, 1.0] raises ValidationError."""
    with pytest.raises(ValidationError):
        Verdict(decision=VerdictDecision.ALLOW, reasoning="test", confidence_score=bad_score)


@settings(max_examples=200)
@given(bad_score=out_of_bounds_unit_st)
def test_behavior_score_invalid_score_raises(bad_score: float) -> None:
    """Property: BehaviorScore score out of [0.0, 1.0] raises ValidationError."""
    with pytest.raises(ValidationError):
        BehaviorScore(score=bad_score, risk_level="HIGH")


@settings(max_examples=200)
@given(bad_score=out_of_bounds_unit_st)
def test_refactoring_hint_invalid_confidence_raises(bad_score: float) -> None:
    """Property: RefactoringHint confidence out of [0.0, 1.0] raises ValidationError."""
    with pytest.raises(ValidationError):
        RefactoringHint(suggestion="test", confidence=bad_score)


@settings(max_examples=200)
@given(bad_score=out_of_bounds_unit_st)
def test_resolver_metrics_invalid_cache_hit_rate_raises(bad_score: float) -> None:
    """Property: ResolverMetrics cache_hit_rate out of [0.0, 1.0] raises ValidationError."""
    with pytest.raises(ValidationError):
        ResolverMetrics(
            total_batches=1,
            average_batch_size=1.0,
            average_latency_ms=10.0,
            rate_limit_hits=0,
            cache_hit_rate=bad_score,
        )


@settings(max_examples=200)
@given(bad_version=invalid_semver_st)
def test_policy_server_state_invalid_semver_raises(bad_version: str) -> None:
    """Property: PolicyServerState with invalid semver format raises ValidationError."""
    with pytest.raises(ValidationError):
        PolicyServerState(
            version=bad_version,
            last_updated=datetime.now(timezone.utc),
            active_signatures=5,
        )


@settings(max_examples=200)
@given(bad_event_type=st.text().filter(lambda s: s not in [e.value for e in EventType]))
def test_security_event_invalid_event_type_raises(bad_event_type: str) -> None:
    """Property: SecurityEvent with invalid event_type raises ValidationError."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_type=bad_event_type,  # type: ignore
            tool_context=ToolCallContext(tool_name="test", arguments={}),
        )


@settings(max_examples=200)
@given(bad_confidence=out_of_bounds_unit_st)
def test_incident_report_invalid_confidence_raises(bad_confidence: float) -> None:
    """Property: IncidentReport attribution_confidence out of [0.0, 1.0] raises ValidationError."""
    with pytest.raises(ValidationError):
        IncidentReport(
            event_id=uuid.uuid4(),
            verdict=VerdictDecision.BLOCK,
            attacker_identity=AttackerIdentity(),
            attacker_profile=AttackerProfile(fingerprint="test"),
            exploited_tool="bash",
            attack_technique="T1059",
            mitigation_action="kill",
            recommended_user_action="isolate",
            attribution_confidence=bad_confidence,
        )


@settings(max_examples=200)
@given(bad_fingerprint=st.text(min_size=1, max_size=30).filter(lambda s: len(s) != 64))
def test_attacker_identity_mismatched_fingerprint_raises(bad_fingerprint: str) -> None:
    """Property: AttackerIdentity with explicitly mismatched fingerprint raises ValidationError."""
    with pytest.raises(ValidationError):
        AttackerIdentity(
            agent_id="test_agent",
            identity_fingerprint=bad_fingerprint,
        )


# ---------------------------------------------------------------------------
# Property 3: Serialization round-trip preserves all field values
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(v=verdict_st)
def test_verdict_serialization_round_trip(v: Verdict) -> None:
    """Property: Verdict.model_validate(v.model_dump()) preserves all field values."""
    dumped = v.model_dump()
    reconstructed = Verdict.model_validate(dumped)
    assert reconstructed == v


@settings(max_examples=200)
@given(tc=tool_call_context_st)
def test_tool_call_context_serialization_round_trip(tc: ToolCallContext) -> None:
    """Property: ToolCallContext.model_validate(tc.model_dump()) preserves all field values."""
    dumped = tc.model_dump()
    reconstructed = ToolCallContext.model_validate(dumped)
    assert reconstructed == tc


@settings(max_examples=200)
@given(ts=threat_signature_st)
def test_threat_signature_serialization_round_trip(ts: ThreatSignature) -> None:
    """Property: ThreatSignature.model_validate(ts.model_dump()) preserves all field values."""
    dumped = ts.model_dump()
    reconstructed = ThreatSignature.model_validate(dumped)
    assert reconstructed == ts


@settings(max_examples=200)
@given(cbm=cbm_response_st)
def test_cbm_response_serialization_round_trip(cbm: CBMResponse) -> None:
    """Property: CBMResponse.model_validate(cbm.model_dump()) preserves all field values."""
    dumped = cbm.model_dump()
    reconstructed = CBMResponse.model_validate(dumped)
    assert reconstructed == cbm


@settings(max_examples=200)
@given(gti=gti_response_st)
def test_gti_response_serialization_round_trip(gti: GTIResponse) -> None:
    """Property: GTIResponse.model_validate(gti.model_dump()) preserves all field values."""
    dumped = gti.model_dump()
    reconstructed = GTIResponse.model_validate(dumped)
    assert reconstructed == gti


@settings(max_examples=200)
@given(se=security_event_strategy())
def test_security_event_serialization_round_trip(se: SecurityEvent) -> None:
    """Property: SecurityEvent.model_validate(se.model_dump()) preserves all field values."""
    dumped = se.model_dump()
    reconstructed = SecurityEvent.model_validate(dumped)
    assert reconstructed == se


@settings(max_examples=200)
@given(br=batch_response_st)
def test_batch_response_serialization_round_trip(br: BatchResponse) -> None:
    """Property: BatchResponse.model_validate(br.model_dump()) preserves all field values."""
    dumped = br.model_dump()
    reconstructed = BatchResponse.model_validate(dumped)
    assert reconstructed == br


@settings(max_examples=200)
@given(sm=security_metrics_st)
def test_security_metrics_serialization_round_trip(sm: SecurityMetrics) -> None:
    """Property: SecurityMetrics.model_validate(sm.model_dump()) preserves all field values."""
    dumped = sm.model_dump()
    reconstructed = SecurityMetrics.model_validate(dumped)
    assert reconstructed == sm


@settings(max_examples=200)
@given(rm=resolver_metrics_st)
def test_resolver_metrics_serialization_round_trip(rm: ResolverMetrics) -> None:
    """Property: ResolverMetrics.model_validate(rm.model_dump()) preserves all field values."""
    dumped = rm.model_dump()
    reconstructed = ResolverMetrics.model_validate(dumped)
    assert reconstructed == rm


@settings(max_examples=200)
@given(srm=sync_resolver_metrics_st)
def test_sync_resolver_metrics_serialization_round_trip(srm: SyncResolverMetrics) -> None:
    """Property: SyncResolverMetrics.model_validate(srm.model_dump()) preserves all field values."""
    dumped = srm.model_dump()
    reconstructed = SyncResolverMetrics.model_validate(dumped)
    assert reconstructed == srm


@settings(max_examples=200)
@given(pss=policy_server_state_st)
def test_policy_server_state_serialization_round_trip(pss: PolicyServerState) -> None:
    """Property: PolicyServerState.model_validate(pss.model_dump()) preserves all field values."""
    dumped = pss.model_dump()
    reconstructed = PolicyServerState.model_validate(dumped)
    assert reconstructed == pss


@settings(max_examples=200)
@given(gs=graph_statistics_st)
def test_graph_statistics_serialization_round_trip(gs: GraphStatistics) -> None:
    """Property: GraphStatistics.model_validate(gs.model_dump()) preserves all field values."""
    dumped = gs.model_dump()
    reconstructed = GraphStatistics.model_validate(dumped)
    assert reconstructed == gs


@settings(max_examples=200)
@given(ct=callback_token_st)
def test_callback_token_serialization_round_trip(ct: CallbackToken) -> None:
    """Property: CallbackToken.model_validate(ct.model_dump()) preserves all field values."""
    dumped = ct.model_dump()
    reconstructed = CallbackToken.model_validate(dumped)
    assert reconstructed == ct


@settings(max_examples=200)
@given(ai=attacker_identity_st)
def test_attacker_identity_serialization_round_trip(ai: AttackerIdentity) -> None:
    """Property: AttackerIdentity.model_validate(ai.model_dump()) preserves all field values."""
    dumped = ai.model_dump()
    reconstructed = AttackerIdentity.model_validate(dumped)
    assert reconstructed == ai


@settings(max_examples=200)
@given(ap=attacker_profile_strategy())
def test_attacker_profile_serialization_round_trip(ap: AttackerProfile) -> None:
    """Property: AttackerProfile.model_validate(ap.model_dump()) preserves all field values."""
    dumped = ap.model_dump()
    reconstructed = AttackerProfile.model_validate(dumped)
    assert reconstructed == ap


@settings(max_examples=200)
@given(ir=incident_report_strategy())
def test_incident_report_serialization_round_trip(ir: IncidentReport) -> None:
    """Property: IncidentReport.model_validate(ir.model_dump()) preserves all field values."""
    dumped = ir.model_dump()
    reconstructed = IncidentReport.model_validate(dumped)
    assert reconstructed == ir


# ---------------------------------------------------------------------------
# Property 4: UUID fields are unique across 1,000 generations
# ---------------------------------------------------------------------------

def test_uuid_fields_unique_across_1000_generations() -> None:
    """Property: Auto-generated UUID fields produce 1,000 unique UUIDs without collisions."""
    tokens = [CallbackToken(thread_id=f"thread-{i}") for i in range(1000)]
    token_ids = {t.token_id for t in tokens}
    assert len(token_ids) == 1000
    assert all(isinstance(t_id, uuid.UUID) and t_id.version == 4 for t_id in token_ids)

    events = [
        SecurityEvent(
            event_type=EventType.INTERCEPTION,
            tool_context=ToolCallContext(tool_name="tool", arguments={}),
            verdict=Verdict(decision=VerdictDecision.ALLOW, reasoning="test", confidence_score=0.9),
        )
        for _ in range(1000)
    ]
    event_ids = {e.event_id for e in events}
    assert len(event_ids) == 1000

    hints = [RefactoringHint(suggestion="hint", confidence=0.8) for _ in range(1000)]
    hint_ids = {h.hint_id for h in hints}
    assert len(hint_ids) == 1000

    signatures = [
        ThreatSignature(
            pattern="regex",
            description="desc",
            sink_type=SinkType.NETWORK,
        )
        for _ in range(1000)
    ]
    sig_ids = {s.signature_id for s in signatures}
    assert len(sig_ids) == 1000
