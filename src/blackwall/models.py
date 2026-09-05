import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class EventType(str, Enum):
    INTERCEPTION = "INTERCEPTION"
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    SIGNATURE_CREATED = "SIGNATURE_CREATED"


class VerdictDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class SinkType(str, Enum):
    FILE_SYSTEM = "FILE_SYSTEM"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    PROCESS = "PROCESS"


class RelationshipType(str, Enum):
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    MODIFIES = "MODIFIES"
    SIMILAR_TO = "SIMILAR_TO"
    MITIGATED_BY = "MITIGATED_BY"


class GroundTruthLabel(str, Enum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class TestResult(BaseModel):
    verdict_decision: VerdictDecision


class Verdict(BaseModel):
    decision: VerdictDecision
    reasoning: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)


class ToolCallContext(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    metadata: dict[str, Any] | None = None


class CallbackToken(BaseModel):
    token_id: UUID = Field(default_factory=uuid4)
    thread_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_context: ToolCallContext | None = None
    resumeCallback: Callable[[Verdict], Any] | None = Field(
        default=None, exclude=True
    )
    correlation_id: str | None = None
    telemetry_span_id: str | None = None

    model_config = {"arbitrary_types_allowed": True}


class BatchPayload(BaseModel):
    batch_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sanitized_contexts: list[ToolCallContext]
    policy_snapshot: dict[str, Any]
    previous_interaction_id: str | None = None


class BatchResponse(BaseModel):
    verdicts: list[Verdict]
    processing_time: float
    tokens_consumed: int
    cache_hit_count: int


class ThreatSignature(BaseModel):
    signature_id: UUID = Field(default_factory=uuid4)
    pattern: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str
    sink_type: SinkType


class BehaviorScore(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str


class RefactoringHint(BaseModel):
    hint_id: UUID = Field(default_factory=uuid4)
    suggestion: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    target_code: str | None = None
    vulnerability_type: str | None = None
    suggested_fix: str | None = None


class IndicatorType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"


class GTIResponse(BaseModel):
    indicator: str
    is_malicious: bool
    threat_categories: list[str] = Field(default_factory=list)
    detection_rate: float = Field(default=0.0)
    last_analysis_date: str | None = None
    related_campaigns: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CBMResponse(BaseModel):
    blast_radius: int
    critical_sinks: list[SinkType]


class SecurityMetrics(BaseModel):
    false_refusal_rate: float = 0.0
    evasion_rate: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    quarantine_count: int = 0


class GraphStatistics(BaseModel):
    node_count: int
    edge_count: int


class ResolverMetrics(BaseModel):
    total_batches: int
    average_batch_size: float
    average_latency_ms: float
    rate_limit_hits: int
    cache_hit_rate: float = Field(..., ge=0.0, le=1.0)


class SyncResolverMetrics(BaseModel):
    """Metrics for the free-tier SyncResolver."""

    total_evaluations: int = 0
    average_latency_ms: float = 0.0
    rate_limit_hits: int = 0
    gti_queries_executed: int = 0
    gti_queries_deferred: int = 0
    inline_signatures_generated: int = 0
    block_count: int = 0
    quarantine_count: int = 0
    allow_count: int = 0


from blackwall.validators import (
    validate_semver_format,
    validate_temporal_sequence,
    validate_utc_datetime,
)


class PolicyServerState(BaseModel):
    version: str
    last_updated: datetime
    active_signatures: int

    @field_validator("version")
    @classmethod
    def validate_semver(cls, v: str) -> str:
        return validate_semver_format(v)


class SecurityEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_context: ToolCallContext
    verdict: Verdict | None = None
    behavior_score: BehaviorScore | None = None
    agent_id: str | None = None
    gti_response: GTIResponse | None = None
    cbm_response: CBMResponse | None = None
    related_signatures: list[UUID] = Field(default_factory=list)
    telemetry_span_id: str | None = None

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() != UTC.utcoffset(v):
            raise ValueError("Timestamp must be timezone-aware")
        now = datetime.now(UTC)
        diff = abs((now - v).total_seconds())
        if diff > 5.0:
            raise ValueError(
                f"Timestamp must be within 5 seconds of current time, got diff {diff}s"
            )
        return v



    @model_validator(mode="after")
    def validate_verdict_presence(self) -> "SecurityEvent":
        if self.verdict is None and self.event_type in {
            EventType.INTERCEPTION,
            EventType.BLOCK,
            EventType.ALLOW,
            EventType.QUARANTINE,
        }:
            raise ValueError(
                f"Verdict is required for event_type {self.event_type.value}"
            )
        return self


class IdentitySource(str, Enum):
    ADK_METADATA = "ADK_METADATA"
    SYSTEM_PROCESS = "SYSTEM_PROCESS"
    EBPF_KERNEL = "EBPF_KERNEL"
    CONTAINER = "CONTAINER"
    NETWORK_IP = "NETWORK_IP"
    VAULT_TOKEN = "VAULT_TOKEN"


class LinguisticSwarmMarkers(BaseModel):
    is_collective: bool = False
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    detected_pronouns: list[str] = Field(default_factory=list)
    consensus_keywords: list[str] = Field(default_factory=list)
    collective_identity_inferred: str | None = None


class SwarmContextSummary(BaseModel):
    swarm_id: UUID | None = None
    is_collective: bool = False
    collective_name: str | None = None
    collective_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    coordinating_agents: list[str] = Field(default_factory=list)
    suspected_covert_channels: list[str] = Field(default_factory=list)
    covert_channel_type: str | None = None
    deduction_rationale: str | None = None
    first_detected: datetime | None = None
    last_detected: datetime | None = None

    @field_validator("first_detected", "last_detected")
    @classmethod
    def validate_utc_timestamps(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return validate_utc_datetime(v)

    @model_validator(mode="after")
    def validate_temporal_ordering(self) -> "SwarmContextSummary":
        if self.first_detected is not None and self.last_detected is not None:
            validate_temporal_sequence(
                self.first_detected,
                self.last_detected,
                start_name="first_detected",
                end_name="last_detected",
            )
        return self


class AttackerIdentity(BaseModel):
    identity_id: UUID = Field(default_factory=uuid4)
    agent_id: str | None = None
    agent_name: str | None = None
    agent_model: str | None = None
    thread_id: str | None = None
    process_pid: int | None = None
    process_uid: int | None = None
    process_name: str | None = None
    process_cmdline: str | None = None
    container_id: str | None = None
    source_ip: str | None = None
    vault_token_accessor: str | None = None
    primary_source: IdentitySource = IdentitySource.ADK_METADATA
    identity_fingerprint: str = ""
    is_collective: bool = False
    collective_name: str | None = None
    linguistic_markers: LinguisticSwarmMarkers | None = None
    session_salt: str | None = None

    @model_validator(mode="after")
    def compute_fingerprint(self) -> "AttackerIdentity":
        uid_str = "" if self.process_uid is None else str(self.process_uid)
        salt_str = f":{self.session_salt}" if self.session_salt else ""
        raw = f"{self.agent_id or ''}:{self.agent_name or ''}:{self.thread_id or ''}:{uid_str}:{self.source_ip or ''}:{self.primary_source.value}{salt_str}"
        computed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.identity_fingerprint and self.identity_fingerprint != computed:
            raise ValueError("Provided identity_fingerprint does not match computed identity fingerprint")

        self.identity_fingerprint = computed
        return self


class AttackerProfile(BaseModel):
    fingerprint: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_attacks: int = Field(default=1, ge=1)
    threat_score: float = Field(default=0.5, ge=0.0, le=1.0)
    associated_signatures: list[str] = Field(default_factory=list)
    targeted_tools: list[str] = Field(default_factory=list)
    risk_category: str = "HIGH"
    swarm_memberships: list[UUID] = Field(default_factory=list)
    suspected_covert_channels: list[str] = Field(default_factory=list)
    collective_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    collective_name: str | None = None

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        return validate_utc_datetime(v)

    @model_validator(mode="after")
    def validate_temporal_ordering(self) -> "AttackerProfile":
        validate_temporal_sequence(
            self.first_seen,
            self.last_seen,
            start_name="first_seen",
            end_name="last_seen",
        )
        return self


class IncidentReport(BaseModel):
    report_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_id: UUID
    verdict: VerdictDecision
    attacker_identity: AttackerIdentity
    attacker_profile: AttackerProfile
    exploited_tool: str
    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)
    attack_technique: str
    mitigation_action: str
    recommended_user_action: str
    attribution_confidence: float = Field(..., ge=0.0, le=1.0)
    swarm_id: UUID | None = None
    is_collective: bool = False
    suspected_covert_channels: list[str] = Field(default_factory=list)
    collective_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    collective_attribution_summary: str | None = None

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        return validate_utc_datetime(v)

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        base = f"""# Blackwall Incident Attribution Report
- **Report ID**: `{self.report_id}`
- **Timestamp**: {self.timestamp.isoformat()}
- **Verdict**: `{self.verdict.value}`
- **Exploited Tool**: `{self.exploited_tool}`
- **Attacker Agent**: `{self.attacker_identity.agent_name or self.attacker_identity.agent_id or 'Unknown'}`
- **Attacker Fingerprint**: `{self.attacker_identity.identity_fingerprint}`
- **Attack Technique**: {self.attack_technique}
- **Mitigation Action**: {self.mitigation_action}
- **Recommended Action**: {self.recommended_user_action}
- **Attribution Confidence**: {self.attribution_confidence * 100:.1f}%
"""
        if self.is_collective:
            collective_name_str = (
                self.attacker_identity.collective_name
                or self.attacker_profile.collective_name
                or "Unknown Fleet"
            )
            base += f"""- **Swarm Attribution**: Collective Swarm Detected (`{collective_name_str}`)
- **Swarm ID**: `{self.swarm_id or 'Unassigned'}`
- **Collective Confidence**: {self.collective_confidence * 100:.1f}%
- **Suspected Covert Channels**: {', '.join(self.suspected_covert_channels) if self.suspected_covert_channels else 'None'}
"""
            if self.collective_attribution_summary:
                base += f"- **Summary**: {self.collective_attribution_summary}\n"
        return base



