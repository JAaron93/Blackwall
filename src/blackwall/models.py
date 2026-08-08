from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional
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
    arguments: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class CallbackToken(BaseModel):
    token_id: UUID = Field(default_factory=uuid4)
    thread_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_context: Optional[ToolCallContext] = None
    resumeCallback: Optional[Callable[[Verdict], Any]] = Field(
        default=None, exclude=True
    )
    correlation_id: Optional[str] = None
    telemetry_span_id: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}


class BatchPayload(BaseModel):
    batch_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sanitized_contexts: List[ToolCallContext]
    policy_snapshot: Dict[str, Any]
    previous_interaction_id: Optional[str] = None


class BatchResponse(BaseModel):
    verdicts: List[Verdict]
    processing_time: float
    tokens_consumed: int
    cache_hit_count: int


class ThreatSignature(BaseModel):
    signature_id: UUID = Field(default_factory=uuid4)
    pattern: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str
    sink_type: SinkType


class BehaviorScore(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str


class RefactoringHint(BaseModel):
    hint_id: UUID = Field(default_factory=uuid4)
    suggestion: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    target_code: Optional[str] = None
    vulnerability_type: Optional[str] = None
    suggested_fix: Optional[str] = None


class IndicatorType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"


class GTIResponse(BaseModel):
    indicator: str
    is_malicious: bool
    threat_categories: List[str] = Field(default_factory=list)
    detection_rate: float = Field(default=0.0)
    last_analysis_date: Optional[str] = None
    related_campaigns: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CBMResponse(BaseModel):
    blast_radius: int
    critical_sinks: List[SinkType]


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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_context: ToolCallContext
    verdict: Optional[Verdict] = None
    behavior_score: Optional[BehaviorScore] = None
    agent_id: Optional[str] = None
    gti_response: Optional[GTIResponse] = None
    cbm_response: Optional[CBMResponse] = None
    related_signatures: List[UUID] = Field(default_factory=list)
    telemetry_span_id: Optional[str] = None

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() != timezone.utc.utcoffset(v):
            raise ValueError("Timestamp must be timezone-aware")
        now = datetime.now(timezone.utc)
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


class AttackerIdentity(BaseModel):
    identity_id: UUID = Field(default_factory=uuid4)
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_model: Optional[str] = None
    thread_id: Optional[str] = None
    process_pid: Optional[int] = None
    process_uid: Optional[int] = None
    process_name: Optional[str] = None
    process_cmdline: Optional[str] = None
    container_id: Optional[str] = None
    source_ip: Optional[str] = None
    vault_token_accessor: Optional[str] = None
    primary_source: IdentitySource = IdentitySource.ADK_METADATA
    identity_fingerprint: str = ""

    @model_validator(mode="after")
    def compute_fingerprint(self) -> "AttackerIdentity":
        uid_str = "" if self.process_uid is None else str(self.process_uid)
        raw = f"{self.agent_id or ''}:{self.agent_name or ''}:{self.thread_id or ''}:{uid_str}:{self.source_ip or ''}:{self.primary_source.value}"
        computed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        if self.identity_fingerprint and self.identity_fingerprint != computed:
            raise ValueError("Provided identity_fingerprint does not match computed identity fingerprint")

        self.identity_fingerprint = computed
        return self


class AttackerProfile(BaseModel):
    fingerprint: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_attacks: int = Field(default=1, ge=1)
    threat_score: float = Field(default=0.5, ge=0.0, le=1.0)
    associated_signatures: List[str] = Field(default_factory=list)
    targeted_tools: List[str] = Field(default_factory=list)
    risk_category: str = "HIGH"

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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: UUID
    verdict: VerdictDecision
    attacker_identity: AttackerIdentity
    attacker_profile: AttackerProfile
    exploited_tool: str
    sanitized_arguments: Dict[str, Any] = Field(default_factory=dict)
    attack_technique: str
    mitigation_action: str
    recommended_user_action: str
    attribution_confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        return validate_utc_datetime(v)

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        return f"""# Blackwall Incident Attribution Report
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


