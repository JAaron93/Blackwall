import re
from datetime import datetime, timezone
from enum import Enum
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


class GTIResponse(BaseModel):
    ioc_match: bool
    malware_campaign: Optional[str] = None
    threat_score: float = Field(..., ge=0.0, le=1.0)


class CBMResponse(BaseModel):
    blast_radius: int
    critical_sinks: List[SinkType]


class SecurityMetrics(BaseModel):
    total_events: int
    blocked_events: int
    allowed_events: int


class GraphStatistics(BaseModel):
    node_count: int
    edge_count: int


class ResolverMetrics(BaseModel):
    total_batches: int
    average_batch_size: float
    average_latency_ms: float
    rate_limit_hits: int
    cache_hit_rate: float = Field(..., ge=0.0, le=1.0)


class PolicyServerState(BaseModel):
    version: str
    last_updated: datetime
    active_signatures: int

    @field_validator("version")
    @classmethod
    def validate_semver(cls, v: str) -> str:
        if not re.match(r"^\d+\.\d+\.\d+$", v):
            raise ValueError(
                "Version must be in MAJOR.MINOR.PATCH semantic versioning format"
            )
        return v


class SecurityEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_context: ToolCallContext
    verdict: Optional[Verdict] = None
    behavior_score: Optional[BehaviorScore] = None

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
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
