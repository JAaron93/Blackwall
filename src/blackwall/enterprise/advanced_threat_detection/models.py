"""Data models for Blackwall Advanced Threat Detection pillar."""

from datetime import UTC, datetime
import math
from typing import Any
from uuid import UUID, uuid4

from pydantic import UUID4, BaseModel, Field, field_validator, model_validator

from blackwall.enterprise.advanced_threat_detection.enums import (
    AlertSeverity,
    CovertChannelType,
    EventSource,
    ExploitCategory,
    InboundMethodType,
    InboundProtocolType,
    InjectionSourceType,
    ReactionActionType,
)
from blackwall.validators import (
    validate_min_items,
    validate_non_empty_string,
    validate_temporal_sequence,
    validate_utc_datetime,
    validate_uuid_v4_format,
)


class NormalizedEvent(BaseModel):
    """Normalized threat event schema across all five Blackwall pillars."""

    event_id: UUID4
    timestamp: datetime
    source: EventSource
    agent_id: str
    action: str
    target: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(..., ge=0.0, le=1.0)

    @field_validator("event_id")
    @classmethod
    def validate_uuid_v4(cls, v: Any) -> UUID:
        """Validate event_id is a valid UUID v4."""
        return validate_uuid_v4_format(v)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("agent_id")
    @classmethod
    def validate_non_empty_agent_id(cls, v: str) -> str:
        """Validate agent_id is not empty or whitespace only."""
        return validate_non_empty_string(v, field_name="agent_id")


class AttackNode(BaseModel):
    """Graph node encapsulating a normalized event and edge connections."""

    node_id: UUID4
    event: NormalizedEvent
    incoming_edges: list[UUID4] = Field(default_factory=list)
    outgoing_edges: list[UUID4] = Field(default_factory=list)


class AttackPath(BaseModel):
    """Multi-hop attack path correlated across sequence of nodes."""

    path_id: UUID4
    agent_id: str
    nodes: list[AttackNode] = Field(..., min_length=2)
    start_time: datetime
    end_time: datetime
    risk_score: float = Field(..., ge=0.0, le=1.0)
    attack_stages: list[str] = Field(default_factory=list)
    correlation_score: float = Field(..., ge=0.0, le=1.0)

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_utc_timestamps(cls, v: datetime) -> datetime:
        """Validate start_time and end_time are UTC timezone-aware."""
        return validate_utc_datetime(v)

    @field_validator("nodes")
    @classmethod
    def validate_min_nodes(cls, v: list[AttackNode]) -> list[AttackNode]:
        """Validate nodes contains at least 2 nodes."""
        return validate_min_items(
            v, min_items=2, custom_msg="AttackPath nodes must contain at least 2 events"
        )

    @model_validator(mode="after")
    def validate_temporal_ordering(self) -> "AttackPath":
        """Validate end_time >= start_time."""
        validate_temporal_sequence(
            self.start_time,
            self.end_time,
            start_name="start_time",
            end_name="end_time",
        )
        return self


class SwarmEvidence(BaseModel):
    """Evidence structure for coordinated multi-agent swarm behavior."""

    swarm_id: UUID4
    agent_ids: set[str] = Field(..., min_length=2)
    shared_patterns: list[str] = Field(default_factory=list)
    temporal_correlation: float = Field(..., ge=0.0, le=1.0)
    coordination_score: float = Field(..., ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_utc_timestamps(cls, v: datetime) -> datetime:
        """Validate first_seen and last_seen are UTC timezone-aware."""
        return validate_utc_datetime(v)

    @field_validator("agent_ids")
    @classmethod
    def validate_min_agents(cls, v: set[str]) -> set[str]:
        """Validate agent_ids contains at least 2 agents."""
        return validate_min_items(
            v,
            min_items=2,
            custom_msg="SwarmEvidence agent_ids must contain at least 2 agents",
        )

    @model_validator(mode="after")
    def validate_temporal_ordering(self) -> "SwarmEvidence":
        """Validate last_seen >= first_seen."""
        validate_temporal_sequence(
            self.first_seen,
            self.last_seen,
            start_name="first_seen",
            end_name="last_seen",
        )
        return self


class CovertChannelEvidence(BaseModel):
    """Evidence structure for covert coordination channels and latent message boards."""

    channel_id: UUID4 = Field(default_factory=uuid4)
    channel_type: CovertChannelType
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    coordinating_agents: set[str] = Field(..., min_length=2)
    observed_artifacts: list[str] = Field(default_factory=list)
    deduction_rationale: str
    first_detected: datetime
    last_detected: datetime

    @field_validator("channel_id")
    @classmethod
    def validate_channel_id(cls, v: Any) -> UUID:
        """Validate channel_id is a valid UUID v4."""
        return validate_uuid_v4_format(v, field_name="channel_id")

    @field_validator("first_detected", "last_detected")
    @classmethod
    def validate_utc_timestamps(cls, v: datetime) -> datetime:
        """Validate first_detected and last_detected are UTC timezone-aware."""
        return validate_utc_datetime(v)

    @field_validator("coordinating_agents")
    @classmethod
    def validate_min_agents(cls, v: set[str]) -> set[str]:
        """Validate coordinating_agents contains at least 2 agents."""
        return validate_min_items(
            v,
            min_items=2,
            custom_msg="CovertChannelEvidence coordinating_agents must contain at least 2 agents",
        )

    @model_validator(mode="after")
    def validate_temporal_ordering(self) -> "CovertChannelEvidence":
        """Validate last_detected >= first_detected."""
        validate_temporal_sequence(
            self.first_detected,
            self.last_detected,
            start_name="first_detected",
            end_name="last_detected",
        )
        return self


class ExploitChainEvidence(BaseModel):
    """Evidence structure for zero-day exploit chaining sequences."""

    chain_id: UUID4
    exploits: list[tuple[str, ExploitCategory]] = Field(default_factory=list)
    novelty_score: float = Field(..., ge=0.0, le=1.0)
    chaining_confidence: float = Field(..., ge=0.0, le=1.0)


class PermissionGrant(BaseModel):
    """Permission grant schema for AI-Induced Lateral Movement tracking."""

    grant_id: UUID4 = Field(default_factory=uuid4)
    permission: str
    granted_by: UUID4
    granted_to: UUID4
    timestamp: datetime
    scope: str

    @field_validator("grant_id", "granted_by", "granted_to")
    @classmethod
    def validate_uuid_v4_fields(cls, v: Any, info: Any) -> UUID:
        """Validate grant_id, granted_by, and granted_to are valid UUID v4."""
        return validate_uuid_v4_format(v, field_name=info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("permission", "scope")
    @classmethod
    def validate_non_empty_fields(cls, v: str, info: Any) -> str:
        """Validate string fields are not empty or whitespace only."""
        return validate_non_empty_string(v, field_name=info.field_name)


class AILMEvidence(BaseModel):
    """Evidence structure for AI-Induced Lateral Movement (AILM)."""

    agent_id: str
    composed_permissions: set[str] = Field(default_factory=set)
    boundary_crossings: list[str] = Field(default_factory=list)
    risk_level: str


class C2Evidence(BaseModel):
    """Evidence structure for Command-and-Control (C2) infrastructure establishment."""

    agent_id: str
    c2_endpoints: list[str] = Field(default_factory=list)
    communication_pattern: str
    persistence_indicators: list[str] = Field(default_factory=list)


class K8sThreatEvidence(BaseModel):
    """Evidence structure for Kubernetes-specific container threats."""

    threat_type: str
    namespace: str
    pod_name: str
    service_account: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class RegistryThreatEvidence(BaseModel):
    """Evidence structure for package registry probing or exploitation."""

    registry_type: str
    package_name: str
    exploit_indicators: list[str] = Field(default_factory=list)
    cve_candidates: list[str] = Field(default_factory=list)
    probing_event_count: int = 1
    event_ids: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    """Real-time security alert published across Blackwall threat detection engines."""

    alert_id: UUID4 = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: AlertSeverity
    threat_type: str
    title: str
    description: str
    evidence_id: UUID4 | None = None
    agent_id: str | None = None
    agent_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("alert_id", "evidence_id")
    @classmethod
    def validate_uuid_v4_fields(cls, v: Any, info: Any) -> Any:
        """Validate alert_id and evidence_id are valid UUID v4."""
        if v is None:
            return None
        return validate_uuid_v4_format(v, field_name=info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("threat_type", "title", "description")
    @classmethod
    def validate_non_empty_fields(cls, v: str, info: Any) -> str:
        """Validate required string fields are not empty or whitespace only."""
        return validate_non_empty_string(v, field_name=info.field_name)


class ActiveReactionPayload(BaseModel):
    """Model representing an automated threat mitigation action dispatched across Pillars 1, 2, and 3."""

    reaction_id: UUID4 = Field(default_factory=uuid4)
    trigger_evidence_id: UUID4
    target_agent_id: str
    target_pid: int | None = Field(default=None, gt=0)
    target_ip: str | None = None
    action_type: ReactionActionType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evaluation_env_id: str | None = None
    status: str = "PENDING"
    execution_duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reaction_id", "trigger_evidence_id")
    @classmethod
    def validate_uuid_v4_fields(cls, v: Any, info: Any) -> Any:
        """Validate reaction_id and trigger_evidence_id are valid UUID v4."""
        return validate_uuid_v4_format(v, field_name=info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("target_agent_id")
    @classmethod
    def validate_target_agent_id(cls, v: str) -> str:
        """Validate target_agent_id is not empty or whitespace only."""
        return validate_non_empty_string(v, field_name="target_agent_id")

    @field_validator("target_pid")
    @classmethod
    def validate_target_pid(cls, v: int | None) -> int | None:
        """Validate target_pid is positive if provided."""
        if v is not None and v <= 0:
            raise ValueError("target_pid must be greater than 0")
        return v

    @field_validator("target_ip")
    @classmethod
    def validate_target_ip(cls, v: str | None) -> str | None:
        """Validate target_ip is a valid IPv4 or IPv6 address if provided."""
        if v is not None:
            clean = v.strip()
            if not clean:
                raise ValueError("target_ip must not be empty if specified")
            import ipaddress
            try:
                ipaddress.ip_address(clean)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address format: {v}") from exc
            return clean
        return None

    @field_validator("evaluation_env_id")
    @classmethod
    def validate_evaluation_env_id(cls, v: str | None) -> str | None:
        """Validate evaluation_env_id matches format if provided."""
        if v is not None:
            import re
            clean = validate_non_empty_string(v, field_name="evaluation_env_id")
            if not re.match(r"^[a-zA-Z0-9_-]+$", clean):
                raise ValueError(f"evaluation_env_id must match ^[a-zA-Z0-9_-]+$: {v}")
            return clean
        return None


class InboundProtocolMessage(BaseModel):
    """Model representing an incoming A2A or MCP JSON-RPC protocol message."""

    message_id: UUID4 = Field(default_factory=uuid4)
    sender_id: str = Field(..., min_length=1)
    recipient_agent_id: str = Field(..., min_length=1)
    protocol: InboundProtocolType
    method: InboundMethodType
    payload: dict[str, Any] = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("message_id")
    @classmethod
    def validate_uuid_v4(cls, v: Any, info: Any) -> UUID:
        """Validate message_id is a valid UUID v4."""
        return validate_uuid_v4_format(v, field_name=info.field_name)

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("sender_id", "recipient_agent_id")
    @classmethod
    def validate_non_empty_ids(cls, v: str, info: Any) -> str:
        """Validate string identifiers are not empty or whitespace only."""
        return validate_non_empty_string(v, field_name=info.field_name)

    @field_validator("payload")
    @classmethod
    def validate_non_empty_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate payload is a non-empty dictionary."""
        if not v or not isinstance(v, dict):
            raise ValueError("payload must be a non-empty dictionary")
        return v


class PromptInjectionEvidence(BaseModel):
    """Evidence structure for indirect prompt injection and data poisoning attempts."""

    scan_id: UUID4 = Field(default_factory=uuid4)
    source_context: InjectionSourceType
    detected_patterns: list[str] = Field(..., min_length=1)
    injection_confidence: float = Field(..., ge=0.0, le=1.0)
    sanitized_content: str = Field(..., min_length=1)

    @field_validator("scan_id")
    @classmethod
    def validate_uuid_v4(cls, v: Any, info: Any) -> UUID:
        """Validate scan_id is a valid UUID v4."""
        return validate_uuid_v4_format(v, field_name=info.field_name)

    @field_validator("detected_patterns")
    @classmethod
    def validate_min_patterns(cls, v: list[str]) -> list[str]:
        """Validate detected_patterns contains at least 1 pattern."""
        return validate_min_items(
            v, min_items=1, custom_msg="PromptInjectionEvidence detected_patterns must contain at least 1 pattern"
        )

    @field_validator("sanitized_content")
    @classmethod
    def validate_sanitized_content(cls, v: str, info: Any) -> str:
        """Validate sanitized_content is not empty or whitespace only."""
        return validate_non_empty_string(v, field_name=info.field_name)


class AgentQuotaUsage(BaseModel):
    """Model tracking real-time token consumption and velocity per agent identity (Pillar 6 Task 27)."""

    agent_id: str = Field(..., min_length=1)
    time_window_start: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tokens_consumed: int = Field(..., ge=0)
    api_call_count: int = Field(..., ge=0)
    token_burn_rate_per_sec: float = Field(..., ge=0.0)
    quota_exceeded: bool

    @field_validator("agent_id")
    @classmethod
    def validate_non_empty_agent_id(cls, v: str) -> str:
        """Validate agent_id is not empty or whitespace only."""
        return validate_non_empty_string(v, field_name="agent_id")

    @field_validator("time_window_start")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate time_window_start is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("tokens_consumed", "api_call_count")
    @classmethod
    def validate_non_negative_counts(cls, v: int, info: Any) -> int:
        """Validate token and call counts are non-negative integers."""
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"{info.field_name} must be a non-negative integer")
        return v

    @field_validator("token_burn_rate_per_sec")
    @classmethod
    def validate_non_negative_rate(cls, v: float) -> float:
        """Validate token burn rate is a finite non-negative float."""
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0.0:
            raise ValueError("token_burn_rate_per_sec must be a finite non-negative float")
        return float(v)





