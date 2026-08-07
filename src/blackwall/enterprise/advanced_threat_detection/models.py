"""Data models for Blackwall Advanced Threat Detection pillar."""

from datetime import datetime
from typing import Any, Dict, List, Set, Tuple
from uuid import UUID

from pydantic import BaseModel, Field, UUID4, field_validator, model_validator

from blackwall.enterprise.advanced_threat_detection.enums import (
    EventSource,
    ExploitCategory,
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
    metadata: Dict[str, Any] = Field(default_factory=dict)
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
    incoming_edges: List[UUID4] = Field(default_factory=list)
    outgoing_edges: List[UUID4] = Field(default_factory=list)


class AttackPath(BaseModel):
    """Multi-hop attack path correlated across sequence of nodes."""

    path_id: UUID4
    agent_id: str
    nodes: List[AttackNode] = Field(..., min_length=2)
    start_time: datetime
    end_time: datetime
    risk_score: float = Field(..., ge=0.0, le=1.0)
    attack_stages: List[str] = Field(default_factory=list)
    correlation_score: float = Field(..., ge=0.0, le=1.0)

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_utc_timestamps(cls, v: datetime) -> datetime:
        """Validate start_time and end_time are UTC timezone-aware."""
        return validate_utc_datetime(v)

    @field_validator("nodes")
    @classmethod
    def validate_min_nodes(cls, v: List[AttackNode]) -> List[AttackNode]:
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
    agent_ids: Set[str] = Field(..., min_items=2)
    shared_patterns: List[str] = Field(default_factory=list)
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
    def validate_min_agents(cls, v: Set[str]) -> Set[str]:
        """Validate agent_ids contains at least 2 agents."""
        return validate_min_items(
            v, min_items=2, custom_msg="SwarmEvidence agent_ids must contain at least 2 agents"
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


class ExploitChainEvidence(BaseModel):
    """Evidence structure for zero-day exploit chaining sequences."""

    chain_id: UUID4
    exploits: List[Tuple[str, ExploitCategory]] = Field(default_factory=list)
    novelty_score: float = Field(..., ge=0.0, le=1.0)
    chaining_confidence: float = Field(..., ge=0.0, le=1.0)


class PermissionGrant(BaseModel):
    """Permission grant schema for AI-Induced Lateral Movement tracking."""

    permission: str
    granted_by: str
    granted_to: str
    timestamp: datetime
    scope: str

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: datetime) -> datetime:
        """Validate timestamp is timezone-aware and set to UTC."""
        return validate_utc_datetime(v)

    @field_validator("permission", "granted_by", "granted_to", "scope")
    @classmethod
    def validate_non_empty_fields(cls, v: str, info: Any) -> str:
        """Validate string fields are not empty or whitespace only."""
        return validate_non_empty_string(v, field_name=info.field_name)


class AILMEvidence(BaseModel):
    """Evidence structure for AI-Induced Lateral Movement (AILM)."""

    agent_id: str
    composed_permissions: Set[str] = Field(default_factory=set)
    boundary_crossings: List[str] = Field(default_factory=list)
    risk_level: str


class C2Evidence(BaseModel):
    """Evidence structure for Command-and-Control (C2) infrastructure establishment."""

    agent_id: str
    c2_endpoints: List[str] = Field(default_factory=list)
    communication_pattern: str
    persistence_indicators: List[str] = Field(default_factory=list)


class K8sThreatEvidence(BaseModel):
    """Evidence structure for Kubernetes-specific container threats."""

    threat_type: str
    namespace: str
    pod_name: str
    service_account: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class RegistryThreatEvidence(BaseModel):
    """Evidence structure for package registry probing or exploitation."""

    registry_type: str
    package_name: str
    exploit_indicators: List[str] = Field(default_factory=list)
    cve_candidates: List[str] = Field(default_factory=list)
