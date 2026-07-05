import re
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class StructuralAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE_TO_SEMANTIC = "ESCALATE_TO_SEMANTIC"


class GlobalConfig(BaseModel):
    threatThreshold: float = Field(..., ge=0.0, le=1.0)
    quarantineThreshold: float = Field(..., ge=0.0, le=1.0)
    enableStructuralGating: bool
    enableSemanticGating: bool


class EnvironmentRoleConfig(BaseModel):
    allowedTools: List[str]
    blockedTools: List[str]
    requireSemanticReview: bool
    maxThreatScore: float = Field(..., ge=0.0, le=1.0)


class StructuralRule(BaseModel):
    ruleId: str
    condition: str
    action: StructuralAction
    priority: int
    enabled: bool
    requireSemanticReview: Optional[bool] = None


class MCPServerConfig(BaseModel):
    enabled: bool
    apiKey: Optional[str] = None
    cacheEnabled: bool
    cacheTTL: int = Field(..., ge=0)
    timeout: int = Field(..., ge=0)  # in ms


class MCPServersConfig(BaseModel):
    gti: MCPServerConfig
    codebaseMemory: MCPServerConfig


class ThreatSignatureGraphConfig(BaseModel):
    dbPath: str
    walMode: bool
    maxConnections: int = Field(..., ge=1)
    similarityThreshold: float = Field(..., ge=0.0, le=1.0)
    ttlSeconds: int
    maxSignatures: int
    embeddingDimension: int

    @field_validator("walMode")
    @classmethod
    def validate_wal_mode(cls, v: bool) -> bool:
        if not v:
            raise ValueError("walMode must be enabled (true) for SQLite integrity")
        return v


class PolicyConfig(BaseModel):
    version: str
    global_config: GlobalConfig = Field(..., alias="global")
    environmentRoles: Dict[str, EnvironmentRoleConfig]
    structuralRules: List[StructuralRule]
    semanticGuidelines: List[str]
    mcpServers: MCPServersConfig
    threatSignatureGraph: ThreatSignatureGraphConfig

    model_config = {
        "populate_by_name": True,
    }

    @field_validator("version")
    @classmethod
    def validate_semver(cls, v: str) -> str:
        if not re.match(r"^\d+\.\d+\.\d+$", v):
            raise ValueError(
                "Version must be in MAJOR.MINOR.PATCH semantic versioning format"
            )
        return v

    @model_validator(mode="after")
    def validate_rules_and_roles(self) -> "PolicyConfig":
        # Validate unique rule IDs
        rule_ids = set()
        for rule in self.structuralRules:
            if rule.ruleId in rule_ids:
                raise ValueError(f"Duplicate structural rule ID: {rule.ruleId}")
            rule_ids.add(rule.ruleId)

        # Verify that we have at minimum "sandbox" and "production" environment roles
        required_roles = {"sandbox", "production"}
        missing_roles = required_roles - set(self.environmentRoles.keys())
        if missing_roles:
            raise ValueError(
                f"Missing required environment roles: {', '.join(missing_roles)}"
            )

        return self
