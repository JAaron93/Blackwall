"""
Evaluation Scenario Pydantic Schema Definitions (`blackwall.eval.scenarios`).

Defines structured schema models and validators for all Blackwall evaluation domains.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvalScenarioBase(BaseModel):
    """Base schema for all Blackwall evaluation scenarios."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., min_length=1, description="Unique scenario identifier")
    domain: str = Field(..., min_length=1, description="Evaluation domain identifier")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary scenario metadata"
    )


class ThreatInterceptionScenario(EvalScenarioBase):
    """Scenario schema for Core SyncResolver threat interception evaluations."""

    domain: Literal["threat_interception"] = "threat_interception"
    prompt: str | None = Field(
        default=None, description="User prompt or simulated tool invocation prompt"
    )
    tool_call: dict[str, Any] | None = Field(
        default=None, description="Tool invocation payload and arguments"
    )
    ground_truth_verdict: str = Field(
        ..., description="Expected verdict: ALLOW, BLOCK, or QUARANTINE"
    )
    ground_truth_label: str = Field(
        ..., description="Expected ground truth classification: BENIGN or MALICIOUS"
    )
    expected_score_range: tuple[float, float] | None = Field(
        default=None, description="Optional min/max score range for threshold gating"
    )
    reference_trajectory: list[str] = Field(
        default_factory=list,
        description="Expected sequence of interception callback steps",
    )

    @field_validator("ground_truth_verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        upper_v = v.upper()
        if upper_v not in ("ALLOW", "BLOCK", "QUARANTINE"):
            raise ValueError(f"Invalid ground_truth_verdict: '{v}'. Must be ALLOW, BLOCK, or QUARANTINE.")
        return upper_v

    @field_validator("ground_truth_label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        upper_v = v.upper()
        if upper_v not in ("BENIGN", "MALICIOUS"):
            raise ValueError(f"Invalid ground_truth_label: '{v}'. Must be BENIGN or MALICIOUS.")
        return upper_v


class AILMScenario(EvalScenarioBase):
    """Scenario schema for AI-Induced Lateral Movement evaluations."""

    domain: Literal["ailm"] = "ailm"
    permission_grants: list[dict[str, Any]] = Field(
        ..., min_length=1, description="Sequence of permission grant events"
    )
    ground_truth_crossings: list[dict[str, Any]] = Field(
        ..., description="List of expected trust boundary crossings"
    )
    expected_risk_level: str = Field(
        ..., description="Expected risk level: LOW, MEDIUM, HIGH, or CRITICAL"
    )

    @field_validator("expected_risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        upper_v = v.upper()
        if upper_v not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid expected_risk_level: '{v}'. Must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return upper_v


class PromptInjectionScenario(EvalScenarioBase):
    """Scenario schema for Prompt Injection and Jailbreak evaluations."""

    domain: Literal["prompt_injection"] = "prompt_injection"
    payload: str = Field(..., min_length=1, description="Raw input text or injected prompt payload")
    ground_truth_is_injection: bool = Field(
        ..., description="Whether the payload is an actual injection attempt"
    )
    expected_severity: str = Field(
        ..., description="Expected severity classification (e.g., LOW, MEDIUM, HIGH, CRITICAL, INFO)"
    )

    @field_validator("expected_severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        upper_v = v.upper()
        if upper_v not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"):
            raise ValueError(f"Invalid expected_severity: '{v}'. Must be INFO, LOW, MEDIUM, HIGH, CRITICAL, or NONE.")
        return upper_v


class InboundFilterScenario(EvalScenarioBase):
    """Scenario schema for Inbound Protocol Filter evaluations."""

    domain: Literal["inbound_filter"] = "inbound_filter"
    request_headers: dict[str, str] = Field(
        ..., description="HTTP/RPC request headers (Origin, Host, etc.)"
    )
    rpc_payload: dict[str, Any] = Field(
        ..., description="RPC method and arguments payload"
    )
    ground_truth_allowed: bool = Field(
        ..., description="Whether the inbound request should be allowed through"
    )


class QuotaEnforcementScenario(EvalScenarioBase):
    """Scenario schema for Denial-of-Wallet / Quota Enforcement evaluations."""

    domain: Literal["quota_enforcement"] = "quota_enforcement"
    activity_stream: list[dict[str, Any]] = Field(
        ..., min_length=1, description="Stream of token or API consumption events"
    )
    ground_truth_throttled: bool = Field(
        ..., description="Whether quota enforcement should trigger throttling/quarantine"
    )
    expected_alert_type: str = Field(
        ..., description="Expected alert type (e.g. VELOCITY_BURST, SUSTAINED_BURN, NONE, QUARANTINE)"
    )


class ContextHygieneScenario(EvalScenarioBase):
    """Scenario schema for Context Hygiene and Secret Sanitization evaluations."""

    domain: Literal["context_hygiene"] = "context_hygiene"
    raw_payload: str = Field(
        ..., description="Unsanitized raw string or tool arguments payload"
    )
    expected_sanitized: str = Field(
        ..., description="Expected sanitized output string containing [[VARIABLE_NAME]] placeholders"
    )
    sensitive_patterns: list[str] = Field(
        default_factory=list,
        description="Identified sensitive credential patterns expected to be redacted",
    )


class SwarmDetectionScenario(EvalScenarioBase):
    """Scenario schema for Agent Swarm Coordination evaluations."""

    domain: Literal["swarm_detection"] = "swarm_detection"
    agent_events: list[dict[str, Any]] = Field(
        ..., min_length=1, description="Multi-agent event stream"
    )
    ground_truth_coordination: dict[str, Any] = Field(
        ..., description="Expected coordination score and detected agent IDs"
    )
    expected_action: str = Field(
        ..., description="Expected containment action (e.g., DROP_CONNECTION, ISOLATE)"
    )


class ExploitChainScenario(EvalScenarioBase):
    """Scenario schema for Multi-Stage Exploit Chain evaluations."""

    domain: Literal["exploit_chain"] = "exploit_chain"
    stages: list[str] = Field(
        ..., min_length=1, description="Ordered sequence of exploit execution stages"
    )
    novelty_score: float = Field(
        ..., ge=0.0, le=1.0, description="Assessed novelty score between 0.0 and 1.0"
    )
    mitre_mappings: list[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK technique IDs"
    )
    expected_action: str = Field(
        ..., description="Expected containment action (e.g., REVOKE_STS_TOKEN, BLOCK)"
    )


class C2DetectionScenario(EvalScenarioBase):
    """Scenario schema for Command & Control (C2) evaluations."""

    domain: Literal["c2_detection"] = "c2_detection"
    network_events: list[dict[str, Any]] = Field(
        ..., min_length=1, description="Network connection and DNS query events"
    )
    c2_endpoints: list[str] = Field(
        ..., description="Target C2 hostnames, IP addresses, or destination URLs"
    )
    expected_action: str = Field(
        ..., description="Expected containment action (e.g., DROP_SOCKET, BLOCK)"
    )


DOMAIN_SCENARIO_MAP: dict[str, type[EvalScenarioBase]] = {
    "threat_interception": ThreatInterceptionScenario,
    "ailm": AILMScenario,
    "prompt_injection": PromptInjectionScenario,
    "inbound_filter": InboundFilterScenario,
    "quota_enforcement": QuotaEnforcementScenario,
    "context_hygiene": ContextHygieneScenario,
    "swarm_detection": SwarmDetectionScenario,
    "exploit_chain": ExploitChainScenario,
    "c2_detection": C2DetectionScenario,
}


def parse_eval_scenario(data: dict[str, Any]) -> EvalScenarioBase:
    """
    Parse and validate a dictionary into its appropriate domain-specific EvalScenario model.

    Raises:
        ValueError: If domain is unknown or validation fails.
    """
    if not isinstance(data, dict):
        raise TypeError(f"Scenario data must be a dictionary, got {type(data).__name__}")

    domain = data.get("domain")
    if not domain or not isinstance(domain, str):
        raise ValueError("Scenario data missing required 'domain' string field.")

    model_cls = DOMAIN_SCENARIO_MAP.get(domain)
    if not model_cls:
        raise ValueError(
            f"Unknown evaluation domain: '{domain}'. Supported domains: {list(DOMAIN_SCENARIO_MAP.keys())}"
        )

    return model_cls.model_validate(data)
