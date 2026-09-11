"""
Pydantic Rubric Models for Blackwall Agent-as-a-Judge Evaluation (`blackwall.eval.rubrics`).

Defines structured rubric models for all 9 evaluation domains plus pairwise regression comparison.
Strictly adheres to:
- ConfigDict(extra="forbid")
- Dimension scores: Field(ge=1, le=5) [or Field(ge=-5, le=5) for deltas]
- justification: str = Field(min_length=10)
- is_fallback: bool = Field(default=False)
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ThreatInterceptionRubric(BaseModel):
    """Evaluation rubric for Core SyncResolver threat interception."""

    model_config = ConfigDict(extra="forbid")

    detection_accuracy_score: int = Field(
        ge=1, le=5, description="Accuracy of threat detection vs ground truth verdict"
    )
    false_positive_control_score: int = Field(
        ge=1, le=5, description="Precision in avoiding false positive blocking of benign tools"
    )
    reasoning_quality_score: int = Field(
        ge=1, le=5, description="Clarity, correctness, and soundness of verdict reasoning"
    )
    trajectory_soundness_score: int = Field(
        ge=1, le=5, description="Compliance with callback chain and SLA timing bounds"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class SwarmDetectionRubric(BaseModel):
    """Evaluation rubric for multi-agent swarm coordination detection."""

    model_config = ConfigDict(extra="forbid")

    coordination_detection_score: int = Field(
        ge=1, le=5, description="Identification of distributed multi-agent coordinated behavior"
    )
    temporal_precision_score: int = Field(
        ge=1, le=5, description="Precision of event clustering within temporal burst windows"
    )
    shared_infra_identification_score: int = Field(
        ge=1, le=5, description="Accuracy in correlating shared infrastructure or endpoints"
    )
    fingerprint_quality_score: int = Field(
        ge=1, le=5, description="Quality and uniqueness of generated swarm fingerprints"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class ExploitChainRubric(BaseModel):
    """Evaluation rubric for exploit chain analysis and novel sequence detection."""

    model_config = ConfigDict(extra="forbid")

    chain_completeness_score: int = Field(
        ge=1, le=5, description="Completeness of reconstructed multi-step exploit stages"
    )
    novelty_calibration_score: int = Field(
        ge=1, le=5, description="Calibration of novelty scoring against known vs novel attack graphs"
    )
    mitre_mapping_accuracy_score: int = Field(
        ge=1, le=5, description="Accuracy of mapped MITRE ATT&CK technique identifiers"
    )
    chaining_confidence_score: int = Field(
        ge=1, le=5, description="Soundness of stage connection confidence and transition probabilities"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class C2DetectionRubric(BaseModel):
    """Evaluation rubric for Command & Control (C2) infrastructure detection."""

    model_config = ConfigDict(extra="forbid")

    endpoint_classification_score: int = Field(
        ge=1, le=5, description="Accuracy in classifying suspicious domains and Pastebin/RequestBin drops"
    )
    beaconing_detection_score: int = Field(
        ge=1, le=5, description="Precision in detecting periodic or jittered outbound beaconing"
    )
    persistence_identification_score: int = Field(
        ge=1, le=5, description="Detection of persistence mechanisms and long-lived C2 channels"
    )
    cross_pillar_correlation_score: int = Field(
        ge=1, le=5, description="Cross-pillar correlation between network events and kernel/identity logs"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class AILMDetectionRubric(BaseModel):
    """Evaluation rubric for AI-Induced Lateral Movement (AILM) detection."""

    model_config = ConfigDict(extra="forbid")

    boundary_crossing_detection_score: int = Field(
        ge=1, le=5, description="Accuracy in identifying trust boundary crossings across services/clusters"
    )
    permission_composition_accuracy_score: int = Field(
        ge=1, le=5, description="Precision in tracking progressive permission accumulation across time"
    )
    risk_classification_score: int = Field(
        ge=1, le=5, description="Appropriateness of assigned risk level (LOW/MEDIUM/HIGH/CRITICAL)"
    )
    evidence_completeness_score: int = Field(
        ge=1, le=5, description="Completeness of accumulated permission grants and crossing trails"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class PromptInjectionRubric(BaseModel):
    """Evaluation rubric for prompt injection and structural jailbreak detection."""

    model_config = ConfigDict(extra="forbid")

    injection_detection_rate_score: int = Field(
        ge=1, le=5, description="Sensitivity in identifying prompt injection and jailbreak payloads"
    )
    redaction_completeness_score: int = Field(
        ge=1, le=5, description="Completeness in neutralizing and redacting malicious prompt spans"
    )
    false_positive_control_score: int = Field(
        ge=1, le=5, description="Specificity in passing benign user prompts without false alerts"
    )
    alert_severity_accuracy_score: int = Field(
        ge=1, le=5, description="Calibration of alert severity levels based on attack sophistication"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class InboundFilterRubric(BaseModel):
    """Evaluation rubric for inbound protocol interception and RPC filter validation."""

    model_config = ConfigDict(extra="forbid")

    header_validation_accuracy_score: int = Field(
        ge=1, le=5, description="Accuracy in validating origin, host, and authorization headers"
    )
    rate_limit_precision_score: int = Field(
        ge=1, le=5, description="Precision in rate limit enforcement and burst handling"
    )
    sanitization_quality_score: int = Field(
        ge=1, le=5, description="Quality of payload sanitization and dangerous token stripping"
    )
    error_response_safety_score: int = Field(
        ge=1, le=5, description="Safety of error responses without internal architecture disclosure"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class QuotaEnforcementRubric(BaseModel):
    """Evaluation rubric for Denial-of-Wallet defense and agent quota enforcement."""

    model_config = ConfigDict(extra="forbid")

    burn_rate_detection_score: int = Field(
        ge=1, le=5, description="Accuracy in detecting rapid token and API call burn rate surges"
    )
    throttling_precision_score: int = Field(
        ge=1, le=5, description="Precision in throttling excess velocity while allowing normal bursts"
    )
    alert_timeliness_score: int = Field(
        ge=1, le=5, description="Speed and timeliness of Denial-of-Wallet alert emission"
    )
    quarantine_accuracy_score: int = Field(
        ge=1, le=5, description="Correctness of agent isolation/quarantine under sustained burn"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class ContextHygieneRubric(BaseModel):
    """Evaluation rubric for context hygiene and secret sanitization quality."""

    model_config = ConfigDict(extra="forbid")

    redaction_completeness_score: int = Field(
        ge=1, le=5, description="Completeness of secret redaction across all credential categories"
    )
    placeholder_format_compliance_score: int = Field(
        ge=1, le=5, description="Strict compliance with [[VARIABLE_NAME]] placeholder syntax"
    )
    metadata_preservation_score: int = Field(
        ge=1, le=5, description="Preservation of non-secret structural metadata and formatting"
    )
    non_sensitive_passthrough_score: int = Field(
        ge=1, le=5, description="Accuracy in passing non-sensitive strings without over-redaction"
    )
    justification: str = Field(
        min_length=10, description="Step-by-step reasoning justifying the assigned scores"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


class RegressionComparisonRubric(BaseModel):
    """Evaluation rubric for pairwise model/algorithm regression comparisons."""

    model_config = ConfigDict(extra="forbid")

    overall_quality_delta: int = Field(
        ge=-5, le=5, description="Overall quality delta: candidate score minus baseline score"
    )
    precision_delta: int = Field(
        ge=-5, le=5, description="Precision score delta between candidate and baseline"
    )
    recall_delta: int = Field(
        ge=-5, le=5, description="Recall score delta between candidate and baseline"
    )
    trajectory_quality_delta: int = Field(
        ge=-5, le=5, description="Trajectory soundness delta between candidate and baseline"
    )
    regression_detected: bool = Field(
        default=False, description="True if candidate exhibits statistically meaningful regression"
    )
    justification: str = Field(
        min_length=10, description="Detailed comparative reasoning and regression analysis"
    )
    is_fallback: bool = Field(
        default=False, description="Flag indicating if this score originated from heuristic fallback"
    )


RUBRIC_MAP: dict[str, type[BaseModel]] = {
    "threat_interception": ThreatInterceptionRubric,
    "swarm_detection": SwarmDetectionRubric,
    "exploit_chain": ExploitChainRubric,
    "c2_detection": C2DetectionRubric,
    "ailm": AILMDetectionRubric,
    "prompt_injection": PromptInjectionRubric,
    "inbound_filter": InboundFilterRubric,
    "quota_enforcement": QuotaEnforcementRubric,
    "context_hygiene": ContextHygieneRubric,
    "regression_comparison": RegressionComparisonRubric,
    "pairwise_regression": RegressionComparisonRubric,
}


def get_rubric_for_domain(domain: str) -> type[BaseModel]:
    """Retrieve the Pydantic rubric schema corresponding to an evaluation domain."""
    normalized = domain.strip().lower()
    if normalized not in RUBRIC_MAP:
        raise ValueError(
            f"Unknown evaluation domain '{domain}'. Valid domains: {sorted(RUBRIC_MAP.keys())}"
        )
    return RUBRIC_MAP[normalized]
