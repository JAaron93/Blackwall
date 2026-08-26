"""
Heuristic Fallback Scorers for Offline / Degraded Evaluation Mode (`blackwall.eval.fallback_scorer`).

Provides rule-based deterministic evaluation scoring when Vertex AI is unavailable,
timeouts occur, or retry limits are exhausted.

INVARIANT: All fallback scorers MUST return a rubric with `is_fallback=True`.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from blackwall.eval.rubrics import (
    AILMDetectionRubric,
    C2DetectionRubric,
    ContextHygieneRubric,
    ExploitChainRubric,
    InboundFilterRubric,
    PromptInjectionRubric,
    QuotaEnforcementRubric,
    RegressionComparisonRubric,
    SwarmDetectionRubric,
    ThreatInterceptionRubric,
)


class HeuristicFallbackScorer(ABC):
    """Abstract Base Class for domain-specific heuristic fallback scorers."""

    @property
    @abstractmethod
    def rubric_class(self) -> type[BaseModel]:
        """The Pydantic rubric model class produced by this fallback scorer."""

    @abstractmethod
    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> BaseModel:
        """
        Compute heuristic scores for a scenario and candidate result.

        Must return an instance of `rubric_class` with `is_fallback=True`.
        """


class ThreatInterceptionFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for Core SyncResolver threat interception."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return ThreatInterceptionRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> ThreatInterceptionRubric:
        gt_verdict = str(scenario_data.get("ground_truth_verdict", "")).upper()
        pred_verdict = str(candidate_result.get("verdict", candidate_result.get("decision", ""))).upper()

        is_match = (gt_verdict == pred_verdict) and (gt_verdict != "")
        score = 5 if is_match else 1

        justification = (
            f"[HEURISTIC FALLBACK] Predicted verdict '{pred_verdict}' matched ground truth '{gt_verdict}'."
            if is_match
            else f"[HEURISTIC FALLBACK] Predicted verdict '{pred_verdict}' mismatched ground truth '{gt_verdict}'."
        )

        return ThreatInterceptionRubric(
            detection_accuracy_score=score,
            false_positive_control_score=score,
            reasoning_quality_score=3 if is_match else 1,
            trajectory_soundness_score=4 if is_match else 2,
            justification=justification,
            is_fallback=True,
        )


class SwarmDetectionFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for agent swarm coordination detection."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return SwarmDetectionRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> SwarmDetectionRubric:
        gt_coord = scenario_data.get("ground_truth_coordination")
        if isinstance(gt_coord, dict):
            expected_swarm = bool(
                gt_coord.get("agents")
                or gt_coord.get("detected_agents")
                or gt_coord.get("score", gt_coord.get("coordination_score", 0)) >= 0.7
            )
        else:
            expected_swarm = bool(scenario_data.get("expected_swarm", True))

        detected_swarms = candidate_result.get("swarms", candidate_result.get("detected_swarms", []))
        has_detection = len(detected_swarms) > 0 or bool(candidate_result.get("swarm_detected", False))

        is_correct = (expected_swarm == has_detection)
        score = 5 if is_correct else 1

        justification = (
            f"[HEURISTIC FALLBACK] Swarm detection status ({has_detection}) aligned with ground truth ({expected_swarm})."
            if is_correct
            else f"[HEURISTIC FALLBACK] Swarm detection status ({has_detection}) failed to match ground truth ({expected_swarm})."
        )

        return SwarmDetectionRubric(
            coordination_detection_score=score,
            temporal_precision_score=score,
            shared_infra_identification_score=score,
            fingerprint_quality_score=3 if is_correct else 1,
            justification=justification,
            is_fallback=True,
        )


class ExploitChainFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for exploit chain analysis."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return ExploitChainRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> ExploitChainRubric:
        expected_stages = scenario_data.get("stages", scenario_data.get("expected_stages", []))
        detected_stages = candidate_result.get("stages", candidate_result.get("detected_stages", []))

        if expected_stages:
            matched = sum(1 for s in expected_stages if s in detected_stages)
            ratio = matched / len(expected_stages)
            score = max(1, min(5, round(1 + 4 * ratio)))
        else:
            score = 5 if not detected_stages else 3

        justification = (
            f"[HEURISTIC FALLBACK] Exploit chain stage overlap: {len(detected_stages)} detected vs {len(expected_stages)} expected."
        )

        return ExploitChainRubric(
            chain_completeness_score=score,
            novelty_calibration_score=score,
            mitre_mapping_accuracy_score=score,
            chaining_confidence_score=score,
            justification=justification,
            is_fallback=True,
        )


class C2DetectionFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for C2 infrastructure detection."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return C2DetectionRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> C2DetectionRubric:
        expected_endpoints = set(scenario_data.get("c2_endpoints", scenario_data.get("expected_c2_endpoints", [])))
        detected_endpoints = set(candidate_result.get("c2_endpoints", candidate_result.get("detected_endpoints", [])))

        if expected_endpoints:
            overlap = len(expected_endpoints.intersection(detected_endpoints))
            ratio = overlap / len(expected_endpoints)
            score = max(1, min(5, round(1 + 4 * ratio)))
        else:
            score = 5 if not detected_endpoints else 2

        justification = (
            f"[HEURISTIC FALLBACK] C2 endpoint match: {len(detected_endpoints)} detected, {len(expected_endpoints)} expected."
        )

        return C2DetectionRubric(
            endpoint_classification_score=score,
            beaconing_detection_score=score,
            persistence_identification_score=score,
            cross_pillar_correlation_score=score,
            justification=justification,
            is_fallback=True,
        )


class AILMDetectionFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for AI-Induced Lateral Movement (AILM) detection."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return AILMDetectionRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> AILMDetectionRubric:
        expected_crossings = scenario_data.get("ground_truth_crossings", scenario_data.get("expected_crossings", []))
        detected_crossings = candidate_result.get("boundary_crossings", candidate_result.get("crossings", []))

        exp_count = len(expected_crossings)
        det_count = len(detected_crossings)

        if exp_count == 0:
            score = 5 if det_count == 0 else 2
        else:
            ratio = min(1.0, det_count / exp_count)
            score = max(1, min(5, round(1 + 4 * ratio)))

        justification = (
            f"[HEURISTIC FALLBACK] Boundary crossings: {det_count} detected vs {exp_count} ground truth."
        )

        return AILMDetectionRubric(
            boundary_crossing_detection_score=score,
            permission_composition_accuracy_score=score,
            risk_classification_score=score,
            evidence_completeness_score=score,
            justification=justification,
            is_fallback=True,
        )


class PromptInjectionFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for prompt injection detection."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return PromptInjectionRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> PromptInjectionRubric:
        gt_is_injection = bool(scenario_data.get("ground_truth_is_injection", False))
        pred_is_injection = bool(candidate_result.get("is_injection", candidate_result.get("detected", False)))

        is_match = (gt_is_injection == pred_is_injection)
        score = 5 if is_match else 1

        justification = (
            f"[HEURISTIC FALLBACK] Injection detection ({pred_is_injection}) matched ground truth ({gt_is_injection})."
            if is_match
            else f"[HEURISTIC FALLBACK] Injection detection ({pred_is_injection}) mismatched ground truth ({gt_is_injection})."
        )

        return PromptInjectionRubric(
            injection_detection_rate_score=score,
            redaction_completeness_score=score,
            false_positive_control_score=score,
            alert_severity_accuracy_score=3 if is_match else 1,
            justification=justification,
            is_fallback=True,
        )


class InboundFilterFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for inbound protocol interception."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return InboundFilterRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> InboundFilterRubric:
        gt_allowed = bool(scenario_data.get("ground_truth_allowed", True))
        pred_allowed = bool(candidate_result.get("allowed", candidate_result.get("passed", True)))

        is_match = (gt_allowed == pred_allowed)
        score = 5 if is_match else 1

        justification = (
            f"[HEURISTIC FALLBACK] Inbound filter decision ({pred_allowed}) matched policy ground truth ({gt_allowed})."
            if is_match
            else f"[HEURISTIC FALLBACK] Inbound filter decision ({pred_allowed}) conflicted with ground truth ({gt_allowed})."
        )

        return InboundFilterRubric(
            header_validation_accuracy_score=score,
            rate_limit_precision_score=score,
            sanitization_quality_score=score,
            error_response_safety_score=4 if is_match else 2,
            justification=justification,
            is_fallback=True,
        )


class QuotaEnforcementFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for agent quota enforcement."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return QuotaEnforcementRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> QuotaEnforcementRubric:
        gt_throttled = bool(scenario_data.get("ground_truth_throttled", False))
        pred_throttled = bool(candidate_result.get("throttled", candidate_result.get("quarantined", False)))

        is_match = (gt_throttled == pred_throttled)
        score = 5 if is_match else 1

        justification = (
            f"[HEURISTIC FALLBACK] Quota throttling decision ({pred_throttled}) matched ground truth ({gt_throttled})."
            if is_match
            else f"[HEURISTIC FALLBACK] Quota throttling decision ({pred_throttled}) failed to match ground truth ({gt_throttled})."
        )

        return QuotaEnforcementRubric(
            burn_rate_detection_score=score,
            throttling_precision_score=score,
            alert_timeliness_score=4 if is_match else 1,
            quarantine_accuracy_score=score,
            justification=justification,
            is_fallback=True,
        )


class ContextHygieneFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for context hygiene and secret sanitization."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return ContextHygieneRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> ContextHygieneRubric:
        sanitized_output = str(candidate_result.get("sanitized_output", candidate_result.get("output", "")))

        # Check for unredacted sensitive token patterns (e.g. sk-..., eyJ..., AKIA...)
        leak_pattern = re.compile(r"sk-[a-zA-Z0-9_-]{10,}|eyJ[a-zA-Z0-9_-]{15,}|AKIA[0-9A-Z]{16}")
        has_leak = bool(leak_pattern.search(sanitized_output))

        score = 1 if has_leak else 5
        justification = (
            "[HEURISTIC FALLBACK] Secret leak detected in sanitized output payload."
            if has_leak
            else "[HEURISTIC FALLBACK] No credential leak patterns detected in output."
        )

        return ContextHygieneRubric(
            redaction_completeness_score=score,
            placeholder_format_compliance_score=score,
            metadata_preservation_score=4 if not has_leak else 2,
            non_sensitive_passthrough_score=5 if not has_leak else 2,
            justification=justification,
            is_fallback=True,
        )


class RegressionComparisonFallbackScorer(HeuristicFallbackScorer):
    """Heuristic fallback scorer for pairwise regression comparison."""

    @property
    def rubric_class(self) -> type[BaseModel]:
        return RegressionComparisonRubric

    def score(self, scenario_data: dict[str, Any], candidate_result: dict[str, Any]) -> RegressionComparisonRubric:
        baseline_score = float(scenario_data.get("baseline_mean", 3.5))
        candidate_score = float(candidate_result.get("candidate_mean", candidate_result.get("mean_score", 3.5)))

        delta = round(candidate_score - baseline_score)
        delta = max(-5, min(5, delta))

        regression_detected = delta < 0 and abs(candidate_score - baseline_score) > 0.5

        justification = (
            f"[HEURISTIC FALLBACK] Candidate score ({candidate_score:.2f}) vs Baseline ({baseline_score:.2f}): "
            f"delta = {delta}, regression_detected = {regression_detected}."
        )

        return RegressionComparisonRubric(
            overall_quality_delta=delta,
            precision_delta=delta,
            recall_delta=delta,
            trajectory_quality_delta=delta,
            regression_detected=regression_detected,
            justification=justification,
            is_fallback=True,
        )


FALLBACK_SCORERS: dict[str, HeuristicFallbackScorer] = {
    "threat_interception": ThreatInterceptionFallbackScorer(),
    "swarm_detection": SwarmDetectionFallbackScorer(),
    "exploit_chain": ExploitChainFallbackScorer(),
    "c2_detection": C2DetectionFallbackScorer(),
    "ailm": AILMDetectionFallbackScorer(),
    "prompt_injection": PromptInjectionFallbackScorer(),
    "inbound_filter": InboundFilterFallbackScorer(),
    "quota_enforcement": QuotaEnforcementFallbackScorer(),
    "context_hygiene": ContextHygieneFallbackScorer(),
    "regression_comparison": RegressionComparisonFallbackScorer(),
    "pairwise_regression": RegressionComparisonFallbackScorer(),
}


def get_fallback_scorer_for_domain(domain: str) -> HeuristicFallbackScorer:
    """Retrieve the fallback scorer for an evaluation domain."""
    normalized = domain.strip().lower()
    if normalized not in FALLBACK_SCORERS:
        raise ValueError(f"Unknown domain '{domain}'. Available: {sorted(FALLBACK_SCORERS.keys())}")
    return FALLBACK_SCORERS[normalized]
