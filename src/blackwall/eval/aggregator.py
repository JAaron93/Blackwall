"""
Evaluation Results Aggregator with Fallback Isolation (`blackwall.eval.aggregator`).

Collects evaluation rubric records across domains, isolates heuristic fallback rows
from judge mean calculations, computes dimension-level aggregates, and enforces
CI/CD threshold gating.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class EvaluationResultRecord(BaseModel):
    """A single scenario evaluation result record."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(description="Evaluated scenario identifier")
    domain: str = Field(description="Security evaluation domain")
    rubric: Any = Field(description="Pydantic rubric instance or dictionary")
    is_fallback: bool = Field(default=False, description="Whether this score is from a heuristic fallback")
    execution_time_ms: float | None = Field(default=None, description="Execution duration in milliseconds")

    def model_post_init(self, __context: Any) -> None:
        """Infer is_fallback from rubric if not explicitly set."""
        if not self.is_fallback:
            if hasattr(self.rubric, "is_fallback"):
                self.is_fallback = bool(self.rubric.is_fallback)
            elif isinstance(self.rubric, dict) and "is_fallback" in self.rubric:
                self.is_fallback = bool(self.rubric["is_fallback"])


class DomainSummary(BaseModel):
    """Aggregate quality and fallback statistics for a single evaluation domain."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(description="Evaluation domain name")
    total_scenarios: int = Field(ge=0, description="Total number of evaluated scenarios")
    fallback_count: int = Field(ge=0, description="Count of heuristic fallback verdicts")
    fallback_rate: float = Field(ge=0.0, le=1.0, description="Ratio of fallbacks to total scenarios")
    valid_count: int = Field(ge=0, description="Count of genuine judge evaluations")
    dimension_means: dict[str, float | None] = Field(
        default_factory=dict,
        description="Mean score per rubric dimension (excluding fallbacks)",
    )
    overall_mean: float | None = Field(
        default=None,
        description="Overall domain mean score across dimensions (None if 100% fallback)",
    )
    passed: bool = Field(description="True if domain overall mean meets or exceeds the threshold")


class AggregateSummary(BaseModel):
    """Overall evaluation pipeline summary across all domains."""

    model_config = ConfigDict(extra="forbid")

    domain_summaries: dict[str, DomainSummary] = Field(description="Summary per evaluated domain")
    total_scenarios: int = Field(ge=0, description="Total evaluated scenarios across all domains")
    total_fallbacks: int = Field(ge=0, description="Total fallbacks across all domains")
    overall_fallback_rate: float = Field(ge=0.0, le=1.0, description="Overall fallback percentage")
    overall_mean: float | None = Field(
        default=None,
        description="Overall mean across all non-fallback domain scores",
    )
    all_passed: bool = Field(description="True if all evaluated domains passed their thresholds")
    threshold: float = Field(description="Configured passing score threshold")


class EvaluationAggregator:
    """
    Aggregates domain-level rubric scores with strict fallback isolation.
    """

    def __init__(self, threshold: float = 3.5) -> None:
        self.threshold = float(threshold)
        self._records: list[EvaluationResultRecord] = []

    def add_record(self, record: EvaluationResultRecord) -> None:
        """Add an evaluation result record to the aggregator."""
        self._records.append(record)

    def summarize(self) -> AggregateSummary:
        """
        Compute aggregate statistics, isolating is_fallback=True rows from mean computations.
        """
        # Group records by domain
        by_domain: dict[str, list[EvaluationResultRecord]] = {}
        for r in self._records:
            norm_domain = r.domain.strip().lower()
            if norm_domain not in by_domain:
                by_domain[norm_domain] = []
            by_domain[norm_domain].append(r)

        domain_summaries: dict[str, DomainSummary] = {}
        total_scenarios = len(self._records)
        total_fallbacks = 0

        for domain, records in by_domain.items():
            total_d = len(records)
            fallbacks_d = [r for r in records if r.is_fallback]
            valid_d = [r for r in records if not r.is_fallback]
            fallback_count = len(fallbacks_d)
            total_fallbacks += fallback_count
            valid_count = len(valid_d)
            fallback_rate = (fallback_count / total_d) if total_d > 0 else 0.0

            if valid_count == 0:
                # 100% fallback domain: report None for means, cannot pass
                domain_summaries[domain] = DomainSummary(
                    domain=domain,
                    total_scenarios=total_d,
                    fallback_count=fallback_count,
                    fallback_rate=round(fallback_rate, 4),
                    valid_count=0,
                    dimension_means={},
                    overall_mean=None,
                    passed=False,
                )
                continue

            # Extract numeric dimension scores from valid rubrics
            dimension_totals: dict[str, float] = {}
            dimension_counts: dict[str, int] = {}
            rubric_means: list[float] = []

            for r in valid_d:
                data = (
                    r.rubric.model_dump()
                    if hasattr(r.rubric, "model_dump")
                    else (r.rubric if isinstance(r.rubric, dict) else {})
                )

                score_values: list[float] = []
                for k, v in data.items():
                    if k in ("justification", "is_fallback", "regression_detected"):
                        continue
                    if isinstance(v, (int, float)):
                        score_values.append(float(v))
                        dimension_totals[k] = dimension_totals.get(k, 0.0) + float(v)
                        dimension_counts[k] = dimension_counts.get(k, 0) + 1

                if score_values:
                    rubric_means.append(sum(score_values) / len(score_values))

            dimension_means: dict[str, float | None] = {}
            for k in dimension_totals:
                count = dimension_counts[k]
                dimension_means[k] = round(dimension_totals[k] / count, 4) if count > 0 else None

            overall_mean = (
                round(sum(rubric_means) / len(rubric_means), 4)
                if rubric_means
                else (
                    round(sum(v for v in dimension_means.values() if v is not None) / len(dimension_means), 4)
                    if dimension_means
                    else None
                )
            )

            passed = (overall_mean is not None) and (overall_mean >= self.threshold)

            domain_summaries[domain] = DomainSummary(
                domain=domain,
                total_scenarios=total_d,
                fallback_count=fallback_count,
                fallback_rate=round(fallback_rate, 4),
                valid_count=valid_count,
                dimension_means=dimension_means,
                overall_mean=overall_mean,
                passed=passed,
            )

        overall_fallback_rate = (total_fallbacks / total_scenarios) if total_scenarios > 0 else 0.0
        valid_domain_means = [ds.overall_mean for ds in domain_summaries.values() if ds.overall_mean is not None]
        overall_mean = (
            round(sum(valid_domain_means) / len(valid_domain_means), 4)
            if valid_domain_means
            else None
        )

        # All evaluated domains must pass for overall pass
        all_passed = bool(domain_summaries) and all(ds.passed for ds in domain_summaries.values())

        return AggregateSummary(
            domain_summaries=domain_summaries,
            total_scenarios=total_scenarios,
            total_fallbacks=total_fallbacks,
            overall_fallback_rate=round(overall_fallback_rate, 4),
            overall_mean=overall_mean,
            all_passed=all_passed,
            threshold=self.threshold,
        )

    def clear(self) -> None:
        """Clear all recorded evaluation records."""
        self._records.clear()
