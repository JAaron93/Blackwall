"""
SLA Validation Engine for Blackwall Security Evaluations (`blackwall.eval.sla_validator`).

Provides high-precision latency measurement, SLA threshold validation, Cloud Trace
telemetry recording, and trajectory soundness factoring for evaluation scenarios.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Generator, Optional

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Canonical SLA latency thresholds in milliseconds (Requirements 12.1-12.3, Design §6)
DEFAULT_SLA_THRESHOLDS_MS: dict[str, float] = {
    "tsg_signature_match": 10.0,
    "structural_gating": 5.0,
    "active_reaction": 50.0,
    "ebpf_drop": 50.0,
    "mesh_broadcast": 15.0,
    # Evaluation-pipeline components executed by scripts/run_gcp_eval.py workers.
    # Each threshold belongs to the operation its domain worker actually runs.
    "eval_context_sanitization": 10.0,
    "eval_prompt_injection_scan": 50.0,
    "eval_inbound_filter_validation": 5.0,
    "eval_quota_enforcement": 50.0,
    "eval_swarm_detection": 50.0,
    "eval_c2_detection": 50.0,
    "eval_exploit_chain_analysis": 50.0,
    "eval_ailm_tracking": 50.0,
}

# Synonyms/aliases for component names
COMPONENT_ALIASES: dict[str, str] = {
    "tsg": "tsg_signature_match",
    "threat_signature_graph": "tsg_signature_match",
    "gating": "structural_gating",
    "structural_gate": "structural_gating",
    "reaction": "active_reaction",
    "containment": "active_reaction",
    "active_reaction_containment": "active_reaction",
    "ebpf": "ebpf_drop",
    "ebpf_socket_drop": "ebpf_drop",
    "mesh": "mesh_broadcast",
    "threat_mesh_broadcast": "mesh_broadcast",
}


class SLAMeasurement(BaseModel):
    """Structured SLA latency measurement result."""

    model_config = ConfigDict(extra="forbid")

    component: str = Field(description="Evaluated security component or operation")
    threshold_ms: float = Field(ge=0.0, description="Target SLA threshold in milliseconds")
    measured_ms: float = Field(ge=0.0, description="Measured execution duration in milliseconds")
    violated: bool = Field(description="True if measured_ms exceeds threshold_ms")
    timestamp_ns: int = Field(default_factory=time.time_ns, description="Measurement timestamp in nanoseconds")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context metadata")


class SLAValidator:
    """
    SLA Validation Engine measuring component latencies and enforcing SLA contracts.
    """

    def __init__(self, thresholds: dict[str, float] | None = None) -> None:
        self._thresholds: dict[str, float] = dict(DEFAULT_SLA_THRESHOLDS_MS)
        if thresholds:
            self._thresholds.update(thresholds)
        self._measurements: list[SLAMeasurement] = []

    @property
    def measurements(self) -> list[SLAMeasurement]:
        """Return all recorded SLA measurements."""
        return list(self._measurements)

    def resolve_component_name(self, component: str) -> str:
        """Resolve component name or alias to canonical threshold key."""
        norm = component.strip().lower()
        if norm in self._thresholds:
            return norm
        if norm in COMPONENT_ALIASES:
            return COMPONENT_ALIASES[norm]
        return norm

    def get_threshold(self, component: str) -> float:
        """Retrieve SLA threshold in milliseconds for a component."""
        key = self.resolve_component_name(component)
        if key not in self._thresholds:
            logger.debug("Component '%s' not found in SLA thresholds, defaulting to 50.0ms", component)
            return 50.0
        return self._thresholds[key]

    def record_measurement(
        self,
        component: str,
        measured_ms: float,
        span: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> SLAMeasurement:
        """
        Record an SLA latency measurement, evaluate violation, and record Cloud Trace span attributes.
        """
        key = self.resolve_component_name(component)
        threshold_ms = self.get_threshold(key)
        # Measured time strictly greater than threshold is a violation
        violated = measured_ms > threshold_ms

        measurement = SLAMeasurement(
            component=key,
            threshold_ms=threshold_ms,
            measured_ms=max(0.0, float(measured_ms)),
            violated=violated,
            metadata=metadata or {},
        )

        if span is not None:
            attrs = getattr(span, "attributes", None)
            if isinstance(attrs, dict):
                attrs["blackwall.sla.component"] = key
                attrs["blackwall.sla.threshold_ms"] = threshold_ms
                attrs["blackwall.sla.measured_ms"] = measurement.measured_ms
                attrs["blackwall.sla.violated"] = violated

            # If it's an OpenTelemetry span object
            otel_span = getattr(span, "_otel_span", None)
            if otel_span is not None:
                try:
                    otel_span.set_attribute("blackwall.sla.component", key)
                    otel_span.set_attribute("blackwall.sla.threshold_ms", threshold_ms)
                    otel_span.set_attribute("blackwall.sla.measured_ms", measurement.measured_ms)
                    otel_span.set_attribute("blackwall.sla.violated", violated)
                except Exception as exc:
                    logger.debug("Failed to set SLA attributes on OTel span: %s", exc)

        self._measurements.append(measurement)
        return measurement

    @contextmanager
    def measure(
        self,
        component: str,
        span: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> Generator[SLAMeasurement, None, None]:
        """
        Context manager measuring execution time using time.perf_counter_ns().
        """
        key = self.resolve_component_name(component)
        threshold_ms = self.get_threshold(key)

        # Pre-allocate measurement with placeholder timing
        measurement = SLAMeasurement(
            component=key,
            threshold_ms=threshold_ms,
            measured_ms=0.0,
            violated=False,
            metadata=metadata or {},
        )

        t0 = time.perf_counter_ns()
        try:
            yield measurement
        finally:
            t1 = time.perf_counter_ns()
            elapsed_ms = (t1 - t0) / 1_000_000.0
            # Mutate measurement in place and update attributes
            measurement.measured_ms = elapsed_ms
            measurement.violated = elapsed_ms > threshold_ms

            if span is not None:
                attrs = getattr(span, "attributes", None)
                if isinstance(attrs, dict):
                    attrs["blackwall.sla.component"] = key
                    attrs["blackwall.sla.threshold_ms"] = threshold_ms
                    attrs["blackwall.sla.measured_ms"] = elapsed_ms
                    attrs["blackwall.sla.violated"] = measurement.violated

            self._measurements.append(measurement)

    def compute_trajectory_soundness_factor(
        self,
        measurements: list[SLAMeasurement] | None = None,
    ) -> int:
        """
        Calculate trajectory soundness score (1 to 5) factoring in SLA compliance.

        - If no measurements: returns 5 (perfect).
        - If 0 violations (100% compliant): returns 5.
        - Proportionally scales from 5 down to 1 based on violation rate.
        """
        target = self._measurements if measurements is None else measurements
        if not target:
            return 5

        total = len(target)
        violations = sum(1 for m in target if m.violated)
        if violations == 0:
            return 5

        compliant_rate = (total - violations) / total
        if compliant_rate >= 0.8:
            return 4
        elif compliant_rate >= 0.6:
            return 3
        elif compliant_rate >= 0.3:
            return 2
        else:
            return 1

    def get_summary(self) -> dict[str, Any]:
        """Return aggregate SLA measurement summary."""
        total = len(self._measurements)
        violations = sum(1 for m in self._measurements if m.violated)
        violation_rate = (violations / total) if total > 0 else 0.0

        by_component: dict[str, dict[str, Any]] = {}
        for m in self._measurements:
            if m.component not in by_component:
                by_component[m.component] = {"count": 0, "violations": 0, "max_ms": 0.0, "avg_ms": 0.0, "total_ms": 0.0}
            entry = by_component[m.component]
            entry["count"] += 1
            if m.violated:
                entry["violations"] += 1
            entry["total_ms"] += m.measured_ms
            entry["max_ms"] = max(entry["max_ms"], m.measured_ms)
            entry["avg_ms"] = entry["total_ms"] / entry["count"]

        return {
            "total_measurements": total,
            "violations_count": violations,
            "violation_rate": round(violation_rate, 4),
            "by_component": by_component,
        }

    def clear(self) -> None:
        """Clear recorded measurements."""
        self._measurements.clear()
