"""
Unit tests for SLA Validation Engine (Track D.2 / Task D.2.1).

Verifies:
- Threshold lookup for TSG (<10ms), structural gating (<5ms), active reaction (<50ms), eBPF (<50ms), Mesh (<15ms).
- Accurate time measurement and violation calculation.
- Cloud Trace span attribute recording.
- Trajectory soundness score factoring.
"""

import time
import pytest
from blackwall.enterprise.advanced_threat_detection.gcp_trace_exporter import GCPCloudTraceExporter
from blackwall.eval.sla_validator import (
    DEFAULT_SLA_THRESHOLDS_MS,
    SLAMeasurement,
    SLAValidator,
)


def test_sla_validator_default_thresholds():
    """Verify default SLA thresholds match specification."""
    validator = SLAValidator()
    assert validator.get_threshold("tsg_signature_match") == 10.0
    assert validator.get_threshold("structural_gating") == 5.0
    assert validator.get_threshold("active_reaction") == 50.0
    assert validator.get_threshold("ebpf_drop") == 50.0
    assert validator.get_threshold("mesh_broadcast") == 15.0


def test_sla_validator_record_measurement():
    """Verify recording measurement within and exceeding threshold."""
    validator = SLAValidator()

    # Non-violating measurement
    m1 = validator.record_measurement("tsg_signature_match", measured_ms=4.2)
    assert m1.component == "tsg_signature_match"
    assert m1.threshold_ms == 10.0
    assert m1.measured_ms == 4.2
    assert m1.violated is False

    # Violating measurement
    m2 = validator.record_measurement("structural_gating", measured_ms=7.8)
    assert m2.component == "structural_gating"
    assert m2.threshold_ms == 5.0
    assert m2.measured_ms == 7.8
    assert m2.violated is True

    # Exact threshold boundary: measured == threshold is NOT a violation (must be > threshold)
    m3 = validator.record_measurement("mesh_broadcast", measured_ms=15.0)
    assert m3.violated is False


def test_sla_validator_context_manager():
    """Verify context manager measures execution time accurately."""
    validator = SLAValidator()

    with validator.measure("structural_gating") as measurement:
        time.sleep(0.006)  # ~6ms

    assert measurement.component == "structural_gating"
    assert measurement.measured_ms >= 5.0
    assert measurement.violated is True
    assert len(validator.measurements) == 1


def test_sla_validator_span_attributes():
    """Verify SLA validator records attributes on GCPTraceSpan."""
    exporter = GCPCloudTraceExporter(project_id="unit-test-proj")
    span = exporter.start_span(name="vertex_eval.sla_test")

    validator = SLAValidator()
    measurement = validator.record_measurement(
        component="tsg_signature_match",
        measured_ms=12.5,
        span=span,
    )

    assert span.attributes["blackwall.sla.component"] == "tsg_signature_match"
    assert span.attributes["blackwall.sla.threshold_ms"] == 10.0
    assert span.attributes["blackwall.sla.measured_ms"] == 12.5
    assert span.attributes["blackwall.sla.violated"] is True


def test_sla_validator_trajectory_soundness_factor():
    """Verify trajectory soundness score factoring based on SLA compliance."""
    validator = SLAValidator()

    # No measurements -> default 5
    assert validator.compute_trajectory_soundness_factor([]) == 5

    # All compliant -> 5
    m_clean = [
        SLAMeasurement(component="tsg_signature_match", threshold_ms=10.0, measured_ms=2.0, violated=False),
        SLAMeasurement(component="structural_gating", threshold_ms=5.0, measured_ms=1.5, violated=False),
    ]
    assert validator.compute_trajectory_soundness_factor(m_clean) == 5

    # Some violations -> penalize appropriately
    m_mixed = [
        SLAMeasurement(component="tsg_signature_match", threshold_ms=10.0, measured_ms=2.0, violated=False),
        SLAMeasurement(component="structural_gating", threshold_ms=5.0, measured_ms=10.0, violated=True),
    ]
    score = validator.compute_trajectory_soundness_factor(m_mixed)
    assert 1 <= score <= 4

    # All violated -> 1
    m_all_bad = [
        SLAMeasurement(component="tsg_signature_match", threshold_ms=10.0, measured_ms=20.0, violated=True),
        SLAMeasurement(component="structural_gating", threshold_ms=5.0, measured_ms=10.0, violated=True),
    ]
    assert validator.compute_trajectory_soundness_factor(m_all_bad) == 1
