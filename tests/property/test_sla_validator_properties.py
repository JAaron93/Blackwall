"""
Property-based tests for SLA Validator (Track D.2 / Task D.2.2).

Verifies:
- Property E-12: Measured time always >= 0
- Property E-13: Violation correctly flagged when measured > threshold
- Property E-14: Non-violation correctly flagged when measured <= threshold
"""

from hypothesis import given, strategies as st
from blackwall.eval.sla_validator import (
    DEFAULT_SLA_THRESHOLDS_MS,
    SLAValidator,
)


@given(st.sampled_from(list(DEFAULT_SLA_THRESHOLDS_MS.keys())), st.floats(min_value=0.0, max_value=1000.0))
def test_property_e12_measured_time_non_negative(component: str, measured_ms: float):
    """Property E-12: Measured time always >= 0."""
    validator = SLAValidator()
    measurement = validator.record_measurement(component=component, measured_ms=measured_ms)
    assert measurement.measured_ms >= 0.0


@given(
    st.sampled_from(list(DEFAULT_SLA_THRESHOLDS_MS.keys())),
    st.floats(min_value=0.001, max_value=500.0),
)
def test_property_e13_violation_flagged_when_exceeding_threshold(component: str, delta: float):
    """Property E-13: Violation correctly flagged when measured > threshold."""
    validator = SLAValidator()
    threshold = validator.get_threshold(component)
    measured_ms = threshold + delta

    measurement = validator.record_measurement(component=component, measured_ms=measured_ms)
    assert measurement.violated is True
    assert measurement.measured_ms > measurement.threshold_ms


@given(
    st.sampled_from(list(DEFAULT_SLA_THRESHOLDS_MS.keys())),
    st.floats(min_value=0.0, max_value=1.0),
)
def test_property_e14_non_violation_flagged_when_within_threshold(component: str, ratio: float):
    """Property E-14: Non-violation correctly flagged when measured <= threshold."""
    validator = SLAValidator()
    threshold = validator.get_threshold(component)
    measured_ms = threshold * ratio

    measurement = validator.record_measurement(component=component, measured_ms=measured_ms)
    assert measurement.violated is False
    assert measurement.measured_ms <= measurement.threshold_ms
