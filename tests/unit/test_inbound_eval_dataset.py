"""
Unit tests for Inbound Protocol Filter Evaluation Scenarios (Task A.2.3 / Requirements 7.1, 7.2, 7.3, 7.4).
"""

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_inbound_filter_eval_samples,
)
from blackwall.eval.scenarios import InboundFilterScenario


def test_inbound_filter_eval_dataset_quantity_and_schema():
    """Verify at least 10 scenarios exist and all satisfy InboundFilterScenario schema."""
    samples = get_inbound_filter_eval_samples()
    assert len(samples) >= 10

    for s in samples:
        scenario = InboundFilterScenario.model_validate(s)
        assert scenario.domain == "inbound_filter"
        assert isinstance(scenario.request_headers, dict)
        assert isinstance(scenario.rpc_payload, dict)
        assert isinstance(scenario.ground_truth_allowed, bool)


def test_inbound_filter_eval_dataset_origin_checks():
    """Verify loopback is allowed and remote / untrusted origins are rejected."""
    samples = get_inbound_filter_eval_samples()
    allowed_cases = [s for s in samples if s["ground_truth_allowed"] is True]
    rejected_cases = [s for s in samples if s["ground_truth_allowed"] is False]

    assert len(allowed_cases) >= 4
    assert len(rejected_cases) >= 4

    for s in allowed_cases:
        origin = s["request_headers"].get("Origin", "")
        host = s["request_headers"].get("Host", "")
        assert "127.0.0.1" in origin or "localhost" in origin or "::1" in origin or "127.0.0.1" in host

    for s in rejected_cases:
        origin = s["request_headers"].get("Origin", "")
        # Remote/malicious origin or rate burst or malformed
        is_suspicious = (
            "malicious" in origin
            or "null" in origin
            or "evil" in origin
            or "10.0.0.5" in origin
            or "X-Rate-Burst" in s["request_headers"]
            or "invalidMethod" in s["rpc_payload"].get("method", "")
            or "203.0.113" in s["request_headers"].get("X-Forwarded-For", "")
        )
        assert is_suspicious
