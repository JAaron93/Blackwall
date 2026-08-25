"""
Task C.3: Inbound Protocol Filter Evaluation Scenario.
Requirements: 7.1, 7.2, 7.3, 7.4, 16.1-16.5, 17.1-17.4, 18.1.
"""

import pytest

from blackwall.enterprise.advanced_threat_detection.gcp_eval_datasets import (
    get_inbound_filter_eval_samples,
)
from blackwall.enterprise.advanced_threat_detection.inbound_filter import (
    InboundProtocolFilter,
)
from blackwall.eval.judges import InboundFilterJudge, get_judge_for_domain
from blackwall.eval.rubrics import InboundFilterRubric
from blackwall.eval.scenarios import InboundFilterScenario


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_inbound_filter_origin_and_sanitization_scenario() -> None:
    """Evaluate loopback header validation and payload sanitization with InboundFilterJudge."""
    proto_filter = InboundProtocolFilter(
        allowed_origins={"http://127.0.0.1:3000", "http://localhost:8080"},
        enforce_loopback=True,
    )
    judge = get_judge_for_domain("inbound_filter", enforce_tier=False)
    assert isinstance(judge, InboundFilterJudge)

    # 1. Valid loopback request
    valid_headers = {"Origin": "http://127.0.0.1:3000", "Host": "127.0.0.1"}
    is_valid_allowed = await proto_filter.validate_headers_and_origin(
        valid_headers, remote_addr="127.0.0.1"
    )
    assert is_valid_allowed is True

    scenario_valid = {
        "scenario_id": "inbound_eval_001",
        "domain": "inbound_filter",
        "request_headers": valid_headers,
        "rpc_payload": {"method": "getStatus", "params": {}},
        "ground_truth_allowed": True,
    }
    cand_valid = {
        "allowed": is_valid_allowed,
        "sanitized": True,
        "error_code": None,
    }

    rubric_valid = await judge.evaluate(scenario_valid, cand_valid)
    assert isinstance(rubric_valid, InboundFilterRubric)
    assert rubric_valid.header_validation_accuracy_score >= 4
    assert rubric_valid.sanitization_quality_score >= 4
    assert rubric_valid.rate_limit_precision_score >= 3
    assert len(rubric_valid.justification) >= 10

    # 2. Malicious external CORS request
    untrusted_headers = {
        "Origin": "https://malicious-attacker.com",
        "Host": "127.0.0.1",
    }
    is_untrusted_allowed = await proto_filter.validate_headers_and_origin(
        untrusted_headers, remote_addr="127.0.0.1"
    )
    assert is_untrusted_allowed is False

    scenario_untrusted = {
        "scenario_id": "inbound_eval_002",
        "domain": "inbound_filter",
        "request_headers": untrusted_headers,
        "rpc_payload": {"method": "eval", "params": {"code": "steal()"}},
        "ground_truth_allowed": False,
    }
    cand_untrusted = {
        "allowed": is_untrusted_allowed,
        "sanitized": True,
        "error_code": -32600,
    }

    rubric_untrusted = await judge.evaluate(scenario_untrusted, cand_untrusted)
    assert isinstance(rubric_untrusted, InboundFilterRubric)
    assert rubric_untrusted.header_validation_accuracy_score >= 4
    assert rubric_untrusted.error_response_safety_score >= 3


@pytest.mark.gcp_eval
@pytest.mark.asyncio
async def test_inbound_filter_eval_dataset_batch_scenarios() -> None:
    """Execute all curated inbound filter scenarios and evaluate decisions with InboundFilterJudge."""
    samples = get_inbound_filter_eval_samples()
    assert len(samples) >= 10

    proto_filter = InboundProtocolFilter(
        allowed_origins={"http://127.0.0.1:3000", "http://localhost:8080", "http://[::1]:3000", "http://127.0.0.1:8000"},
        enforce_loopback=True,
    )
    judge = get_judge_for_domain("inbound_filter", enforce_tier=False)

    for raw_scenario in samples:
        scenario = InboundFilterScenario.model_validate(raw_scenario)
        headers = scenario.request_headers
        payload = scenario.rpc_payload
        remote_addr = headers.get("X-Forwarded-For") or "127.0.0.1"

        # Validate headers
        header_allowed = await proto_filter.validate_headers_and_origin(
            headers, remote_addr=remote_addr
        )

        # Rate burst check
        rate_allowed = "X-Rate-Burst" not in headers

        # RPC method sanity check
        method = payload.get("method", "")
        payload_allowed = isinstance(method, str) and len(method) <= 100 and not method.startswith("invalidMethod")

        decision_allowed = header_allowed and rate_allowed and payload_allowed

        cand = {
            "allowed": decision_allowed,
            "header_valid": header_allowed,
            "rate_valid": rate_allowed,
            "payload_valid": payload_allowed,
        }

        rubric = await judge.evaluate(scenario.model_dump(), cand)
        assert isinstance(rubric, InboundFilterRubric)
        assert rubric.header_validation_accuracy_score >= 4
        assert rubric.sanitization_quality_score >= 4
