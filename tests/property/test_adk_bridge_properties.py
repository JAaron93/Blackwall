"""
Property-based tests for ADK-to-EvalTask Dataset Bridge (`scripts/bridge_adk_to_eval.py`).

Validates:
- Property E-1: Bridge output schema compliance
- Property E-2: Bridge bijection (no cases dropped, no duplicates)
- Property E-3: Verdict mapping correctness (ALLOW/BLOCK/QUARANTINE preserved)
"""

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.eval.scenarios import ThreatInterceptionScenario
from scripts.bridge_adk_to_eval import bridge_adk_evalset, transform_adk_case

# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

verdicts = st.sampled_from(["ALLOW", "BLOCK", "QUARANTINE", "allow", "block", "quarantine"])
labels = st.sampled_from(["BENIGN", "MALICIOUS", "benign", "malicious"])
identifiers = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-"),
    min_size=1,
    max_size=40,
)
prompts = st.text(min_size=0, max_size=200)
tool_names = st.sampled_from(["database_query", "bash_exec", "file_read", "http_request", "custom_tool"])


@st.composite
def adk_case_strategy(draw: Any) -> dict[str, Any]:
    case_id = draw(identifiers)
    verdict = draw(verdicts)
    label = draw(labels)
    prompt = draw(prompts)
    tool_name = draw(tool_names)

    return {
        "eval_case_id": case_id,
        "conversation": [{"role": "user", "parts": [{"text": prompt}]}],
        "expected_tool_use": [
            {
                "tool_use": {
                    "tool_name": "before_tool_callback",
                    "tool_input": {"tool_name": tool_name},
                },
                "tool_use_result": {"verdict": verdict.upper()},
            }
        ],
        "reference": verdict,
        "metadata": {
            "ground_truth": label,
            "tool_name": tool_name,
            "attack_type": draw(st.text(max_size=30)),
            "severity": draw(st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"])),
        },
    }


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------


@settings(max_examples=50)
@given(case=adk_case_strategy())
def test_property_e1_bridge_output_schema_compliance(case: dict[str, Any]):
    """
    Property E-1: Bridge output schema compliance.
    Every transformed ADK case must satisfy the ThreatInterceptionScenario Pydantic model.
    """
    transformed = transform_adk_case(case)

    # Validate with Pydantic
    model = ThreatInterceptionScenario.model_validate(transformed)

    assert model.scenario_id == case["eval_case_id"]
    assert model.domain == "threat_interception"
    assert model.ground_truth_verdict in ("ALLOW", "BLOCK", "QUARANTINE")
    assert model.ground_truth_label in ("BENIGN", "MALICIOUS")
    assert isinstance(model.reference_trajectory, list)
    assert len(model.reference_trajectory) >= 1
    assert isinstance(model.metadata, dict)


@settings(max_examples=50)
@given(cases=st.lists(adk_case_strategy(), min_size=1, max_size=20, unique_by=lambda c: c["eval_case_id"]))
def test_property_e2_bridge_bijection(cases: list[dict[str, Any]]):
    """
    Property E-2: Bridge bijection.
    Bridging a list of unique ADK cases yields an exact 1-to-1 mapping with no dropped or duplicated cases.
    """
    bridged = bridge_adk_evalset(cases)

    assert len(bridged) == len(cases)

    input_ids = [c["eval_case_id"] for c in cases]
    output_ids = [s["scenario_id"] for s in bridged]

    assert input_ids == output_ids
    assert len(set(output_ids)) == len(cases)


@settings(max_examples=50)
@given(case=adk_case_strategy())
def test_property_e3_verdict_mapping_correctness(case: dict[str, Any]):
    """
    Property E-3: Verdict mapping correctness.
    ALLOW, BLOCK, and QUARANTINE references must be faithfully preserved in uppercase ground_truth_verdict.
    """
    transformed = transform_adk_case(case)
    expected_verdict = case["reference"].upper()

    assert transformed["ground_truth_verdict"] == expected_verdict
