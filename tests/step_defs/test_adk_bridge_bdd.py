"""
BDD step definitions for ADK-to-EvalTask Dataset Bridge (`tests/features/adk_bridge.feature`).
"""

from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from scripts.bridge_adk_to_eval import transform_adk_case

scenarios("../features/adk_bridge.feature")


class BridgeBDDState:
    def __init__(self) -> None:
        self.adk_case: dict[str, Any] = {}
        self.scenario: dict[str, Any] = {}


@pytest.fixture
def bdd_state() -> BridgeBDDState:
    return BridgeBDDState()


# ---------------------------------------------------------------------------
# Given Steps
# ---------------------------------------------------------------------------


@given(parsers.parse('a benign ADK eval case with ID "{case_id}" and tool "{tool_name}"'))
def given_benign_case(bdd_state: BridgeBDDState, case_id: str, tool_name: str) -> None:
    bdd_state.adk_case = {
        "eval_case_id": case_id,
        "conversation": [
            {"role": "user", "parts": [{"text": f"Run safe operation on {tool_name}"}]}
        ],
        "expected_tool_use": [
            {
                "tool_use": {
                    "tool_name": "before_tool_callback",
                    "tool_input": {"tool_name": tool_name},
                },
                "tool_use_result": {"verdict": "ALLOW"},
            }
        ],
        "reference": "ALLOW",
        "metadata": {
            "ground_truth": "BENIGN",
            "scenario_type": "benign",
            "tool_name": tool_name,
        },
    }


@given(parsers.parse('a malicious ADK eval case with ID "{case_id}" and attack type "{attack_type}"'))
def given_malicious_case(bdd_state: BridgeBDDState, case_id: str, attack_type: str) -> None:
    bdd_state.adk_case = {
        "eval_case_id": case_id,
        "conversation": [
            {"role": "user", "parts": [{"text": f"Run exploit for {attack_type}"}]}
        ],
        "expected_tool_use": [
            {
                "tool_use": {
                    "tool_name": "before_tool_callback",
                    "tool_input": {"tool_name": "bash_exec"},
                },
                "tool_use_result": {"verdict": "BLOCK"},
            }
        ],
        "reference": "BLOCK",
        "metadata": {
            "ground_truth": "MALICIOUS",
            "scenario_type": "malicious",
            "attack_type": attack_type,
            "severity": "CRITICAL",
        },
    }


@given(parsers.parse('an evasion ADK eval case with ID "{case_id}", parent "{parent_id}", and evasion type "{evasion_type}"'))
def given_evasion_case(
    bdd_state: BridgeBDDState, case_id: str, parent_id: str, evasion_type: str
) -> None:
    bdd_state.adk_case = {
        "eval_case_id": case_id,
        "conversation": [
            {"role": "user", "parts": [{"text": f"Obfuscated attack using {evasion_type}"}]}
        ],
        "expected_tool_use": [
            {
                "tool_use": {
                    "tool_name": "before_tool_callback",
                    "tool_input": {"tool_name": "database_query"},
                },
                "tool_use_result": {"verdict": "BLOCK"},
            }
        ],
        "reference": "BLOCK",
        "metadata": {
            "ground_truth": "MALICIOUS",
            "scenario_type": "evasion",
            "evasion_type": evasion_type,
            "parent_case_id": parent_id,
            "severity": "CRITICAL",
        },
    }


# ---------------------------------------------------------------------------
# When Steps
# ---------------------------------------------------------------------------


@when("the ADK case is transformed by the bridge")
def when_transformed(bdd_state: BridgeBDDState) -> None:
    bdd_state.scenario = transform_adk_case(bdd_state.adk_case)


# ---------------------------------------------------------------------------
# Then Steps
# ---------------------------------------------------------------------------


@then(parsers.parse('the judge scenario ID should be "{expected_id}"'))
def then_scenario_id(bdd_state: BridgeBDDState, expected_id: str) -> None:
    assert bdd_state.scenario["scenario_id"] == expected_id


@then(parsers.parse('the ground_truth_verdict should be "{expected_verdict}"'))
def then_verdict(bdd_state: BridgeBDDState, expected_verdict: str) -> None:
    assert bdd_state.scenario["ground_truth_verdict"] == expected_verdict


@then(parsers.parse('the ground_truth_label should be "{expected_label}"'))
def then_label(bdd_state: BridgeBDDState, expected_label: str) -> None:
    assert bdd_state.scenario["ground_truth_label"] == expected_label


@then(parsers.parse('the reference_trajectory should contain "{expected_tool}"'))
def then_reference_trajectory_contains(bdd_state: BridgeBDDState, expected_tool: str) -> None:
    assert expected_tool in bdd_state.scenario["reference_trajectory"]


@then(parsers.parse('the metadata field "{field_name}" should equal "{expected_value}"'))
def then_metadata_field_equals(
    bdd_state: BridgeBDDState, field_name: str, expected_value: str
) -> None:
    assert str(bdd_state.scenario["metadata"].get(field_name)) == expected_value
