"""TASK-F05 (ADR 0008 Open Item 10, ADR 0009): malicious and evasion attack
payloads carry real attack syntax, not a bracket placeholder standing in for
one.

Scope: the attack content only. The benign/malicious wrapper templates in
``scripts/build_evalset.py`` and the class-blind production-shaped states are
a separate concern (unaffected here); this test does not claim or require
benign and malicious cases to be merged into one class — they remain two
classes, distinguished by their payload, not by a placeholder token.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER = re.compile(r"\[\[[A-Z0-9_]+\]\]")


def _load(name: str) -> list[dict]:
    return json.loads(
        (REPO_ROOT / "tests/eval/test_data" / name).read_text(encoding="utf-8")
    )


def test_malicious_attack_patterns_carry_no_bracket_placeholder():
    cases = _load("malicious_cases.json")
    offenders = [c["id"] for c in cases if PLACEHOLDER.search(c["attack_pattern"])]
    assert not offenders, offenders


def test_evasion_attack_patterns_carry_no_bracket_placeholder():
    cases = _load("evasion_cases.json")
    offenders = [c["id"] for c in cases if PLACEHOLDER.search(c["attack_pattern"])]
    assert not offenders, offenders


def test_malicious_case_count_and_fields_are_unchanged():
    """The fix replaces attack_pattern values; it does not add, remove, or
    relabel cases, and every CWE/attack_type field a judge would check stays."""
    cases = _load("malicious_cases.json")
    assert len(cases) == 59
    assert all(c["ground_truth"] == "MALICIOUS" for c in cases)
    assert all(c.get("cwe_id") for c in cases)


def test_evasion_case_count_and_parent_links_are_unchanged():
    cases = _load("evasion_cases.json")
    assert len(cases) == 30
    assert all(c["ground_truth"] == "MALICIOUS" for c in cases)
    assert all(c.get("parent_case_id") for c in cases)


def test_built_evalset_carries_no_bracket_placeholder_in_malicious_prompts():
    """scripts/build_evalset.py must be re-run after editing the source JSON;
    this guards against the committed evalset drifting from its source."""
    evalset = json.loads(
        (
            REPO_ROOT / "tests/eval/evalsets/blackwall_security.evalset.json"
        ).read_text(encoding="utf-8")
    )
    offenders = [
        c["eval_case_id"]
        for c in evalset["eval_cases"]
        if c["metadata"]["scenario_type"] in ("malicious", "evasion")
        and PLACEHOLDER.search(c["prompt"]["parts"][0]["text"])
    ]
    assert not offenders, offenders


def test_sql_injection_patterns_are_syntactically_plausible_sql():
    """A spot check that the substitutes are real SQL, not just non-bracket
    text — each still parses as the SQL statement its id implies."""
    cases = {c["id"]: c for c in _load("malicious_cases.json")}
    assert cases["malicious_sql_001"]["attack_pattern"].upper().startswith("SELECT")
    assert "UNION SELECT" in cases["malicious_sql_003"]["attack_pattern"].upper()
    assert "DROP TABLE" in cases["malicious_sql_004"]["attack_pattern"].upper()


def test_reverse_shell_ip_is_a_documentation_range_address():
    """No live attacker infrastructure: RFC 5737 TEST-NET-1, never routable."""
    cases = {c["id"]: c for c in _load("malicious_cases.json")}
    assert "192.0.2." in cases["malicious_revshell_002"]["attack_pattern"]


def test_deserialization_cases_stay_descriptive_not_literal_bytes():
    """The two deserialization cases are the one place literal substitution
    would mint functional serialized-object payload bytes rather than attack
    syntax; they keep a labeled, non-literal technique description."""
    cases = {c["id"]: c for c in _load("malicious_cases.json")}
    assert "<" in cases["malicious_deser_001"]["attack_pattern"]
    assert "CommonsCollections" in cases["malicious_deser_002"]["attack_pattern"]
