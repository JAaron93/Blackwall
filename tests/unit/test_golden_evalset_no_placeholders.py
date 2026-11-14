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


# --- Replacement payloads must be well-formed (Greptile PR #202) -------------
# Static checks only: payloads are parsed (shlex / ast.parse), never executed.


def _shell_arg(pattern: str) -> str:
    """Strip the ``execute_shell(...)`` wrapper, leaving the command line."""
    assert pattern.startswith("execute_shell(") and pattern.endswith(")")
    return pattern[len("execute_shell("):-1]


def _python_dash_c_source(pattern: str) -> str:
    """The Python source a ``python[3] -c '<src>'`` command line would run."""
    import shlex

    argv = shlex.split(_shell_arg(pattern))
    assert argv[0] in {"python", "python3"} and argv[1] == "-c", argv
    assert len(argv) == 3, f"quoting split the -c source into {argv}"
    return argv[2]


def test_xor_evasion_decodes_to_a_command_that_a_shell_runs_not_exec():
    """exec() would evaluate the decoded text as Python (NameError on
    ``whoami``); the decoded command has to reach a shell."""
    import ast

    case = {c["id"]: c for c in _load("evasion_cases.json")}["evasion_xor_encoding_001"]
    tree = ast.parse(_python_dash_c_source(case["attack_pattern"]))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    names = {ast.unparse(n.func) for n in calls}
    assert "exec" not in names and "eval" not in names, names
    assert names & {"os.system", "subprocess.call", "subprocess.run"}, names
    key = 42
    data = next(
        ast.literal_eval(n) for n in ast.walk(tree) if isinstance(n, ast.List)
    )
    assert "".join(chr(b ^ key) for b in data) == "whoami"


def test_python_reverse_shell_source_is_valid_python():
    """The single-quoted -c argument must not be broken by the IP string's
    quotes (it split into three shell words before)."""
    import ast

    case = {c["id"]: c for c in _load("malicious_cases.json")}["malicious_revshell_004"]
    source = _python_dash_c_source(case["attack_pattern"])
    ast.parse(source)
    assert "192.0.2.10" in source


def test_checkpoint_action_option_is_passed_to_tar_not_ls():
    """--checkpoint-action is a GNU tar option; ls rejects it."""
    import ast

    case = {c["id"]: c for c in _load("malicious_cases.json")}["malicious_oscmd_001"]
    call = ast.parse(case["attack_pattern"], mode="eval").body
    argv = ast.literal_eval(call.args[0])
    assert argv[0] == "tar", argv
    assert any(a.startswith("--checkpoint-action=exec=") for a in argv)
