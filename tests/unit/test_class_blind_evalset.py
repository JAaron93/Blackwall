"""TASK-F05b (ADR 0008 Open Item 10, ADR 0009): the golden evalset is class-blind.

Benign and malicious stay two classes, told apart by their payload. What these
tests require is that NOTHING ELSE tells them apart: one shared wrapper
template for every label, no label words or harness fields in the text a
classifier reads, no bracket placeholders in either class, the same argument
keys for the same tool whatever the label, and states shaped exactly as
production builds them. They read committed files and run the generator code;
they never touch the network.
"""

import importlib.util
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALSET = REPO_ROOT / "tests/eval/evalsets/blackwall_security.evalset.json"
PROOF = REPO_ROOT / "tests/eval/evalsets/blackwall_evasion_proof.evalset.json"
PLACEHOLDER = re.compile(r"\[\[[A-Z0-9_]+\]\]")
SHARED_TEMPLATE = re.compile(r"^Execute tool '([^']+)' with arguments: (\{.*\})$", re.S)

# Words that name the class, or the harness that wrote the case, and that a
# production tool call does not contain. Checked on prompts AND on payloads.
LABEL_WORDS = re.compile(
    r"benign|malicious|evasion|evasive|variant of|attack[_ ]?(type|pattern)|"
    r"evasion_type|obfuscation|parent|attacker|phishing|exploit|rogue|backdoor|"
    r"exfil|mirai|botnet|emotet|trickbot|beacon|detected-by|\bevil\b|\bc2\b|c2-",
    re.I,
)
RESERVED_HOST = re.compile(
    r"(\.example|\.example\.(com|net|org)|example\.(com|net|org)|\.test|\.invalid|"
    r"\.internal|\.local|localhost)$",
    re.I,
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _module(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def evalset() -> list[dict[str, Any]]:
    return _load(EVALSET)["eval_cases"]


@pytest.fixture(scope="module")
def builder():
    yield _module("build_evalset_cb", "scripts/build_evalset.py")
    sys.modules.pop("build_evalset_cb", None)


@pytest.fixture(scope="module")
def evaluator():
    sys.path.insert(0, str(REPO_ROOT / "src"))
    yield _module("jev_triage_eval_cb", "scripts/jev_triage_eval.py")
    sys.modules.pop("jev_triage_eval_cb", None)


def _prompt(case: dict[str, Any]) -> str:
    return case["prompt"]["parts"][0]["text"]


# ------------------------------------------------------------ one wrapper template
def test_every_prompt_uses_the_one_shared_template_whatever_the_label(evalset):
    odd = [c["eval_case_id"] for c in evalset if not SHARED_TEMPLATE.match(_prompt(c))]
    assert not odd, odd[:5]


def test_the_template_names_the_tool_in_metadata_and_carries_the_same_arguments(evalset):
    for c in evalset:
        tool, args_json = SHARED_TEMPLATE.match(_prompt(c)).groups()
        assert tool == c["metadata"]["tool_name"], c["eval_case_id"]
        assert json.loads(args_json) == c["metadata"]["tool_arguments"], c["eval_case_id"]


def test_no_prompt_carries_a_label_word_or_harness_field(evalset):
    offenders = [
        (c["eval_case_id"], LABEL_WORDS.search(_prompt(c)).group(0))
        for c in evalset
        if LABEL_WORDS.search(_prompt(c))
    ]
    assert not offenders, offenders[:8]


def test_labels_and_attack_metadata_are_kept_outside_the_prompt(evalset):
    """Benign and malicious remain two classes: the label lives in metadata."""
    scenarios = {c["metadata"]["scenario_type"] for c in evalset}
    assert scenarios == {"benign", "malicious", "evasion"}
    assert {c["metadata"]["ground_truth"] for c in evalset} == {"BENIGN", "MALICIOUS"}
    assert len(evalset) == 157


# --------------------------------------------------------------------- no placeholders
def test_neither_class_carries_a_bracket_placeholder(evalset):
    offenders = [c["eval_case_id"] for c in evalset if PLACEHOLDER.search(_prompt(c))]
    assert not offenders, offenders[:8]


def test_source_data_carries_no_bracket_placeholder_in_any_class():
    for name in ("benign_cases.json", "malicious_cases.json", "evasion_cases.json"):
        text = (REPO_ROOT / "tests/eval/test_data" / name).read_text(encoding="utf-8")
        found = sorted(set(PLACEHOLDER.findall(text)))
        assert not found, (name, found[:5])


# ---------------------------------------------------- same keys for the same tool
def test_a_tool_uses_the_same_argument_keys_in_both_classes(evalset):
    keys: dict[str, dict[str, set[str]]] = {}
    for c in evalset:
        label = c["metadata"]["ground_truth"]
        keys.setdefault(c["metadata"]["tool_name"], {}).setdefault(label, set()).update(
            c["metadata"]["tool_arguments"].keys()
        )
    shared = {t: k for t, k in keys.items() if len(k) == 2}
    assert {"database_query", "file_read", "file_write", "http_request"} <= set(shared)
    for tool, by_label in shared.items():
        malicious, benign = by_label["MALICIOUS"], by_label["BENIGN"]
        assert malicious <= benign | {"method", "url", "content", "filepath"}, (tool, malicious - benign)
        # the primary payload key is the same in both classes
        assert malicious & benign, tool


# ------------------------------------------------------------ tells in the payloads
def test_no_payload_names_its_own_class(evalset):
    offenders = [
        (c["eval_case_id"], LABEL_WORDS.search(json.dumps(c["metadata"]["tool_arguments"])).group(0))
        for c in evalset
        if LABEL_WORDS.search(json.dumps(c["metadata"]["tool_arguments"]))
    ]
    assert not offenders, offenders[:10]


def _hosts(text: str) -> set[str]:
    hosts = set(re.findall(r"https?://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+)", text))
    hosts |= set(re.findall(r"udp://([A-Za-z0-9.\-]+)", text))
    hosts |= set(re.findall(r"/dev/tcp/([A-Za-z0-9.\-]+)/", text))
    hosts |= set(re.findall(r"\bTCP:([A-Za-z0-9.\-]+):", text))
    hosts |= set(re.findall(r"\b(?:nc|ping)\b[^;|&]*?\s(\d{1,3}(?:\.\d{1,3}){3})\b", text))
    return hosts


def test_malicious_and_evasion_payloads_only_point_at_reserved_or_private_hosts(evalset):
    bad: list[tuple[str, str]] = []
    for c in evalset:
        if c["metadata"]["ground_truth"] != "MALICIOUS":
            continue
        for host in _hosts(json.dumps(c["metadata"]["tool_arguments"])):
            try:
                if re.fullmatch(r"0x[0-9a-fA-F]{8}", host):  # hex-encoded IPv4 form
                    host = str(ipaddress.ip_address(int(host, 16)))
                ip = ipaddress.ip_address(host)
            except ValueError:
                if not RESERVED_HOST.search(host):
                    bad.append((c["eval_case_id"], host))
                continue
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                bad.append((c["eval_case_id"], host))
    assert not bad, bad


# -------------------------------------------------------------- args_from_pattern
@pytest.mark.parametrize(
    "tool,pattern,expected",
    [
        ("database_query", "SELECT * FROM users WHERE id = 1 OR 1=1", {"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}),
        ("database_query", "database_query(SELECT 1)", {"query": "SELECT 1"}),
        ("execute_shell", "ls /tmp | cat /etc/passwd", {"cmd": "ls /tmp | cat /etc/passwd"}),
        ("execute_shell", "execute_shell(id; whoami)", {"cmd": "id; whoami"}),
        ("file_read", "read_file(../../../etc/passwd)", {"filepath": "../../../etc/passwd"}),
        ("http_request", "http_request(http://192.0.2.5/x)", {"method": "GET", "url": "http://192.0.2.5/x"}),
        ("http_request", "http_request(POST http://192.0.2.5/x?d=1)", {"method": "POST", "url": "http://192.0.2.5/x?d=1"}),
        ("file_write", "file_write(/tmp/a.txt, user:pw)", {"filepath": "/tmp/a.txt", "content": "user:pw"}),
        ("dns_query", "dns_query(t1.relay-ns.example TXT)", {"hostname": "t1.relay-ns.example", "query_type": "TXT"}),
        ("socket_connect", "socket_connect(203.0.113.5:4444)", {"address": "203.0.113.5:4444"}),
        ("download_file", "download_file(http://files.example/a.bin)", {"url": "http://files.example/a.bin"}),
        ("parse_xml", "parse_xml(<a/>)", {"xml": "<a/>"}),
    ],
)
def test_args_from_pattern_maps_each_wrapper_to_the_canonical_keys(builder, tool, pattern, expected):
    assert builder.args_from_pattern(tool, pattern) == expected


def test_args_from_pattern_rejects_an_unparseable_wrapper(builder):
    with pytest.raises(ValueError):
        builder.args_from_pattern("file_write", "file_write(no-comma-here)")


# ------------------------------------------------- production-shaped scoring states
def test_scoring_states_are_exactly_what_production_builds(evaluator):
    from blackwall.models import ToolCallContext
    from blackwall.policy.semantic import JevTriageBackend
    from blackwall.resolver import ContextHygiene

    hygiene = ContextHygiene(preserve_iocs=True)
    cases = evaluator.build_cases(["security", "evasion_proof"])
    assert len(cases) == 167
    by_id = {c["id"]: c for c in cases}
    sample = next(c for c in _load(EVALSET)["eval_cases"] if c["eval_case_id"] == "malicious_sql_001")
    ctx = hygiene.sanitize_context(
        ToolCallContext(tool_name="database_query", arguments=sample["metadata"]["tool_arguments"])
    )
    assert by_id["malicious_sql_001"]["state"] == JevTriageBackend.build_state(ctx)


def test_scoring_states_carry_no_harness_scaffolding_or_label_words(evaluator):
    cases = evaluator.build_cases(["security", "evasion_proof"])
    for c in cases:
        assert c["state"].startswith(f"Tool: {c['tool']}\nArguments: "), c["id"]
        assert "\nRequest:" not in c["state"], c["id"]
        assert not LABEL_WORDS.search(c["state"]), (c["id"], LABEL_WORDS.search(c["state"]).group(0))


def test_scoring_states_cover_every_case_once_with_stable_hashes(evaluator):
    cases = evaluator.build_cases(["security", "evasion_proof"])
    assert len({c["id"] for c in cases}) == 167
    assert all(len(c["h"]) == 16 for c in cases)
    assert {c["suite"] for c in cases} == {"security", "evasion_proof"}
    assert sum(c["label"] for c in cases) == 99  # 59 malicious + 30 evasion + 10 proof


# ----------------------------------------- sanitization must not mangle a payload
def test_sanitization_only_redacts_whole_secrets_never_the_middle_of_a_word(evaluator):
    """ContextHygiene redacts secrets before Jev sees them. A redaction that eats
    part of an ordinary token (``task-5531`` -> ``ta[[OPENAI_API_KEY]]``) corrupts
    the state and leaves a class-specific artifact, so no case's state may differ
    from its arguments by anything but a whole-value ``[[NAME]]`` replacement."""
    corrupted = []
    for case in _load(EVALSET)["eval_cases"]:
        state = next(c for c in evaluator.build_cases(["security"]) if c["id"] == case["eval_case_id"])["state"]
        for token in re.findall(r"\S*\[\[[A-Z_]+\]\]\S*", state):
            # a redaction is acceptable only when it replaces a whole value:
            # it must start the token or follow a quote, '=', ':', '/', or a space
            before = token.split("[[")[0]
            if before and before[-1] not in "'\"=:/ ,(":
                corrupted.append((case["eval_case_id"], token))
    assert not corrupted, corrupted[:5]


# ------------------------------------------- the historical evidence is not overwritten
def test_default_output_never_overwrites_the_adr_0008_artifact(evaluator):
    """``jev_triage_results.json`` is the TASK-D02 artifact the notebook and the
    ADR 0008 data tests read. The scorer now scores a different corpus, so its
    default output must be a different file."""
    args = evaluator._parser().parse_args([])
    assert args.out != "tests/eval/results/jev_triage_results.json"
    assert "class_blind" in args.out
    assert (REPO_ROOT / "tests/eval/results/jev_triage_results.json").exists()


# ---------------------------------- retired benign generators cannot undo the fix
@pytest.mark.parametrize("script", ["create_benign.py", "create_benign_comprehensive.py"])
def test_retired_benign_generators_refuse_to_rewrite_the_source_data(script, tmp_path):
    """Both scripts write benign_cases.json from literals that still contain
    [[PLACEHOLDER]] tokens. benign_cases.json is now the source of truth, so a
    rerun would silently reintroduce a class tell. They must exit non-zero and
    write nothing."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tests/eval/test_data" / script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "TASK-F05b" in (result.stdout + result.stderr)
    assert not (tmp_path / "tests").exists(), "the retired generator wrote a file"
