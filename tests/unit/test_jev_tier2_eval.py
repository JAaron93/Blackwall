"""Unit tests for the live Tier-2 harness (scripts/jev_tier2_eval.py).

Governing spec: .kiro/specs/tier-1-jev-addition/ (ADR 0008 Verification; ADR 0009).

The harness spends real money on Vertex AI and the TypeSafe API, so it is dev
tooling that CI never runs. These tests cover only what needs no network: how the
golden cases are read from the committed data, how a config string maps to the
repo's thinking switches, how results are summarised, and that the entry points
refuse to start (before building any client) when credentials are missing. They
never create a client, spawn a process or read a credential file.
"""

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("jev_tier2_eval", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


# ------------------------------------------------------------------ case loading


def test_parse_production_state_reads_tool_and_the_exact_argument_dict(harness):
    state = (
        "Tool: http_request\n"
        "Arguments: {'method': 'POST', 'url': 'http://10.0.4.17:8443/v2/events', "
        "'body': {'host': 'build-07', 'tasks': ['lint']}}\n"
        "Metadata: {}"
    )
    tool, args = harness.parse_production_state(state)
    assert tool == "http_request"
    assert args == {
        "method": "POST",
        "url": "http://10.0.4.17:8443/v2/events",
        "body": {"host": "build-07", "tasks": ["lint"]},
    }


@pytest.mark.parametrize(
    "state",
    [
        "Tool: t\nRequest: not production shaped",
        "Tool: t\nArguments: ['not', 'a', 'dict']\nMetadata: {}",
        "Arguments: {}\nMetadata: {}",
        "Tool: t\nArguments: {}",
    ],
)
def test_parse_production_state_rejects_other_shapes(harness, state):
    with pytest.raises(ValueError):
        harness.parse_production_state(state)


def test_golden_cases_load_with_the_expected_groups(harness):
    cases = harness.load_cases()
    assert len(cases) == 167 and len({c.id for c in cases}) == 167
    counts = {g: sum(1 for c in cases if c.group == g) for g in ("c2", "proof", "benign", "other")}
    assert counts == {"c2": 10, "proof": 8, "benign": 68, "other": 81}
    for c in cases:
        assert c.tool and isinstance(c.args, dict) and c.args, c.id
        assert 0.0 <= c.jev_p <= 1.0, c.id
        assert (c.label == "BENIGN") == (c.group == "benign"), c.id


def test_forced_set_is_the_93_inputs_the_adr_reports(harness):
    forced = harness.forced_cases(harness.load_cases())
    counts = {g: sum(1 for c in forced if c.group == g) for g in ("c2", "proof", "benign", "probe")}
    assert counts == {"c2": 10, "proof": 8, "benign": 68, "probe": 7}
    assert len({c.id for c in forced}) == 93
    probes = [c for c in forced if c.group == "probe"]
    assert {c.label for c in probes} == {"BENIGN", "MALICIOUS"}
    assert all(c.jev_p == 0.50 for c in probes)  # the ambiguity-band midpoint


# --------------------------------------------------------------- config handling


def test_config_string_names_a_model_and_a_thinking_level(harness):
    assert harness.parse_config("gemini-3.5-flash-lite:medium") == ("gemini-3.5-flash-lite", "medium")
    assert harness.parse_config("default:shipped") == (None, "shipped")
    for bad in ("gemini-3.5-flash-lite", "gemini-3.5-flash-lite:ultra", ":medium", ""):
        with pytest.raises(ValueError):
            harness.parse_config(bad)


def test_levels_override_the_pinned_constant_only_inside_the_context(harness):
    from blackwall.policy import semantic

    assert semantic.TIER2_THINKING_LEVEL == "medium"  # ADR 0009 pin
    with harness.pinned_level("low"):
        assert semantic.TIER2_THINKING_LEVEL == "low"
    assert semantic.TIER2_THINKING_LEVEL == "medium"
    with harness.pinned_level("shipped"):
        assert semantic.TIER2_THINKING_LEVEL == "medium"
    assert semantic.TIER2_THINKING_LEVEL == "medium"


def test_pinned_level_is_restored_when_the_run_raises(harness):
    from blackwall.policy import semantic

    with pytest.raises(RuntimeError):
        with harness.pinned_level("high"):
            raise RuntimeError("boom")
    assert semantic.TIER2_THINKING_LEVEL == "medium"


def test_environment_cannot_move_the_shipped_level(harness, monkeypatch):
    """The sweep is a harness-only override; the product ignores the environment."""
    from unittest.mock import MagicMock

    from blackwall.models import ToolCallContext
    from blackwall.policy.semantic import GeminiTier2Backend, SemanticTriageResult
    import asyncio

    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "low")
    monkeypatch.setenv("GEMINI_ALLOW_ANALYTICAL_DOWNGRADE", "true")
    client = MagicMock()
    response = MagicMock()
    response.parsed = None
    response.text = '{"decision": "ALLOW", "threat_score": 0.1, "reasoning": "x"}'
    client.models.generate_content = MagicMock(return_value=response)
    ctx = ToolCallContext(tool_name="t", arguments={"a": "b"})
    t1 = SemanticTriageResult(threat_score=0.5, backend="jev", escalate=True)
    asyncio.run(GeminiTier2Backend(client).escalate(ctx, t1))
    level = client.models.generate_content.call_args.kwargs["config"].thinking_config.thinking_level
    assert str(getattr(level, "value", level)).lower() == "medium"


# -------------------------------------------------------------------- summaries


def _row(cid: str, group: str, label: str, decision: Any, ms: int, config: str = "m:medium") -> dict[str, Any]:
    return {"config": config, "id": cid, "group": group, "label": label,
            "decision": decision, "score": None, "reason": None, "ms": ms}


def test_forced_summary_counts_blocks_false_positives_and_abstentions(harness):
    rows = [
        _row("c2-1", "c2", "MALICIOUS", "BLOCK", 2000),
        _row("c2-2", "c2", "MALICIOUS", "BLOCK", 3000),
        _row("p-1", "proof", "MALICIOUS", "ALLOW", 2500),
        _row("b-1", "benign", "BENIGN", "ALLOW", 1500),
        _row("b-2", "benign", "BENIGN", "BLOCK", 1800),
        _row("b-3", "benign", "BENIGN", None, 30000),  # deadline
        _row("pr-1", "probe", "MALICIOUS", "BLOCK", 2200),
        _row("pr-2", "probe", "BENIGN", "ALLOW", 2100),
    ]
    s = harness.summarize_forced(rows, timeout_s=30.0)["m:medium"]
    assert (s["calls"], s["answered"], s["abstained"], s["deadline_misses"]) == (8, 7, 1, 1)
    assert (s["c2_block"], s["c2_n"]) == (2, 2)
    assert (s["proof_block"], s["proof_n"]) == (0, 1)
    assert (s["benign_block"], s["benign_n"]) == (1, 2)  # answered benign only
    assert (s["probe_mal_block"], s["probe_mal_n"]) == (1, 1)
    assert s["latency_p50_s"] == pytest.approx(2.1, abs=0.15)
    assert s["latency_max_s"] == pytest.approx(3.0)


def test_forced_summary_separates_quota_errors_from_deadline_misses(harness):
    rows = [
        _row("b-1", "benign", "BENIGN", None, 30002),  # deadline
        _row("b-2", "benign", "BENIGN", None, 90),  # fast failure, e.g. a 429
    ]
    s = harness.summarize_forced(rows, timeout_s=30.0)["m:medium"]
    assert (s["abstained"], s["deadline_misses"], s["fast_errors"]) == (2, 1, 1)


def test_e2e_summary_reports_decisions_by_group_and_the_tier2_fire_rate(harness):
    def e2e(cid, group, label, decision, p, tier2, backend="jev"):
        return {"policy": False, "id": cid, "group": group, "label": label, "tool": "t",
                "jev_p": p, "tier1_backend": backend, "tier2_called": tier2,
                "tier2": ({"decision": "BLOCK"} if tier2 else None), "tier2_ms": 5000 if tier2 else None,
                "decision": decision, "score": 0.1, "ms": 100, "error": None}

    rows = [
        e2e("m1", "other", "MALICIOUS", "BLOCK", 0.5, True),
        e2e("m2", "other", "MALICIOUS", "ALLOW", 0.95, False),
        e2e("m3", "proof", "MALICIOUS", "ALLOW", 0.9, False),
        e2e("b1", "benign", "BENIGN", "ALLOW", 0.02, False),
    ]
    s = harness.summarize_e2e(rows)[False]
    assert s["n"] == 4 and s["tier2_called"] == 1 and s["tier2_rate"] == pytest.approx(0.25)
    assert s["malicious_block"] == 1 and s["malicious_n"] == 3
    assert s["proof_block"] == 0 and s["proof_n"] == 1
    assert s["benign_allow"] == 1 and s["benign_n"] == 1
    assert s["clear_high_malicious_allowed"] == 2 and s["clear_high_malicious_n"] == 2
    assert s["tier1_backends"] == {"jev": 4}


# --------------------------------------------------------------------- CLI guards


def test_forced_refuses_to_start_without_a_vertex_project(harness, monkeypatch, capsys):
    for name in ("GCP_PROJECT", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(name, raising=False)

    def _no_client(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("no client may be built without a project")

    monkeypatch.setattr(harness, "get_genai_client", _no_client)
    assert harness.main(["forced", "--configs", "default:shipped"]) == 2
    assert "GCP_PROJECT" in capsys.readouterr().err


def test_e2e_refuses_to_start_without_the_jev_key_instead_of_degrading_to_gemini(
    harness, monkeypatch, capsys
):
    """With no key the registry would silently run the gemini backend and the
    run would not be a Jev run at all."""
    monkeypatch.setenv("GCP_PROJECT", "some-project")
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "legacy-vercel-credential")

    def _no_client(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("no client may be built without the key")

    monkeypatch.setattr(harness, "get_genai_client", _no_client)
    assert harness.main(["e2e"]) == 2
    assert "TYPESAFE_API_KEY" in capsys.readouterr().err


def test_harness_never_reads_credential_files_or_the_legacy_key():
    source = SCRIPT.read_text(encoding="utf-8")
    for needle in ("dotenv", "open(\".env", "AI_GATEWAY_API_KEY", "read_text(\".env"):
        assert needle not in source, needle
