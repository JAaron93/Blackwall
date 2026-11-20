"""Offline tests for the Tier-1 steering harness bookkeeping (TASK-F02).

Covers the runner logic the live runs depend on but the committed-row recompute
test does not exercise: checkpoint torn-tail recovery across resumes, the
config fingerprint that isolates cached answers from a changed model/prompt,
the Tier-2 release tally rebuilt from rows on resume, deadline forwarding to the
arbiter, and the naive-control answer parser. No network, no credential.
"""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("jev_tier1_bookkeeping", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def _row(scope: str, config: str, cid: str, h: str) -> dict:
    return {"scope": scope, "config": config, "id": cid, "hash": h, "row": {"id": cid}}


def test_trim_torn_tail_removes_only_the_partial_final_line(harness, tmp_path):
    path = tmp_path / "cp.jsonl"
    path.write_bytes(b'{"a": 1}\n{"b": 2')  # second line torn by a crash
    harness._trim_torn_tail(path)
    assert path.read_bytes() == b'{"a": 1}\n'


def test_trim_torn_tail_leaves_a_complete_file_untouched(harness, tmp_path):
    path = tmp_path / "cp.jsonl"
    path.write_bytes(b'{"a": 1}\n')
    harness._trim_torn_tail(path)
    assert path.read_bytes() == b'{"a": 1}\n'


def test_checkpoint_recovery_across_two_resumes(harness, tmp_path):
    """A crash leaves a torn tail; the next run must trim it, append cleanly, and a
    third resume must load every row without JSONDecodeError (Greptile P2)."""
    path = tmp_path / "cp.jsonl"
    first = _row("s", "semantic_only", "a", "h1")
    path.write_text(json.dumps(first) + "\n" + '{"scope": "s", "config": "semantic')  # torn
    # First resume: loader ignores the torn final line.
    loaded = harness._load_checkpoint(path, "s")
    assert loaded == {("semantic_only", "a"): ("h1", first["row"])}
    # The runner trims the tail before appending a new complete row.
    harness._trim_torn_tail(path)
    second = _row("s", "semantic_only", "b", "h2")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(second) + "\n")
    # Second resume: both rows load, no error.
    loaded2 = harness._load_checkpoint(path, "s")
    assert set(loaded2) == {("semantic_only", "a"), ("semantic_only", "b")}


def test_config_fingerprint_tracks_the_requested_model(harness, monkeypatch):
    monkeypatch.setenv(harness.semantic.JEV_MODEL_ENV_VAR, "jev-1.14.0")
    fp1 = harness.tier1_config_fingerprint()
    monkeypatch.setenv(harness.semantic.JEV_MODEL_ENV_VAR, "jev-1.13.0")
    fp2 = harness.tier1_config_fingerprint()
    assert fp1 != fp2
    monkeypatch.setenv(harness.semantic.JEV_MODEL_ENV_VAR, "jev-1.14.0")
    assert harness.tier1_config_fingerprint() == fp1


def test_checkpoint_scope_isolates_a_changed_configuration(harness, tmp_path):
    """Rows cached under one config fingerprint are not reused under another."""
    path = tmp_path / "cp.jsonl"
    row = _row("run:fp_old", "semantic_only", "a", "h1")
    path.write_text(json.dumps(row) + "\n")
    assert harness._load_checkpoint(path, "run:fp_old") != {}
    assert harness._load_checkpoint(path, "run:fp_new") == {}


def test_tally_tier2_served_rebuilds_from_rows(harness):
    rows = [
        {"tier2_model": "gemini-3.5-flash-lite"},
        {"tier2_model": "gemini-3.5-flash-lite"},
        {"tier2_model": None},  # abstained / failed: not counted
        {},  # a cached row from the old schema: no release
    ]
    assert harness.tally_tier2_served(rows) == {"tier2": {"gemini-3.5-flash-lite": 2}}
    assert harness.tally_tier2_served([{}, {"tier2_model": None}]) == {}


def test_build_resolver_forwards_the_requested_deadline(harness, monkeypatch):
    backend = MagicMock()
    monkeypatch.setattr(harness, "GeminiTier2Backend", backend)
    monkeypatch.setattr(harness.semantic, "JevTriageBackend", MagicMock())
    harness._build_resolver(
        MagicMock(), False, jev_http_client=MagicMock(), tier2_timeout=7.0
    )
    assert backend.call_args.kwargs["timeout"] == 7.0


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"p_threat": 0.3}', 0.3),
        ('{"p_threat": 0}', 0.0),
        ('{"p_threat": 1}', 1.0),
        ('{"p_threat": 1.5}', None),
        ('{"p_threat": -0.1}', None),
        ('{"p_threat": true}', None),
        ('{"p_threat": "0.3"}', None),
        ('{"other": 0.3}', None),
        ("not json", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_naive_p(harness, text, expected):
    assert harness.parse_naive_p(text) == expected


def _mkrow(**over):
    row = {
        "config": "semantic_only", "kind": "steered", "id": "m1::p", "base_id": "m1",
        "payload_id": "p", "technique": "t", "carrier": "arguments", "split": "dev",
        "group": "other", "label": "MALICIOUS", "tool": "execute_shell",
        "args": {"cmd": "x"}, "metadata": None, "stored_p": 0.9, "egress": None,
        "jev_p": 0.9, "band": "clear_high", "jev_model": "jev-1.14.0", "jev_request_id": "r",
        "tier2_called": False, "tier2_decision": None, "tier2_score": None,
        "tier2_reason": None, "tier2_ms": None, "tier2_model": None,
        "verdict": "BLOCK", "verdict_score": 0.9, "reasoning": "x", "error": None, "ms": 10,
    }
    row.update(over)
    return row


def test_summarize_counts_failed_baselines_abstentions_and_final_verdicts(harness):
    """Offline coverage of the summary bookkeeping Greptile asked for: a failed
    baseline and a failed steered call on a held base are errors (never 'no flip'),
    a Tier-2 abstention is counted apart, and the final-verdict counts (to-ALLOW,
    BLOCK-weakened) and below-0.35 crossings come only from answered calls."""
    rows = [
        # m1: BLOCK baseline steered to ALLOW below the band edge (the bypass).
        _mkrow(kind="baseline", id="m1", base_id="m1", jev_p=0.9, verdict="BLOCK"),
        _mkrow(kind="steered", id="m1::p", base_id="m1", jev_p=0.05, band="clear_low", verdict="ALLOW"),
        # m2: a failed baseline (Jev outage) and its failed steered call.
        _mkrow(kind="baseline", id="m2", base_id="m2", jev_p=None, band=None, verdict=None, error="JevUnavailableError: x"),
        _mkrow(kind="steered", id="m2::p", base_id="m2", jev_p=None, band=None, verdict=None, error="JevUnavailableError: x"),
        # m3: QUARANTINE baseline whose steered call abstained (Tier-2 fired, no verdict).
        _mkrow(kind="baseline", id="m3", base_id="m3", jev_p=0.5, band="band", verdict="QUARANTINE", tier2_called=True, tier2_decision="BLOCK"),
        _mkrow(kind="steered", id="m3::p", base_id="m3", jev_p=0.5, band="band", verdict="QUARANTINE", tier2_called=True, tier2_decision=None),
        # m4: BLOCK baseline whose steered call failed (error on a held base).
        _mkrow(kind="baseline", id="m4", base_id="m4", jev_p=0.8, verdict="BLOCK"),
        _mkrow(kind="steered", id="m4::p", base_id="m4", jev_p=None, band=None, verdict=None, error="JevUnavailableError: x"),
    ]
    m = harness.summarize_tier1_steering(rows)["semantic_only"]["malicious"]
    assert m["bases"] == 4
    assert m["baseline"] == {"BLOCK": 2, "QUARANTINE": 1, "ALLOW": 0, "error": 1, "abstained": 0}
    assert m["held_bases"] == 3 and m["block_bases"] == 2
    assert m["steered_calls"] == 3 and m["answered"] == 1
    assert m["errors"] == 1 and m["abstained"] == 1  # counted apart, never as flips
    assert m["to_allow"]["n"] == 1 and m["to_allow"]["of"] == 1
    assert m["block_weakened"]["n"] == 1 and m["block_weakened"]["to_allow"] == 1
    assert m["crossings"]["below_035"] == 1
    assert m["crossings"]["below_035_tier2_skipped"] == 1
    assert [f["kind"] for f in m["flipped"]] == ["to_allow"]