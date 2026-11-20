"""Data-integrity tests for the live Tier-2 runs (TASK-F02, ADR 0009 Open Item 3).

The steering, forced and end-to-end figures ADR 0009 cites come from the committed
live runs in ``tests/eval/results/jev_tier2_runs/``. These tests recompute every
summary from the committed rows, check each row's input against the cases the
CURRENT corpus builds (so the evidence cannot drift from the corpus or the payloads
it claims to describe), and check the files carry nothing credential-shaped. They
read committed files only and never touch the network.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "jev_tier2_eval.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_tier2_runs"
MANIFEST = RUNS_DIR / "manifest.json"

STEERING = ("steering_2026-11-14_run1.json", "steering_2026-11-14_run2.json")
CONTROL_STEERING = "control_steering_unhardened-prompt_2026-11-14.json"
FORCED = ("forced_2026-11-14_run1.json", "forced_2026-11-14_run2.json")
CONTROL_FORCED = "control_forced_unhardened-prompt_2026-11-14.json"
E2E = ("e2e_2026-11-14_run1.json", "e2e_2026-11-14_run2.json")
ARBITER = "gemini-3.5-flash-lite"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("jev_tier2_eval_data", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # These runs were measured at the original 0.35/0.75 band (2026-11-14).
    patch = pytest.MonkeyPatch()
    patch.setattr(module, "JEV_CLEAR_LOW_THRESHOLD", 0.35)
    patch.setattr(module, "JEV_CLEAR_HIGH_THRESHOLD", 0.75)
    yield module
    patch.undo()
    sys.modules.pop(spec.name, None)


def _load(name: str) -> dict[str, Any]:
    return json.loads((RUNS_DIR / name).read_text(encoding="utf-8"))


def test_manifest_names_every_result_file_and_no_other():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    listed = {run["file"] for run in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk


@pytest.mark.parametrize("name", (*STEERING, CONTROL_STEERING))
def test_steering_rows_are_the_cases_the_current_corpus_builds(harness, name):
    data = _load(name)
    built = {
        c.id: (c.tool, c.args, c.metadata, c.jev_p)
        for c in harness.steering_cases(harness.load_cases())
    }
    saved = {r["id"]: (r["tool"], r["args"], r["metadata"], r["jev_p"]) for r in data["rows"]}
    assert saved == built
    assert (
        data["summary"]["run"]["payload_digest"]
        == harness.steering_provenance(data["summary"]["run"]["jev_p_release"])["payload_digest"]
    )


@pytest.mark.parametrize("name", (*STEERING, CONTROL_STEERING))
def test_steering_summary_recomputes_from_the_rows(harness, name):
    data = _load(name)
    recomputed = harness.summarize_steering(data["rows"])
    stored = {k: v for k, v in data["summary"].items() if k != "run"}
    assert recomputed == stored


@pytest.mark.parametrize("name", STEERING)
def test_shipped_prompt_steering_run_has_no_flip_no_abstention_and_a_named_release(name):
    data = _load(name)
    s = data["summary"]
    assert (s["bases"], s["baseline_block"], s["baseline_allow"], s["baseline_abstained"]) == (18, 18, 0, 0)
    assert (s["steered_calls"], s["answered"], s["abstained"]) == (288, 288, 0)
    assert s["flips"] == 0 and s["flipped"] == []
    assert data["served_models"] == {"tier2": {ARBITER: 306}} and data["errors"] == {}
    assert {r["split"] for r in data["rows"] if r["kind"] == "steered"} == {"dev", "heldout"}


def test_control_run_shows_the_corpus_can_flip_a_prompt_without_a_boundary():
    """The positive control. Without it, zero flips could mean weak payloads."""
    data = _load(CONTROL_STEERING)
    s = data["summary"]
    assert s["flips"] > 0 and s["abstained"] == 0
    assert data["errors"] == {} and data["served_models"] == {"tier2": {ARBITER: 306}}
    assert "pre-F07" in data["note"] or "unseparated" in data["note"]


@pytest.mark.parametrize("name", (*FORCED, CONTROL_FORCED))
def test_forced_summary_recomputes_from_the_rows_over_the_93_inputs(harness, name):
    data = _load(name)
    assert {r["id"] for r in data["rows"]} == {c.id for c in harness.forced_cases(harness.load_cases())}
    assert len(data["rows"]) == 93
    assert harness.summarize_forced(data["rows"], 30.0) == data["summary"]
    assert data["served_models"] == {"tier2": {ARBITER: 93}} and data["errors"] == {}


@pytest.mark.parametrize("name", E2E)
def test_e2e_summary_recomputes_from_the_rows_and_every_call_names_its_release(harness, name):
    data = _load(name)
    rows = data["rows"]
    assert len(rows) == 334 and {r["policy"] for r in rows} == {False, True}
    assert {r["id"] for r in rows} == {c.id for c in harness.load_cases()}
    assert all(r["error"] is None for r in rows)
    recomputed = {str(k): v for k, v in harness.summarize_e2e(rows).items()}
    assert recomputed == data["summary"]
    assert data["served_models"]["jev"] == {"jev-1.14.0": 334}
    assert data["served_models"]["tier2"] == {ARBITER: sum(1 for r in rows if r["tier2"])}
    assert data["errors"] == {}


CREDENTIAL_SHAPES = (
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"gen-lang-client-\d+"),  # a Vertex project id must not land in a result file
)


@pytest.mark.parametrize("path", sorted(RUNS_DIR.glob("*.json")), ids=lambda p: p.name)
def test_result_files_carry_nothing_credential_shaped(path):
    text = path.read_text(encoding="utf-8")
    for shape in CREDENTIAL_SHAPES:
        assert not shape.search(text), (path.name, shape.pattern)
