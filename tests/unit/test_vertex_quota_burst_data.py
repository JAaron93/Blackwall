"""Data-integrity tests for the TASK-F03 Vertex quota burst calibration.

The Tier-2 429 figures ADR 0009 cites come from the committed live run in
``tests/eval/results/vertex_quota_runs/``. These tests recompute every published
figure from the committed counters, verify the artifact's constants against the
production limiter, and check the pointer chain (task note -> ADR -> manifest ->
run -> this test) is documented. They read committed files only and never touch
the network.
"""

import json
import re
from pathlib import Path

import pytest

from blackwall import sync_resolver as sr

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "vertex_quota_runs"
MANIFEST = RUNS_DIR / "manifest.json"
RUN_FILE = "burst_2026-11-19.json"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def run():
    return _load(RUNS_DIR / RUN_FILE)


def test_manifest_names_every_result_file_and_no_other():
    manifest = _load(MANIFEST)
    listed = {entry["file"] for entry in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1
    assert manifest["discarded"]  # invalid runs are recorded, not silently dropped


def test_artifact_constants_match_production(run):
    assert run["schema_version"] == 1
    assert run["model"] == "gemini-3.5-flash-lite"
    assert run["location"] == "global"
    assert run["quota_rpm"] == sr.VERTEX_QUOTA_RPM
    constants = run["constants"]
    assert constants["tier2_reserved_rpm"] == sr.TIER2_RESERVED_RPM
    assert constants["tier2_capacity"] == sr.TIER2_RATE_LIMIT_CAPACITY
    assert constants["tier2_refill_per_s"] == sr.TIER2_RATE_LIMIT_REFILL_PER_S
    assert constants["synthesis_capacity"] == sr.SYNTHESIS_RATE_LIMIT_CAPACITY
    assert constants["synthesis_refill_per_s"] == sr.SYNTHESIS_RATE_LIMIT_REFILL_PER_S
    assert constants["tier2_refill_per_s"] + constants["synthesis_refill_per_s"] == pytest.approx(
        run["quota_rpm"] / 60.0
    )


@pytest.mark.parametrize(
    ("policy", "tier2_429", "synthesis_429", "synthesis_skip"),
    [
        ("uncoordinated", 11, 38, 0),
        ("shared", 10, 31, 0),
        ("reserved", 0, 0, 36),
    ],
)
def test_published_429_rates_recomputed(run, policy, tier2_429, synthesis_429, synthesis_skip):
    counters = run["policies"][policy]
    assert set(counters) == {"tier2", "synthesis"}
    t2, syn = counters["tier2"], counters["synthesis"]
    assert t2["429"] == tier2_429
    assert syn["429"] == synthesis_429
    assert syn["skipped"] == synthesis_skip
    assert t2["ok"] + t2["429"] == t2["sent"]
    assert syn["ok"] + syn["429"] == syn["sent"]
    assert syn["sent"] + syn["skipped"] == syn["attempts"]


def test_no_credentials_in_artifacts():
    forbidden = re.compile(
        r"GCP_PROJECT|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key\s*[:=]",
        re.IGNORECASE,
    )
    for path in (MANIFEST, RUNS_DIR / RUN_FILE):
        text = path.read_text(encoding="utf-8")
        assert not forbidden.search(text), f"credential-shaped content in {path.name}"


def test_pointer_chain_is_documented():
    adr = (
        REPO_ROOT / "docs" / "adr" / "0009-tier2-flash-lite-medium-and-jev-only-fail-fast.md"
    ).read_text(encoding="utf-8")
    tasks = (
        REPO_ROOT / ".kiro" / "specs" / "tier-1-jev-addition" / "tasks.md"
    ).read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs" / "evaluation_guide.md").read_text(encoding="utf-8")
    for label, text in (("ADR 0009", adr), ("F03 task", tasks), ("evaluation guide", guide)):
        assert "vertex_quota_runs" in text or "vertex_quota_burst_test" in text, label
    assert any(
        "test_vertex_quota_burst_data" in text for text in (adr, tasks, guide)
    )
