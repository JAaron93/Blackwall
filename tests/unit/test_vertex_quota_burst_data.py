"""Data-integrity tests for the TASK-F03 Vertex quota burst calibration.

The Tier-2 429 figures ADR 0009 cites come from the committed live run in
``tests/eval/results/vertex_quota_runs/``. These tests recompute every published
figure from the committed counters, verify the artifact's constants against the
production limiter, check every manifest-listed run for format and credential
safety, and check the pointer chain (task note -> ADR -> manifest -> run -> this
test). They read committed files only and never touch the network.
"""

import importlib.util
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from blackwall import sync_resolver as sr

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "vertex_quota_burst_test.py"
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "vertex_quota_runs"
MANIFEST = RUNS_DIR / "manifest.json"
HISTORICAL_RUN = "burst_2026-11-19.json"

# Exact published counters. Pinning the whole record (not just the 429 count)
# means a changed total or success count invalidates the published rate.
PUBLISHED = {
    "uncoordinated": {
        "tier2": {"attempts": 40, "sent": 40, "ok": 29, "429": 11, "skipped": 0},
        "synthesis": {"attempts": 128, "sent": 128, "ok": 90, "429": 38, "skipped": 0},
    },
    "shared": {
        "tier2": {"attempts": 40, "sent": 40, "ok": 30, "429": 10, "skipped": 0},
        "synthesis": {"attempts": 128, "sent": 128, "ok": 97, "429": 31, "skipped": 0},
    },
    "reserved": {
        "tier2": {"attempts": 40, "sent": 40, "ok": 40, "429": 0, "skipped": 0},
        "synthesis": {"attempts": 128, "sent": 92, "ok": 92, "429": 0, "skipped": 36},
    },
}
TIER2_429_RATE = {"uncoordinated": 11 / 40, "shared": 10 / 40, "reserved": 0.0}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _listed_runs():
    return [entry["file"] for entry in _load(MANIFEST)["runs"]]


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("vertex_quota_burst_test_data", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def run():
    return _load(RUNS_DIR / HISTORICAL_RUN)


def test_manifest_names_every_result_file_and_no_other():
    manifest = _load(MANIFEST)
    listed = {entry["file"] for entry in manifest["runs"]}
    on_disk = {p.name for p in RUNS_DIR.glob("*.json") if p.name != MANIFEST.name}
    assert listed == on_disk
    assert manifest["schema_version"] == 1
    assert manifest["discarded"]  # invalid runs are recorded, not silently dropped


@pytest.mark.parametrize("name", _listed_runs())
def test_every_listed_run_has_valid_schema_and_counters(name):
    data = _load(RUNS_DIR / name)
    assert data["schema_version"] == 1
    assert data["model"] == "gemini-3.5-flash-lite"
    assert data["location"] == "global"
    assert data["quota_rpm"] == sr.VERTEX_QUOTA_RPM
    constants = data["constants"]
    assert constants["tier2_reserved_rpm"] == sr.TIER2_RESERVED_RPM
    assert constants["tier2_capacity"] == sr.TIER2_RATE_LIMIT_CAPACITY
    assert constants["tier2_refill_per_s"] == sr.TIER2_RATE_LIMIT_REFILL_PER_S
    assert constants["synthesis_capacity"] == sr.SYNTHESIS_RATE_LIMIT_CAPACITY
    assert constants["synthesis_refill_per_s"] == sr.SYNTHESIS_RATE_LIMIT_REFILL_PER_S
    assert constants["tier2_refill_per_s"] + constants["synthesis_refill_per_s"] == pytest.approx(
        data["quota_rpm"] / 60.0
    )
    assert set(data["policies"]) == set(PUBLISHED)
    for counters in data["policies"].values():
        assert set(counters) == {"tier2", "synthesis"}
        for stats in counters.values():
            assert set(stats) >= {"attempts", "sent", "ok", "429", "skipped"}
            assert stats["ok"] + stats["429"] == stats["sent"]
            assert stats["sent"] + stats["skipped"] == stats["attempts"]


@pytest.mark.parametrize("name", ["manifest.json", *_listed_runs()])
def test_no_credentials_in_artifacts(name):
    forbidden = re.compile(
        r"GCP_PROJECT|gen-lang-client-|AIza|BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key\s*[:=]",
        re.IGNORECASE,
    )
    text = (RUNS_DIR / name).read_text(encoding="utf-8")
    assert not forbidden.search(text), f"credential-shaped content in {name}"


@pytest.mark.parametrize(("policy", "expected"), PUBLISHED.items())
def test_published_figures_pinned(run, policy, expected):
    assert run["policies"][policy] == expected
    t2 = expected["tier2"]
    assert t2["429"] / t2["attempts"] == pytest.approx(TIER2_429_RATE[policy])
    assert t2["ok"] + t2["429"] == t2["sent"]
    syn = expected["synthesis"]
    assert syn["ok"] + syn["429"] == syn["sent"]
    assert syn["sent"] + syn["skipped"] == syn["attempts"]


def test_normalize_counters_writes_explicit_zeros(script):
    normalized = script.normalize_counters({"attempts": 3, "sent": 2, "ok": 2})
    assert normalized == {"attempts": 3, "sent": 2, "ok": 2, "429": 0, "skipped": 0}
    # Unexpected outcome keys (e.g. an error class) must survive normalization.
    assert script.normalize_counters({"ok": 1, "ClientError": 2})["ClientError"] == 2


def test_build_artifact_exports_explicit_zero_counters(script):
    results = {
        "reserved": {
            "tier2": {"attempts": 1, "sent": 1, "ok": 1},
            "synthesis": {"attempts": 1, "sent": 0, "skipped": 1},
        }
    }
    artifact = script.build_artifact(results, datetime(2026, 11, 19, tzinfo=UTC))
    for stats in artifact["policies"]["reserved"].values():
        assert set(stats) == {"attempts", "sent", "ok", "429", "skipped"}


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
