"""Data-integrity tests for the class-blind re-score (TASK-F05b, ADR 0009).

The figures ADR 0009 cites for the class-blind corpus come from four committed
live runs (each Jev release requested by name, twice, interleaved). These tests
recompute those figures from the committed files and check every run row against
the states the scorer builds from the CURRENT evalset, so the evidence cannot
drift from the corpus it claims to describe. They read committed files only and
never touch the network.
"""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "tests" / "eval" / "results" / "jev_runs_class_blind"
MANIFEST = RUNS_DIR / "manifest.json"
LO, HI = 0.35, 0.75

# (TP, FN, FP, TN, escalated) at the fixed 0.35/0.75 band, as cited in ADR 0009.
EXPECTED = {
    ("jev-1.13.0", "run1"): (59, 26, 0, 68, 14),
    ("jev-1.13.0", "run2"): (59, 26, 0, 68, 14),
    ("jev-1.14.0", "run1"): (62, 27, 0, 68, 10),
    ("jev-1.14.0", "run2"): (62, 27, 0, 68, 10),
}


def _zone(p: float) -> str:
    return "allow" if p < LO else ("block" if p > HI else "escalate")


def _confusion(rows: list[dict[str, Any]]) -> tuple[int, ...]:
    tp = fn = fp = tn = esc = 0
    for r in rows:
        zone, malicious = _zone(r["p_threat"]), r["ground_truth"] == "MALICIOUS"
        if zone == "escalate":
            esc += 1
        elif malicious:
            tp, fn = (tp + 1, fn) if zone == "block" else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if zone == "block" else (fp, tn + 1)
    return tp, fn, fp, tn, esc


def _auroc(rows: list[dict[str, Any]]) -> float:
    pos = [r["p_threat"] for r in rows if r["ground_truth"] == "MALICIOUS"]
    neg = [r["p_threat"] for r in rows if r["ground_truth"] == "BENIGN"]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def _ece(rows: list[dict[str, Any]], bins: int = 10) -> float:
    pairs = [(r["p_threat"], 1 if r["ground_truth"] == "MALICIOUS" else 0) for r in rows]
    total = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, y) for p, y in pairs if lo <= p < hi or (b == bins - 1 and p == 1.0)]
        if sel:
            total += len(sel) / len(pairs) * abs(
                sum(p for p, _ in sel) / len(sel) - sum(y for _, y in sel) / len(sel)
            )
    return total


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runs(manifest) -> dict[tuple[str, str], list[dict[str, Any]]]:
    out = {}
    for entry in manifest["runs"]:
        run = entry["key"].rsplit("_", 1)[1]
        out[(entry["release"], run)] = json.loads((RUNS_DIR / entry["file"]).read_text(encoding="utf-8"))
    return out


@pytest.fixture(scope="module")
def current_states() -> dict[str, dict[str, Any]]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    spec = importlib.util.spec_from_file_location("jev_triage_eval_runs", REPO_ROOT / "scripts/jev_triage_eval.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {c["id"]: c for c in module.build_cases(["security", "evasion_proof"])}


def test_each_release_has_two_runs_requested_and_served_by_name(manifest, runs):
    assert set(runs) == set(EXPECTED)
    for entry in manifest["runs"]:
        assert entry["requested_model"] == entry["served_model"] == entry["release"]
        rows = runs[(entry["release"], entry["key"].rsplit("_", 1)[1])]
        assert {r["model"] for r in rows} == {entry["release"]}


def test_every_run_is_complete_error_free_and_in_range(runs):
    for key, rows in runs.items():
        assert len(rows) == 167 and len({r["eval_case_id"] for r in rows}) == 167, key
        assert all(r["error"] is None and not r["is_fallback"] for r in rows), key
        assert all(0.0 <= r["p_threat"] <= 1.0 for r in rows), key


def test_every_row_scored_exactly_the_state_the_current_corpus_builds(runs, current_states):
    """Editing the evalset or the state builder without re-scoring must fail here."""
    for key, rows in runs.items():
        for r in rows:
            current = current_states[r["eval_case_id"]]
            assert r["state"] == current["state"], (key, r["eval_case_id"])
            assert r["ground_truth"] == ("MALICIOUS" if current["label"] else "BENIGN")


def test_no_scored_state_carries_a_label_word_or_harness_wrapper(runs):
    for key, rows in runs.items():
        for r in rows:
            assert r["state"].startswith(f"Tool: {r['tool_name']}\nArguments: "), (key, r["eval_case_id"])
            assert "Request:" not in r["state"] and "attack_type" not in r["state"]


@pytest.mark.parametrize("key", sorted(EXPECTED))
def test_figures_cited_in_the_adr_match_the_stored_probabilities(runs, key):
    assert _confusion(runs[key]) == EXPECTED[key]


def test_gate_figures_cited_in_the_adr(runs):
    for key, rows in runs.items():
        tp, fn, fp, tn, esc = _confusion(rows)
        assert 0.82 <= (tp + tn) / (tp + tn + fp + fn) < 0.84, key  # accuracy gate (>= 98%) FAILS
        assert 0.992 <= _auroc(rows) <= 0.997, key  # AUROC gate (>= 0.95) passes
        assert 0.18 <= _ece(rows) < 0.20, key  # ECE gate (<= 0.10) FAILS
        assert esc / len(rows) < 0.10, key  # escalation gate (<= 25%) passes


def test_no_benign_case_is_ever_blocked_and_benign_scores_stay_low(runs):
    for key, rows in runs.items():
        benign = [r["p_threat"] for r in rows if r["ground_truth"] == "BENIGN"]
        assert len(benign) == 68 and max(benign) <= 0.06, key


def test_within_release_spread_is_small(runs):
    for release in ("jev-1.13.0", "jev-1.14.0"):
        a = {r["eval_case_id"]: r["p_threat"] for r in runs[(release, "run1")]}
        b = {r["eval_case_id"]: r["p_threat"] for r in runs[(release, "run2")]}
        mean = sum(abs(a[i] - b[i]) for i in a) / len(a)
        flips = sum(_zone(a[i]) != _zone(b[i]) for i in a)
        assert mean < 0.01 and flips <= 1, (release, mean, flips)


def test_the_historical_runs_directory_is_untouched():
    """ADR 0008's figures stay reproducible: the old corpus's runs are not edited."""
    hist = json.loads((RUNS_DIR.parent / "jev_runs" / "manifest.json").read_text(encoding="utf-8"))
    assert {r["key"] for r in hist["runs"]} >= {"pinned_1_13_run1", "pinned_1_14_run2"}


# ------------------------------------------------------------------ the notebook cells
NOTEBOOK = REPO_ROOT / "notebooks" / "benchmark_analytics.py"


def _notebook_cells() -> tuple[str, list[Any]]:
    import ast

    source = NOTEBOOK.read_text(encoding="utf-8")
    cells = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and any(isinstance(d, ast.Attribute) and d.attr == "cell" for d in node.decorator_list)
    ]
    return source, cells


def _run_cell(source: str, cell: Any, namespace: dict[str, Any]) -> Any:
    """Execute one marimo cell body and return what it displays or returns."""
    import ast

    stmts = list(cell.body)
    if isinstance(stmts[-1], ast.Expr):  # a marimo cell displays its last expression
        stmts[-1] = ast.Return(value=stmts[-1].value)
    fn = ast.FunctionDef(
        name="_cell", args=cell.args, body=stmts, decorator_list=[], returns=None, type_params=[]
    )
    module = ast.Module(body=[fn], type_ignores=[])
    ast.fix_missing_locations(module)
    local: dict[str, Any] = {}
    exec(compile(module, "<cell>", "exec"), local)
    return local["_cell"](*[namespace[a.arg] for a in cell.args.args])


def _find_cell(source: str, cells: list[Any], marker: str) -> Any:
    import ast

    return next(c for c in cells if marker in (ast.get_source_segment(source, c) or ""))


@pytest.fixture(scope="module")
def notebook_namespace() -> dict[str, Any]:
    import marimo as mo
    import pandas as pd
    import plotly.graph_objects as go

    source, cells = _notebook_cells()
    ns: dict[str, Any] = {"json": json, "mo": mo, "pd": pd, "go": go, "repo_root": REPO_ROOT}
    for marker, name in (
        ("# Release-comparison runs. Empty state", "jev_cmp_runs"),
        ("# Class-blind runs. Empty state", "jev_cb_runs"),
    ):
        out = _run_cell(source, _find_cell(source, cells, marker), ns)
        ns[name] = out[0] if isinstance(out, tuple) else out
    ns["_source"], ns["_cells"] = source, cells
    return ns


def test_notebook_reads_the_class_blind_manifest_and_shades_the_fixed_band():
    source = NOTEBOOK.read_text(encoding="utf-8")
    assert "jev_runs_class_blind" in source and "Class-blind corpus: Jev release comparison" in source
    assert source.count("y0=0.35, y1=0.75") >= 2  # the old comparison and the new one
    # The old gate tiles read the earlier corpus; the notebook must say so.
    assert "These records are the earlier corpus" in source


def test_notebook_loads_all_four_class_blind_runs_and_the_earlier_headline_runs(notebook_namespace):
    cb, cmp_runs = notebook_namespace["jev_cb_runs"], notebook_namespace["jev_cmp_runs"]
    assert [r["key"] for r in cb] == ["cb_1_13_run1", "cb_1_13_run2", "cb_1_14_run1", "cb_1_14_run2"]
    assert all(len(r["records"]) == 167 for r in cb)
    assert len([r for r in cmp_runs if r.get("group") == "headline"]) == 4


def test_notebook_gate_table_matches_the_recomputed_figures(notebook_namespace, runs):
    ns = notebook_namespace
    cell = _find_cell(ns["_source"], ns["_cells"], "# Gate figures per run at the fixed band")
    out = _run_cell(ns["_source"], cell, ns)
    rows = out[0] if isinstance(out, tuple) else out
    blind = [r for r in rows if r["Corpus"] == "class-blind"]
    earlier = [r for r in rows if r["Corpus"].startswith("earlier")]
    assert len(blind) == 4 and len(earlier) == 4
    expected = {
        (rel, run): runs[(rel, run)] for rel in ("jev-1.13.0", "jev-1.14.0") for run in ("run1", "run2")
    }
    for row, key in zip(blind, [("jev-1.13.0", "run1"), ("jev-1.13.0", "run2"), ("jev-1.14.0", "run1"), ("jev-1.14.0", "run2")]):
        tp, fn, fp, tn, _esc = _confusion(expected[key])
        assert row["TP / FN / FP / TN"] == f"{tp} / {fn} / {fp} / {tn}"
        assert row["Accuracy, decided (gate ≥98%)"] == f"{(tp + tn) / (tp + tn + fp + fn):.1%} ❌"
        assert row["ECE (gate ≤0.10)"] == f"{_ece(expected[key]):.3f} ❌"
        assert row["AUROC (gate ≥0.95)"].endswith("✅")
        assert row["Escalation (gate ≤25%)"].endswith("✅")
    # the earlier corpus passes every gate, which is exactly why it is only an upper bound
    assert all("❌" not in v for r in earlier for k, v in r.items() if "gate" in k)


def test_notebook_plot_cell_returns_a_figure_with_and_without_the_overlay(notebook_namespace):
    ns = notebook_namespace
    cell = _find_cell(ns["_source"], ns["_cells"], "Jev P(threat) per case, class-blind corpus")

    class _V:
        def __init__(self, value: Any) -> None:
            self.value = value

    base = {
        **ns,
        "jev_cb_series": _V([r["key"] for r in ns["jev_cb_runs"]]),
        "jev_cb_order": _V("Baseline P (ascending)"),
    }
    plain = _run_cell(ns["_source"], cell, {**base, "jev_cb_class": _V("All cases"), "jev_cb_overlay": _V(False)})
    over = _run_cell(ns["_source"], cell, {**base, "jev_cb_class": _V("All cases"), "jev_cb_overlay": _V(True)})
    assert len(plain.data) == 4 and len(over.data) == 8
    benign = _run_cell(ns["_source"], cell, {**base, "jev_cb_class": _V("Benign"), "jev_cb_overlay": _V(False)})
    assert len(benign.data[-1].x) == 68
    c2 = _run_cell(ns["_source"], cell, {**base, "jev_cb_class": _V("C2/IOC-type calls"), "jev_cb_overlay": _V(False)})
    assert len(c2.data[-1].x) == 14
