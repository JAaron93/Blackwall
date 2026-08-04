"""
Unit tests for blackwall.eval.report_generator.ReportGenerator.

All tests use mock data — no live ADK runner, no real network calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackwall.eval.report_generator import (
    ReportGenerator,
    _parse_ground_truth,
    _parse_verdict,
)
from blackwall.models import GroundTruthLabel, VerdictDecision


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BENIGN_CASE_ID = "benign_db_select_001"
MALICIOUS_CASE_ID = "malicious_sql_001"
EVASION_CASE_ID = "evasion_sqli_001"
QUARANTINE_CASE_ID = "malicious_shell_001"


def _make_evalset(cases: list[dict]) -> dict:
    return {"eval_cases": cases}


def _evalset_case(
    case_id: str,
    ground_truth: str = "BENIGN",
    scenario_type: str = "benign",
    expected_verdict: str = "ALLOW",
    tool_name: str = "database_query",
) -> dict:
    return {
        "eval_case_id": case_id,
        "conversation": [
            {"role": "user", "parts": [{"text": f"Test prompt for {case_id}"}]}
        ],
        "expected_tool_use": [
            {
                "tool_use": {"tool_name": "before_tool_callback", "tool_input": {"tool_name": tool_name}},
                "tool_use_result": {"verdict": expected_verdict},
            }
        ],
        "reference": expected_verdict,
        "metadata": {
            "ground_truth": ground_truth,
            "scenario_type": scenario_type,
            "tool_name": tool_name,
        },
    }


def _result_record(case_id: str, actual_verdict: str) -> dict:
    return {"eval_case_id": case_id, "actual_verdict": actual_verdict}


@pytest.fixture()
def minimal_evalset() -> dict:
    """Four cases: 1 benign, 2 malicious (one quarantine), 1 evasion."""
    return _make_evalset(
        [
            _evalset_case(BENIGN_CASE_ID, "BENIGN", "benign", "ALLOW"),
            _evalset_case(MALICIOUS_CASE_ID, "MALICIOUS", "malicious", "BLOCK"),
            _evalset_case(EVASION_CASE_ID, "MALICIOUS", "evasion", "BLOCK"),
            _evalset_case(QUARANTINE_CASE_ID, "MALICIOUS", "malicious", "QUARANTINE", "execute_command"),
        ]
    )


@pytest.fixture()
def perfect_results(minimal_evalset: dict) -> list[dict]:
    """All verdicts match ground truth exactly — expect 100% accuracy."""
    return [
        _result_record(BENIGN_CASE_ID, "ALLOW"),
        _result_record(MALICIOUS_CASE_ID, "BLOCK"),
        _result_record(EVASION_CASE_ID, "BLOCK"),
        _result_record(QUARANTINE_CASE_ID, "QUARANTINE"),
    ]


@pytest.fixture()
def false_negative_results(minimal_evalset: dict) -> list[dict]:
    """Evasion case slips through — one false negative (missed attack)."""
    return [
        _result_record(BENIGN_CASE_ID, "ALLOW"),
        _result_record(MALICIOUS_CASE_ID, "BLOCK"),
        _result_record(EVASION_CASE_ID, "ALLOW"),   # ← missed evasion
        _result_record(QUARANTINE_CASE_ID, "QUARANTINE"),
    ]


@pytest.fixture()
def false_positive_results(minimal_evalset: dict) -> list[dict]:
    """Benign case wrongly blocked — one false positive."""
    return [
        _result_record(BENIGN_CASE_ID, "BLOCK"),    # ← false refusal
        _result_record(MALICIOUS_CASE_ID, "BLOCK"),
        _result_record(EVASION_CASE_ID, "BLOCK"),
        _result_record(QUARANTINE_CASE_ID, "QUARANTINE"),
    ]


def _generator_with_data(
    evalset: dict,
    results: list[dict],
    tmp_path: Path,
) -> ReportGenerator:
    evalset_file = tmp_path / "test.evalset.json"
    results_file = tmp_path / "raw_results.json"
    evalset_file.write_text(json.dumps(evalset), encoding="utf-8")
    results_file.write_text(json.dumps({"results": results}), encoding="utf-8")
    return ReportGenerator(evalset_path=evalset_file, results_path=results_file)


# ---------------------------------------------------------------------------
# _parse_verdict unit tests
# ---------------------------------------------------------------------------


class TestParseVerdict:
    def test_string_block(self):
        assert _parse_verdict("BLOCK") == VerdictDecision.BLOCK

    def test_string_allow(self):
        assert _parse_verdict("ALLOW") == VerdictDecision.ALLOW

    def test_string_quarantine(self):
        assert _parse_verdict("QUARANTINE") == VerdictDecision.QUARANTINE

    def test_string_case_insensitive(self):
        assert _parse_verdict("block") == VerdictDecision.BLOCK

    def test_dict_verdict_key(self):
        assert _parse_verdict({"verdict": "BLOCK"}) == VerdictDecision.BLOCK

    def test_dict_decision_key(self):
        assert _parse_verdict({"decision": "ALLOW"}) == VerdictDecision.ALLOW

    def test_nested_tool_use_result(self):
        payload = {"tool_use_result": {"verdict": "QUARANTINE"}}
        assert _parse_verdict(payload) == VerdictDecision.QUARANTINE

    def test_unknown_defaults_to_allow(self):
        assert _parse_verdict("UNKNOWN_VERDICT") == VerdictDecision.ALLOW

    def test_none_defaults_to_allow(self):
        assert _parse_verdict(None) == VerdictDecision.ALLOW  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _parse_ground_truth unit tests
# ---------------------------------------------------------------------------


class TestParseGroundTruth:
    def test_malicious(self):
        assert _parse_ground_truth("MALICIOUS") == GroundTruthLabel.MALICIOUS

    def test_benign(self):
        assert _parse_ground_truth("BENIGN") == GroundTruthLabel.BENIGN

    def test_case_insensitive_malicious(self):
        assert _parse_ground_truth("malicious") == GroundTruthLabel.MALICIOUS

    def test_unknown_defaults_to_benign(self):
        assert _parse_ground_truth("UNKNOWN") == GroundTruthLabel.BENIGN


# ---------------------------------------------------------------------------
# ReportGenerator.generate() — perfect run
# ---------------------------------------------------------------------------


class TestReportGeneratorPerfectRun:
    def test_total_cases(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.total_cases == 4

    def test_scenario_counts(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.benign_count == 1
        assert report.malicious_count == 2
        assert report.evasion_count == 1

    def test_confusion_matrix_perfect(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        # 3 malicious → all caught (TP=3), 1 benign allowed (TN=1)
        assert report.true_positives == 3
        assert report.true_negatives == 1
        assert report.false_positives == 0
        assert report.false_negatives == 0

    def test_accuracy_100pct(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.metrics.accuracy == pytest.approx(100.0, abs=0.01)

    def test_frr_zero(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.metrics.false_refusal_rate == pytest.approx(0.0, abs=0.01)

    def test_evasion_rate_zero(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.metrics.evasion_rate == pytest.approx(0.0, abs=0.01)

    def test_quarantine_count(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.metrics.quarantine_count == 1

    def test_threshold_checks_pass(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        assert report.metrics.false_refusal_rate < 10.0
        assert report.metrics.evasion_rate < 10.0


# ---------------------------------------------------------------------------
# ReportGenerator.generate() — false negative (evasion slips through)
# ---------------------------------------------------------------------------


class TestReportGeneratorFalseNegative:
    def test_false_negative_increments_fn(self, minimal_evalset, false_negative_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_negative_results, tmp_path)
        report = gen.generate()
        assert report.false_negatives == 1

    def test_evasion_rate_nonzero(self, minimal_evalset, false_negative_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_negative_results, tmp_path)
        report = gen.generate()
        # 1 FN out of 3 malicious = 33.3%
        assert report.metrics.evasion_rate == pytest.approx(100.0 / 3, abs=0.01)

    def test_tp_still_two(self, minimal_evalset, false_negative_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_negative_results, tmp_path)
        report = gen.generate()
        assert report.true_positives == 2


# ---------------------------------------------------------------------------
# ReportGenerator.generate() — false positive (benign wrongly blocked)
# ---------------------------------------------------------------------------


class TestReportGeneratorFalsePositive:
    def test_false_positive_increments_fp(self, minimal_evalset, false_positive_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_positive_results, tmp_path)
        report = gen.generate()
        assert report.false_positives == 1

    def test_frr_nonzero(self, minimal_evalset, false_positive_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_positive_results, tmp_path)
        report = gen.generate()
        # 1 FP out of 1 benign = 100%
        assert report.metrics.false_refusal_rate == pytest.approx(100.0, abs=0.01)

    def test_tn_zero(self, minimal_evalset, false_positive_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, false_positive_results, tmp_path)
        report = gen.generate()
        assert report.true_negatives == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestReportGeneratorEdgeCases:
    def test_unknown_case_id_skipped(self, minimal_evalset, tmp_path):
        results = [
            _result_record("nonexistent_case_id", "BLOCK"),
            _result_record(BENIGN_CASE_ID, "ALLOW"),
        ]
        gen = _generator_with_data(minimal_evalset, results, tmp_path)
        report = gen.generate()
        # Only the known case should be counted
        assert report.total_cases == 1

    def test_empty_results(self, minimal_evalset, tmp_path):
        gen = _generator_with_data(minimal_evalset, [], tmp_path)
        report = gen.generate()
        assert report.total_cases == 0
        assert report.metrics.accuracy == pytest.approx(0.0, abs=0.01)

    def test_all_quarantine(self, tmp_path):
        evalset = _make_evalset(
            [_evalset_case(f"mal_{i}", "MALICIOUS", "malicious", "QUARANTINE") for i in range(5)]
        )
        results = [_result_record(f"mal_{i}", "QUARANTINE") for i in range(5)]
        gen = _generator_with_data(evalset, results, tmp_path)
        report = gen.generate()
        assert report.metrics.quarantine_count == 5
        assert report.true_positives == 5

    def test_bare_results_list(self, minimal_evalset, tmp_path):
        """Raw results file is a bare list (no envelope dict)."""
        evalset_file = tmp_path / "eval.json"
        results_file = tmp_path / "results.json"
        evalset_file.write_text(json.dumps(minimal_evalset), encoding="utf-8")
        results_file.write_text(
            json.dumps([_result_record(BENIGN_CASE_ID, "ALLOW")]),
            encoding="utf-8",
        )
        gen = ReportGenerator(evalset_path=evalset_file, results_path=results_file)
        report = gen.generate()
        assert report.total_cases == 1

    def test_verdict_from_nested_actual_tool_use(self, minimal_evalset, tmp_path):
        """Verdict resolved from ADK actual_tool_use array."""
        results = [
            {
                "eval_case_id": MALICIOUS_CASE_ID,
                "actual_tool_use": [
                    {"tool_use_result": {"verdict": "BLOCK"}}
                ],
            }
        ]
        gen = _generator_with_data(minimal_evalset, results, tmp_path)
        report = gen.generate()
        assert report.case_results[0].actual_verdict == VerdictDecision.BLOCK


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------


class TestExportJson:
    def test_json_exported_successfully(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "reports" / "security_report.json"
        gen.export_json(report, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "metrics" in data
        assert "case_results" in data
        assert "threshold_checks" in data

    def test_json_metrics_keys(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "security_report.json"
        gen.export_json(report, out)
        metrics = json.loads(out.read_text())["metrics"]
        required_keys = {
            "false_refusal_rate",
            "evasion_rate",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "quarantine_count",
        }
        assert required_keys <= set(metrics.keys())

    def test_threshold_checks_in_json(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "security_report.json"
        gen.export_json(report, out)
        checks = json.loads(out.read_text())["threshold_checks"]
        assert checks["frr_below_10pct"] is True
        assert checks["evasion_below_10pct"] is True

    def test_export_creates_parent_dirs(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        nested = tmp_path / "a" / "b" / "c" / "report.json"
        gen.export_json(report, nested)
        assert nested.exists()


class TestExportSummary:
    def test_summary_file_created(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "summary.txt"
        gen.export_summary(report, out)
        assert out.exists()

    def test_summary_contains_required_sections(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "summary.txt"
        gen.export_summary(report, out)
        text = out.read_text()
        assert "False Refusal Rate" in text
        assert "Evasion Rate" in text
        assert "Accuracy" in text
        assert "Precision" in text
        assert "F1 Score" in text

    def test_summary_contains_threshold_icons(self, minimal_evalset, perfect_results, tmp_path):
        gen = _generator_with_data(minimal_evalset, perfect_results, tmp_path)
        report = gen.generate()
        out = tmp_path / "summary.txt"
        gen.export_summary(report, out)
        text = out.read_text()
        assert "✅" in text
