import pytest
from hypothesis import given, strategies as st

from blackwall.eval.metrics import calculateMetrics
from blackwall.models import GroundTruthLabel, TestResult, VerdictDecision


@given(
    results_and_truth=st.lists(
        st.tuples(
            st.builds(TestResult, verdict_decision=st.sampled_from(VerdictDecision)),
            st.sampled_from(GroundTruthLabel),
        ),
        min_size=1,
        max_size=100,
    )
)
def test_metrics_partition_invariant(results_and_truth):
    """Property 8: Evaluation Metrics Partition Invariant (Requirements 9.1, 9.10)"""
    results = [r for r, t in results_and_truth]
    truth = [t for r, t in results_and_truth]

    metrics = calculateMetrics(results, truth)

    # Re-calculate TP, TN, FP, FN manually to verify the partition invariant
    tp = fp = tn = fn = 0
    for r, t in zip(results, truth):
        verdict = r.verdict_decision
        if t == GroundTruthLabel.MALICIOUS:
            if verdict in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
                tp += 1
            elif verdict == VerdictDecision.ALLOW:
                fn += 1
        elif t == GroundTruthLabel.BENIGN:
            if verdict in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
                fp += 1
            elif verdict == VerdictDecision.ALLOW:
                tn += 1

    # Verify invariant: TP + TN + FP + FN = total tests
    assert (tp + tn + fp + fn) == len(results)

    # Re-verify calculations to ensure logic aligns
    total_tests = len(results)
    assert total_tests == (tp + tn + fp + fn)

    if (tp + tn + fp + fn) > 0:
        assert abs(metrics.accuracy - (((tp + tn) / total_tests) * 100)) < 1e-6


def test_calculate_metrics_empty():
    metrics = calculateMetrics([], [])
    assert metrics.false_refusal_rate == 0.0
    assert metrics.evasion_rate == 0.0
    assert metrics.accuracy == 0.0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
    assert metrics.quarantine_count == 0


def test_calculate_metrics_mismatched_lengths():
    with pytest.raises(ValueError, match="Input arrays must have matching sizes"):
        calculateMetrics([TestResult(verdict_decision=VerdictDecision.ALLOW)], [])
