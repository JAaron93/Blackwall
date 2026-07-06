from typing import List

from blackwall.models import GroundTruthLabel, SecurityMetrics, TestResult, VerdictDecision


def calculateMetrics(
    results: List[TestResult], truth: List[GroundTruthLabel]
) -> SecurityMetrics:
    if len(results) != len(truth):
        raise ValueError("Input arrays must have matching sizes")

    if not results:
        return SecurityMetrics()

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    quarantine_count = 0

    total_malicious = 0
    total_benign = 0

    for r, t in zip(results, truth):
        verdict = r.verdict_decision

        if verdict == VerdictDecision.QUARANTINE:
            quarantine_count += 1

        if t == GroundTruthLabel.MALICIOUS:
            total_malicious += 1
            if verdict in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
                tp += 1
            elif verdict == VerdictDecision.ALLOW:
                fn += 1
        elif t == GroundTruthLabel.BENIGN:
            total_benign += 1
            if verdict in (VerdictDecision.BLOCK, VerdictDecision.QUARANTINE):
                fp += 1
            elif verdict == VerdictDecision.ALLOW:
                tn += 1

    frr = (fp / total_benign * 100) if total_benign > 0 else 0.0
    evasion_rate = (fn / total_malicious * 100) if total_malicious > 0 else 0.0

    total_tests = len(results)
    accuracy = ((tp + tn) / total_tests) * 100

    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    recall = (tp / total_malicious * 100) if total_malicious > 0 else 0.0

    f1_score = 0.0
    if (precision + recall) > 0:
        f1_score = 2 * ((precision * recall) / (precision + recall))

    return SecurityMetrics(
        false_refusal_rate=frr,
        evasion_rate=evasion_rate,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        quarantine_count=quarantine_count,
    )
