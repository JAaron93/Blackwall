import asyncio
import math
import resource
import sys
import time
from pathlib import Path
from typing import List

import pytest

from blackwall.eval.metrics import calculateMetrics
from blackwall.models import (
    GroundTruthLabel,
    TestResult,
    ToolCallContext,
    VerdictDecision,
)
from blackwall.policy.models import StructuralAction
from blackwall.policy.server import HybridPolicyServer

# Shared helpers: POLICY_YAML constant, make_structural_engine,
# make_mock_semantic_engine, and make_policy_file live in helpers.py so that
# this file does not duplicate the definitions from test_pipeline_checkpoint.
from tests.integration.helpers import (
    make_mock_semantic_engine,
    make_policy_file,
    make_structural_engine,
)

# Prevent pytest from trying to collect TestResult as a test class
TestResult.__test__ = False


@pytest.fixture
def policy_yaml_path(tmp_path: Path) -> str:
    return make_policy_file(tmp_path, db_name="test_checkpoint_18.db")


def get_memory_rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    if sys.platform == "darwin":
        return usage.ru_maxrss / (1024 * 1024)
    else:
        return usage.ru_maxrss / 1024


def _p99(latencies: List[float]) -> float:
    """Helper to extract the 99th percentile latency from a list of samples.
    Referenced in latency validation section of the test module."""
    if not latencies:
        return 0.0
    n = len(latencies)
    p99_index = max(0, min(math.ceil(0.99 * n) - 1, n - 1))
    return latencies[p99_index]


# ===========================================================================
# Test 1: Verify FRR < 10% and Evasion Rate < 10% on test suite
# ===========================================================================
@pytest.mark.asyncio
async def test_system_metrics_frr_and_evasion(policy_yaml_path: str) -> None:
    structural = make_structural_engine(policy_yaml_path)

    # We will simulate 100 total inputs (50 Benign, 50 Malicious)
    # Benign inputs will use read_file which is allowed by structural rules.
    # Malicious inputs will use execute_bash which is blocked by structural rules.
    # Let's collect results and labels.
    results: List[TestResult] = []
    labels: List[GroundTruthLabel] = []

    # 50 Benign:
    for i in range(50):
        ctx = ToolCallContext(
            tool_name="read_file", arguments={"path": f"/data/safe_{i}.txt"}
        )
        verdict = structural.evaluate(ctx, "sandbox")
        # Ensure structural allows benign
        assert verdict.decision == StructuralAction.ALLOW
        results.append(TestResult(verdict_decision=VerdictDecision.ALLOW))
        labels.append(GroundTruthLabel.BENIGN)

    # 50 Malicious:
    for i in range(50):
        ctx = ToolCallContext(
            tool_name="execute_bash", arguments={"cmd": f"rm -rf /root/{i}"}
        )
        verdict = structural.evaluate(ctx, "sandbox")
        # Ensure structural blocks execute_bash
        assert verdict.decision == StructuralAction.BLOCK
        results.append(TestResult(verdict_decision=VerdictDecision.BLOCK))
        labels.append(GroundTruthLabel.MALICIOUS)

    metrics = calculateMetrics(results, labels)

    # Validate requirements: FRR < 10% and Evasion Rate < 10%
    assert (
        metrics.false_refusal_rate < 10.0
    ), f"FRR is {metrics.false_refusal_rate}%, which is >= 10%"
    assert (
        metrics.evasion_rate < 10.0
    ), f"Evasion Rate is {metrics.evasion_rate}%, which is >= 10%"
    assert metrics.accuracy == 100.0


# ===========================================================================
# Test 2: Verify all latency targets met: 5ms structural, 300ms semantic
# ===========================================================================
@pytest.mark.asyncio
async def test_system_latency_targets(policy_yaml_path: str) -> None:
    structural = make_structural_engine(policy_yaml_path)

    # Measure structural fast-path (ALLOW)
    ctx_allow = ToolCallContext(
        tool_name="read_file", arguments={"path": "/data/test.txt"}
    )
    latencies_struct: List[float] = []

    # Warmup runs to avoid first-run overhead
    for _ in range(10):
        structural.evaluate(ctx_allow, "sandbox")

    for _ in range(100):
        t0 = time.perf_counter()
        structural.evaluate(ctx_allow, "sandbox")
        t1 = time.perf_counter()
        latencies_struct.append((t1 - t0) * 1000.0)

    latencies_struct.sort()
    # Call _p99 helper to calculate 99th percentile (referencing the module's latency validation section)
    p99_struct = _p99(latencies_struct)
    assert (
        p99_struct < 5.0
    ), f"Structural P99 latency {p99_struct:.2f}ms exceeds 5ms target"

    # Measure semantic gating latency
    mock_semantic = make_mock_semantic_engine(
        verdict=VerdictDecision.ALLOW, latency_ms=10.0
    )
    server = HybridPolicyServer(structural, mock_semantic)

    # ESCALATE to semantic
    ctx_escalate = ToolCallContext(
        tool_name="write_file", arguments={"path": "/data/out.txt"}
    )
    latencies_semantic: List[float] = []

    # Warmup
    for _ in range(5):
        await server.evaluate(ctx_escalate, "production")

    for _ in range(50):
        t0 = time.perf_counter()
        await server.evaluate(ctx_escalate, "production")
        t1 = time.perf_counter()
        latencies_semantic.append((t1 - t0) * 1000.0)

    latencies_semantic.sort()
    # Call _p99 helper to calculate 99th percentile (referencing the module's latency validation section)
    p99_semantic = _p99(latencies_semantic)
    assert (
        p99_semantic < 300.0
    ), f"Semantic P99 latency {p99_semantic:.2f}ms exceeds 300ms target"


# ===========================================================================
# Test 3: Resource usage under load (Memory < 512MB, CPU < 50%)
# ===========================================================================
@pytest.mark.asyncio
async def test_system_resource_consumption_load(policy_yaml_path: str) -> None:
    structural = make_structural_engine(policy_yaml_path)
    # cpu_spin_ms=5.0 replicates the original 5 ms busy-wait to generate measurable CPU load
    mock_semantic = make_mock_semantic_engine(
        verdict=VerdictDecision.ALLOW, latency_ms=1.0, cpu_spin_ms=5.0
    )
    server = HybridPolicyServer(structural, mock_semantic)

    # We will simulate sustained 300 RPM load (5 requests per second) for 5 seconds.
    # Total of 25 requests. We run this under 'production' role so it escalates to
    # semantic gating, triggering actual CPU-heavy spin work in the mocked path.
    requests_to_run = 25
    ctx = ToolCallContext(tool_name="read_file", arguments={"path": "/data/test.txt"})

    async def execute_request(delay: float):
        await asyncio.sleep(delay)
        await server.evaluate(ctx, "production")

    tasks = [execute_request(i * 0.2) for i in range(requests_to_run)]

    start_cpu = time.process_time()
    start_perf = time.perf_counter()

    await asyncio.gather(*tasks)

    end_cpu = time.process_time()
    end_perf = time.perf_counter()

    wall_time = end_perf - start_perf
    cpu_time = end_cpu - start_cpu

    # Calculate CPU usage percentage of the process relative to the wall time elapsed
    cpu_usage_pct = (cpu_time / wall_time) * 100 if wall_time > 0 else 0.0

    rss_mb = get_memory_rss_mb()

    # Assert constraints: Memory < 512MB, CPU < 50% system load on a 2-core machine.
    # (Since 50% CPU load on 2 cores means using up to 100% CPU time of 1 core, we check if cpu_usage_pct < 100)
    assert (
        rss_mb < 512.0
    ), f"Sustained RSS memory usage {rss_mb:.2f}MB exceeds 512MB budget"
    # CPU usage must be non-zero (demonstrating actual work and avoiding near-zero sleeps) but under the limit
    assert (
        0.0 < cpu_usage_pct < 100.0
    ), f"CPU usage {cpu_usage_pct:.2f}% is outside the expected 0-50% load target on 2-core VM"
