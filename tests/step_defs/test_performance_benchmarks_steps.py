"""Pytest-BDD step definitions for Performance Benchmarking and Resource Validation (Task 26)."""

import os
import tempfile
from typing import Any

import pytest
from pytest_bdd import given, scenarios, then, when

from blackwall.benchmarks.runner import BenchmarkRunner
from blackwall.db.repository import SQLiteThreatRepository
from blackwall.policy.engine import StructuralGatingEngine
from blackwall.sync_resolver import SyncResolver
from tests.step_defs.async_utils import run_async

scenarios("../features/performance_benchmarks.feature")


class PerformanceBenchmarkState:
    """Container for state across BDD benchmark steps."""

    def __init__(self) -> None:
        self.runner: BenchmarkRunner = BenchmarkRunner()
        self.structural_engine: StructuralGatingEngine | None = None
        self.structural_p99: float = 0.0
        self.semantic_resolver: SyncResolver | None = None
        self.semantic_p99: float = 0.0
        self.repo: SQLiteThreatRepository | None = None
        self.db_path: str = ""
        self.tsg_p99: float = 0.0
        self.memory_rss_mb: float = 0.0
        self.cpu_percent: float = 0.0
        self.avg_batch_size: float = 0.0


@pytest.fixture
def bdd_bench_state() -> Any:
    state = PerformanceBenchmarkState()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        state.db_path = tmp.name

    state.repo = SQLiteThreatRepository(db_path=state.db_path)
    run_async(state.repo.initialize())
    state.runner = BenchmarkRunner(repo=state.repo)

    yield state

    if state.repo:
        run_async(state.repo.close())
    if os.path.exists(state.db_path):
        os.remove(state.db_path)


# ---------------------------------------------------------------------------
# Scenario 1: Structural gating latency < 5ms p99
# ---------------------------------------------------------------------------


@given("a StructuralGatingEngine configured with production rules")
def init_structural_engine(bdd_bench_state: PerformanceBenchmarkState) -> None:
    bdd_bench_state.structural_engine = bdd_bench_state.runner.create_default_structural_engine()


@when("100 concurrent tool call requests are evaluated")
def evaluate_structural_load(bdd_bench_state: PerformanceBenchmarkState) -> None:
    _, _, p99 = run_async(
        bdd_bench_state.runner.benchmark_structural_gating(
            engine=bdd_bench_state.structural_engine, count=100
        )
    )
    bdd_bench_state.structural_p99 = p99


@then("the structural gating p99 latency must be under 5.0 milliseconds")
def verify_structural_p99(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.structural_p99 < 5.0
    ), f"Structural p99 was {bdd_bench_state.structural_p99:.3f}ms (target < 5.0ms)"


# ---------------------------------------------------------------------------
# Scenario 2: Semantic gating latency < 300ms p99
# ---------------------------------------------------------------------------


@given("a SyncResolver with mock GTI and CBM intelligence")
def init_semantic_resolver(bdd_bench_state: PerformanceBenchmarkState) -> None:
    pass


@when("50 semantic tool calls are evaluated")
def evaluate_semantic_calls(bdd_bench_state: PerformanceBenchmarkState) -> None:
    _, _, p99 = run_async(bdd_bench_state.runner.benchmark_semantic_gating(count=50))
    bdd_bench_state.semantic_p99 = p99


@then("the semantic gating p99 latency must be under 300.0 milliseconds")
def verify_semantic_p99(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.semantic_p99 < 300.0
    ), f"Semantic p99 was {bdd_bench_state.semantic_p99:.3f}ms (target < 300.0ms)"


# ---------------------------------------------------------------------------
# Scenario 3: TSG query latency < 10ms p99 with 10k signatures
# ---------------------------------------------------------------------------


@given("a Threat Signature Graph populated with 10000 signatures")
def populated_tsg_database(bdd_bench_state: PerformanceBenchmarkState) -> None:
    pass


@when("100 similarity queries are executed")
def execute_similarity_queries(bdd_bench_state: PerformanceBenchmarkState) -> None:
    _, _, p99 = run_async(
        bdd_bench_state.runner.benchmark_tsg_query_latency(
            repo=bdd_bench_state.repo, total_signatures=10000, query_count=100
        )
    )
    bdd_bench_state.tsg_p99 = p99


@then("the TSG query p99 latency must be under 10.0 milliseconds")
def verify_tsg_query_p99(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.tsg_p99 < 10.0
    ), f"TSG query p99 was {bdd_bench_state.tsg_p99:.3f}ms (target < 10.0ms)"


# ---------------------------------------------------------------------------
# Scenario 4: Resource consumption under sustained load
# ---------------------------------------------------------------------------


@given("an active Blackwall firewall instance under sustained 300 RPM load")
def active_firewall_instance(bdd_bench_state: PerformanceBenchmarkState) -> None:
    pass


@when("100 tool calls are processed at sustained rate")
def process_sustained_load(bdd_bench_state: PerformanceBenchmarkState) -> None:
    mem_rss, cpu_pct = run_async(
        bdd_bench_state.runner.benchmark_sustained_load(count=100, rate_rpm=300)
    )
    bdd_bench_state.memory_rss_mb = mem_rss
    bdd_bench_state.cpu_percent = cpu_pct


@then("the resident memory RSS must remain under 350.0 megabytes")
def verify_memory_rss(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.memory_rss_mb <= 350.0
    ), f"Memory RSS was {bdd_bench_state.memory_rss_mb:.2f}MB (target <= 350.0MB)"


@then("the CPU utilization on a 2-core baseline must remain under 2.0 percent")
def verify_cpu_usage(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.cpu_percent < 2.0
    ), f"CPU usage was {bdd_bench_state.cpu_percent:.2f}% (target < 2.0%)"


# ---------------------------------------------------------------------------
# Scenario 5: Average batch size >= 3 at full load
# ---------------------------------------------------------------------------


@given("a BatchResolver receiving concurrent tool call batches")
def init_batch_resolver(bdd_bench_state: PerformanceBenchmarkState) -> None:
    pass


@when("full batch load is processed")
def process_full_batch_load(bdd_bench_state: PerformanceBenchmarkState) -> None:
    avg_batch_sz = run_async(bdd_bench_state.runner.benchmark_batch_efficiency())
    bdd_bench_state.avg_batch_size = avg_batch_sz


@then("the average batch size must be at least 3.0")
def verify_avg_batch_size(bdd_bench_state: PerformanceBenchmarkState) -> None:
    assert (
        bdd_bench_state.avg_batch_size >= 3.0
    ), f"Average batch size was {bdd_bench_state.avg_batch_size:.2f} (target >= 3.0)"
