"""
Integration tests for Performance Benchmarking and Resource Validation (Task 26).
Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9 (Req 16 in requirements.md).
"""

import os
import tempfile
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from blackwall.benchmarks.runner import BenchmarkReport, BenchmarkRunner
from blackwall.db.repository import SQLiteThreatRepository


@pytest_asyncio.fixture
async def benchmark_repo() -> AsyncGenerator[SQLiteThreatRepository, None]:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    repo = SQLiteThreatRepository(db_path=db_path)
    await repo.initialize()
    yield repo

    await repo.close()
    if os.path.exists(db_path):
        os.remove(db_path)


# ===========================================================================
# Test 1: Structural gating latency < 5ms p99 under 100 concurrent requests
# ===========================================================================


@pytest.mark.asyncio
async def test_structural_gating_latency_p99() -> None:
    """
    Subtask 26.2: Assert structural gating p99 latency < 5ms under 100 concurrent requests.
    Validates Requirement 16.1.
    """
    runner = BenchmarkRunner()
    p50, p95, p99 = await runner.benchmark_structural_gating(count=100)

    assert p99 < 5.0, f"Structural gating p99 latency was {p99:.3f}ms (target < 5.0ms)"
    assert p50 < p99


# ===========================================================================
# Test 2: Semantic gating latency < 300ms p99 with mock responses
# ===========================================================================


@pytest.mark.asyncio
async def test_semantic_gating_latency_p99() -> None:
    """
    Subtask 26.2: Assert semantic gating p99 latency < 300ms with GTI/CBM mock responses.
    Validates Requirement 16.6.
    """
    runner = BenchmarkRunner()
    p50, p95, p99 = await runner.benchmark_semantic_gating(count=50)

    assert p99 < 300.0, f"Semantic gating p99 latency was {p99:.3f}ms (target < 300.0ms)"


# ===========================================================================
# Test 3: TSG query latency < 10ms p99 with 10,000 signatures
# ===========================================================================


@pytest.mark.asyncio
async def test_tsg_query_latency_10k_signatures_p99(
    benchmark_repo: SQLiteThreatRepository,
) -> None:
    """
    Subtask 26.2: Assert TSG query p99 latency < 10ms with 10,000 signatures in database.
    Validates Requirement 16.4 and Requirement 8.11.
    """
    runner = BenchmarkRunner(repo=benchmark_repo)
    p50, p95, p99 = await runner.benchmark_tsg_query_latency(
        repo=benchmark_repo, total_signatures=10000, query_count=100
    )

    assert p99 < 10.0, f"TSG query p99 latency was {p99:.3f}ms with 10,000 signatures (target < 10.0ms)"


# ===========================================================================
# Test 4: Memory RSS < 512MB under sustained load
# ===========================================================================


@pytest.mark.asyncio
async def test_memory_rss_sustained_load() -> None:
    """
    Subtask 26.2: Assert memory RSS < 512MB under sustained 300 RPM processing.
    Validates Requirement 16.11.
    """
    runner = BenchmarkRunner()
    memory_rss_mb, _ = await runner.benchmark_sustained_load(count=100, rate_rpm=300)

    assert (
        memory_rss_mb < 512.0
    ), f"Memory RSS was {memory_rss_mb:.2f}MB (target < 512.0MB)"


# ===========================================================================
# Test 5: CPU usage < 50% on 2-core under 300 RPM
# ===========================================================================


@pytest.mark.asyncio
async def test_cpu_usage_sustained_load() -> None:
    """
    Subtask 26.2: Assert CPU usage < 50% on 2-core VM during sustained 300 RPM load.
    Validates Requirement 16.12.
    """
    runner = BenchmarkRunner()
    _, cpu_percent = await runner.benchmark_sustained_load(count=100, rate_rpm=300)

    assert (
        cpu_percent < 50.0
    ), f"CPU usage was {cpu_percent:.2f}% (target < 50.0% on 2-core)"


# ===========================================================================
# Test 6: Average batch size >= 3 at full load
# ===========================================================================


@pytest.mark.asyncio
async def test_average_batch_size_full_load() -> None:
    """
    Subtask 26.2: Assert average batch size >= 3 at full load.
    Validates Requirement 16.8.
    """
    runner = BenchmarkRunner()
    avg_batch_sz = await runner.benchmark_batch_efficiency()

    assert (
        avg_batch_sz >= 3.0
    ), f"Average batch size was {avg_batch_sz:.2f} (target >= 3.0)"


# ===========================================================================
# Test 7: Full benchmark suite report generation
# ===========================================================================


@pytest.mark.asyncio
async def test_benchmark_full_report_generation(
    benchmark_repo: SQLiteThreatRepository,
) -> None:
    """
    Subtask 26.1: Full benchmark execution generates valid report satisfying all SLA criteria.
    """
    runner = BenchmarkRunner(repo=benchmark_repo)
    report = await runner.run_all(repo=benchmark_repo)

    assert isinstance(report, BenchmarkReport)
    assert report.passed is True
    assert all(report.targets_met.values()), f"Unmet targets: {report.targets_met}"
    assert "BLACKWALL FIREWALL PERFORMANCE BENCHMARK REPORT" in report.summary_table()
