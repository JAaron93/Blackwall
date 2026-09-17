"""Unit and SLA regression tests for Threat Intelligence Benchmarking (TASK-H03).

Verifies:
1. Cache lookup latency <= 1.0 ms.
2. RSS process memory overhead <= 50 MB.
3. Zero CUDA allocations.
"""

from __future__ import annotations

import os
import sys
import pytest

# Ensure scripts directory is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts")))

from benchmark_threat_intel import check_zero_cuda_allocations, run_benchmark


@pytest.mark.asyncio
async def test_threat_intel_cache_latency_sla() -> None:
    """Assert that 100 cache lookups resolve within the 1.0ms SLA."""
    result = await run_benchmark(iterations=100)
    assert result["passed"] is True
    assert result["avg_latency_ms"] <= 1.0, f"Average latency {result['avg_latency_ms']:.3f}ms exceeded 1.0ms SLA"
    assert result["min_latency_ms"] <= 1.0


@pytest.mark.asyncio
async def test_threat_intel_memory_overhead_sla() -> None:
    """Assert that RSS process memory overhead attributable to threat intel <= 50MB."""
    result = await run_benchmark(iterations=50)
    assert result["memory_passed"] is True
    assert result["rss_overhead_mb"] <= 50.0, f"Memory overhead {result['rss_overhead_mb']:.2f}MB exceeded 50MB"


def test_zero_cuda_allocations() -> None:
    """Assert that zero CUDA / GPU tensor memory allocations occur."""
    assert check_zero_cuda_allocations() is True
