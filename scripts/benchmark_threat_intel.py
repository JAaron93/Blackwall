#!/usr/bin/env python3
"""Threat Intelligence Engine Performance & Resource Benchmarking Harness (TASK-H03).

Verifies:
1. SQLite threat_intel_cache lookup latency <= 1.0 ms (SLA).
2. RSS process memory overhead attributable to threat intelligence engine <= 50 MB.
3. Zero CUDA / GPU tensor allocations initiated.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import os
import resource
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.threat_intel.models import ThreatIndicatorType, ThreatIntelResponse


def get_rss_bytes() -> int:
    """Return current process resident set size in bytes across macOS and Linux."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return usage
    return usage * 1024


def check_zero_cuda_allocations(daemon_pid: Optional[int] = None) -> bool:
    """
    Multi-layer zero-CUDA verification for DGX Spark / Linux and local environments:
    1. Verify torch.cuda.is_initialized() is False and memory_allocated() == 0.
    2. Inspect target daemon PID's file descriptors (/proc/<daemon_pid>/fd/) for /dev/nvidia*.
    3. Verify target daemon PID absence from NVML active compute processes.
    """
    # 1. PyTorch CUDA context and allocation check
    try:
        import torch

        if hasattr(torch, "cuda"):
            if torch.cuda.is_initialized():
                return False
            if torch.cuda.is_available() and torch.cuda.memory_allocated() > 0:
                return False
    except ImportError:
        pass

    # Resolve target daemon PID if not explicitly supplied
    target_pid = daemon_pid
    if target_pid is None:
        pid_file = os.path.expanduser("~/.blackwall/blackwall.pid")
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    content = f.read().strip()
                    if content.isdigit():
                        target_pid = int(content)
            except Exception:
                target_pid = None

    # 2. Inspect /proc/<daemon_pid>/fd/ on Linux for /dev/nvidia* descriptors
    if target_pid is not None and sys.platform.startswith("linux"):
        fd_dir = f"/proc/{target_pid}/fd"
        if os.path.exists(fd_dir):
            try:
                for entry in os.listdir(fd_dir):
                    entry_path = os.path.join(fd_dir, entry)
                    try:
                        target = os.readlink(entry_path)
                        if "/dev/nvidia" in target:
                            return False
                    except (OSError, FileNotFoundError):
                        continue
            except Exception:
                pass

    # 3. NVML active compute process verification
    if target_pid is not None:
        try:
            import pynvml

            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()
            for i in range(device_count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                compute_procs = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
                for proc in compute_procs:
                    if proc.pid == target_pid:
                        return False
            pynvml.nvmlShutdown()
        except Exception:
            # NVML not available or no NVIDIA driver present (e.g., macOS or non-GPU CI)
            pass

    return True


async def run_benchmark(iterations: int = 100) -> Dict[str, Any]:
    """Execute latency and memory overhead benchmarks."""
    gc.collect()
    rss_baseline = get_rss_bytes()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        repo = SQLiteThreatRepository(db_path=db_path)
        await repo.initialize()

        # Seed realistic threat intelligence records
        test_indicators = [
            ("198.51.100.1", ThreatIndicatorType.IPV4, True, 0.95),
            ("203.0.113.42", ThreatIndicatorType.IPV4, False, 0.05),
            ("malicious-c2-node.com", ThreatIndicatorType.DOMAIN, True, 0.88),
            ("trusted-partner-api.org", ThreatIndicatorType.DOMAIN, False, 0.02),
            ("http://malware-distribution.net/payload.bin", ThreatIndicatorType.URL, True, 0.99),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ThreatIndicatorType.FILE_HASH, False, 0.0),
            ("d41d8cd98f00b204e9800998ecf8427e", ThreatIndicatorType.FILE_HASH, True, 0.75),
        ]

        for ind, ind_type, is_mal, risk in test_indicators:
            resp = ThreatIntelResponse(
                indicator=ind,
                indicator_type=ind_type,
                is_malicious=is_mal,
                risk_score=risk,
                provider_name="otx",
            )
            await repo.cache_threat_intel(resp, provider="otx")
            await repo.cache_threat_intel(resp, provider="aggregate")

        # Warmup
        for ind, ind_type, _, _ in test_indicators:
            await repo.get_cached_threat_intel(ind, ind_type.value, provider="otx")

        # Benchmark cache hit latency
        latencies: List[float] = []
        for i in range(iterations):
            ind, ind_type, _, _ = test_indicators[i % len(test_indicators)]
            t0 = time.perf_counter()
            cached = await repo.get_cached_threat_intel(ind, ind_type.value, provider="otx")
            t1 = time.perf_counter()
            assert cached is not None
            latencies.append(t1 - t0)

        latencies_ms = [lat * 1000 for lat in latencies]
        latencies_ms.sort()

        min_latency_ms = min(latencies_ms)
        avg_latency_ms = sum(latencies_ms) / len(latencies_ms)
        p50_latency_ms = latencies_ms[len(latencies_ms) // 2]
        p95_latency_ms = latencies_ms[int(len(latencies_ms) * 0.95)]
        p99_latency_ms = latencies_ms[int(len(latencies_ms) * 0.99)]

        gc.collect()
        rss_current = get_rss_bytes()
        rss_overhead_mb = max(0.0, (rss_current - rss_baseline) / (1024 * 1024))

        zero_cuda = check_zero_cuda_allocations()
        latency_passed = avg_latency_ms <= 1.0
        memory_passed = rss_overhead_mb <= 50.0

        all_passed = latency_passed and memory_passed and zero_cuda

        return {
            "passed": all_passed,
            "iterations": iterations,
            "min_latency_ms": min_latency_ms,
            "avg_latency_ms": avg_latency_ms,
            "p50_latency_ms": p50_latency_ms,
            "p95_latency_ms": p95_latency_ms,
            "p99_latency_ms": p99_latency_ms,
            "latency_sla_ms": 1.0,
            "latency_passed": latency_passed,
            "rss_overhead_mb": rss_overhead_mb,
            "memory_sla_mb": 50.0,
            "memory_passed": memory_passed,
            "zero_cuda": zero_cuda,
        }

    finally:
        await repo.close()
        await asyncio.sleep(0.02)
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


def print_report(res: Dict[str, Any]) -> None:
    """Renders formatted benchmark report."""
    print("=" * 65)
    print("🎯 BLACKWALL THREAT INTEL PERFORMANCE & RESOURCE BENCHMARK")
    print("=" * 65)
    print(f"Iterations (cache hits) : {res['iterations']}")
    print(f"Min Latency             : {res['min_latency_ms']:.4f} ms")
    print(f"Average Latency         : {res['avg_latency_ms']:.4f} ms (SLA <= {res['latency_sla_ms']:.1f} ms) -> {'PASS' if res['latency_passed'] else 'FAIL'}")
    print(f"P50 Latency             : {res['p50_latency_ms']:.4f} ms")
    print(f"P95 Latency             : {res['p95_latency_ms']:.4f} ms")
    print(f"P99 Latency             : {res['p99_latency_ms']:.4f} ms")
    print("-" * 65)
    print(f"RSS Memory Overhead     : {res['rss_overhead_mb']:.2f} MB (SLA <= {res['memory_sla_mb']:.1f} MB) -> {'PASS' if res['memory_passed'] else 'FAIL'}")
    print(f"Zero CUDA Allocations   : {'PASS' if res['zero_cuda'] else 'FAIL'}")
    print("=" * 65)
    verdict = "✅ ALL SLAS VERIFIED" if res["passed"] else "❌ SLA VIOLATIONS DETECTED"
    print(f"Verdict: {verdict}\n")


async def main() -> int:
    parser = argparse.ArgumentParser(description="Blackwall Threat Intel Benchmark")
    parser.add_argument("--iterations", "-n", type=int, default=100, help="Number of cache lookup iterations")
    args = parser.parse_args()

    results = await run_benchmark(iterations=args.iterations)
    print_report(results)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
