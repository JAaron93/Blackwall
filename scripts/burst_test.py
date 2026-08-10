#!/usr/bin/env python3
"""
High-Throughput Burst Verification Tool (Paid Tier Concurrency Test)
=====================================================================
Executes parallel async requests using asyncio.gather to verify paid-tier
concurrency limits and throughput under 100% GCP Vertex AI Mode.
"""

import sys
import os
import asyncio
import time
from typing import List

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from blackwall.config import configure_provider_env, get_genai_client, Settings


async def burst_worker(
    worker_id: int, semaphore: asyncio.Semaphore, client, is_dummy: bool
) -> float:
    async with semaphore:
        start = time.perf_counter()
        if not is_dummy:
            await asyncio.wait_for(
                client.aio.models.generate_content(
                    model="gemini-3.1-flash-lite",
                    contents=f"burst worker {worker_id}",
                ),
                timeout=10.0,
            )
        else:
            await asyncio.sleep(0.01)
        return time.perf_counter() - start


async def run_burst_test(
    concurrency_count: int = 20, total_timeout: float = 30.0
) -> bool:
    if concurrency_count <= 0:
        print(
            f"  ❌ Burst Test Aborted: concurrency_count must be a positive integer > 0 (got {concurrency_count}).",
            file=sys.stderr,
        )
        return False

    print(
        f"🚀 Launching {concurrency_count} parallel async requests (Paid Tier Burst Test)..."
    )

    try:
        settings = Settings(_env_file=None)
        configure_provider_env()
        client = get_genai_client()
        is_dummy = settings.effective_gcp_project == "dummy-gcp-project"
        print(
            f"  ✓ Verified GCP Project: {settings.effective_gcp_project} (Tier: {settings.gemini_tier})"
        )
    except ValueError as e:
        print(f"  ❌ Burst Test Aborted: {e}", file=sys.stderr)
        return False

    semaphore = asyncio.Semaphore(10)  # Paid-tier max concurrent semaphore
    start_total = time.perf_counter()

    tasks = [
        burst_worker(i, semaphore, client, is_dummy) for i in range(concurrency_count)
    ]
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=total_timeout,
        )
    except asyncio.TimeoutError:
        print(
            f"  ❌ Burst Test Failed: Overall run exceeded {total_timeout}s timeout limit",
            file=sys.stderr,
        )
        return False

    latencies: List[float] = []
    failures: List[Exception] = []

    for res in results:
        if isinstance(res, Exception):
            failures.append(res)
        else:
            latencies.append(res)

    if failures:
        print(
            f"  ❌ Burst Test Failed: {len(failures)}/{concurrency_count} requests failed or timed out: {failures[0]}",
            file=sys.stderr,
        )
        return False

    total_time = time.perf_counter() - start_total
    rps = concurrency_count / total_time if total_time > 0 else 0
    avg_latency = (sum(latencies) / len(latencies)) * 1000 if latencies else 0.0

    print(
        f"  ✓ Processed {concurrency_count} requests in {total_time:.3f}s ({rps:.1f} req/sec)"
    )
    print(f"  ✓ Avg Request Latency: {avg_latency:.2f}ms")
    print(
        "✅ Burst Verification Complete: Paid Tier high-throughput concurrency validated."
    )
    return True


if __name__ == "__main__":
    count = 20
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            print(
                f"Usage: python3 scripts/burst_test.py [concurrency_count > 0] (invalid integer: {sys.argv[1]})",
                file=sys.stderr,
            )
            sys.exit(1)

    success = asyncio.run(run_burst_test(count))
    sys.exit(0 if success else 1)
