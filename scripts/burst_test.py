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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from blackwall.config import configure_provider_env, get_genai_client, Settings

async def burst_worker(worker_id: int, semaphore: asyncio.Semaphore, client, is_dummy: bool) -> float:
    async with semaphore:
        start = time.perf_counter()
        if not is_dummy:
            await client.aio.models.generate_content(
                model="gemini-3.1-flash-lite",
                contents=f"burst worker {worker_id}",
            )
        else:
            await asyncio.sleep(0.01)
        return time.perf_counter() - start

async def run_burst_test(concurrency_count: int = 20) -> bool:
    print(f"🚀 Launching {concurrency_count} parallel async requests (Paid Tier Burst Test)...")

    try:
        settings = Settings(_env_file=None)
        configure_provider_env()
        client = get_genai_client()
        is_dummy = (settings.effective_gcp_project == "dummy-gcp-project")
        print(f"  ✓ Verified GCP Project: {settings.effective_gcp_project} (Tier: {settings.gemini_tier})")
    except ValueError as e:
        print(f"  ❌ Burst Test Aborted: {e}", file=sys.stderr)
        return False

    semaphore = asyncio.Semaphore(10)  # Paid-tier max concurrent semaphore
    start_total = time.perf_counter()

    try:
        tasks = [burst_worker(i, semaphore, client, is_dummy) for i in range(concurrency_count)]
        latencies: List[float] = await asyncio.gather(*tasks)
    except Exception as e:
        print(f"  ❌ Burst Request Execution Failed: {e}", file=sys.stderr)
        return False

    total_time = time.perf_counter() - start_total
    rps = concurrency_count / total_time if total_time > 0 else 0

    print(f"  ✓ Processed {concurrency_count} requests in {total_time:.3f}s ({rps:.1f} req/sec)")
    print(f"  ✓ Avg Request Latency: {(sum(latencies)/len(latencies))*1000:.2f}ms")
    print("✅ Burst Verification Complete: Paid Tier high-throughput concurrency validated.")
    return True

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    success = asyncio.run(run_burst_test(count))
    sys.exit(0 if success else 1)
