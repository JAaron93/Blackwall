#!/usr/bin/env python3
"""
Performance Benchmarking and Resource Validation CLI (Task 26).
Usage:
    python scripts/benchmark_performance.py [--output report.json] [--signatures 10000]
"""

import argparse
import asyncio
import os
import sys
import tempfile

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from blackwall.benchmarks.runner import BenchmarkRunner
from blackwall.db.repository import SQLiteThreatRepository


async def main() -> int:
    parser = argparse.ArgumentParser(description="Blackwall Performance & Resource Benchmarking Runner")
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional path to output the JSON benchmark report",
    )
    parser.add_argument(
        "--signatures",
        type=int,
        default=10000,
        help="Number of signatures to populate in TSG (default: 10000)",
    )
    args = parser.parse_args()

    print("🚀 Starting Blackwall Agentic Firewall Performance & Resource Benchmarks...")
    print(f"   Target: 10k TSG Signatures, 100 Concurrent Structural Requests, 300 RPM Sustained Load\n")

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    repo = SQLiteThreatRepository(db_path=db_path)
    await repo.initialize()

    try:
        runner = BenchmarkRunner(repo=repo)
        report = await runner.run_all(repo=repo)

        print(report.summary_table())

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            print(f"\n📁 Benchmark report successfully written to {args.output}")

        return 0 if report.passed else 1

    finally:
        await repo.close()
        await asyncio.sleep(0.05)
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
