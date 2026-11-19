"""F03 burst test: 429 + Tier-2 starvation under uncoordinated/shared/reserved quota.

Exercises the PRODUCTION ``TokenBucketRateLimiter`` with the production constants
from ``blackwall.sync_resolver`` so the comparison validates the shipped policy.
The ``reserved`` policy is the shipped rate-partition (Tier-2 reserved share +
synthesis remainder, separate refills summing to the provider quota). Simulates a
steady Tier-2 caller (band escalations) and a bursty signature-synthesis caller
(BLOCK waves) against the real flash-lite Vertex quota (~300 RPM). Measures, per
policy: actual 429s from Vertex and caller skips (bucket starvation). Real calls,
small prompts. Project id is read from env at runtime, never written to output.

Pass ``--out tests/eval/results/vertex_quota_runs/<date>.json`` to persist a
machine-readable result: the counters, the production constants and the model,
with no project id or credentials. Add every persisted file to that directory's
``manifest.json`` and keep ``tests/unit/test_vertex_quota_burst_data.py`` green.
"""
import argparse
import asyncio
import json
import os
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from dotenv import dotenv_values
from google import genai
from google.genai import types

from blackwall import sync_resolver as sr
from blackwall.resolver import TokenBucketRateLimiter

client = None  # created in main(), so this module can be imported for hermetic tests


def load_environment():
    """Apply runtime env setup only when the script is actually run.

    Importing this module for hermetic tests must not mutate the shared process
    environment (proxy settings, values from .env).
    """
    for k, v in dotenv_values(".env").items():
        if v is not None:
            os.environ[k] = v
    for p in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        os.environ.pop(p, None)


def make_client():
    return genai.Client(vertexai=True, project=os.environ["GCP_PROJECT"], location="global")


MODEL = "gemini-3.5-flash-lite"
QUOTA_RPS = sr.VERTEX_QUOTA_RPM / 60.0   # 5/s ~ 300 RPM
DURATION = 40.0          # seconds per policy
TIER2_RPS = 1.0          # steady band-escalation demand (60 RPM)
SYNTH_BURST_RPS = 8.0    # synthesis burst demand
SYNTH_BURST_ON = 4.0     # burst length
SYNTH_BURST_OFF = 8.0    # idle between bursts


async def call():
    try:
        await client.aio.models.generate_content(
            model=MODEL, contents="Reply OK.",
            config=types.GenerateContentConfig(max_output_tokens=5),
        )
        return "ok"
    except Exception as e:  # noqa: BLE001
        return "429" if getattr(e, "code", None) == 429 else type(e).__name__


async def caller(name, demand_rps, bucket, stats, t_start, bursty=False):
    interval = 1.0 / demand_rps
    end = time.monotonic() + DURATION
    tasks = []

    async def do_call():
        res = await call()
        stats[name][res] += 1

    while time.monotonic() < end:
        if bursty:
            phase = (time.monotonic() - t_start) % (SYNTH_BURST_ON + SYNTH_BURST_OFF)
            if phase >= SYNTH_BURST_ON:
                await asyncio.sleep(0.05)
                continue
        stats[name]["attempts"] += 1
        if bucket is None or await bucket.consume(1.0):
            stats[name]["sent"] += 1
            tasks.append(asyncio.create_task(do_call()))
        else:
            stats[name]["skipped"] += 1
        await asyncio.sleep(interval)
    if tasks:
        await asyncio.gather(*tasks)


async def run_policy(policy):
    stats = {"tier2": Counter(), "synthesis": Counter()}
    if policy == "uncoordinated":
        # Tier-2 own full bucket; synthesis uncounted (the pre-F03 bug).
        t2 = TokenBucketRateLimiter(capacity=sr.VERTEX_QUOTA_RPM, refill_rate=QUOTA_RPS)
        syn = None
    elif policy == "shared":
        # One shared bucket (over-commits the provider window: burst + refill).
        shared = TokenBucketRateLimiter(capacity=sr.VERTEX_QUOTA_RPM, refill_rate=QUOTA_RPS)
        t2 = syn = shared
    elif policy == "reserved":
        # The shipped rate-partition: production constants, separate refills.
        t2 = TokenBucketRateLimiter(
            capacity=sr.TIER2_RATE_LIMIT_CAPACITY,
            refill_rate=sr.TIER2_RATE_LIMIT_REFILL_PER_S,
        )
        syn = TokenBucketRateLimiter(
            capacity=sr.SYNTHESIS_RATE_LIMIT_CAPACITY,
            refill_rate=sr.SYNTHESIS_RATE_LIMIT_REFILL_PER_S,
        )
    t_start = time.monotonic()
    await asyncio.gather(
        caller("tier2", TIER2_RPS, t2, stats, t_start),
        caller("synthesis", SYNTH_BURST_RPS, syn, stats, t_start, bursty=True),
    )
    # Guard against invalid runs (bad ADC/project/network/model): if a caller got
    # no Vertex response at all, the 429 comparison is meaningless. Fail loudly.
    for name, s in stats.items():
        if s["ok"] + s["429"] == 0:
            raise RuntimeError(
                f"{policy}/{name}: no Vertex responses ({dict(s)}). "
                "Check GCP_PROJECT / ADC / model availability."
            )
    return stats


STANDARD_COUNTERS = ("attempts", "sent", "ok", "429", "skipped")


def normalize_counters(stats):
    """Return stats with every standard counter present, explicit zeros included.

    A ``Counter`` omits keys that were never incremented; a JSON export must not
    inherit that, or a fresh run cannot be checked against the committed schema.
    Unexpected outcome keys (error classes) are preserved.
    """
    normalized = {name: stats.get(name, 0) for name in STANDARD_COUNTERS}
    normalized.update({key: value for key, value in stats.items() if key not in STANDARD_COUNTERS})
    return normalized


def build_artifact(results, now):
    """Return the credential-free, machine-readable record of one burst run."""
    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "script": "scripts/vertex_quota_burst_test.py",
        "model": MODEL,
        "location": "global",
        "quota_rpm": sr.VERTEX_QUOTA_RPM,
        "duration_s": DURATION,
        "demand": {
            "tier2_rps": TIER2_RPS,
            "synthesis_burst_rps": SYNTH_BURST_RPS,
            "synthesis_burst_on_s": SYNTH_BURST_ON,
            "synthesis_burst_off_s": SYNTH_BURST_OFF,
        },
        "constants": {
            "tier2_reserved_rpm": sr.TIER2_RESERVED_RPM,
            "tier2_capacity": sr.TIER2_RATE_LIMIT_CAPACITY,
            "tier2_refill_per_s": sr.TIER2_RATE_LIMIT_REFILL_PER_S,
            "synthesis_capacity": sr.SYNTHESIS_RATE_LIMIT_CAPACITY,
            "synthesis_refill_per_s": sr.SYNTHESIS_RATE_LIMIT_REFILL_PER_S,
        },
        "policies": {
            policy: {name: normalize_counters(stats) for name, stats in callers.items()}
            for policy, callers in results.items()
        },
        "note": (
            "Aggregate counters only; no project id, credentials or response bodies. "
            "Each policy ran after a 65s quiet window against the live flash-lite quota."
        ),
    }


async def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Write a machine-readable result JSON here (recommended: "
             "tests/eval/results/vertex_quota_runs/<date>.json).",
    )
    global client
    load_environment()
    client = make_client()
    args = parser.parse_args()
    results = {}
    for policy in ("uncoordinated", "shared", "reserved"):
        await asyncio.sleep(65)  # fresh per-minute Vertex quota window before each policy
        stats = await run_policy(policy)
        results[policy] = {name: dict(s) for name, s in stats.items()}
        print(f"\n== {policy} ==", flush=True)
        for name in ("tier2", "synthesis"):
            s = stats[name]
            other = {k: v for k, v in s.items()
                     if k not in ("attempts", "sent", "ok", "429", "skipped")}
            print(f"  {name}: attempts={s['attempts']} sent={s['sent']} "
                  f"ok={s['ok']} 429={s['429']} skipped={s['skipped']} "
                  f"other={other}",
                  flush=True)
    if args.out is not None:
        artifact = build_artifact(results, datetime.now(UTC))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Wrote {args.out}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
