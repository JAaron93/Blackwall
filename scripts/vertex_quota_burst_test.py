"""F03 burst test: 429 + Tier-2 starvation under uncoordinated/shared/reserved quota.

Simulates a steady Tier-2 caller (band escalations) and a bursty signature-synthesis
caller (BLOCK waves) against the real flash-lite Vertex quota (~300 RPM). Measures,
per policy: actual 429s from Vertex and Tier-2 skips (bucket starvation). Real calls,
small prompts. Project id is read from env at runtime, never written to output.
"""
import asyncio
import os
import time
from collections import Counter

from dotenv import dotenv_values

for k, v in dotenv_values(".env").items():
    if v is not None:
        os.environ[k] = v
for p in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(p, None)

from google import genai
from google.genai import types

client = genai.Client(vertexai=True, project=os.environ["GCP_PROJECT"], location="global")
MODEL = "gemini-3.5-flash-lite"
QUOTA_RPS = 5.0          # ~300 RPM
DURATION = 40.0          # seconds per policy
TIER2_RPS = 1.0          # steady band-escalation demand (60 RPM)
SYNTH_BURST_RPS = 8.0    # synthesis burst demand
SYNTH_BURST_ON = 4.0     # burst length
SYNTH_BURST_OFF = 8.0    # idle between bursts
RESERVE_TIER2_RPS = 1.0  # reserved floor for Tier-2


class Bucket:
    def __init__(self, rate, cap):
        self.rate = rate
        self.cap = cap
        self.tokens = cap
        self.last = time.monotonic()

    def try_acquire(self):
        now = time.monotonic()
        self.tokens = min(self.cap, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


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
        if bucket is None or bucket.try_acquire():
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
        t2 = Bucket(QUOTA_RPS, QUOTA_RPS)   # Tier-2 own full bucket
        syn = None                          # synthesis uncounted (the current bug)
    elif policy == "shared":
        shared = Bucket(QUOTA_RPS, QUOTA_RPS)
        t2 = syn = shared
    elif policy == "reserved":
        t2 = Bucket(RESERVE_TIER2_RPS, RESERVE_TIER2_RPS * 2)
        syn = Bucket(QUOTA_RPS - RESERVE_TIER2_RPS, (QUOTA_RPS - RESERVE_TIER2_RPS) * 2)
    t_start = time.monotonic()
    await asyncio.gather(
        caller("tier2", TIER2_RPS, t2, stats, t_start),
        caller("synthesis", SYNTH_BURST_RPS, syn, stats, t_start, bursty=True),
    )
    return stats


async def main():
    for policy in ("uncoordinated", "shared", "reserved"):
        await asyncio.sleep(65)  # fresh per-minute Vertex quota window before each policy
        stats = await run_policy(policy)
        print(f"\n== {policy} ==", flush=True)
        for name in ("tier2", "synthesis"):
            s = stats[name]
            print(f"  {name}: attempts={s['attempts']} sent={s['sent']} "
                  f"ok={s['ok']} 429={s['429']} skipped={s['skipped']} "
                  f"other={sum(v for k, v in s.items() if k not in ('attempts','sent','ok','429','skipped'))}",
                  flush=True)


asyncio.run(main())