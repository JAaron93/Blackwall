# Jev 1.13 vs 1.14 — calibration comparison and the TASK-F12 pin (2026-11-23)

> **Decision:** production pins **`jev-1.13.0`**. This supersedes ADR 0008
> Decision 7 (the moving `jev-latest` alias). The pin is a maintainer decision
> recorded under `.kiro/specs/tier-1-jev-addition/tasks.md` TASK-F12; no alias is
> sent, and the backend normalizes `jev-latest`/`jev-preview` back to the pin.
> This document explains *where and why 1.13 outperformed 1.14*, and where it
> did not — so the decision can be revisited with evidence rather than folklore.

## 1. Scope of the claim

The claim is narrow: **on the original 167-case golden suite and on the
properties this Tier-1 triage cares about (C2/IOC detection, benign-score
margin, calibration), Jev 1.13 measured better than 1.14.** On later,
class-blind and tool-name-balanced corpora the two releases are effectively
tied. There is **no** head-to-head steering/defense experiment between the two
releases, so this retrospective does *not* claim 1.13 resists adversarial
tool-call text better.

## 2. Measured evidence

### 2.1 Original golden suite — 1.13 wins (ADR 0008, 2026-11-12)

Each release was requested **by name** (`JEV_MODEL=jev-1.13.0` /
`jev-1.14.0`), twice, interleaved, from an empty cache on the paid first-party
API, over the same 167 states, 0 errors in all four runs. Within-release noise
was a mean 0.004 per case (largest 0.04, 0–1 zone changes); the releases differed
by a mean 0.012–0.014 (largest 0.21).

| Metric (run 1 / run 2) | `jev-1.13.0` | `jev-1.14.0` |
| --- | --- | --- |
| Accuracy, decided cases | **99.4% / 99.4%** (FN 1 / 1) | 98.8% / 98.8% (FN 2 / 2) |
| AUROC | 1.000 / 1.000 | 0.9999 / 1.000 |
| ECE | **0.058 / 0.059** | 0.067 / 0.070 |
| Escalated to Tier-2 | 3 / 4 | 3 / 3 |
| Highest benign P | **0.14 / 0.14** | 0.19 / 0.22 |
| Mean P — benign / other-malicious / C2 | 0.048 / 0.960 / **0.692–0.703** | 0.056 / 0.953 / **0.632–0.635** |
| Evasion-proof misses (of 10) | **1** (1 escalated) | **2** |

The C2-class mean fell by **0.065** from 1.13 to 1.14 — about sixteen times the
within-release noise — led by `malicious_c2_001` (0.71 → 0.52),
`malicious_c2_003`/`_004` (0.85/0.86 → 0.77) and `wave2_c2_beacon_001`
(0.41 → 0.33, band → clear-low). Only two cases changed zone when averaging each
release's runs. ADR 0008's own verdict: "1.14 is not an improvement on this
suite."

### 2.2 Class-blind corpus — no material difference (2026-11-13)

Four runs (two releases × two repeats) over the label-free shared-template
corpus: both releases ≈0.83 decided accuracy, AUROC 0.992–0.997, ECE 0.18–0.20,
escalation 6–10%. The accuracy and ECE gate failures are corpus-wide, not
release-specific.

### 2.3 Balanced corpus, G04 golden A/B (2026-11-21)

The legacy single-question arm was scored for **both** releases at the current
0.08/0.40 band on the 197-case balanced corpus (two interleaved passes each):

| Held-out (101 cases) | `jev-1.13.0` | `jev-1.14.0` |
| --- | --- | --- |
| Accuracy | 0.8636–0.8736 | 0.8721–0.8750 |
| AUROC | 0.9753–0.9780 | 0.9700–0.9812 |
| ECE | 0.2555–0.2559 | 0.2530–0.2552 |
| In-band Tier-2 fire | 12.9–13.9% | 12.9–14.9% |
| FRR | 0 | 0 |

Both releases passed the five re-baselined F10 gates plus FRR; both failed the
retained evasion gate (33.3%, plain C2 beacons). This run is what makes the
pin *evidence-backed* rather than an unvalidated config flip: the pinned release
already has fresh held-out gate figures at the band the decision depends on.

### 2.4 What is NOT in the evidence

F02's steering/defense experiments (nonce-XML boundary, structured state,
atomic questions) were all run with **`jev-1.14.0`**. There is no 1.13-vs-1.14
comparison under adversarial tool-call text, so "1.13 is more secure against
steering" is unmeasured. The TypeSafe jaggedness page lists adversarial content
as a known weak spot of Jev generally ("we expect to improve on this in the
future"); it does not rank the releases.

## 3. Why 1.13 came out ahead for this use case

1. **1.14's changes do not target our workload.** The vendor changelog lists
   better multilingual support, the Box image-grounding question type, and
   image placement in `state`/`instructions`/`criteria`. Blackwall's Tier-1
   request is English text, one `is_threat` `noul` over a sanitized tool-call
   state, with no images or Box questions. There is no feature in 1.14 that this
   integration can exploit.
2. **The regression is concentrated in the weak class.** The loss is in C2/IOC
   scores and benign-score margin — exactly the cases ADR 0008 and ADR 0009
   already flag as the hard part (plain requests to odd hosts, no attack text).
   A lower C2 probability pushes those calls under the band edge, where Tier-1
   can no longer decide them; a higher benign P costs false-alarm margin.
3. **Calibration shifts are release-specific, not hypothetical.** TypeSafe's
   models docs advise sending a versioned ID when confidence thresholds were
   tuned against a release. Our 0.08/0.40 band was re-baselined by F10 against
   named-release runs, so following an alias would silently change the meaning
   of the thresholds — the precise failure mode that motivated this pin.

## 4. The trade-off being accepted

- **Given up:** newest-release coverage. If TypeSafe ships a 1.15, this
  integration will not pick it up automatically. F07 is closed N/A precisely
  because there is no alias to track; a future change needs its own A/B.
- **Gained:** verdict stability and reproducible calibration. The band, the
  stored runs and the gate figures all refer to a named release; `served_model`
  telemetry now verifies the pin instead of detecting silent drift.
- **Not gained:** no defense against steering is claimed, and the C2/IOC Tier-1
  weakness (33.3% evasion misses in G04) remains open — F02 is closed with that
  residual explicitly accepted.

## 5. Reopen conditions

Revisit the pin only if (a) a new TypeSafe release demonstrates a material gain
on the balanced corpus **and** under matched steering payloads, with two
interleaved passes per release and the within-release spread reported; or (b)
this workload starts using 1.14-only capabilities (Box/image grounding).
Any flip requires a spec amendment plus the same-change `AGENTS.md`,
`.agents/rules/`, `.greptile/` sync — the pin is not an `.env`-only change.

## 6. Artifact and documentation chain

- ADR 0008, Verification — "Release comparison, 1.13 vs 1.14 (2026-11-12)" and
  Decision 7 amendment (2026-11-23).
- `tests/eval/results/jev_runs/manifest.json` — four named-release headline runs;
  recomputed by `tests/unit/test_jev_run_comparison_data.py`.
- `tests/eval/results/jev_runs_class_blind/manifest.json` — class-blind release
  comparison; recomputed by `tests/unit/test_jev_class_blind_runs_data.py`.
- `tests/eval/results/jev_g04_ab/manifest.json` — balanced-corpus A/B for both
  releases; recomputed by `tests/unit/test_jev_g04_ab_data.py`.
- `.kiro/specs/tier-1-jev-addition/tasks.md` TASK-F12 (decision) and TASK-F07
  (N/A); FR-11 and design.md amendments; `.agents/rules/architecture_and_security.md`,
  `.agents/rules/testing_and_hygiene.md`, `.greptile/rules` config synced.
- Vendor docs consulted 2026-11-23: `https://docs.typesafe.ai/go/models.md`,
  `https://docs.typesafe.ai/go/jaggedness.md`, `https://docs.typesafe.ai/changelog.md`.
