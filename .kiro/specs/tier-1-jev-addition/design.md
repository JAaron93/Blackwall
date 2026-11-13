# Design Document: Tier-1 Jev Addition (Additive Semantic Triage)

## Overview

Blackwall Core's synchronous interception path (`SyncResolver`) currently performs
semantic triage exclusively via Gemini 3.5 Flash-Lite
(`src/blackwall/config.py:20` `DEFAULT_RAPID_TRIAGE_MODEL`,
`src/blackwall/sync_resolver.py:878` `_evaluate_semantic_intent`), whose float
`threat_score` feeds the weighted aggregation in `_compute_threat_score`
(`src/blackwall/sync_resolver.py:957`: Threat Intel 40% + CBM 30% + Context 30%).

This spec introduces **TypeSafe Jev**, accessed through the official TypeSafe
AI API, as an **additive Tier-1 decision classifier** that absorbs the boring
95%+ of clear-cut tool calls, while Gemini is retained for Tier-2 ambiguity
escalation and async forensic/signature synthesis. Jev is a probabilistic
evaluation model (a typed `noul` yes/no `P(threat)`, no text generation); it
cannot replace Gemini's generative duties. **Additive, not substitution.**

> **Amendment (2026-11-12, ADR 0008):** this spec was written for Jev reached
> through the Vercel AI Gateway (`typesafe-ai/jev`, `POST /v1/evaluate`,
> `boolean` question, `disallowPromptTraining`). The transport is now the
> official TypeSafe AI API (`POST /v1/systemone`, `noul` question). Sections 2
> and 4, the diagram and the constraints below are amended; the Experimental
> Basis is left as the historical record of the Gateway-era run.

## Experimental Basis (A/B run, 2026-09-19, branch `exp/jev-ab-eval-plan`)

> *Historical: every figure in this section was measured through the Vercel AI
> Gateway, before ADR 0008. Gateway-specific wording is preserved as recorded.*

A swap-only A/B compared the Gemini baseline against Jev over the golden sets
(`tests/eval/evalsets/blackwall_security.evalset.json`: 157 cases —
68 benign / 59 malicious / 30 evasion; plus
`blackwall_evasion_proof.evalset.json`: 10 cases). Only the
`_evaluate_semantic_intent -> float` seam was swapped
(`threat_score = Jev P(is_threat=true)`, thresholds `0.35 / 0.75` fixed a
priori); Tier-0, TSG, judges, and weights were frozen. Every call carried
`providerOptions.gateway = { disallowPromptTraining: true }` on sanitized state.

| Metric | Gemini baseline (2026-09-12) | Jev (this run) | Gate | Pass |
|---|---|---|---|---|
| Accuracy (157) | 100% | **100%** (TP=89 FN=0 FP=0 TN=68) | ≥98% | ✅ |
| Recall | 1.0 | **1.0** | ≥0.98 | ✅ |
| Evasion recall (30) | 100% | **30/30** | ≥0.97 | ✅ |
| FRR | 0% | **0%** | <5% | ✅ |
| AUROC | n/a (LLM) | **1.0** | ≥0.95 | ✅ |
| ECE (10-bin) | n/a | **0.028** | ≤0.10 | ✅ |
| Escalation rate (157) | n/a | **0%** | ≤25% | ✅ |
| Evasion-proof (10) | n/a | 7 BLOCK + 3 escalate (0.51/0.68/0.70) | resolve via Tier-2 | ✅ |
| Full-pass cost | — | **$0.0025** (60k in / 3.5k out tokens) | — | ✅ |
| Latency p50/p95 | — | **~0.9s / ~1.3s** via Gateway | interim p95 <2s (amended; `<100ms` deferred to local/in-VPC) | ✅ |

Separation margins: benign `P ≤ 0.06`, malicious `P ≥ 0.89` — nothing near the
ambiguity band on the main suite. The 3 proof-set escalations (C2 beacon, path
traversal) are precisely the cases Tier-2 exists for. Latency over the Gateway
cannot meet a `<100ms` Tier-1 SLA; accepted as network parity with LLM API
calls (a future local/in-VPC Jev deployment may revisit this).

Free-tier observation (motivates paid operation): the `$5/mo` credit covered
spend trivially, but Jev's free per-model rate limit allowed only a ~20-call
burst, then a multi-hour trickle (`429 GatewayRateLimitError`, no
`retry-after`). Paid AI Gateway Credits remove Gateway-side limits entirely.
Decision: **operate Jev on paid credits**; keep free-tier findings as
cost evidence only.

### Re-validation on the TypeSafe API (TASK-D02, 2026-11-12, `jev-1.14.0`, paid)

The run above is the Gateway-era record. TASK-D02 repeated it through the
official API with `jev-latest` (served: `jev-1.14.0`): accuracy 99.4% (TP 93,
FN 1, FP 0, TN 68), AUROC 1.000, ECE 0.059, escalation 3.0% (5/167), p50 92 ms
and p95 143 ms, about $0.003 per pass; all gates pass. Across two runs, outside
the C2 class every malicious case scores P ≥ 0.74 and benign P ≤ 0.19. The C2 class is still the
weak spot and weaker than on 1.13 (mean P 0.70 to 0.63; `wave1_c2_beacon_001`
still missed at P 0.19). Same-model reruns differ by up to 0.03 per case and
changed zone in 3 of 167, so a second run of the same pass scored 98.8% (one
more C2 beacon missed), one case above the 98% gate. See ADR 0008.
*(2026-11-13: these figures are for the earlier corpus, whose states reveal their
class. On the class-blind corpus decided accuracy is 82.2% to 82.6% and ECE is
0.19, so those two gates fail while AUROC and escalation pass; see ADR 0009,
Verification.)*

## Architecture Diagram

```text
Tool Call Intercepted
        │
Tier 0: Deterministic & AST Graph (<5ms)  [UNCHANGED]
        ├── Definite Match / Known Sig → Fast ALLOW or BLOCK
        └── Novel / Suspicious Payload
                    │
Tier 1: SemanticTriageProvider  [Jev only; fails fast, ADR 0009]
        ├── backend=jev (TypeSafe API, paid): P(threat)
        │     ├── P < 0.35 → clear-low SIGNAL → Score Aggregation (no Tier-2 call)
        │     ├── P > 0.75 → clear-high SIGNAL → Score Aggregation (no Tier-2 call)
        │     └── 0.35 ≤ P ≤ 0.75 → Tier-2 escalation
        └── Jev unavailable (any reason) → JevUnavailableError; no fallback
                    │
          AGGREGATION SUPREMACY: triage outputs are weighted SIGNALS only.
          Terminal ALLOW/BLOCK/QUARANTINE are decided exclusively at Score
          Aggregation + Threshold Verdict (weights and thresholds unchanged),
          so deterministic BLOCKs (structural, TSG) can never be overridden
          by a low P, and a high P alone cannot BLOCK. The Tier-1 win is
          skipping the Tier-2 Gemini call — never skipping aggregation
          (local, microseconds).
                    │
Tier 2 Escalation: Gemini (3.5 Flash-Lite, medium thinking, pinned)  [ADR 0009]
        ├── Ambiguity band referrals from Tier-1
        ├── Deterministic-vs-semantic disagreement
        │     (high-risk keywords present but P < 0.2)
        └── Final verdict: ALLOW / BLOCK
                    │
Async Background (on novel BLOCK): Gemini signature & forensics gen  [RETAINED, NOVEL-ONLY]
        └── ThreatSignaturePayload → SQLite TSG (Wave-2 learning). Blocks
            served by an existing TSG match return immediately with no
            generation — regenerating per repeat would add cost and churn.
```

## Components

### 1. `SemanticTriageProvider` Interface (`src/blackwall/policy/semantic.py`)
Implemented only by `JevTriageBackend` (ADR 0009). There is no backend
selection and no `BW_SEMANTIC_BACKEND`. `triage` returns a
`SemanticTriageResult { threat_score: float, confidence: float|None,
backend: str, escalate: bool }` so `_compute_threat_score` stays untouched, or
raises `JevUnavailableError`; there is no abstain value. The resolver builds the
backend on first use, so an unset `TYPESAFE_API_KEY` raises there.

### 2. Jev Backend (`JevTriageBackend`)

Single-question `noul` evaluation per intercepted call:
`POST {TYPESAFE_BASE_URL}/v1/systemone` with `state` = sanitized
`Tool / Arguments / Metadata` (sanitized **first**),
`questions = { is_threat: { type: "noul", instructions } }`,
`threat_score = answers.is_threat.noul`. Fixed thresholds `0.35 / 0.75`
(recalibration requires a spec amendment with fresh labeled data — no silent
tuning). Records `latency_ms` and token usage per call for the regression
tracker; `confidence` is `None` because a `noul` answer carries none, and cost
is derived from the token counts. A throttled call (`429` / `529`) is retried
once after a fixed 0.5s, then fails closed. Rate limits are per organization
(requests/s and tokens/s, set in the TypeSafe console; this organization, as of
2026-11-12: 80 requests/s and 100,000 input tokens/s, both default and shared
across keys, i.e. 4,800 RPM); there is no client-side pacing. The model is
`jev-latest`, deliberately unpinned (ADR 0008).

### 3. Tier-2 Escalation Policy (retained, narrowed)

Gemini (3.5 Flash-Lite, medium) fires only on: (a) ambiguity band, (b) deterministic-vs-semantic
disagreement (high-risk argument novelty vs `P < 0.2`), (c) async forensics.
Expected Tier-2 rate: ~0% on routine suites, ~30% on hard evasion probes
(measured). This is the cost control: Gemini deep reasoning spends only where
judgment exists. A 300 RPM bucket guards only the Tier-2 call; Tier-2 returning no verdict
for any reason (including an empty bucket) QUARANTINEs an ALLOW (FR-03). The
front bucket is 80 req/s.

### 4. Privacy & Data Handling

`ContextHygiene.sanitize_*` runs **before** any TypeSafe API payload is built —
the API sees only `[[PLACEHOLDER]]`-redacted synthetic/operational tool
descriptions, never raw env vars, ADC credentials, or secrets. The request
body is an allowlist of exactly `model`, `state` and `questions`.
The Vercel-era `disallowPromptTraining: true` flag does not exist on the
first-party API (ADR 0008), so no request can assert it. The remaining
no-training protection is TypeSafe's published data-handling commitment
("Jev is not trained on customer requests or responses"); that is a vendor
assurance, not a control Blackwall can verify per request. Zero data retention
(ZDR) is an enterprise feature and is **not available on this account** (a
regular customer; maintainer-confirmed 2026-11-12). TypeSafe's DPA (last updated
2026-04-24) sets no fixed retention period: personal data is retained "for as
long as necessary taking into account the purpose of the Processing".
`preserve_iocs=True` leaves IOCs (URLs, IPs, hostnames, paths) in the state by
design, so those are what TypeSafe receives and may retain. See ADR 0008.

### 5. Evaluation & Regression Coupling

The A/B harness (`tests/eval/jev_ab_run_plan.md` method) becomes the standing
acceptance: same golden sets, same report generator, same Vertex judges.
`HistoricalRegressionTracker` records per-backend baselines; any backend swap
or threshold change must re-run the full suite and meet §5 gates from the
experimental plan (accuracy ≥98%, AUROC ≥0.95, ECE ≤0.10, escalation ≤25%).

## Constraints & Assumptions

* Paid per-token billing on the official TypeSafe AI API funds all Jev traffic.
  (The Gateway-era free tier was rate-capped to ~20-call bursts and unsuitable
  for 300 RPM interception; that observation is historical.)
* No changes to Tier-0, TSG schema/matching, aggregation weights, or the
  Vertex `EvalTask` CI gate (`tool_trajectory_avg_score: 1.0` dual-gate stays).
* Triage is off by default; with it off, GCP-only operation must keep passing
  unchanged (NFR-02). With it on, Jev is required and has no fallback.
* The official TypeSafe AI API is a plain HTTPS JSON endpoint
  (`POST /v1/systemone`); the backend uses a minimal vendored `httpx` caller —
  no vendor SDK dependency and no new non-Python runtime (Node.js sidecar
  prohibited).
* MCP Gateway implementation stands at Phase 4 (docs/E01); Phase 5
  packaging (F01–F05: LaunchAgent/systemd, menu bar, .dmg/.deb pipeline)
  and Phase 6 demo showcase are NOT yet built. This spec therefore
  introduces zero new system-level dependencies and claims no showcase
  coverage — the Jev backend must install and test with the current
  unpackaged Python tree, and a packaging-compat check is scheduled
  against F04 when it lands (see TASK-D03).
* BDD `tests/features/` scenarios + unit tests precede implementation (TDD).

## Glossary

* **Tier-1**: Calibrated fast classifier path (Jev `P(threat)`), clear-case signals feeding aggregation.
* **Tier-2**: Gemini deep-reasoning escalation for ambiguity/disagreement + forensics.
* **Escalation band**: `0.35 ≤ P ≤ 0.75` — Gemini decides.
* **Disagreement trigger**: deterministic high-risk novelty with `P < 0.2`.
* **SemanticTriageProvider**: Tier-1 interface in `policy/semantic.py`; Jev is the only implementation.
