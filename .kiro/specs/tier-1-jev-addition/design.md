# Design Document: Tier-1 Jev Addition (Additive Semantic Triage)

## Overview

Blackwall Core's synchronous interception path (`SyncResolver`) currently performs
semantic triage exclusively via Gemini 3.5 Flash-Lite
(`src/blackwall/config.py:20` `DEFAULT_RAPID_TRIAGE_MODEL`,
`src/blackwall/sync_resolver.py:878` `_evaluate_semantic_intent`), whose float
`threat_score` feeds the weighted aggregation in `_compute_threat_score`
(`src/blackwall/sync_resolver.py:957`: Threat Intel 40% + CBM 30% + Context 30%).

This spec introduces **TypeSafe Jev** (`typesafe-ai/jev`, accessed via Vercel AI
Gateway) as an **additive Tier-1 decision classifier** that absorbs the boring
95%+ of clear-cut tool calls, while Gemini is retained for Tier-2 ambiguity
escalation and async forensic/signature synthesis. Jev is a probabilistic
evaluation model (typed boolean `P(threat)` + confidence, no text generation);
it cannot replace Gemini's generative duties. **Additive, not substitution.**

## Experimental Basis (A/B run, 2026-09-19, branch `exp/jev-ab-eval-plan`)

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
| Latency p50/p95 | — | **~0.9s / ~1.3s** via Gateway | aspirational <100ms | ⚠️ |

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

## Architecture Diagram

```text
Tool Call Intercepted
        │
Tier 0: Deterministic & AST Graph (<5ms)  [UNCHANGED]
        ├── Definite Match / Known Sig → Fast ALLOW or BLOCK
        └── Novel / Suspicious Payload
                    │
Tier 1: SemanticTriageProvider  [NEW ABSTRACTION]
        ├── backend=jev (paid Gateway): P(threat) [+ confidence]
        │     ├── P < 0.35 → ALLOW (immediate)
        │     ├── P > 0.75 → BLOCK + Incident Action
        │     └── 0.35 ≤ P ≤ 0.75 → Tier-2 escalation
        └── backend=gemini (legacy): threat_score float [PRESERVED, default-off]
                    │
Tier 2 Escalation: Gemini (3.8 Flash, high thinking)  [RETAINED]
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

### 1. `SemanticTriageProvider` Interface (new, `src/blackwall/policy/semantic.py`)

Pluggable seam over the current inline Gemini call. Backends: `jev`
(primary) and `gemini` (legacy fallback). Env-gated selection
(`BW_SEMANTIC_BACKEND=jev|gemini`, default `jev` once validated; `gemini`
preserved for regression and air-gapped/GCP-only operation). Returns a
`SemanticTriageResult { threat_score: float, confidence: float|None,
backend: str, escalate: bool }` so `_compute_threat_score` stays untouched.

### 2. Jev Backend (`JevTriageBackend`)

Single-question boolean evaluation per intercepted call:
`state` = sanitized `Tool / Arguments / Metadata` (sanitized **first**),
`questions = { is_threat: boolean }`, `threat_score = P(true)`. Fixed
thresholds `0.35 / 0.75` (recalibration requires a spec amendment with fresh
labeled data — no silent tuning). Records `confidence`, `latency_ms`, token
usage per call for the regression tracker. Sequential issuance with bounded
`429` backoff; never parallel-burst the Gateway.

### 3. Tier-2 Escalation Policy (retained, narrowed)

Gemini fires only on: (a) ambiguity band, (b) deterministic-vs-semantic
disagreement (high-risk argument novelty vs `P < 0.2`), (c) async forensics.
Expected Tier-2 rate: ~0% on routine suites, ~30% on hard evasion probes
(measured). This is the cost control: Gemini (especially 3.8 Flash
deep-reasoning) spends only where judgment exists.

### 4. Privacy & Data Handling

`ContextHygiene.sanitize_*` runs **before** any Gateway payload is built —
Gateway sees only `[[PLACEHOLDER]]`-redacted synthetic/operational tool
descriptions, never raw env vars, ADC credentials, or secrets.
`disallowPromptTraining: true` is mandatory on **every** Jev call (available
on all tiers). Full `zeroDataRetention` remains Pro/Enterprise-only; until
available, no-training + sanitization is the documented protection, and
production rollout should prefer Pro with per-request ZDR enabled.

### 5. Evaluation & Regression Coupling

The A/B harness (`tests/eval/jev_ab_run_plan.md` method) becomes the standing
acceptance: same golden sets, same report generator, same Vertex judges.
`HistoricalRegressionTracker` records per-backend baselines; any backend swap
or threshold change must re-run the full suite and meet §5 gates from the
experimental plan (accuracy ≥98%, AUROC ≥0.95, ECE ≤0.10, escalation ≤25%).

## Constraints & Assumptions

* Paid Vercel AI Gateway Credits fund all Jev traffic (free tier is
  rate-capped to ~20-call bursts; unsuitable for 300 RPM interception).
* No changes to Tier-0, TSG schema/matching, aggregation weights, or the
  Vertex `EvalTask` CI gate (`tool_trajectory_avg_score: 1.0` dual-gate stays).
* `gemini` backend remains shipped and tested — Jev is additive; GCP-only
  operation must keep passing with `BW_SEMANTIC_BACKEND=gemini`.
* AI SDK 7+ is the only Gateway path for evaluation models (no
  OpenAI-compatible endpoint); the backend uses a pure-Python client
  (Python AI SDK beta or a minimal vendored HTTPS caller) — no new
  non-Python runtime (Node.js sidecar prohibited).
* MCP Gateway implementation stands at Phase 4 (docs/E01); Phase 5
  packaging (F01–F05: LaunchAgent/systemd, menu bar, .dmg/.deb pipeline)
  and Phase 6 demo showcase are NOT yet built. This spec therefore
  introduces zero new system-level dependencies and claims no showcase
  coverage — the Jev backend must install and test with the current
  unpackaged Python tree, and a packaging-compat check is scheduled
  against F04 when it lands (see TASK-D03).
* BDD `tests/features/` scenarios + unit tests precede implementation (TDD).

## Glossary

* **Tier-1**: Calibrated fast classifier path (Jev `P(threat)`), clear-case verdicts.
* **Tier-2**: Gemini deep-reasoning escalation for ambiguity/disagreement + forensics.
* **Escalation band**: `0.35 ≤ P ≤ 0.75` — Jev abstains, Gemini decides.
* **Disagreement trigger**: deterministic high-risk novelty with `P < 0.2`.
* **SemanticTriageProvider**: New pluggable `jev|gemini` interface in `policy/semantic.py`.
