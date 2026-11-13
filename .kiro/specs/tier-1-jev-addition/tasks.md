# Implementation Plan: Tier-1 Jev Addition

Traceability: tasks map to FR/NFR/US IDs in `requirements.md`. TDD-first
throughout: failing test → minimum code → green suite. No live TypeSafe API
calls in unit/BDD tests (mocked); live calls only in the eval harness.

> **Amendment (2026-11-12, ADR 0008):** Track B/C/D tasks marked `[x]` below
> were completed against the Vercel AI Gateway contract and are kept as the
> historical record. The transport has since moved to the official TypeSafe AI
> API; each affected task carries an "Amended by ADR 0008" note, and the
> deferred live-acceptance tasks (D02, D03) now target the new transport.

## Track A — Provider Seam (foundation; all else depends on this)

> [!TIP] PARALLEL EXECUTION — TASK-A01 and TASK-A02 may run concurrently once
> the `SemanticTriageResult` schema is agreed.

* [x] **TASK-A01: `SemanticTriageResult` schema + provider interface**
  (FR-01; NFR-03). Define the dataclass and `SemanticTriageProvider` ABC in
  `src/blackwall/policy/semantic.py`; port the existing Gemini inline logic
  behind `GeminiTriageBackend` with byte-identical behavior.
  Dependencies: none. Acceptance: existing
  `tests/unit/test_sync_resolver_semantic_triage.py` passes unmodified
  against the `gemini` backend.
* [x] **TASK-A02: `BW_SEMANTIC_BACKEND` selection + `_compute_threat_score` wiring**
  (FR-01). Env-gated backend choice (`jev|gemini`), default `gemini` until
  Track D signs off; `_compute_threat_score` consumes only
  `result.threat_score` (weights untouched).
  Dependencies: TASK-A01. Acceptance: suite green under both settings.
  > [!NOTE] Track A lands unit-layer coverage only (`tests/unit/test_policy_semantic_triage_provider.py`,
  > `tests/unit/test_sync_resolver_semantic_backend_selection.py`). The Gherkin
  > acceptance scenarios for this seam are owned by TASK-D01 (NFR-04).

## Track B — Jev Backend (depends on Track A)

* [x] **TASK-B01: `JevTriageBackend` evaluation call** (FR-02, FR-05).
  Sanitized `state` build → single boolean `is_threat` via a pure-Python
  Gateway evaluation client (Python AI SDK beta or minimal vendored HTTPS
  caller — Node.js sidecar prohibited per NFR-06),
  `disallowPromptTraining: true` mandatory, fixed
  `0.35/0.75` mapping to `escalate`. *(As completed on 2026-09; see the
  ADR 0008 note below.)* TDD with mocked SDK responses
  (P=0.02 allow, P=0.98 block, P=0.60 escalate).
  Dependencies: TASK-A01. Acceptance: threshold unit tests + SVM-style
  boundary tests at 0.349/0.35/0.75/0.751; `pip install` closure gains no
  non-Python runtime deps.
  > **Amended by ADR 0008:** now a single `noul` `is_threat` question via
  > `POST /v1/systemone` on the official TypeSafe AI API (minimal vendored
  > `httpx` caller, still no SDK or Node sidecar). The mandatory
  > `disallowPromptTraining` flag is replaced by a `model`/`state`/`questions`
  > request-body allowlist. The 0.35/0.75 mapping is unchanged.
* [x] **TASK-B02: Bounded 429 backoff + fail-closed** (FR-06).
  Exponential backoff (bounded attempts), then fail-closed to `gemini`
  backend/Tier-2 — never ALLOW. Mock `429` storms in tests.
  Dependencies: TASK-B01.
  > **Amended by ADR 0008:** now a single retry (not a backoff loop) on `429`
  > and `529` (Overloaded), the two statuses TypeSafe documents; storms of both
  > are tested, and the old tuning knobs (`JEV_MAX_ATTEMPTS`, backoff
  > parameters) are gone.
  > [!TIP] PARALLEL EXECUTION — TASK-B03 may run alongside TASK-B02.
* [x] **TASK-B03: Observability fields** (FR-07). Record `backend`, `P`,
  `confidence`, `latency_ms`, token usage per triage into existing telemetry.
  Dependencies: TASK-B01.
  > **Amended by ADR 0008:** `confidence` is `None` (a `noul` answer carries
  > none) and the per-call `gateway_cost` field is gone; token counts remain.

## Track C — Escalation & Forensics (depends on Track A; integrates Track B)

* [x] **TASK-C01: Tier-2 routing rules** (FR-03). Ambiguity-band and
  disagreement (`P < 0.2` + high-risk novelty) escalation to Gemini high
  thinking; final verdict contract.
  Dependencies: TASK-A02, TASK-B01. Acceptance: BDD scenarios —
  ```gherkin
  Scenario: Ambiguous C2 beacon escalates
    Given Jev returns P=0.51 for a suspected C2 beacon call
    When the resolver aggregates the verdict
    Then Tier-2 Gemini is invoked and the final verdict is recorded
  ```
  plus aggregation-supremacy regression tests: a clear-low Jev signal
  (P=0.05) combined with a structural BLOCK still verdicts BLOCK, and a
  clear-high Jev signal (P=0.95) with all other signals benign still
  passes through Score Aggregation (no direct-to-verdict short-circuit).
* [x] **TASK-C02: Async signature path untouched** (FR-04). Regression tests
  proving every novel (non-signature-matched) BLOCK still yields
  `ThreatSignaturePayload` → TSG append off the hot path, and that
  TSG-matched BLOCKs return immediately with zero generation calls.
  Dependencies: TASK-C01.

## Track D — Validation & Rollout (depends on Tracks B + C)

> [!NOTE] DEFERRAL (2026-09-25, updated 2026-11-12): a paid `TYPESAFE_API_KEY`
> now exists and TASK-D02 was run live on 2026-11-12 (done, below). TASK-D03
> stays deferred until the GCP dual-gate (Vertex `EvalTask`) can run on paid
> Vertex budget. TASK-D04 remains gated on D03.
> TASK-D01 is complete on `feature/tier1-jev-escalation`.

* [x] **TASK-D01: BDD acceptance suite** (NFR-04). `tests/features/`
  scenarios: clear ALLOW (P≈0.02), clear BLOCK (P≈0.98), ambiguity
  escalation (P≈0.60), disagreement escalation, async signature write,
  sanitization-before-egress (assert `[[PLACEHOLDER]]` in outbound state,
  no raw secrets), 429 fail-closed. All mocked.
  Dependencies: TASK-B02, TASK-C01.
  > **Amended by ADR 0008:** the "disallows prompt training" assertion became
  > "targets the System One endpoint" and "carries only the allowlisted
  > fields", and a 529 fail-closed scenario was added.
* [x] **TASK-D02: Golden A/B re-run on the TypeSafe API + gate check** (NFR-05,
  US-01, US-02). Live paid run of `scripts/jev_triage_eval.py` over the 157 + 10
  golden cases against `jev-latest` (deliberately unpinned, ADR 0008); it
  regenerates `tests/eval/results/jev_triage_results.json`. The Gateway-era
  artifact it replaced came from the Gateway's rate-limited free tier on the
  previous Jev release and is not valid evidence for this transport. Must meet
  the A/B gates (accuracy ≥98%, AUROC ≥0.95, ECE ≤0.10, escalation ≤25%).
  Record the results, the served release (`model` field) and the Tier-2 fire
  rate. The 2026-09-19 figures (100% / 1.0 / 0.028 / 0%) are historical context,
  not the pass criteria. Re-run after TypeSafe ships a release behind
  `jev-latest`, since the band is fixed and the model is not.
  Dependencies: TASK-C02, TASK-D01. Requires `TYPESAFE_API_KEY` (paid). Never
  simulated (testing rules, Live Paid-Credential Acceptance Gates).
  > **Done 2026-11-12** (commit `426166d`; 167 live calls, 0 errors, every row
  > served by `jev-1.14.0`): accuracy 99.4% (TP 93, FN 1, FP 0, TN 68), AUROC
  > 1.000, ECE 0.059, escalation 3.0% (5/167), so all four gates pass. Security
  > suite: every decided case correct, 30/30 evasion blocked, 0 false alarms
  > (benign P ≤ 0.17). Evasion-proof suite: 8 blocked, 1 escalated, 1 missed
  > (`wave1_c2_beacon_001`, P 0.19, below the band). Tier-2 fire rate: 3.0%
  > overall (2.5% security, 10% evasion-proof). p50 92 ms, p95 143 ms. A second
  > full run passes too but with one case of margin on accuracy (98.8%: another
  > C2 beacon fell just under the band), because same-model reruns differ by up
  > to 0.03 per case and band-edge cases change zone between runs. Details:
  > ADR 0008, Verification.
  >
  > **Caveats added the same day.** The security suite's states carry
  > class-revealing text (a prefix test alone classifies all 157 correctly), so
  > the accuracy and AUROC above can overstate Jev on real tool calls; the
  > evasion-proof suite (8 blocked, 1 escalated, 1 missed) is the realistic
  > signal. The Tier-2 handoff was then run live on Vertex with Tier-1 replayed
  > from these recorded values. Results, and the findings that a clear-high P
  > alone does not block and that a Tier-2 abstention is an ALLOW at production
  > thresholds, are in ADR 0008, Verification and Open Items 8 to 10.
* [ ] **TASK-D03: Benchmark + dual-gate CI confirmation** (NFR-01, NFR-02).
  `benchmark_report.json` SLAs green; full suite green under
  `BW_SEMANTIC_BACKEND=gemini` (GCP-only no-regression) and `jev`.
  Vertex `EvalTask` dual-gate still enforced. Additionally verify the
  `jev` install closure adds no system/non-Python deps and log a
  packaging-compat note for Gateway F04 (re-verify when F04 lands).
  Dependencies: TASK-D02.
* [ ] **TASK-D04: Default-flip + docs** (US-01, US-03). Flip default to
  `jev`, document paid-usage ops (budgets derived from token counts, the
  organization's rate limits, and the retention terms of a non-ZDR account),
  update `AGENTS.md` interception sequence
  (Rate → Hygiene → TSG → Jev Tier-1 → Gemini Tier-2 → forensics).
  Dependencies: TASK-D03.

## Execution Order

`A01 → (A02 + B01) → (B02 + B03 + C01) → C02 → D01 → D02 → D03 → D04`.
Tracks B/C overlap after A01; D is strictly sequential. Each task lands with
tests green; no batch commits without a test run (repo TDD gate).
