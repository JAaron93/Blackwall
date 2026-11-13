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
* [x] **TASK-A02: Tier-1 provider wiring + `_compute_threat_score`**
  (FR-01). *Amended by ADR 0009: the env-gated `jev|gemini` selection was
  removed; Jev is the only backend.* `_compute_threat_score` consumes only
  `result.threat_score` (weights untouched).
  Dependencies: TASK-A01. Acceptance: suite green under both settings.
  > [!NOTE] Track A lands unit-layer coverage only (`tests/unit/test_policy_semantic_triage_provider.py`,
  > `tests/unit/test_sync_resolver_semantic_adapter.py`, renamed from
  > `..._backend_selection.py` by ADR 0009). The Gherkin
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
  not the pass criteria. Re-run with `--fresh` after TypeSafe ships a release
  behind `jev-latest` (the resume cache would otherwise replay the old rows),
  since the band is fixed and the model is not.
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
  > class-revealing text (a prefix test alone classifies all 157 correctly).
  > Re-scoring the same cases with the tells removed gives 84.1% accuracy and
  > 13% escalation for `jev-1.14.0` (98.8% and 2 to 3% with them), so the figures
  > above are a ceiling and the blinded ones a floor; the evasion-proof suite
  > (8 blocked, 1 to 2 missed) is the only tell-free evidence. Pinned reruns of
  > `jev-1.13.0` and `jev-1.14.0` (two each) show 1.14 is not an improvement on
  > this suite and escalate 3 of 167 (so read the 3.0% above as 2 to 3%). The
  > Tier-2 handoff was run live on Vertex, end to end with the real Jev backend:
  > with the semantic tiers alone, 0 of the 10 evasion-proof attacks and 0 of 56
  > clear-high malicious calls were blocked (by design: "a high P alone cannot
  > BLOCK"), and a Tier-2 abstention is an ALLOW at production thresholds. Results
  > are in ADR 0008, Verification and Open Items 8 to 10.
* [ ] **TASK-D03: Benchmark + dual-gate CI confirmation** (NFR-01, NFR-02).
  `benchmark_report.json` SLAs green; full suite green under
  triage disabled (GCP-only no-regression) and enabled with Jev.
  Vertex `EvalTask` dual-gate still enforced. Additionally verify the
  `jev` install closure adds no system/non-Python deps and log a
  packaging-compat note for Gateway F04 (re-verify when F04 lands).
  Dependencies: TASK-D02.
* [x] **TASK-D04: Default-flip + docs** (US-01, US-03). *Superseded by ADR
  0009: there is no `gemini` backend to flip away from.* Document paid-usage ops (budgets derived from token counts, the
  organization's rate limits, and the retention terms of a non-ZDR account),
  update `AGENTS.md` interception sequence
  (Rate → Hygiene → TSG → Jev Tier-1 → Gemini Tier-2 → forensics).
  Dependencies: TASK-D03.

## Track E — Jev-only, fail-fast and Flash-Lite Tier-2 (ADR 0009)
* [x] **TASK-E01: Model standardization** (FR-03). `gemini-3.8-flash` removed
  everywhere; Tier-2 on `gemini-3.5-flash-lite` with thinking pinned to `medium`
  (`TIER2_THINKING_LEVEL`), unaffected by `GEMINI_THINKING_LEVEL`.
  Tests: `tests/unit/test_tier2_escalation.py`, `test_gemini_model_optimization.py`.
* [x] **TASK-E02: Jev only, fail fast** (FR-01, FR-06). `GeminiTriageBackend`,
  the registry, `BW_SEMANTIC_BACKEND` and the fallback removed;
  `JevUnavailableError` on any failure; Tier-1 no longer needs a Gemini client.
  Tests: `tests/unit/test_jev_fail_fast.py`, `tests/features/jev_tier1_triage.feature`.
* [x] **TASK-E03: Two rate limits, and Tier-2 unavailable** (FR-03, FR-08).
  80 req/s front bucket; 300 RPM Tier-2 bucket; a Tier-2 that fired and
  returned no verdict (empty bucket, deadline, malformed answer, Vertex error or
  429, no client) QUARANTINEs an ALLOW and leaves a BLOCK alone.
  Tests: `tests/unit/test_sync_resolver_rate_limits.py`,
  `tests/unit/test_tier2_escalation.py`.
* [x] **TASK-E04: Live Tier-2 harness.** `scripts/jev_tier2_eval.py` (`forced`,
  `e2e`). Unit-tested, and both subcommands were run live on 2026-11-13
  (ADR 0009, Verification).
* [x] **TASK-E05: Same-change sync** of `AGENTS.md`, `.agents/rules/` and
  `.greptile/` (constitution 6.4). Approved by the maintainer 2026-11-13 and applied.
## Track F — Open work from ADR 0008 and ADR 0009
Each item below is open. Every one that changes behavior starts with a failing
test (repo TDD gate); every one that needs a live key or Vertex budget follows
testing rule 74 (never simulated, deferred in this file until it can run).
* [x] **TASK-F01: Run the Tier-2 harness live** (ADR 0009 OI5; NFR-05). Done
  2026-11-13: `forced` over the 93 inputs and `e2e` over the 167 cases, with and
  without `policy.yaml`; figures and the comparison with ADR 0008 are in ADR 0009
  Verification. Rerun after any Gemini or Jev model change.
  Dependencies: TASK-E04.
* [ ] **TASK-F02: Measure, then harden, Tier-2 against steering by tool-call
  text** (ADR 0009 OI3). The arbiter prompt interpolates tool name, arguments and
  metadata unseparated, and its ALLOW is final unless aggregation already blocks.
  Add adversarial cases whose arguments carry instructions aimed at the arbiter;
  measure how often a BLOCK flips to ALLOW; if any do, delimit the data (nonce
  XML, as the judge agents already do) test-first and re-measure.
  Dependencies: TASK-F01.
* [ ] **TASK-F03: Account for the shared Vertex quota** (ADR 0009 OI2). Signature
  synthesis, the judges and other Gemini calls share the project quota that
  Tier-2 depends on and are not counted by the Tier-2 bucket. Decide between one
  shared budget and a reservation for Tier-2, then implement it with tests.
  Needs a maintainer decision first (amend FR-08).
* [ ] **TASK-F04: Make Tier-2 outages visible** (ADR 0009 OI1). Count Tier-2
  "no verdict" outcomes by reason in `SyncResolverMetrics` (today only
  `tier2_rate_limit_hits` exists) so an operator can see the QUARANTINEs that
  Decision 6 causes.
* [ ] **TASK-F05: Class-blind golden evalset** (ADR 0008 OI10, ADR 0009 OI4).
  One template for both classes, no `attack_type`/`evasion_type`/`obfuscation`
  fields in the state, and malicious payloads that contain the attack text; then
  re-score both Jev releases and update the gate figures. Needs a live Jev key to
  re-score.
* [ ] **TASK-F06: Decide whether a clear-high Jev P alone may BLOCK** (ADR 0008
  OI8). Commit `176ad80` made it a kept invariant (rule 106). A clear-high score
  that cannot BLOCK is why Tier-2 availability matters so much. This is a
  maintainer decision; any change is a spec amendment with a same-change sync of
  `AGENTS.md`, `.agents/rules/` and `.greptile/`.
* [ ] **TASK-F07: Re-run TASK-D02 after each TypeSafe release** behind
  `jev-latest` (ADR 0008 OI1). The fixed 0.35/0.75 band does not follow the
  model. Recurring; needs a live Jev key.
## Execution Order

`A01 → (A02 + B01) → (B02 + B03 + C01) → C02 → D01 → D02 → D03 → D04 → E01 → E02 → E03 → E04 → E05`; Track F items are independent except where a
dependency is stated.
Tracks B/C overlap after A01; D is strictly sequential. Each task lands with
tests green; no batch commits without a test run (repo TDD gate).
