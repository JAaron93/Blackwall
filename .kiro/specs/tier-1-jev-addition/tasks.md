# Implementation Plan: Tier-1 Jev Addition

Traceability: tasks map to FR/NFR/US IDs in `requirements.md`. TDD-first
throughout: failing test → minimum code → green suite. No live Gateway calls
in unit/BDD tests (mocked); live calls only in the eval harness.

## Track A — Provider Seam (foundation; all else depends on this)

> [!TIP] PARALLEL EXECUTION — TASK-A01 and TASK-A02 may run concurrently once
> the `SemanticTriageResult` schema is agreed.

* [ ] **TASK-A01: `SemanticTriageResult` schema + provider interface**
  (FR-01; NFR-03). Define the dataclass and `SemanticTriageProvider` ABC in
  `src/blackwall/policy/semantic.py`; port the existing Gemini inline logic
  behind `GeminiTriageBackend` with byte-identical behavior.
  Dependencies: none. Acceptance: existing
  `tests/unit/test_sync_resolver_semantic_triage.py` passes unmodified
  against the `gemini` backend.
* [ ] **TASK-A02: `BW_SEMANTIC_BACKEND` selection + `_compute_threat_score` wiring**
  (FR-01). Env-gated backend choice (`jev|gemini`), default `gemini` until
  Track D signs off; `_compute_threat_score` consumes only
  `result.threat_score` (weights untouched).
  Dependencies: TASK-A01. Acceptance: suite green under both settings.

## Track B — Jev Backend (depends on Track A)

* [ ] **TASK-B01: `JevTriageBackend` evaluation call** (FR-02, FR-05).
  Sanitized `state` build → single boolean `is_threat` via a pure-Python
  Gateway evaluation client (Python AI SDK beta or minimal vendored HTTPS
  caller — Node.js sidecar prohibited per NFR-06),
  `disallowPromptTraining: true` mandatory, fixed
  `0.35/0.75` mapping to `escalate`. TDD with mocked SDK responses
  (P=0.02 allow, P=0.98 block, P=0.60 escalate).
  Dependencies: TASK-A01. Acceptance: threshold unit tests + SVM-style
  boundary tests at 0.349/0.35/0.75/0.751; `pip install` closure gains no
  non-Python runtime deps.
* [ ] **TASK-B02: Bounded 429 backoff + fail-closed** (FR-06).
  Exponential backoff (bounded attempts), then fail-closed to `gemini`
  backend/Tier-2 — never ALLOW. Mock `429` storms in tests.
  Dependencies: TASK-B01.
  > [!TIP] PARALLEL EXECUTION — TASK-B03 may run alongside TASK-B02.
* [ ] **TASK-B03: Observability fields** (FR-07). Record `backend`, `P`,
  `confidence`, `latency_ms`, token usage per triage into existing telemetry.
  Dependencies: TASK-B01.

## Track C — Escalation & Forensics (depends on Track A; integrates Track B)

* [ ] **TASK-C01: Tier-2 routing rules** (FR-03). Ambiguity-band and
  disagreement (`P < 0.2` + high-risk novelty) escalation to Gemini high
  thinking; final verdict contract.
  Dependencies: TASK-A02, TASK-B01. Acceptance: BDD scenarios —
  ```gherkin
  Scenario: Ambiguous C2 beacon escalates
    Given Jev returns P=0.51 for a suspected C2 beacon call
    When the resolver aggregates the verdict
    Then Tier-2 Gemini is invoked and the final verdict is recorded
  ```
* [ ] **TASK-C02: Async signature path untouched** (FR-04). Regression tests
  proving every novel (non-signature-matched) BLOCK still yields
  `ThreatSignaturePayload` → TSG append off the hot path, and that
  TSG-matched BLOCKs return immediately with zero generation calls.
  Dependencies: TASK-C01.

## Track D — Validation & Rollout (depends on Tracks B + C)

* [ ] **TASK-D01: BDD acceptance suite** (NFR-04). `tests/features/`
  scenarios: clear ALLOW (P≈0.02), clear BLOCK (P≈0.98), ambiguity
  escalation (P≈0.60), disagreement escalation, async signature write,
  sanitization-before-egress (assert `[[PLACEHOLDER]]` in outbound state,
  no raw secrets), 429 fail-closed. All mocked.
  Dependencies: TASK-B02, TASK-C01.
* [ ] **TASK-D02: Golden A/B re-run + gate check** (NFR-05, US-01, US-02).
  Live paid-credit run over 157 + 10 golden cases; must meet A/B gates
  (accuracy ≥98%, AUROC ≥0.95, ECE ≤0.10, escalation ≤25%) vs the
  2026-09-19 baseline (100% / 1.0 / 0.028 / 0%). Record results + Tier-2
  fire rate.
  Dependencies: TASK-C02, TASK-D01. Requires `AI_GATEWAY_API_KEY` (paid).
* [ ] **TASK-D03: Benchmark + dual-gate CI confirmation** (NFR-01, NFR-02).
  `benchmark_report.json` SLAs green; full suite green under
  `BW_SEMANTIC_BACKEND=gemini` (GCP-only no-regression) and `jev`.
  Vertex `EvalTask` dual-gate still enforced. Additionally verify the
  `jev` install closure adds no system/non-Python deps and log a
  packaging-compat note for Gateway F04 (re-verify when F04 lands).
  Dependencies: TASK-D02.
* [ ] **TASK-D04: Default-flip + docs** (US-01, US-03). Flip default to
  `jev`, document paid-credit ops (budgets, free-tier eval-only note,
  per-request ZDR when on Pro), update `AGENTS.md` interception sequence
  (Rate → Hygiene → TSG → Jev Tier-1 → Gemini Tier-2 → forensics).
  Dependencies: TASK-D03.

## Execution Order

`A01 → (A02 + B01) → (B02 + B03 + C01) → C02 → D01 → D02 → D03 → D04`.
Tracks B/C overlap after A01; D is strictly sequential. Each task lands with
tests green; no batch commits without a test run (repo TDD gate).
