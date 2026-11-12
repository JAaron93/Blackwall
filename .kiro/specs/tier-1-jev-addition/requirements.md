# Requirements Document: Tier-1 Jev Addition

## Introduction

Derived from `design.md` (Tier-1 Jev Addition, additive semantic triage). This
spec wires TypeSafe Jev — validated by the 2026-09-19 A/B run (157/157 at
100%, AUROC 1.0, ECE 0.028, 0% escalation on the main suite) — into Blackwall
Core as the primary Tier-1 classifier, with Gemini retained for Tier-2
escalation and async forensics. Paid per-token billing on the official
TypeSafe AI API funds Jev traffic.

> **Amendment (2026-11-12, ADR 0008):** the transport moved from the Vercel AI
> Gateway to the official TypeSafe AI API. FR-02, FR-05, FR-06, FR-07, NFR-01,
> NFR-03 and US-03 below are amended accordingly. The 2026-09-19 A/B figures
> quoted in this document were measured through the Gateway.

## Glossary

* **P(threat)**: Jev `noul` (yes/no) probability for `is_threat`.
* **Escalation band**: `0.35 ≤ P ≤ 0.75`.
* **SemanticTriageResult**: `{ threat_score, confidence, backend, escalate }`.
* **A/B gates**: accuracy ≥98%, recall ≥0.98, AUROC ≥0.95, ECE ≤0.10,
  escalation ≤25%, FRR <5%, evasion <10%.

## Functional Requirements

### FR-01: Pluggable Triage Interface
The system SHALL expose `SemanticTriageProvider` in
`src/blackwall/policy/semantic.py` with `jev` and `gemini` backends,
selectable via `BW_SEMANTIC_BACKEND` (`jev` default post-validation, `gemini`
preserved). `_compute_threat_score` SHALL consume only
`SemanticTriageResult.threat_score`, with no weight changes.

### FR-02: Jev Tier-1 Evaluation (Signals, Not Verdicts)
The `jev` backend SHALL issue one `noul` `is_threat` evaluation per novel
tool call with fixed thresholds: `P < 0.35` → clear-low signal,
`P > 0.75` → clear-high signal, otherwise `escalate=true`. These are
weighted triage SIGNALS feeding Score Aggregation (`_compute_threat_score`,
weights and verdict thresholds unchanged) — NEVER terminal verdicts.
Terminal ALLOW/BLOCK/QUARANTINE SHALL be decided exclusively at Score
Aggregation + Threshold Verdict, preserving deterministic overrides.
Threshold changes SHALL require a spec amendment with fresh labeled evidence.

### FR-03: Tier-2 Escalation Routing
The system SHALL route to Gemini Tier-2 on (a) `escalate=true`, or
(b) deterministic-vs-semantic disagreement (high-risk argument novelty with
`P < 0.2`). Tier-2 SHALL return the final ALLOW/BLOCK verdict.

### FR-04: Async Forensics Preservation (Novel Blocks Only)
Every novel BLOCK — i.e. a block with NO existing TSG signature match,
whether from Tier-1 or Tier-2 — SHALL trigger async Gemini generation of
`ThreatSignaturePayload` appended to the SQLite TSG without stalling the
agent. Blocks served by an existing signature match return immediately
(`SyncResolver.evaluate` TSG fast path) and SHALL NOT invoke generation —
the signature already exists, and regenerating per repeat would add
Gemini cost and graph churn. Jev SHALL NOT be used for signature synthesis.

### FR-05: Sanitization-Before-Egress
`ContextHygiene` sanitization SHALL execute before any TypeSafe API payload
is built. Raw `context.arguments` / `metadata` / env vars / ADC credentials
SHALL NEVER leave the host. Every Jev request body SHALL contain exactly
`model`, `state` and `questions` and nothing else.

> **Amended by ADR 0008:** this clause formerly required
> `disallowPromptTraining: true` on every call. That was a Vercel AI Gateway
> request option with no equivalent on the first-party API. The remaining
> no-training assurance is TypeSafe's published data-handling commitment, which
> is a vendor assurance and not something a request can assert or a test can
> verify (see ADR 0008, Open Items).

### FR-06: Paid Operation with Bounded Retries
Jev traffic SHALL run on paid per-token billing on the official TypeSafe AI
API. The backend SHALL retry `429` and `529` (Overloaded), the two statuses
TypeSafe documents as retry-with-backoff, with exponential backoff (bounded
attempts, then fail-closed to the `gemini` backend or Tier-2 — never fail-open
to ALLOW). Every other non-200 outcome SHALL fail closed without retry.
Free-tier or trial behavior, if any, SHALL be documented as eval-only.

### FR-07: Observability
Each triage SHALL record `backend`, `P`, `confidence`, `latency_ms`, and token
usage for logs, budgets, and `HistoricalRegressionTracker` baselines.

> **Amended by ADR 0008:** a `noul` answer carries no separate confidence, so
> `confidence` is recorded as `None` for Jev. The API returns no per-call cost;
> spend is derived from the recorded token counts.

## Non-Functional Requirements

### NFR-01: Preserved Interception SLAs
Tier-0 `<5ms` and TSG `<10ms p99` behavior SHALL NOT regress (benchmark suite
`tests/eval/results/benchmark_report.json` stays green). Network latency
(~0.9s p50 measured through the Vercel Gateway on 2026-09-19; not yet
re-measured against the first-party API) is accepted for the semantic path; the
`<100ms` Tier-1 aspiration is explicitly deferred to a future local/in-VPC
Jev deployment.

### NFR-02: No Regression on GCP-Only Path
With `BW_SEMANTIC_BACKEND=gemini`, the full suite (unit, BDD, Vertex
`EvalTask` dual-gate `tool_trajectory_avg_score: 1.0`) SHALL pass unchanged.

### NFR-03: Test-Driven Development (TDD)
Every FR SHALL ship with a failing-first unit test (mocked TypeSafe API; no live
calls in unit tests). Live Jev calls are permitted ONLY in the eval harness
with explicit credentials.

### NFR-04: Behavior-Driven Development (BDD)
Acceptance SHALL include Gherkin scenarios in `tests/features/` covering:
clear ALLOW, clear BLOCK, ambiguity escalation, disagreement escalation, async
signature write, sanitization-before-egress, and 429 fail-closed behavior.

### NFR-05: Calibration Stability
Post-merge, the golden A/B (157 + 10) SHALL be re-run against any backend or
threshold change and meet the A/B gates; results SHALL be recorded alongside
the 2026-09-19 baseline (100% / AUROC 1.0 / ECE 0.028).

### NFR-06: Packaging Compatibility (Gateway Phases 5–6 Pending)
The MCP Gateway is implemented only through Phase 4; Phase 5 packaging
(.dmg/.deb pipeline, services, menu bar) and Phase 6 demo showcase are
future work. This spec SHALL introduce no new system-level or non-Python
runtime dependencies (protecting the Python-exclusivity invariant the F04
packaging pipeline will assume), SHALL NOT depend on showcase
infrastructure, and SHALL schedule a compat re-verification against F04
when it lands.

## User Stories

### US-01: Cheap Clear-Case Triage
As Blackwall Core, I want Jev to verdict obvious tool calls for fractions of
a cent, so Gemini spend is reserved for ambiguous threats.
Acceptance: Tier-2 fire rate ~0% on routine suites (measured 0/157).

### US-02: Safe Ambiguity Handling
As a security operator, I want uncertain calls (`0.35–0.75`, C2-beacon-like
evasions measured at 0.51–0.70) escalated to Gemini reasoning, so nothing
borderline is decided by threshold alone.

### US-03: Egress Safety
As a platform owner, I want secrets redacted before any TypeSafe API call and
the request body limited to an allowlist, so paid Jev operation never
exfiltrates credentials.
