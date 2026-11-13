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

> **Amendment (2026-11-13, ADR 0009):** Tier-1 is Jev only and fails fast;
> Tier-2 is `gemini-3.5-flash-lite` at a pinned medium thinking level; the
> single 300 RPM bucket is split into an 80 req/s front bucket and a Tier-2
> bucket. FR-01, FR-03, FR-06, FR-07, FR-08, NFR-02 and NFR-04 are amended
> accordingly. TASK-D04 (default flip to `jev`) is moot.
## Functional Requirements

### FR-01: Triage Interface (Jev Only)
The system SHALL expose `SemanticTriageProvider` in
`src/blackwall/policy/semantic.py`, implemented only by the `jev` backend.
There is no backend selection, no `BW_SEMANTIC_BACKEND`, and no `gemini`
Tier-1 backend. `SemanticTriageProvider.triage` SHALL return a
`SemanticTriageResult` or raise `JevUnavailableError`; it has no abstain value.
`_compute_threat_score` SHALL consume only `SemanticTriageResult.threat_score`,
with no weight changes.
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
`P < 0.2`). Tier-2 SHALL return the final ALLOW/BLOCK verdict. Tier-2 SHALL
use `gemini-3.5-flash-lite` with thinking pinned to `medium` in code; no
environment variable changes it (ADR 0009). When Tier-2 is triggered and
returns no verdict for any reason (an empty Tier-2 rate bucket, a deadline miss,
a malformed answer, a Vertex error or 429, or no Gemini client), an ALLOW from
Score Aggregation SHALL become QUARANTINE and a BLOCK SHALL stand. A Tier-2
abstention SHALL NOT fall through to an ALLOW (ADR 0009, Decision 6).

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

### FR-06: Paid Operation, a Single Bounded Retry, and Fail-Fast
Jev traffic SHALL run on paid per-token billing on the official TypeSafe AI
API. The backend SHALL retry a throttled response (`429`, or `529` Overloaded,
the two statuses TypeSafe documents as "retry after a short delay") exactly
once after a short fixed delay. When Jev cannot answer for any reason (no key,
any other non-200 status, a throttle that outlasts the retry, a transport
error, a non-JSON body, or a malformed or out-of-range probability) the backend
SHALL raise `JevUnavailableError`. There is no fallback backend and no
substitute score; the error propagates out of `SyncResolver.evaluate()` and the
tool call SHALL NOT be forwarded. The error message SHALL NOT contain the API
key or a response body. There is no client-side pacing and no retry-tuning
environment variable; the organization's rate limit is set by TypeSafe (see
ADR 0008, ADR 0009).

### FR-07: Observability
Each triage SHALL record `backend`, `P`, `confidence`, `latency_ms`, and token
usage for logs, budgets, and `HistoricalRegressionTracker` baselines.

> **Amended by ADR 0008:** a `noul` answer carries no separate confidence, so
> `confidence` is recorded as `None` for Jev. The API returns no per-call cost;
> spend is derived from the recorded token counts.
> **Amended by ADR 0009:** failures raise instead of being recorded; there is no
> `is_fallback` field.

### FR-08: Two Rate Limits
The front bucket SHALL be 80 req/s (Jev's organization limit) and guard every
evaluation, QUARANTINEing on exhaustion. A separate 300 RPM bucket SHALL guard
only the Tier-2 Vertex call. When that bucket is empty and Tier-2 is triggered,
FR-03 applies (QUARANTINE an ALLOW, let a BLOCK stand).

## Non-Functional Requirements

### NFR-01: Preserved Interception SLAs
Tier-0 `<5ms` and TSG `<10ms p99` behavior SHALL NOT regress (benchmark suite
`tests/eval/results/benchmark_report.json` stays green). Network latency
(p50 92 to 107 ms, p95 143 to 159 ms in two runs against the first-party API on
2026-11-12 from one client, sequentially and unloaded; ~0.9s p50 through the Vercel Gateway on
2026-09-19) is accepted for the semantic path; the `<100ms` Tier-1 aspiration
is explicitly deferred to a future local/in-VPC Jev deployment (the measured
p95 is above it, and latency under load has not been measured).

### NFR-02: No Regression on GCP-Only Path
With triage disabled (`BLACKWALL_ENABLE_SYNC_SEMANTIC_TRIAGE=false`, the
default), the full suite (unit, BDD, Vertex `EvalTask` dual-gate
`tool_trajectory_avg_score: 1.0`) SHALL pass unchanged.

### NFR-03: Test-Driven Development (TDD)
Every FR SHALL ship with a failing-first unit test (mocked TypeSafe API; no live
calls in unit tests). Live Jev calls are permitted ONLY in the eval harness
with explicit credentials.

### NFR-04: Behavior-Driven Development (BDD)
Acceptance SHALL include Gherkin scenarios in `tests/features/` covering:
clear ALLOW, clear BLOCK, ambiguity escalation, disagreement escalation, async
signature write, sanitization-before-egress, and 429/529 fail-fast behavior.

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
