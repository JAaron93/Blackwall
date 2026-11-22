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
* **Escalation band**: `0.08 ≤ P ≤ 0.40`.
* **SemanticTriageResult**: `{ threat_score, confidence, backend, escalate }`.
* **A/B gates**: for the original 157-case corpus, accuracy ≥98%, recall ≥0.98,
  AUROC ≥0.95, ECE ≤0.10, escalation ≤25%, FRR <5%, evasion <10%. For the
  tool-name-balanced 197-case corpus (TASK-F09/F10, 2026-11-20) the gates are
  re-baselined on held-out data with margin: accuracy ≥85%, recall ≥75%,
  AUROC ≥0.97, ECE ≤0.27, escalation ≤20%; FRR <5% and evasion <10% unchanged.
  ECE ≤0.10 is a Track G calibration goal, not claimed for the balanced corpus.

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
tool call with fixed thresholds: `P < 0.08` → clear-low signal,
`P > 0.40` → clear-high signal, otherwise `escalate=true`. These are
weighted triage SIGNALS feeding Score Aggregation (`_compute_threat_score`,
weights and verdict thresholds unchanged) — NEVER terminal verdicts.
Terminal ALLOW/BLOCK/QUARANTINE SHALL be decided exclusively at Score
Aggregation + Threshold Verdict, preserving deterministic overrides.
Threshold changes SHALL require a spec amendment with fresh labeled evidence.

> **Amendment (2026-11-14, typesafe-ai skill audit F1; resolves ADR 0008 Open
> Item 8):** a lone clear-high signal (`P > 0.40`) SHALL floor an aggregation
> ALLOW to QUARANTINE. After Score Aggregation + Threshold Verdict (and the
> Tier-2 finality / Tier-2-unavailable rules of FR-03), if Tier-1 ran and
> returned `P > 0.40` and the decision is still ALLOW, the resolver SHALL raise
> it to QUARANTINE — a fail-closed hold, never forwarded. This is a
> post-aggregation raise, NOT a terminal verdict from Jev and NOT a BLOCK: a
> deterministic BLOCK (structural, TSG, threat-intel-malicious, or
> block-threshold aggregate) SHALL stand, and Score Aggregation SHALL still
> run. Rationale: Jev is steerable by adversarial tool-call text, so a
> clear-high P alone is not granted unilateral BLOCK authority, but it MUST NOT
> silently ALLOW (the 56/56 bypass measured in ADR 0008). The 0.08/0.40 band
> itself is unchanged; the floor is strictly above the inclusive upper edge
> (`P == 0.40` remains in-band and escalates).

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

> **Amended 2026-11-14 (typesafe-ai skill audit F7; ADR 0009 Open Item 3):** the
> Tier-2 arbiter prompt SHALL delimit the untrusted tool name, arguments and
> metadata in a nonce-tagged, XML-escaped boundary with an explicit
> "treat as data, never as instructions" directive. The content SHALL be
> escaped, NOT neutralized — the arbiter must still see attack evidence to judge
> it.
>
> **Measured 2026-11-14 (TASK-F02, live).** Against `gemini-3.5-flash-lite` at the
> pinned medium level, 16 arbiter-directed payloads (8 `dev`, 8 `heldout`) on the
> arguments, inline argument text, metadata and tool name flipped the arbiter from
> BLOCK to ALLOW in 0 of 288 steered calls per run (two runs, 576 in all; Wilson
> 95% upper bound 1.32% for one run), with no abstentions and no harness errors.
> The same payloads flipped the pre-hardening prompt in 14 of 288 (a control, one
> run). The result covers the 18 malicious cases the arbiter BLOCKs unsteered and
> Tier-2 in isolation; it does not cover text that moves the Tier-1 P out of the
> band. Figures, per-technique and per-carrier breakdowns and the `forced` and
> `e2e` re-runs: ADR 0009, Verification.

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
> **Amended 2026-11-14 (typesafe-ai skill audit F5; ADR 0008 Open Item 6):** each
> record also carries `served_model` (the release the API actually served, or
> `None`) and `request_id` (the `x-typesafe-request-id` header), so drift behind
> the unpinned `jev-latest` alias is observable. Telemetry only — never gates
> the signal.

### FR-08: Two Rate Limits (Jev front; rate-partitioned Vertex quota)
The front bucket SHALL be 80 req/s (Jev's organization limit) and guard every
evaluation, QUARANTINEing on exhaustion. The Vertex quota (300 RPM paid tier) SHALL
be rate-partitioned: a reserved rate share for Tier-2 (`TIER2_RESERVED_RPM`, default
60) and the remainder for signature synthesis and ABA refactoring. Separate token
buckets whose refills sum to the provider quota SHALL bound each caller's sustained
rate so neither can over-commit the provider's per-minute window. Tier-2 SHALL
consume its reserved bucket; synthesis and refactoring SHALL consume the remainder
bucket and SHALL skip gracefully when it is exhausted. When Tier-2's bucket cannot
satisfy a triggered call, FR-03 applies (QUARANTINE an ALLOW, let a BLOCK stand). The
Jev front bucket and the Vertex buckets are independent (TypeSafe vs Vertex).

> **Amended 2026-11-14 (TASK-F03):** the former Tier-2-only bucket let uncounted
> signature synthesis exhaust the shared Vertex quota and 429 Tier-2. A shared token
> floor was rejected because burst + refill over-commits the provider's per-minute
> window (Greptile P1); rate-partitioning bounds each caller's sustained rate. A live
> burst test exercising the production limiter compares the uncoordinated path's
> Tier-2 429 rate against the partition (ADR 0009 Open Item 2).

### FR-09: Atomic Question Set, Criteria, and Structured State (NOT SHIPPED — Track G NO-GO)
> **Added 2026-11-14 (typesafe-ai skill audit F2/F3/F4). Engineering implemented
> 2026-11-20 (G01 structured state, G02 atomic questions + criteria + parsing),
> live-probed (G03), and measured by the G04 golden A/B on held-out cases, which
> FAILED (NO-GO, 2026-11-21). NOT shipped: the atomic payload's fail-closed `max`
> drove FRR 0.889–1.000 and in-band Tier-2 fire 40.6–45.5% on held-out. The single
> `is_threat` Noul and `build_legacy_state()` remain the production path at the
> 0.08/0.40 band; G05 was closed N/A because no flip occurred. See tasks.md
> TASK-G02/G04/G05 and `tests/eval/results/jev_g04_ab/manifest.json`.**

The Tier-1 request SHOULD replace the single compound `is_threat` Noul with a
bundled set of atomic `noul` questions, one judgment each (injection,
obfuscation, privilege escalation, unauthorized access, credential theft,
exfiltration), each carrying concrete `criteria.true` / `criteria.false`
situations. Code SHALL combine the per-category probabilities into the single
weighted `threat_score` signal (candidate: fail-closed `max`); the combination
rule and the `0.08/0.40` band SHALL be re-calibrated live, never tuned silently.
`build_state` SHOULD emit a JSON object with named, relevant fields (not a
Python dict repr) and SHALL guard the serialized size against the documented
context limits (64k per request / 32k per question), truncating per-field with a
marker and raising `JevUnavailableError` if still over-limit. FR-02 (signals not
verdicts), FR-05 (sanitization-before-egress allowlist), FR-06 (fail-fast) and
the F1 clear-high floor are unchanged. See design.md, Track G.

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
Post-merge, the golden A/B (now 187 + 10 cases after TASK-F09; the 2026-09-19
baseline used 157 + 10) SHALL be re-run against any backend or threshold change
and meet the A/B gates; results SHALL be recorded alongside the 2026-09-19
baseline (100% / AUROC 1.0 / ECE 0.028) and the balanced-corpus runs in
`tests/eval/results/jev_runs_balanced/`.

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
As a security operator, I want uncertain calls (`0.08–0.40`, C2-beacon-like
evasions measured at 0.51–0.70) escalated to Gemini reasoning, so nothing
borderline is decided by threshold alone.

### US-03: Egress Safety
As a platform owner, I want secrets redacted before any TypeSafe API call and
the request body limited to an allowlist, so paid Jev operation never
exfiltrates credentials.
