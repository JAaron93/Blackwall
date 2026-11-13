# ADR 0009: Tier-2 Standardizes on Gemini 3.5 Flash-Lite at Medium Thinking; Tier-1 Is Jev Only and Fails Fast

## Status

Accepted 2026-11-13. Records the maintainer's decisions of 2026-11-12/13 and
takes effect when this PR is merged. Amends ADR 0006 (Tier-2 model, thinking
level, the Gemini Tier-1 backend and the Jev-to-Gemini fallback, FR-06) and
ADR 0008 (Open Items 1 and 8 are unchanged; the Tier-2 comparison it reports is
the evidence for this decision).

## Context

ADR 0006 shipped Tier-2 as `gemini-3.8-flash` with thinking pinned HIGH, kept the
`gemini` Tier-1 backend as a selectable alternative, and routed a degraded Jev
to that backend (FR-06). ADR 0008 measured Tier-2 candidates over the same 93
inputs (10 C2, 8 other evasion-proof, 68 benign, 7 authored probes); see its
Verification section for the method and the per-input data:

| Configuration | Result |
|---|---|
| `gemini-3.5-flash-lite`, medium | the same ALLOW/BLOCK decision as `gemini-3.8-flash` HIGH on all 81 inputs both answered |
| Median latency | 0.39x of `gemini-3.8-flash` HIGH |
| List price | 0.63x (0.31x from 2027-01-01, when the listed `gemini-3.8-flash` price doubles) |
| Missed the 30 s deadline | 0 of 93, against 12 of 93 for `gemini-3.8-flash` HIGH |
| Benign false positives by level | minimal 10.3%, low 4.4%, medium 1.5%, high 2.9% |

Flash-Lite at medium is therefore sufficient for Tier-2, and `gemini-3.8-flash`
is redundant. That redundancy, not a saving, is the reason it is removed.

The 300 RPM token bucket in `SyncResolver` guarded every evaluation although
the limit belongs to Vertex AI. With Tier-1 on Jev (80 req/s, 100,000 tokens/s
organization limit, ADR 0008) it throttled the path that Vertex does not bound.

## Decision

1. **`gemini-3.8-flash` is removed completely.** `gemini-3.5-flash-lite` is the
   only Gemini model at every call site: Tier-2, the Agent-as-a-Judge agents,
   forensics, signature synthesis, analytics, and the evaluation harnesses. No
   configuration names the old model and none keeps a path to it.
2. **Tier-2 thinking is pinned to `medium` in code.** `TIER2_THINKING_LEVEL` is
   not read from the environment. `GEMINI_THINKING_LEVEL` and
   `GEMINI_ALLOW_ANALYTICAL_DOWNGRADE` do not affect it, and `tier2_escalation`
   leaves the analytical HIGH-floor set. Changing the level is a code change that
   needs a new measurement; `scripts/jev_tier2_eval.py forced` produces it.
3. **Tier-1 is Jev only.** `GeminiTriageBackend`, its output schema, the backend
   registry, `BW_SEMANTIC_BACKEND` and the `semantic_backend` argument are
   removed. Tier-1 no longer needs a Gemini client; only Tier-2 does.
4. **Jev has no fallback and fails fast.** When triage is enabled and Jev cannot
   answer, `JevTriageBackend` raises `JevUnavailableError`. Causes: no key
   (raised at construction), an HTTP error, a 429/529 that outlasts the single
   retry, a transport error, a non-JSON body, or a malformed or out-of-range
   probability. `SemanticTriageProvider.triage` has no abstain value. The error
   propagates out of `SyncResolver.evaluate()`; the resolver never turns it into
   ALLOW or into a synthetic score. The gateway answers with a `-32603` error and
   does not forward the tool call; the ADK callback lets the exception raise so
   the tool does not run. Messages carry no key and no response body. The one
   retry after 0.5 s on 429/529 (ADR 0008, Decision 4) stays.
5. **Two rate limits, each sized to the service it protects** (resolves ADR 0008,
   Open Item 2). The front bucket is 80 req/s (capacity 80, refill 80/s) and
   guards every evaluation. A separate 300 RPM bucket (capacity 300, refill 5/s)
   is consumed immediately before a Tier-2 Vertex call. When Tier-2 is triggered
   and that bucket is empty, the call is **QUARANTINEd**: the resolver computes its
   normal verdict and raises an ALLOW to QUARANTINE; a BLOCK from deterministic
   aggregation stands. This is deliberately not an abstention. An abstention
   reaches Score Aggregation, which allows a lone band signal at production
   thresholds (ADR 0008, Open Item 9), so an attacker who aims calls at the band
   could drain the bucket and be allowed. Before this change the single 300 RPM
   bucket QUARANTINEd on exhaustion; this keeps that outcome for the one call it
   protects. `tier2_calls` counts only calls that reached Vertex; skipped calls
   are counted in `tier2_rate_limit_hits`.
6. **The live Tier-2 harness is committed** as `scripts/jev_tier2_eval.py`,
   reading only the committed class-blind data. It is dev tooling and CI never
   runs it.

## Consequences

- A Jev outage or a missing key stops evaluation instead of degrading to another
  model. Availability of the interception path now depends on one vendor when
  `BLACKWALL_ENABLE_SYNC_SEMANTIC_TRIAGE` is true. The operator's lever is that
  switch; there is no automatic substitute by design.
- Callers that enable triage need `TYPESAFE_API_KEY`. That includes
  `scripts/run_evasion_wave.py`.
- Tier-2 costs less and answers faster on the measured inputs (table above). The
  figures in ADR 0008 for `gemini-3.8-flash` stay valid as measurements of that
  model; they no longer describe the shipped Tier-2.
- ADR 0006, ADR 0008 and the archived specs under `.kiro/specs/` keep the model
  names they were written with, as dated records. This ADR supersedes them where
  they conflict.
- No behavior of Score Aggregation changes. In particular a clear-high Jev
  probability alone still cannot produce BLOCK (ADR 0008, Open Item 8).

## Open Items

1. **Tier-2 unavailable for other reasons.** A Tier-2 abstention (deadline miss,
   malformed answer, a Vertex error or a Vertex 429) still falls back to Score
   Aggregation with the Tier-1 signal, which allows a lone band signal (ADR 0008,
   Open Item 9). ADR 0008 measured 3 of 19 in-band attacks ALLOWED on a deadline
   miss with the old model; Flash-Lite missed 0 of 93. Whether Tier-2 should also
   fail fast, or QUARANTINE like the empty bucket, is not decided here.
2. **Class-specific templates.** `scripts/build_evalset.py` writes different
   wording for benign and malicious cases (ADR 0008, class-blind ablation).
   Whether to change the generator is not decided here.
3. **Live verification of the harness.** `scripts/jev_tier2_eval.py` is covered
   by unit tests only; its live path has not been run since it was committed.
