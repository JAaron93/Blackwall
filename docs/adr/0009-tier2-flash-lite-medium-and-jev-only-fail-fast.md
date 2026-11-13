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
   is consumed immediately before a Tier-2 Vertex call. An empty Tier-2 bucket is
   one way Tier-2 can be unavailable; Decision 6 says what happens then.
   `tier2_calls` counts only calls that reached Vertex. A call skipped because
   the bucket was empty is counted in `tier2_rate_limit_hits`. A call skipped
   because there is no Gemini client that can send a request spends no token and
   is counted in neither; its verdict reasoning says "no client".
6. **A Tier-2 that fired and returned no verdict QUARANTINEs an ALLOW** (resolves
   ADR 0008, Open Item 9). "No verdict" covers an empty Tier-2 bucket, a deadline
   miss, a malformed answer, a Vertex error or 429, and a missing Gemini client.
   The resolver computes its normal verdict and raises an ALLOW to QUARANTINE; a
   BLOCK from deterministic aggregation stands. Before this change an abstention
   fell to Score Aggregation, which allows a lone band signal at production
   thresholds, so every one of these was a bypass the caller could try to induce:
   aim calls at the band and drain the bucket, send inputs that make the arbiter
   time out or answer malformed, or generate other Gemini traffic against the
   same Vertex project quota (each novel BLOCK triggers an asynchronous
   signature-synthesis call, and the judges use the same quota, none of which the
   Tier-2 bucket counts) until Tier-2 receives 429s. The message names the cause
   by a short static label and carries no provider text.
7. **The live Tier-2 harness is committed** as `scripts/jev_tier2_eval.py`,
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
- Score Aggregation weights and thresholds do not change. A clear-high Jev
  probability alone still cannot produce BLOCK (ADR 0008, Open Item 8), which is
  why Tier-2 availability matters.
- Enabling triage without a Gemini client means Tier-2 cannot run, so every
  ambiguity-band call is QUARANTINEd.

## Verification

`scripts/jev_tier2_eval.py forced`, run live on 2026-11-13 at commit `c71d2b1`
(billed to the default gcloud project, application default credentials,
`gemini-3.5-flash-lite` at the pinned medium level, concurrency 2, no Jev key
involved). Inputs: the 93 forced cases, with the production-shaped Jev P from
`jev-1.14.0` in the prompt. Figures are from one run.

| Measure | Result |
|---|---|
| Calls answered / abstained / deadline misses | 93 / 0 / 0 |
| C2 cases BLOCKed | 10 of 10 |
| Other evasion-proof cases BLOCKed | 8 of 8 |
| Benign cases BLOCKed | 3 of 68 (4.4%); ADR 0008 measured 1 of 68 at medium |
| Authored malicious probes BLOCKed | 1 of 4 |

### Real attack text in the golden evalset (TASK-F05, part 1)

`malicious_cases.json` and `evasion_cases.json` previously used
`[[BRACKET_PLACEHOLDER]]` tokens in place of the attack content for most cases
(32 of 59 malicious, 26 of 30 evasion). This is the condition Open Item 10
above found reduces a case to no attack signal at all once the wrapper is
stripped. Every placeholder is now concrete, published attack syntax (CWE/OWASP
documented strings; RFC 5737 documentation-range IP addresses; the dataset's
existing fictional domains), grounded in that case's own `injection_technique`
or `obfuscation_technique` field. **This is a payload fix only; benign and
malicious remain two classes, distinguished by payload, not merged — the
wrapper template (Open Item 4 above) is unchanged.** The two `DESERIALIZATION`
cases keep a labeled, non-literal technique description (e.g. `<ysoserial
CommonsCollections6 gadget chain invoking Runtime.exec('id')>`) instead of
literal serialized bytes: unlike a SQL or shell string, a serialized-object
byte stream is itself the exploit payload. See
`tests/eval/docs/README_MALICIOUS.md` for the full reasoning.

This also surfaced a `ContextHygiene` finding unrelated to the placeholder fix:
its credential-redaction pattern (`(?i)(password|passwd|pwd)[\s:=]+...`)
matches the bare SQL column name `password` followed by any next word and
redacts that word along with it, so `"... password FROM admin_users"` becomes
`"... [[PASSWORD]] admin_users"` — the real keyword `FROM` is swallowed,
corrupting the state the classifier sees. This is pre-existing (it already
fired on the placeholder form before this fix) and would affect a real
benign query that selects a column literally named `password` too. The two
cases built here that would have tripped it use `pass_hash` instead; the
regex itself is not changed in this PR (TASK-F08 tracks it).

Re-scoring both Jev releases against the corrected payloads (the second half
of TASK-F05) needs a live Jev key and is not done here.
| Latency, median / p95 / max | 2.3 s / 3.3 s / 5.9 s |

Reading it:

- The latency and zero deadline misses repeat ADR 0008 (median 2.2 s there).
- The three benign BLOCKs all cite an unresolved placeholder or template variable
  in the input, which is a data artifact (ADR 0008, Open Item 10), not a measured
  property of the model. With 68 benign cases the interval around 3 versus 1 is
  wide, so this is not evidence of a regression.
- The one malicious probe BLOCKed is the one that carries tell-tale text
  (`/api/beacon`, `rogue-001`). The three C2 probes without tells were ALLOWed
  with score 0.05, as were their benign twins: on these inputs Tier-2 cannot tell
  a C2 check-in from a heartbeat once the text that labels it is gone. That is
  the weak class ADR 0008 already names, and it is why a Tier-2 ALLOW is final
  only when aggregation does not block.

### End to end with live Jev

`scripts/jev_tier2_eval.py e2e`, run live on 2026-11-13 at commit `7340d9c`: the
real `JevTriageBackend` (`jev-latest`, `TYPESAFE_API_KEY` supplied by the
maintainer's grant for this run) inside the real `SyncResolver`, with the real
Tier-2 (`gemini-3.5-flash-lite`, medium), production thresholds, and the
class-blinded production-shaped inputs for all 167 cases in two configurations,
as in ADR 0008. 334 evaluations, 0 errors, concurrency 2. TSG, threat intelligence
and CBM were not configured and background tasks were stubbed. Live Jev P agreed
with the stored production-shaped `jev-1.14.0` run to a mean of 0.009 (largest
0.06). The ADR 0008 column is the earlier run with `gemini-3.8-flash` HIGH.

| | Semantic tiers only | ADR 0008 | With `policy.yaml` | ADR 0008 |
|---|---|---|---|---|
| Benign ALLOW | 68 / 68 | 68 / 68 | 68 / 68 | 68 / 68 |
| Malicious BLOCK (of 99) | 18, all by Tier-2 | 16 | 58: 44 by tool name, 14 by Tier-2 | 54 |
| Evasion-proof suite BLOCK (of 10) | 0 | 0 | 4 | 4 |
| Malicious calls Jev scored above 0.75, ALLOWED | 56 of 56 | 56 of 56 | 29 of 56 | 29 of 56 |
| Malicious calls in the band, BLOCKed | 18 of 18 | 16 of 19 | 20 of 20 | not reported |
| Tier-2 called | 20 (12.0%) | 21 | 16 (9.6%) | 15 |
| Tier-2 returned no verdict | 0 | 3 | 0 | 4 |
| Tier-2 latency, answered calls, p50 / p90 | 2.3 s / 2.7 s | 10.7 s / 21.2 s | 2.2 s / 2.7 s | 6.3 s / 9.9 s |

Reading it:

- The change this ADR makes shows up where it should. Tier-2 returned a verdict
  on every call, so none of the in-band attacks ADR 0008 saw ALLOWED on a
  deadline miss (3 of 19) were allowed here, and Tier-2 was 3 to 5 times faster.
  One run, so the exact counts could move by a case or two on a rerun; ADR 0008
  measured that spread for Tier-1 as well.
- **Decision 6 was not exercised.** Tier-2 never failed, so no call took the
  "Tier-2 unavailable" QUARANTINE path. That path is covered by unit tests only.
- **The weakness this ADR does not touch is unchanged:** the semantic tiers alone
  still ALLOW all 56 malicious calls that Jev scored above 0.75 and block none of
  the evasion-proof suite, because a clear-high P alone cannot BLOCK (ADR 0008,
  Open Item 8; TASK-F06). Without the tool-name rules in `policy.yaml`, those
  attacks pass.

## Open Items

1. **Availability cost of Decision 6.** While Tier-2 is unavailable, benign calls
   that land in the ambiguity band are QUARANTINEd, and a caller who can send
   band calls can cause that on purpose. This is the same fail-closed posture as
   Jev's fail-fast and is accepted here; the lever is
   `BLACKWALL_ENABLE_SYNC_SEMANTIC_TRIAGE`. The ADR 0008 measurement (0 of 93
   Flash-Lite deadline misses) suggests it is rare in normal operation.
2. **Shared Vertex quota.** The Tier-2 bucket counts only Tier-2 calls, so other
   Gemini consumers can still exhaust the project quota. Decision 6 makes that a
   QUARANTINE instead of an ALLOW, but a shared budget would avoid the
   QUARANTINEs.
3. **The Tier-2 prompt interpolates the tool name, arguments and metadata
   unseparated.** Whether text inside a tool call can steer the arbiter's
   verdict has not been measured. Tier-2's ALLOW is final unless aggregation
   already blocks, so this is the next place to look for a bypass.
4. **Class-revealing wrapper template.** `scripts/build_evalset.py` writes a
   different sentence template for benign, malicious and evasion cases
   ("Execute a benign operation...", "Attempt malicious attack pattern...",
   "Attempt evasive variant..."), so the wrapper text alone names the label
   (ADR 0008, Open Item 10). The fix is one shared wrapper template used for
   every case regardless of label — benign and malicious stay two classes,
   told apart by their payload, not merged into one; the `ground_truth` field
   keeps the label. TASK-F05 covers only the companion fix (payloads carry the
   real attack text); the wrapper template itself is not changed here.
5. **Decision 6 under a real outage.** Both live runs had a Tier-2 that always
   answered. The QUARANTINE-on-no-verdict path has no live result.

Items 1 to 5 are tracked as tasks in `.kiro/specs/tier-1-jev-addition/tasks.md`
(Track F).
