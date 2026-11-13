# ADR 0008: Tier-1 Jev Transport Moves from Vercel AI Gateway to the Official TypeSafe AI API
## Status
Proposed 2026-11-12: records the maintainer's decision of that date and takes effect when this PR is merged (amends ADR 0006: transport, billing path and data-handling mechanism only; spec: `.kiro/specs/tier-1-jev-addition/`). TASK-D02 (live acceptance against the real API) ran on 2026-11-12 and passed all four spec gates; see Verification.
## Context
ADR 0006 adopted TypeSafe Jev as the additive Tier-1 triage signal and reached it
through the Vercel AI Gateway: model ID `typesafe-ai/jev`, `POST
https://ai-gateway.vercel.sh/v1/evaluate`, a `boolean` question answered as
`answers.is_threat.probability`, funded by paid Gateway credits
(`AI_GATEWAY_API_KEY`), with `providerOptions.gateway.disallowPromptTraining: true`
on every request.
On 2026-11-12 the maintainer decided to call the vendor's own first-party API
instead of going through an intermediary, and updated `.env.example`
accordingly (commit `46acaa6`): `TYPESAFE_API_KEY`, `TYPESAFE_BASE_URL`,
`JEV_MODEL=jev-latest`. The stated rationale is to use the official first-party
API. No further drivers (cost, latency, data handling) were recorded with the
decision; add them here if they should be on the record. This ADR records the
contract change and what it costs, so the code, specs and rulebooks can follow
it.
Facts below come from the TypeSafe documentation (`docs.typesafe.ai`) and DPA
(`typesafe.ai/legal/data-processing`, last updated 2026-04-24), both read
2026-11-12, from this repository, and from the maintainer. Where something is
not verified it is marked as such.
Maintainer-supplied facts (2026-11-12):
- The account is a regular, non-enterprise customer. **Zero data retention (ZDR)
  is not available on it.**
- Blackwall should always run the newest Jev release, so the default stays
  `jev-latest` and is **deliberately not pinned**. `jev-latest` now resolves to
  `jev-1.14.0` (released 2026-10-14); the 2026-09-19 A/B ran on the previous
  release (1.13), through the Gateway's rate-limited free tier. The committed
  evidence is therefore for a different release and transport than the one now
  in use, and was replaced by a fresh paid-tier run (TASK-D02, 2026-11-12; see
  Verification).
### What the first-party API looks like
| | Vercel AI Gateway (ADR 0006) | TypeSafe AI API (this ADR) |
|---|---|---|
| Endpoint | `POST https://ai-gateway.vercel.sh/v1/evaluate` | `POST {TYPESAFE_BASE_URL}/v1/systemone`, root `https://api.typesafe.ai` |
| Auth | `Authorization: Bearer $AI_GATEWAY_API_KEY` | `Authorization: Bearer $TYPESAFE_API_KEY` |
| Model | `typesafe-ai/jev` | `jev-latest` alias (unpinned by policy) |
| Question | `{"type": "boolean", ...}` | `{"type": "noul", ...}` (TypeSafe's yes/no primitive) |
| Answer | `answers.is_threat.probability` | `answers.is_threat.noul` |
| Usage | `usage.inputTokens` / `outputTokens` | `usage.input_tokens` / `output_tokens` |
| Extras | `providerOptions`, `providerMetadata` (confidence, `gateway.cost`) | none |
| Transient errors | 429 | 429 and 529 Overloaded; docs: "retry after a short delay", with exponential backoff for callers not using their SDK |
| Rate limits | Gateway free tier: ~20-call burst, then a trickle | Per organization, in requests/s and tokens/s, set in the TypeSafe console. This organization (console, 2026-11-12, both "Default", shared across all keys): 80 requests/s and 100,000 input tokens/s, i.e. 4,800 RPM |
The request `instructions` text is unchanged, byte for byte, so the calibrated
prompt is the same; only the question `type` differs.
## Decision
Tier-1 Jev calls the official TypeSafe AI API directly. Everything else in ADR
0006 stands.
1. **Wire contract.** `JevTriageBackend` posts `{model, state, questions:
   {is_threat: {type: "noul", instructions}}}` to `{TYPESAFE_BASE_URL}/v1/systemone`
   and reads P(threat) from `answers.is_threat.noul`. `TYPESAFE_BASE_URL` is an
   API root, never a path. Blank environment values fall back to defaults.
2. **Credentials.** Only `TYPESAFE_API_KEY` is read. `AI_GATEWAY_API_KEY` and
   `JEV_GATEWAY_URL` are deliberately ignored, with no deprecated-alias
   fallback: a Vercel credential must never be presented to a different vendor.
   Without `TYPESAFE_API_KEY`, selecting `jev` still degrades to `gemini` with a
   warning (fail-closed, unchanged).
3. **Egress allowlist replaces the per-request no-training flag.** The request
   body carries exactly `model`, `state` and `questions`. `disallowPromptTraining`
   was a Vercel Gateway option and has no equivalent on the first-party API, so
   it is no longer sent. Sanitization-before-egress
   (`ContextHygiene(preserve_iocs=True)`) is unchanged and remains the control
   Blackwall itself enforces. Because ZDR is unavailable on this account, what
   reaches TypeSafe is retained under the DPA, whose Schedule I sets no fixed
   period ("retained for as long as necessary taking into account the purpose of
   the Processing"). `preserve_iocs=True` leaves IOCs (URLs, IPs, hostnames,
   paths) in the state by design (ADR 0006), so those are what is exposed.
4. **Retries: one, then fail closed.** A throttled response (429, or 529
   Overloaded) is retried exactly once after a fixed 0.5s; a second failure
   falls back to `gemini`. Every other non-200 outcome falls back immediately.
   This replaces the earlier 3-attempt exponential schedule and removes the
   `JEV_MAX_ATTEMPTS` variable, the `max_attempts` / `backoff_*` constructor
   parameters and, in the eval helper, the 2s inter-call pacing, the 8-attempt
   loop and `Retry-After` parsing. Those were sized for the Gateway free tier.
   The docs do not say retries are unnecessary: they say SDK users need no
   handling, and that callers on raw HTTP should retry 429/529 after a short
   delay with exponential backoff. One retry keeps the documented behavior while
   staying inside a latency-bounded hot path that has a ready fallback (the
   vendor SDK's own default is two retries). To change the budget, edit
   `JEV_RETRY_DELAY_S` or the single `_post_with_one_retry` helper.
5. **Confidence.** A `noul` answer is a single probability with no separate
   confidence (TypeSafe: "the probability already carries the uncertainty").
   `SemanticTriageResult.confidence` is therefore `None` for Jev, and the
   `jev_triage` record keeps the `confidence` key with a `None` value. Nothing
   consumes it today. The per-call `gateway_cost` field is removed from the
   record; spend is derived downstream from the token counts it still carries.
6. **Fixed band unchanged.** `0.35 / 0.75` stays as ADR 0006 and the spec set
   it. This ADR is not a recalibration.
7. **Model: `jev-latest`, deliberately unpinned.** The maintainer wants the
   newest Jev release at all times. TypeSafe's docs advise pinning a versioned ID
   if thresholds were tuned against one release; that advice is declined. The
   consequence is that the fixed band is only as validated as the last TASK-D02
   run, which is why every eval row records the release that answered
   (`model`, taken from the response) and why D02 is re-run after TypeSafe
   ships a release behind the alias.
8. **Eval tooling.** The dev-only Node helper (`scripts/jev_evaluate.mjs`) uses
   Node's built-in `fetch`, so the `ai` npm package and its `npm install`
   bootstrap are removed. Its resume cache is keyed on the requested model, so
   Vercel-era rows can never be reused or mixed into a first-party result file.
   Records now carry the Jev release that actually answered.
## Alternatives Considered
- **Keep the Vercel AI Gateway.** Rejected by the maintainer's decision.
- **The vendor's Python SDK (`typesafe_sdk`).** Documented with sync and async
  clients. Rejected for now: it adds a runtime dependency
  and manifest churn to a hot-path security control, and its own retry policy
  (default: two retries on 408, 429 and all 5xx, honoring `Retry-After`) would
  override the backend's single, fail-closed retry. The injectable
  `httpx.AsyncClient` is also the existing test seam. Revisit if the wire
  contract grows beyond a single `noul` question.
- **Support both transports behind a flag.** Rejected: two credentials and two
  response parsers on a security control, to preserve a path the maintainer has
  chosen to leave.
- **Accept `AI_GATEWAY_API_KEY` as a deprecated alias.** Rejected for the
  credential-crossing reason in Decision 2.
- **Pin `JEV_MODEL` to a versioned release.** Rejected by the maintainer, who
  wants the newest release (Decision 7). The cost is calibration drift, below.
## Consequences
### Positive
- **One fewer party in the data path.** Sanitized tool-call state used to transit
  Vercel and then TypeSafe. It now goes to TypeSafe only.
- **Native primitive and documented failure semantics.** `noul` is TypeSafe's own
  yes/no type, and 429 and 529 handling is specified by the vendor. Responses
  carry an `x-typesafe-request-id` header, which Blackwall does not log today.
- **Direct billing.** Jev is billed per input token by the vendor. Documented list
  price on 2026-11-12: $42 per billion tokens ($0.042 per million) for both
  current releases, matching the figure ADR 0006 measured. Prices are not
  hard-coded in the repository.
- **Measured latency is far lower.** p50 92 to 107 ms and p95 143 to 159 ms in
  two TASK-D02 runs, against 787 and 1,009 ms through the Gateway (one client,
  sequential, unloaded). The cause was not isolated: the Gateway hop and the Jev release
  (1.13 to 1.14) both changed at once.
- **Rate headroom.** The organization limit of 80 requests/s (4,800 RPM) is 16
  times Vertex's 300 RPM for Gemini. The request limit binds below about 1,250
  input tokens per call (100,000 / 80); calls here average 381.
- **No dependency or manifest change.** The existing `httpx` caller is reused.
### Negative & Trade-offs
- **Loss of a per-request, machine-checkable no-training control.** Before, every
  call asserted `disallowPromptTraining: true` and a BDD scenario checked it.
  Now the no-training guarantee is TypeSafe's published commitment ("Jev is not
  trained on customer requests or responses", `docs.typesafe.ai/models`, backed
  by their Data Processing Agreement and Privacy Policy), not something a
  request can assert or a test can verify. TypeSafe describes ZDR for enterprise
  customers; this account is a regular customer without it (maintainer-confirmed),
  and the DPA sets no fixed retention period. The scenario that asserted the
  flag is replaced by one that asserts the egress allowlist and the sanitized
  state.
- **The fixed band rides a moving model.** The `0.35 / 0.75` band was set from
  the 2026-09-19 A/B run on the previous Jev release (1.13; the artifact
  recorded only the Gateway alias `typesafe-ai/jev`, so the release is known
  only from the maintainer) through the Gateway's `boolean` question.
  Production now calls `jev-latest`, currently 1.14.0, and will move again
  whenever TypeSafe ships a release. TASK-D02 re-measured it on 1.14.0 and the
  gates still pass, and overall the probabilities agree closely with the
  Gateway-era ones (mean change -0.005; 2 of 167 cases changed zone, both block
  to escalate at the 0.75 edge). That cannot separate the effect of the
  transport from the effect of the release. Two things in the data matter. The
  ten C2-class cases average P 0.70 on 1.13 and 0.63 on 1.14 (0.636 and 0.631
  in two separate runs), while other malicious (0.96 to 0.95) and benign (0.05
  to 0.06) cases barely moved, so the release shift is specific to the weak
  class. And the model is not deterministic at band-edge precision: two
  1.14.0 runs on identical states differed in 56 of 167 cases by up to 0.03 and
  changed zone in 3. One of those is a malicious C2 beacon:
  `wave2_c2_beacon_001` was escalated at P 0.35 in one run and allowed at 0.34
  in the other. Because the alias keeps moving, re-running D02 after each
  release is the only way the band stays validated. Nothing in production
  currently records which release answered a given call (see Open Items).
- **The recorded "confidence" carried no information.** All 167 rows in that
  artifact hold the placeholder `{"confidence": {}}`, with no numeric value. ADR
  0006's statement that Jev "probabilities come with confidence" was not borne
  out by the committed evidence, so dropping the field loses no measured
  signal. The band is a function of `p` alone.
- **Historical evidence was Gateway-era and has been replaced.** The 2026-09-19
  results came from the Gateway's rate-limited free tier on the previous
  release, so they are not valid evidence for this transport. TASK-D02
  regenerated `tests/eval/results/jev_triage_results.json` from a paid-tier run
  on 2026-11-12 (commit `426166d`; the old rows stay in git history).
  `tests/eval/jev_ab_run_plan.md` remains a record of the executed run. New runs
  write `jev_raw_systemone.json`, so the only copy of the raw Gateway rows is
  not overwritten.
- **No per-call cost field.** Budget alerting must compute cost from
  `input_tokens` and a price table kept outside this repository.
## Verification
- Unit and BDD tests specify the new contract (endpoint join, `noul` parse,
  allowlisted body, single 429/529 retry and storm, removed retry knobs inert,
  non-retryable statuses, blank environment, legacy variables ignored, no
  confidence invention). The Node helper has 17 contract tests against a
  loopback server, run with `node --test scripts/jev_evaluate.test.mjs`.
- The unit and BDD tests use `httpx.MockTransport` or loopback servers and never
  call the real API. The live-credential acceptance gate
  (`.agents/rules/testing_and_hygiene.md`, Live Paid-Credential Acceptance
  Gates) forbids simulating that evidence, so it is met only by the run below.
- **Live acceptance (TASK-D02), 2026-11-12.** `scripts/jev_triage_eval.py` made
  167 live calls to the paid API on `jev-latest` (every row served by
  `jev-1.14.0`), sequentially from one client and from an empty cache, with 0
  errors and 0 fallbacks. Definitions match the dashboard (band 0.35/0.75,
  escalations abstain from the decided matrix):

  | Metric | Result | Gate |
  |---|---|---|
  | Accuracy, decided cases | 99.4% (TP 93, FN 1, FP 0, TN 68) | >= 98% |
  | AUROC | 1.000 | >= 0.95 |
  | ECE (10-bin) | 0.059 | <= 0.10 |
  | Escalation to Tier-2 | 3.0% (5 of 167) | <= 25% |

  In the security suite (157) every decided case is correct (85 TP, 68 TN) and 4
  are escalated; all 30 evasion cases are blocked, and there are no false alarms
  (benign P <= 0.17, none sent to Tier-2). Outside the C2 class every malicious
  case scores P >= 0.76 (89 cases). The evasion-proof suite (10) blocks 8,
  escalates 1 and misses 1: `wave1_c2_beacon_001` scores P 0.19, below the band,
  so it never reaches Tier-2. Latency was p50 92 ms and p95 143 ms; the pass used
  63,557 input tokens (mean 381 per call), about $0.003. This measures Tier-1
  only: Tier-2 (Gemini) was not run live.
- **Replication.** A second full live run (167 calls, 0 errors, from an empty
  cache, using the committed tooling) passes the same gates but with less
  margin: accuracy 98.8% (TP 93, FN 2, FP 0, TN 68), AUROC 0.9999, ECE 0.059,
  escalation 2.4% (4/167). The extra miss is `wave2_c2_beacon_001` at P 0.34, a
  C2 beacon that the first run escalated at 0.35. Latency was p50 107 ms and p95
  159 ms; benign max P 0.19, non-C2 malicious min P 0.74. The 98% gate allows
  3 errors among about 163 decided cases, and the two runs had 1 and 2, so the
  margin is one case and the missed-beacon count moves between identical runs.
  The committed artifact is the first full run I made; this one is reported
  alongside it, not chosen over it.
- Full test suite at `d5df14c`, run hermetically (dotenv disabled, no ADC,
  outbound HTTPS blocked, `gcp_eval`/`vertex_evaluation`/`sla_benchmark`
  deselected): 2648 passed, 32 failed, none in Jev code. 29 fail identically on
  pristine `main`; 2 are a `ContextHygiene.sanitize_string` idempotency bug that
  reproduces on `main`; 1 is a wall-clock test that flakes under load. Since then
  only the results artifact and documentation changed.
## Open Items
1. **Repeat TASK-D02 after each TypeSafe release behind `jev-latest`.** The band
   is fixed and the model is not (Decision 7). Recalibration, if a run warrants
   it, needs its own spec amendment with fresh labeled evidence.
2. **The pipeline's Rate Check, not Jev, is the throughput limit.**
   `SyncResolver.evaluate()` begins with a hard-coded
   `TokenBucketRateLimiter(capacity=300, refill_rate=5.0)` sized for Vertex's
   300 RPM; beyond that sustained rate it returns QUARANTINE, so Jev's 4,800 RPM
   is not reachable until it changes. If it is raised, Tier-2 (Gemini, 300 RPM)
   binds once the Tier-2 fire rate exceeds 6.25% at 4,800 RPM: 3.0% (this run)
   is 144 RPM, 10% (the evasion-proof suite) is 480, and the ~30% the spec cites
   for hard evasion probes is 1,440. This is arithmetic from documented limits,
   not a load test.
3. **C2 beacons stay the weak class.** `wave1_c2_beacon_001` is still missed (P
   0.19, below the band, so it never reaches Tier-2) and the C2-class mean fell
   from 0.70 to 0.63. Widening what reaches Tier-2 (for example the
   disagreement trigger) needs its own spec amendment with re-measured Tier-2
   rates (ADR 0006).
4. **Tier-2 handoff has not been exercised live.** Mocked BDD scenarios cover
   the routing (clear-low, clear-high, ambiguity, disagreement, signature
   write); a live check needs Vertex credentials, a separate paid resource.
5. **Known limitation: no ZDR, no fixed retention period** (see Decision 3).
   Revisit if the IOC-bearing states sent to TypeSafe become a concern.
6. **Optional:** log the served release (`response.model`) and
   `x-typesafe-request-id` in the `jev_triage` record. With an unpinned alias
   this is how a change in verdicts could be tied to a release change.
7. **`.env.example` still recommends pinning** (lines 133-135) and shows
   `jev-1.13.0` as an example; that conflicts with Decision 7. The file is not
   edited by this PR.
