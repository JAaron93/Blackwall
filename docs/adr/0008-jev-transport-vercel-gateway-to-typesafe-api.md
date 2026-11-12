# ADR 0008: Tier-1 Jev Transport Moves from Vercel AI Gateway to the Official TypeSafe AI API
## Status
Proposed 2026-11-12: records the maintainer's decision of that date and takes effect when this PR is merged (amends ADR 0006: transport, billing path and data-handling mechanism only; spec: `.kiro/specs/tier-1-jev-addition/`). **Live acceptance against the real API has not been run** — see Verification and Open Items.
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
  in use, and is being replaced by a fresh paid-tier run (TASK-D02).
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
| Rate limits | Gateway free tier: ~20-call burst, then a trickle | Per organization, in requests/s and tokens/s, set in the TypeSafe console |
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
  the 2026-09-19 A/B run on the previous Jev release (1.13) through the
  Gateway's `boolean` question. Production now calls `jev-latest`, currently
  1.14.0, and will move again whenever TypeSafe ships a release. The artifact
  (`tests/eval/results/jev_triage_results.json`, 167 rows) recorded only the
  Gateway alias `typesafe-ai/jev`, so even the original release is known only
  from the maintainer. It is also not verified that Gateway `boolean`
  probabilities and native `noul` values are numerically identical. TASK-D02
  re-measures this on the paid API against the current release; because the
  alias keeps moving, re-running it after each release is the only way the band
  stays validated. Nothing in production currently records which release
  answered a given call (see Open Items).
- **The recorded "confidence" carried no information.** All 167 rows in that
  artifact hold the placeholder `{"confidence": {}}`, with no numeric value. ADR
  0006's statement that Jev "probabilities come with confidence" was not borne
  out by the committed evidence, so dropping the field loses no measured
  signal. The band is a function of `p` alone.
- **Historical evidence is Gateway-era and is being replaced.** The 2026-09-19
  results came from the Gateway's rate-limited free tier on the previous
  release, so they are not valid evidence for this transport. TASK-D02
  regenerates `tests/eval/results/jev_triage_results.json` from a paid-tier run
  (the old rows stay in git history). `tests/eval/jev_ab_run_plan.md` remains a
  record of the executed run. New runs write `jev_raw_systemone.json`, so the
  only copy of the raw Gateway rows is not overwritten.
- **No per-call cost field.** Budget alerting must compute cost from
  `input_tokens` and a price table kept outside this repository.
## Verification
- Unit and BDD tests specify the new contract (endpoint join, `noul` parse,
  allowlisted body, single 429/529 retry and storm, removed retry knobs inert,
  non-retryable statuses, blank environment, legacy variables ignored, no
  confidence invention). The Node helper has 17 contract tests against a
  loopback server, run with `node --test scripts/jev_evaluate.test.mjs`.
- All of it uses `httpx.MockTransport` or loopback servers. **No test calls the
  real TypeSafe API**, so this change does not meet the live-credential
  acceptance gate (`.agents/rules/testing_and_hygiene.md`, Live Paid-Credential
  Acceptance Gates), which forbids simulating that evidence.
## Open Items
1. **Run TASK-D02 (live acceptance).** `TYPESAFE_API_KEY=...
   .venv/bin/python scripts/jev_triage_eval.py` regenerates the results
   artifact on `jev-latest`. Check it against the spec gates (accuracy, AUROC,
   ECE, escalation rate) and note the served release. Recalibration, if the
   result warrants it, needs its own spec amendment with fresh labeled
   evidence. Repeat after TypeSafe ships a new release.
2. **Record the organization's rate limit.** TypeSafe publishes no default;
   limits are per organization, in requests/s and tokens/s, shown in the
   developer console (`console.typesafe.ai/rate-limits`). Record the figure,
   converted to RPM, next to the places that state Vertex AI's 300 RPM for
   Gemini.
3. **Known limitation: no ZDR, no fixed retention period** (see Decision 3).
   Revisit if the IOC-bearing states sent to TypeSafe become a concern.
4. **Optional:** log the served release (`response.model`) and
   `x-typesafe-request-id` in the `jev_triage` record. With an unpinned alias
   this is how a change in verdicts could be tied to a release change.
5. **`.env.example` still recommends pinning** (lines 133-135) and shows
   `jev-1.13.0` as an example; that conflicts with Decision 7. The file is not
   edited by this PR.
