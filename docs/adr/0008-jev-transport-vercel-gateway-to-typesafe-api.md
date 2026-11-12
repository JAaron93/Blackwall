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
Facts below come from the TypeSafe documentation (`docs.typesafe.ai`, read
2026-11-12 through Context7) and from this repository; where something is not
verified it is marked as such.
### What the first-party API looks like
| | Vercel AI Gateway (ADR 0006) | TypeSafe AI API (this ADR) |
|---|---|---|
| Endpoint | `POST https://ai-gateway.vercel.sh/v1/evaluate` | `POST {TYPESAFE_BASE_URL}/v1/systemone`, root `https://api.typesafe.ai` |
| Auth | `Authorization: Bearer $AI_GATEWAY_API_KEY` | `Authorization: Bearer $TYPESAFE_API_KEY` |
| Model | `typesafe-ai/jev` | `jev-latest` alias, or a versioned ID such as `jev-1.13.0` |
| Question | `{"type": "boolean", ...}` | `{"type": "noul", ...}` (TypeSafe's yes/no primitive) |
| Answer | `answers.is_threat.probability` | `answers.is_threat.noul` |
| Usage | `usage.inputTokens` / `outputTokens` | `usage.input_tokens` / `output_tokens` |
| Extras | `providerOptions`, `providerMetadata` (confidence, `gateway.cost`) | none |
| Transient errors | 429 | 429 and 529 Overloaded; both "retry with exponential backoff" |
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
   Blackwall itself enforces.
4. **Retries.** Bounded exponential backoff now covers 529 as well as 429, the
   two statuses TypeSafe documents as retryable. The budget (3 attempts, 0.5s
   base, 4s cap) and the fail-closed fallback to `gemini` are unchanged. Every
   other non-200 outcome falls back immediately.
5. **Confidence.** A `noul` answer is a single probability with no separate
   confidence (TypeSafe: "the probability already carries the uncertainty").
   `SemanticTriageResult.confidence` is therefore `None` for Jev, and the
   `jev_triage` record keeps the `confidence` key with a `None` value. Nothing
   consumes it today. The per-call `gateway_cost` field is removed from the
   record; spend is derived downstream from the token counts it still carries.
6. **Fixed band unchanged.** `0.35 / 0.75` stays as ADR 0006 and the spec set
   it. This ADR is not a recalibration.
7. **Eval tooling.** The dev-only Node helper (`scripts/jev_evaluate.mjs`) uses
   Node's built-in `fetch`, so the `ai` npm package and its `npm install`
   bootstrap are removed. Its resume cache is keyed on the requested model, so
   Vercel-era rows can never be reused or mixed into a first-party result file.
   Records now carry the Jev release that actually answered.
## Alternatives Considered
- **Keep the Vercel AI Gateway.** Rejected by the maintainer's decision.
- **The vendor's Python SDK (`typesafe_sdk`).** Documented with sync and async
  clients. Rejected for now: it adds a runtime dependency
  and manifest churn to a hot-path security control, and its own retry policy
  (default: retry 408, 429 and all 5xx, honor `Retry-After`) would overlap with
  the backend's bounded, fail-closed retry budget. The injectable
  `httpx.AsyncClient` is also the existing test seam. Revisit if the wire
  contract grows beyond a single `noul` question.
- **Support both transports behind a flag.** Rejected: two credentials and two
  response parsers on a security control, to preserve a path the maintainer has
  chosen to leave.
- **Accept `AI_GATEWAY_API_KEY` as a deprecated alias.** Rejected for the
  credential-crossing reason in Decision 2.
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
  request can assert or a test can verify. TypeSafe's Legal page describes zero
  data retention (ZDR) for enterprise customers; whether it applies to this
  account is not verified. The scenario that asserted the flag is
  replaced by one that asserts the egress allowlist and the sanitized state.
- **Calibration continuity is not demonstrated.** The `0.35 / 0.75` band was set
  from the 2026-09-19 A/B run through the Gateway's `boolean` question. The
  committed artifact (`tests/eval/results/jev_triage_results.json`, 167 rows)
  records only the Gateway alias `typesafe-ai/jev`, not a release. It is not
  verified that Gateway `boolean` probabilities and native `noul` values are
  numerically identical, or that the release then served is the one `jev-latest`
  resolves to now (the docs say `jev-latest` points at a release dated
  2026-10-14, after the A/B run). The default is `jev-latest` as set in
  `.env.example`; pinning `JEV_MODEL` to a versioned ID freezes behavior and is
  recommended once a release has been validated.
- **The recorded "confidence" carried no information.** All 167 rows in that
  artifact hold the placeholder `{"confidence": {}}`, with no numeric value. ADR
  0006's statement that Jev "probabilities come with confidence" was not borne
  out by the committed evidence, so dropping the field loses no measured
  signal. The band is a function of `p` alone.
- **Historical evidence is Gateway-era.** The A/B artifact and
  `tests/eval/jev_ab_run_plan.md` remain valid records of that run and are left
  unmodified. New runs write `jev_raw_systemone.json` so the only copy of the
  raw Gateway rows is not overwritten.
- **No per-call cost field.** Budget alerting must compute cost from
  `input_tokens` and a price table kept outside this repository.
## Verification
- Unit and BDD tests specify the new contract (endpoint join, `noul` parse,
  allowlisted body, 429 and 529 retry and storm, non-retryable statuses, blank
  environment, legacy variables ignored, no confidence invention). The Node
  helper has 16 contract tests against a loopback server, run with `node --test
  scripts/jev_evaluate.test.mjs`.
- All of it uses `httpx.MockTransport` or loopback servers. **No test calls the
  real TypeSafe API**, so this change does not meet the live-credential
  acceptance gate (`.agents/rules/testing_and_hygiene.md`, Live Paid-Credential
  Acceptance Gates), which forbids simulating that evidence.
## Open Items
1. **Run live acceptance** before the TASK-D04 default flip: `TYPESAFE_API_KEY=...
   .venv/bin/python scripts/jev_triage_eval.py`, then compare the 167 `p_threat`
   values and the C2-class recall against the committed Gateway-era artifact.
   Recalibration, if the comparison warrants it, needs its own spec amendment
   with fresh labeled evidence.
2. **Review TypeSafe's Data Processing Agreement** for retention terms, since
   there is no per-request opt-out any more and ZDR is documented for enterprise
   customers. Confirm whether this account has it.
3. **Decide whether to pin `JEV_MODEL`** to the release that passes item 1.
4. **Optional:** log `x-typesafe-request-id` in the `jev_triage` record.
5. **`.env.example` drift:** it no longer lists `JEV_MAX_ATTEMPTS`, but the
   backend still honors it (default 3). Either document it again or remove the
   knob in a follow-up.
