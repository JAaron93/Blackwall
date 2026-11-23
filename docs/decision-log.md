# Decision log — Tier-1 Jev calibration program

> **Purpose:** a fast, dated index of choices made during the 2026-11 calibration
> work, so decisions can be recalled without rereading specs, ADRs, manifests and
> PR threads. Reverse-chronological. **Not normative**: the authoritative record
> is always the cited task note / ADR / rulebook. A PR number marked `open` had
> not merged when this log was written (2026-11-23).

## How to use

Scan the newest entry that covers your question, then follow its pointer. If a
decision here conflicts with a spec or rule file, the spec/rule wins — update
this log rather than acting on stale prose.

---

## 2026-11-23

### TASK-F13 — keep the fixed 0.5s single retry; ignore `Retry-After`
- **Decision:** no behavior change. `JevTriageBackend` still retries 429/529
  exactly once after `JEV_RETRY_DELAY_S`, then raises `JevUnavailableError`.
  Server `Retry-After` is deliberately not honored.
- **Rationale:** live TypeSafe docs (skill-verified) describe exponential backoff
  for raw-HTTP callers and say the vendor **SDKs** follow `Retry-After`; Blackwall
  uses raw HTTP, and ADR 0008 Decision 4 already removed `Retry-After` parsing
  to keep the hot path latency-bounded. An arbitrary server delay would stall
  interception and threaten NFR-01, with no security benefit: after the retry,
  `JevUnavailableError` propagates before Tier-2 runs. TypeSafe-specific evidence:
  D02 (167 calls), G04 (1,576), F02 probe (4,600) and F02 full (2,760) all had
  zero HTTP errors at the 80 req/s org limit. F03's 0/40 is Vertex Tier-2 quota
  and is not used here. FR-06/rule 105 stay unchanged.
- **Guard:** `tests/unit/test_policy_jev_triage_backend.py::test_retry_after_header_does_not_extend_the_hot_path`.
- **Pointer:** TASK-F13 note, FR-06 dated decision note.

### Judge model stays `gemini-3.5-flash-lite` at **high** thinking; no 3.8 judge
- **Decision:** no change. The earlier instinct that a judge needs a slower,
  more deliberate model is already satisfied: `judge` is in `ANALYTICAL_TASK_TYPES`
  and `get_gemini_thinking_level()` enforces an immutable **high** floor for it
  (`GEMINI_ALLOW_ANALYTICAL_DOWNGRADE=false`). Tier-2 is separately pinned to
  **medium** (`TIER2_THINKING_LEVEL`), unaffected by `GEMINI_THINKING_LEVEL`.
- **Rationale:** ADR 0009 removed 3.8 Flash from every call site, including
  evaluation judges, on measured Tier-2 evidence. Judge *quality* was never
  compared, so the question was legitimate but unmeasured; the deliberation
  premise was already implemented.
- **Pointer:** `src/blackwall/config.py` (`ANALYTICAL_TASK_TYPES`, `TIER2_THINKING_LEVEL`),
  `src/blackwall/eval/judge_factory.py`, ADR 0009 Decisions 1–2,
  `tests/unit/test_judge_factory.py`.

### D03 judge-model provenance caveat accepted — no re-run
- **Decision:** keep the D03 live-gate runs as-is; record that the per-scenario
  judge model was never captured and may have come from a stale operator `.env`.
- **Rationale:** D03 closed only for *managed Vertex EvalTask service
  invocation*, whose model and `COMPLETED` status are recorded per row. Managed
  scores were `NaN`, so no scoring claim depends on the judge.
- **Pointer:** PR #234 (open), `tests/eval/results/gcp_eval_live_gate/manifest.json`
  → `judge_model_provenance`, TASK-D03 note.

### Dead config removed from tracked templates
- **Decision:** drop `BLACKWALL_DEEP_REASONING_MODEL` (pre-Jev "deep reasoning"
  escalation model) and `GEMINI_RPM_LIMIT` (no reader; enforcement is
  `VERTEX_QUOTA_RPM` in `sync_resolver.py`) from `.env.example` and the Cybench
  guide. The operator also removed `SEMANTIC_FALLBACK_ACTION` from their private
  `.env` — another pre-Jev fallback knob with no reader.
- **Rationale:** dead config invites false assumptions. `BLACKWALL_MODEL` was
  **kept** — it is read by `agent/__init__.py` and `scripts/verify_environment.py`.
- **Pointer:** PR #233 (open), `.env.example`, `LIVE_CYBENCH_CLOUD_TRACE_EVAL_GUIDE.md`,
  `src/blackwall/sync_resolver.py` (quota partition: 60 RPM Tier-2 + 240 RPM synthesis/ABA;
  embeddings are unthrottled on the same project quota).

### TASK-F12 — pin Jev to `jev-1.13.0`; retire `jev-latest`
- **Decision:** production sends the versioned ID; the backend normalizes
  `jev-latest`/`jev-preview` to the pin; harness checkpoints use the resolved
  model (config version 3). TASK-F07 closed N/A (no alias to drift behind).
- **Rationale:** on the original 167-case suite 1.13 beat 1.14 on accuracy,
  ECE, benign P and C2 mean; later corpora showed no compensating gain; G04 had
  already scored both releases at the 0.08/0.40 band. TypeSafe's own docs advise
  a versioned ID when thresholds were tuned against a release.
- **Pointer:** PR #232 (merged), TASK-F12/F07 notes, ADR 0008 Decision 7
  amendment, `docs/jev-1.13-vs-1.14-retrospective.md`.

### TASK-D03 closed under narrowed acceptance
- **Decision:** `[x]` for **managed Vertex EvalTask service invocation only**;
  usable managed scores and a stable CI gate are reopen conditions.
- **Rationale:** two live paid runs returned `COMPLETED`, but autorater scores
  were `NaN` and the CI gate was unstable (one pass, one regression). Both runs,
  the variance, and one discarded SDK-missing run are recorded.
- **Pointer:** PR #231 (merged; #229 re-scoped it first), TASK-D03 note,
  `tests/eval/results/gcp_eval_live_gate/manifest.json`.

### Reviewer-config drift corrected
- **Decision:** `.greptile/config.json`'s three stale `0.35/0.75` quotes updated
  to `0.08/0.40`; a fourth inequality-form quote fixed on review.
- **Rationale:** stale reviewer prose flags correct shipped behavior.
- **Pointer:** PR #230 (merged), `.greptile/config.json`.

## 2026-11-22

### TASK-F02 closed by risk acceptance
- **Decision:** no steering guard shipped; task closed with a retrospective.
- **Rationale:** three candidate families (nonce-XML boundary, atomic questions
  + `max`, native-object state) were ruled out by matched evidence. Full
  validation showed benign gains but worsened matched to-ALLOW flips / crossings
  and no reliable steering resistance.
- **Pointer:** PRs #226–#228 (merged), TASK-F02 note,
  `docs/f02-steering-retrospective.md`, `tests/eval/results/jev_f02_full_defense/`.

### Track G closed
- **Decision:** G02 closed with hypothesis invalidated, G05 closed N/A (no flip
  to sync), G04 NO-GO. Production stayed on the legacy single `is_threat` path.
- **Rationale:** atomic six-question + `max` failed AUROC, escalation, FRR and
  accuracy gates on held-out cases; no architectural invariant changed.
- **Pointer:** PRs #224/#225 (merged), TASK-G02/G04/G05 notes, ADR 0009 OI3,
  `tests/eval/results/jev_g04_ab/`.

## 2026-11-21 and earlier (context for the above)

- **G03/G01/G02 landed** — structured-state foundation, atomic question module,
  live probe with dev/held-out wording check. PRs #219, #220, #222.
- **F10 band re-baselined to 0.08/0.40** on the F09 balanced corpus; gates:
  accuracy ≥0.85, recall ≥0.75, AUROC ≥0.97, ECE ≤0.27, escalation ≤20%.
  ECE ≤0.10 was deferred to Track G and never achieved. PR #217 (and #215).
- **F03 shared Vertex quota** — Tier-2 reserved 60 RPM, synthesis/ABA 240 RPM,
  measured 0/40 429s under partition. PR #212; evidence etiquette PR #213.
- **Evidence doctrine adopted** — every published figure needs a committed
  machine-readable row set, a manifest with provenance/discards, and a hermetic
  recomputation test (AGENTS.md §6.6 / testing rule §80). This is why the
  retrospectives here cite manifests rather than prose numbers.
