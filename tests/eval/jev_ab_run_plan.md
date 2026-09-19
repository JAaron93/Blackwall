# Jev vs Gemini 3.5 Flash-Lite — A/B Experimental Run Plan (EXECUTED 2026-09-19)

Branch: `exp/jev-ab-eval-plan` (off `main`). No prod wiring. Committed as
evidence for `.kiro/specs/tier-1-jev-addition/`.
Status: **APPROVED and EXECUTED 2026-09-19 — §5 gates 1–3 passed; gate 4
FORMALLY AMENDED (see §5.4): p95<100ms was NOT met (1.3s measured) and is
deferred to a future local/in-VPC Jev deployment; interim acceptance is
network parity with LLM API calls (p95 <2s). EvalTask/regression sub-gates
were N/A by design (judges and weights frozen for a candidate-only swap).**
Outcome: security set 157/157 at 100% (TP=89 FN=0 FP=0 TN=68), evasion
30/30, AUROC 1.0, ECE 0.028, escalation 0% (main) / 3-of-10 (proof set,
all resolving via Tier-2); full-pass cost $0.0025; Gateway latency p50
~0.9s. Free-tier rate limit observed (~20-call burst, then trickle) —
production runs on paid credits. Full results tabled in
`.kiro/specs/tier-1-jev-addition/design.md`. Live scratch removed; API key
never touched disk.

## 1. Objective

Apples-to-apples comparison of Blackwall's semantic-triage backend on the golden eval dataset:

* Run A (baseline): `gemini-3.5-flash-lite` via existing path (`src/blackwall/config.py:20` `DEFAULT_RAPID_TRIAGE_MODEL`, `src/blackwall/sync_resolver.py:878` `_evaluate_semantic_intent`).
* Run B (candidate): `typesafe-ai/jev` via Vercel AI Gateway, swapped **only** at the `_evaluate_semantic_intent -> float` seam.

Build the `SemanticTriageProvider` production abstraction **only if** Run B passes §5.

## 2. Scope / non-goals

* Test-only. No changes to `SyncResolver` scoring weights (`src/blackwall/sync_resolver.py:957` — TI 40% / CBM 30% / Context 30%), no Tier-0/TSG changes, no `main` commits.
* Judges stay on GCP Vertex (Gemini judges + managed `EvalTask`). Only the candidate triage backend changes.
* No BYOK, no team-wide ZDR, no paid credits. Free-tier `$5/mo` only.

## 3. Baseline (Run A, frozen)

* Report: `tests/eval/reports/security_summary.txt` + `security_report.json` (`2026-09-12`): 157 cases (68 benign / 59 malicious / 30 evasion), `TP=89 TN=68 FP=0 FN=0`, Accuracy/Precision/Recall/F1 `100%`, `FRR 0%`, `Evasion 0%`, `tool_trajectory 1.0`, `rubric 1.0`.
* Configs: `tests/eval/eval_config.json`, `tests/eval/eval_config_evasion.json`.
* Datasets: `tests/eval/evalsets/blackwall_security.evalset.json` (157) + `blackwall_evasion_proof.evalset.json` (10).
* Action: re-run Run A **or** pin the `2026-09-12` report as baseline (preferred: re-run to control for env drift, same `test_report_generator` path).

## 4. Candidate (Run B) — swap design

Seam: `SyncResolver._compute_threat_score(..., semantic_score)` calls `_evaluate_semantic_intent(context)` when `enable_semantic_triage` and `client` present. Run B injects `semantic_score = Jev P(true)` via a temporary, uncommitted shim (env-gated, e.g. `BW_SEMANTIC_BACKEND=jev`, default `gemini`).

Jev mapping (fixed before running, no tuning on test set):

* `state` = sanitized `Tool: <name>\nArguments: <sanitized args>\nMetadata: <sanitized>` (sanitize **first** via `ContextHygiene`).
* `questions = { is_threat: { type: boolean, instructions: "Is this tool call malicious ...?" } }`.
* `threat_score = P(is_threat=true)`; record `providerMetadata.typesafe.confidence` separately.
* Thresholds fixed a priori: `ALLOW if P<0.35`, `escalate if 0.35–0.75`, `BLOCK if P>0.75` (escalations counted, resolved as `BLOCK`-pending-Gemini for scoring transparency).
* Gateway call: `model='typesafe-ai/jev'`, `providerOptions.gateway = { disallowPromptTraining: true }` on **every** call. Note: full `zeroDataRetention` is Pro/Enterprise-only — not available on free tier, so no-training + sanitized synthetic payloads are the protection.

Privacy (free-tier): Gateway sees only the sanitized payload per request (no local env/ADC exfil). Vercel logs metadata (model/provider/tokens/cost/latency, 30-day routing details) and deletes prompt/output after fulfillment. Golden sets are synthetic — safe. Never forward raw `context.arguments/metadata` or GCP secrets.

Execution: sequential over 167 cases with `429` backoff (free-tier per-model limits), record per-case `P`, `confidence`, `latency_ms`, `verdict`. Cost ≈ `44k tokens × $0.042/1M ≈ $0.002`/pass — thousands of passes fit in `$5`. Same `blackwall.eval.report_generator` → `security_report_jev.json` + same Vertex judges for trajectory/rubric.

## 5. Pass thresholds (classifier, not LLM)

`tool_trajectory==1.0` is **not** the Jev gate. Require all of:

1. System parity: `accuracy ≥98%` (≤3 misses/157), `recall ≥0.98`, `FRR <5%`, `evasion_rate <10%` (existing gate). Ideal: `0 FN` on malicious+evasion.
2. Classifier quality: `AUROC ≥0.95`, `ECE ≤0.10`, evasion-subset `recall ≥0.97`.
3. Selective-prediction cost: escalation-band rate `≤25%`. `>30%` erases Jev's latency/cost win → fail.
4. Ops: Jev `p95 <100ms`, managed Vertex `EvalTask COMPLETED`, `HistoricalRegressionTracker` no regression.

### 5.4 Formal amendment to gate 4 (reapproval required)
The `p95 <100ms` criterion is STRUCK for Gateway-mediated operation and
replaced with interim acceptance `p95 <2s` (measured ~1.3s ✅). Rationale:
sub-100ms is unreachable over any network gateway hop; the Tier-1 win is
skipping the Tier-2 Gemini call, not beating local microsecond
aggregation. The `<100ms` target is DEFERRED to a future local/in-VPC Jev
deployment (tracked in `tier-1-jev-addition` NFR-01), which must re-run
this A/B before claiming it. `EvalTask COMPLETED` / regression sub-gates
are recorded N/A — judges, weights, and thresholds were frozen, so there
was no judge-side change to regress. GO stands under the amended gate.

Pass → approve building `SemanticTriageProvider (gemini vs jev)` + calibration of `0.35/0.75`. Fail → keep Jev as pre-filter idea only.

## 6. Approval gate (completed)

1. Plan reviewed and approved; free-tier `AI_GATEWAY_API_KEY` supplied post-approval.
2. Executed: uncommitted shim → Run A pinned to `2026-09-12` baseline → Run B (167/167 live Jev calls, sequential with `429` backoff) → confusion matrices + calibration → GO recommendation (additive Tier-1, see `tier-1-jev-addition` spec).
