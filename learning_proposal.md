# Learning Proposal — PR #103 (Track D Evaluation Pipeline) Greploop Lessons

**Date:** 2026-08-30
**Status:** APPROVED WITH EDITS (2026-08-30) — Rule #45 (Greptile check-run interpretation) dropped per user. `.agents/rules/` intentionally NOT modified (separate agent will handle it); sections applied to `.qoder/rules/` only: architecture §53–§57, testing mirror sync of §44.
**Scope:** `.qoder/rules/architecture_and_security.md` + `.qoder/rules/testing_and_hygiene.md` (applied); `.agents/rules/*` deferred

## Background

PR #103 required 10+ Greptile review rounds plus two greploop iterations. The same failure classes recurred in different shapes across rounds: ground-truth copying into candidates, managed-evaluation gate bypass, SLA windows measuring the wrong operation, nonexistent detector method calls hidden by broad exception handlers, and silently discarded dataset records. Codifying these as rules prevents future agents from re-discovering them one review round at a time.

## Proposed Changes

### 1. Mirror-drift fix (no new content)

Sync `## 44. Automated Review Agent Circuit Breaker & Anti-Oscillation Protocol` from `.agents/rules/testing_and_hygiene.md` into the `.qoder/rules/testing_and_hygiene.md` mirror (the mirror currently lacks it). Preserve the mirror's `trigger: always_on` frontmatter.

### 2. architecture_and_security.md — append sections 53–57 (both files)

```markdown
## 53. Evaluation Candidate Provenance & No Ground-Truth Synthesis Invariant
* **Rule:** Evaluation pipeline domain workers (`scripts/run_gcp_eval.py` `_build_domain_worker`) MUST produce candidate outputs solely by executing the mapped security component against the scenario input. Copying ground-truth fields (`ground_truth_verdict`, `expected_*`) into candidate results is strictly prohibited. Scenarios whose domain has no mapped component MUST raise during worker preparation, producing an ERROR / `is_fallback=True` candidate that records an execution error and fails the CI gate, rather than fabricating a passing result.
* **Rationale:** Across 10+ PR #103 review rounds, variants of the same flaw recurred ("Ground truth masks misses", "Synthetic operations satisfy SLA", unmatched-domain passes). Ground-truth copying rewards missed detections; fabricated candidates let unevaluated behavior pass the pipeline.

## 54. Managed EvalTask COMPLETED Gate & Autorater Dataset Schema Invariant
* **Rule:** Pipeline runners MUST record a gate error for any managed Vertex AI `EvalTask` status other than `COMPLETED` (including `LOCAL_FALLBACK` when the harness runs with `allow_fallback=True`), so the CI exit code fails when the required managed evaluation never completed. Datasets submitted to Vertex EvalTask autoraters MUST expose the autorater input columns (`prompt`, `context`, `response`) built from the scenario payload, ground-truth context, and the executed candidate output; raw heterogeneous scenario dictionaries MUST NOT be passed through.
* **Rationale:** Treating only `FAILED` as a gate error lets local fallbacks pass CI without executing the required managed evaluation, and submitting raw scenario dicts to autoraters that require specific columns guarantees managed-run failure.

## 55. Scenario-Supplied Input Precedence & Dataset Domain Bridging
* **Rule:** Evaluation detector branches MUST consume scenario-supplied inputs (`events`, `trajectory`, `activity_stream`, `permission_grants`) and fall back to synthetic default events only when the scenario supplies none. Native dataset records lacking a `domain` field (e.g. `complex_attacks`) MUST be bridged into executable scenarios — deriving the domain from `threat_type` and materializing detector events from the record's own structure (`nodes_count`/`coordination_score`, `stages`, `destination`/`periodic_interval_s`) — instead of being silently discarded.
* **Rationale:** Manufacturing fixed high-risk events replaces the scenario's intended behavior with unrelated synthetic evidence, and silently discarding domain-less records means canonical domains never execute in default runs while the gate only checks represented domains.

## 56. Detector API Verification Before Worker Authoring
* **Rule:** Before writing evaluation workers or detector integrations, agents MUST verify the target component's actual API surface. Ingestion paths differ by detector: `ExploitChainAnalyzer` and `AgentSwarmDetector` ingest via `store.insert_event(...)` followed by `detect_chains(...)` / `detect_swarms(...)`; `AILMTracker` uses `track_permission_grant(...)` + `detect_permission_composition(...)`; `C2InfrastructureDetector` uses `record_event(...)` + `detect_c2_establishment(...)`; `AgentQuotaUsage` exposes `token_burn_rate_per_sec` (no `current_burn_rate` field exists).
* **Rationale:** Calls to nonexistent methods (e.g. `record_step`, `analyze_chain`) turn entire evaluation domains into silent ERROR fallbacks swallowed by broad exception handlers, masking that the component never ran.

## 57. SLA Measurement Window & Threshold-to-Operation Alignment
* **Rule:** Module imports and component construction MUST occur outside `SLAValidator.measure(...)` in an untimed preparation phase; only the security operation itself is timed. Every domain→SLA-component mapping MUST reference an explicitly defined threshold for the operation actually executed (an `eval_*` component in `DEFAULT_SLA_THRESHOLDS_MS`); borrowing thresholds that belong to different operations (TSG signature match, active reaction, structural gating) is prohibited.
* **Rationale:** First-run import latency (~1.7s for `blackwall.resolver`) counted as component latency broke sub-10ms SLA tests flakily, and thresholds belonging to other operations produced false SLA passes/violations and incorrect rubric caps.
```

### 3. testing_and_hygiene.md — append section 45 (both files, after §44)

```markdown
## 45. Greptile Check-Run Interpretation & Stale-Thread Hygiene
* **Rule:** When parsing Greptile results from check runs: `conclusion == "success"` MUST be interpreted as a 5/5 pass regardless of title text; otherwise parse the `N/5` score from the check-run output title. Inline findings MUST be fetched from GraphQL `pullRequest.reviewThreads` (not issue comments or the reviews API). After fixes are verified by tests and a passing re-review, threads from prior review rounds MUST be resolved via `resolveReviewThread` so the unresolved count reflects current state.
* **Rationale:** Failure titles on passing checks and stale unresolved threads from earlier rounds obscure true review state during greploop iterations, causing agents to re-fix resolved issues or report incorrect confidence.
```

## Not proposed (already covered elsewhere)

- Oscillation/churn control: covered by existing §44 (circuit breaker) — hence the mirror sync instead of a duplicate rule.
- Worktree/venv/Rust-build operational quirks: saved to Qoder project memory (environment-specific, not code invariants).

## Application plan (after approval)

1. Apply §2–§3 text to `.agents/rules/*.md` (canonical).
2. Mirror into `.qoder/rules/*.md` preserving `trigger: always_on` frontmatter, including the §44 sync.
3. Commit as `docs(rules): codify evaluation-pipeline greploop lessons from PR #103` on the PR branch (or a separate branch if preferred).
