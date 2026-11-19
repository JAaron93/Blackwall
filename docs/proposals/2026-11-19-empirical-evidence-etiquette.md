# Implementation Plan: Empirical Evidence Recording Etiquette (2026-11-19)

## Classification

- **Rule change (constitution §6.3):** high-level invariant in root `AGENTS.md`, detailed
  etiquette in `.agents/rules/testing_and_hygiene.md`, pointer from `AGENTS.md` §5.
- **Evidence artifact addition:** committed JSON + manifest + recomputation test for the
  TASK-F03 Vertex quota burst calibration from PR #212.

## Rationale

The tier-1-jev-addition spec's Cluster 2 tasks treat *evidence* as the deliverable. Tasks
F01/F02/F05b/F07 pair their published figures with a committed per-run JSON set, a
`manifest.json`, and a hermetic recomputation test. PR #212 (TASK-F03) shipped its live
burst-test conclusions only as prose (ADR 0009 OI2, F03 task note, FR-08, rules) plus the
method script: the script printed to stdout and had no `--out`, so no raw result was
committed and no test anchored the numbers. Future agents can find the *conclusion* but
cannot diff against the *measurement*, and the pointer chain the spec relies on was
incomplete.

The user's explicit instruction (2026-11-19) — "add to the AGENTS.md on the proper
etiquette for recording results from empirical / calibration tasks … Just to be extra sure
future agents can always reference these experiments" — is recorded as the §6.3 explicit
user approval for the rule changes below.

## Exact diffs (summary)

1. `AGENTS.md` §5 — extend the `testing_and_hygiene.md` pointer with "empirical evidence
   recording etiquette". §6 — add item 6, **Empirical Evidence Integrity**: published C2
   figures are valid only with a committed machine-readable artifact, manifest, and
   recomputation test; stale or prose-only evidence is not evidence.
2. `.agents/rules/testing_and_hygiene.md` — new `## 80. Empirical & Calibration Evidence
   Recording Etiquette`: artifact + manifest + recompute requirement, script `--out`
   requirement and credential hygiene, the five-link pointer chain (task note → ADR →
   manifest → run JSON → recompute test), invalidation/regeneration duty, discarded-run
   recording, and reviewer guidance.
3. `scripts/vertex_quota_burst_test.py` — add `--out <path>` JSON export (stdout output
   preserved); schema version, production constants, model, per-policy counters.
4. `tests/eval/results/vertex_quota_runs/` — new `manifest.json` and
   `burst_2026-11-19.json` transcribing the merged PR's live re-run, including discarded
   invalid runs in the manifest.
5. `tests/unit/test_vertex_quota_burst_data.py` — hermetic recomputation test for the
   artifact (no network): manifest completeness, constants, figures, credential scan,
   and cross-document pointer check.
6. `.kiro/specs/tier-1-jev-addition/tasks.md` (F03 note) and
   `docs/adr/0009-...md` (OI2) — add the artifact/manifest/test pointers.
7. `docs/evaluation_guide.md` — new §8 documenting the quota burst run set, how to
   regenerate it with `--out`, and where the recomputation test lives.

## Guardrails honored

- Root `AGENTS.md` receives only a high-level invariant and a pointer (§6.1); granular
  rules live in the modular file (§6.2).
- No version pins in prose (§6.5). No `.env`, credentials, or project id in artifacts.
- New work on a dedicated feature branch/worktree; no direct commits to `main`.
