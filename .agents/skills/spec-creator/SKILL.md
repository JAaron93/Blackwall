---
name: spec-creator
description: Generates or updates technical specifications in a strict sequence (design.md to requirements.md to tasks.md) mimicking the Blackwall/Kiro spec pattern. Use this skill when the user asks to create a new project spec, draft architectural documents, or update an existing specification.
---

# Specification Creator (spec-creator)

This skill guides you through generating or updating technical specifications using a strict, three-document sequence, mirroring the structure used in the Blackwall Agentic Firewall (originally modeled after Kiro's specs).

## The Specification Sequence

You MUST generate or update the specifications in this exact sequence:
1. **`design.md`**: The architectural overview, components, and constraints.
2. **`requirements.md`**: Functional and Non-Functional Requirements (including TDD and BDD constraints) and User Stories, derived from the design.
3. **`tasks.md`**: The test-driven implementation plan, breaking down the requirements into actionable execution tracks.

## Formatting Guidelines

When drafting the specs (particularly `tasks.md`), adhere to the following best practices learned from the Blackwall development cycle:
- **Mirror the Kiro Structure**: Use clear headers, glossaries, and traceability metrics (e.g., tying tasks back to FR/NFR/US IDs).
- **Explicit Dependencies & Coupling**: Clearly state one-way dependencies under each task in `tasks.md` (which tasks must complete before others), AND document bi-directional coupling affinities — tasks that mutually inform or invalidate each other and must be planned together. See Task Clusters below.
- **Cluster-Tag Tasks**: When a spec mixes deterministic engineering with empirical/model-calibration or data-science work, tag every task `[C1]`/`[C2]`/`[hybrid]` and define the clusters near the top of `tasks.md`. See Task Clusters below.
- **Highlight Parallelism**: Be creative in highlighting tasks that can be completed in parallel. Use markdown features like GitHub alerts (`> [!TIP] PARALLEL EXECUTION`) or grouped "Tracks" to visually segment concurrent work from linear, sequential work.
- **TDD & BDD Rigor**: Explicitly incorporate Test-Driven Development (TDD) and Behavior-Driven Development (BDD) using Gherkin syntax as mandatory acceptance criteria.
- **Implementation Parity Guardrail (Zero-Drift Invariant)**: Never mark a subtask `[STATUS: COMPLETE]` in `tasks.md` if the underlying repository artifact (source code, unit tests, or dependency manifests like `requirements.txt`) does not satisfy the documented description. Manifests, implementation code, and spec statuses must remain in 100% lockstep.

## Task Clusters (Engineering Type)

When a spec mixes deterministic engineering with empirical work (model/ML
calibration, evaluation, data science), classify and tag every task so the two
kinds of work — which have very different gating and shipping timelines — are
visible at a glance. Place the definitions near the top of `tasks.md` and tag
each task header `[C1]`, `[C2]`, or `[hybrid]`. Keep task IDs stable when
re-grouping existing tasks; label and group, do not renumber (traceability to
FR/NFR/US IDs must survive).

- **`[C1]` Integration / engineering**: deterministic, bounded scope, test-first
  with mocks, no live model-behavior change. Gated on TDD and code review; ships
  on the normal engineering timeline.
- **`[C2]` Empirical calibration / data science**: measures or changes model
  behavior; requires live credentials/budget, labeled data, a held-out protocol,
  and statistical validation (e.g. AUROC / ECE / Wilson). Cannot be mock-validated
  and MUST NOT ship unvalidated. Gated on data, budget, and maintainer decisions —
  user decision-making is heavily involved and shipping timelines extend
  considerably.
- **`[hybrid]`**: both a deterministic part and an empirical part (e.g.
  measure-then-harden). The empirical part carries C2 gating; never treat the
  engineering part as validated while the empirical part is unmeasured.

Use the tags to drive planning: C1 tasks proceed independently of live budget;
C2 tasks must be sequenced around data, live-credential access, and decisions.
Give each C2 task or track a **telos** — the research question it answers, the
hypothesis it tests, and the decision its evidence informs. A C2 task's
deliverable is *evidence* (a committed, recomputed measurement), not code; a
`src/` change is only a validated consequence of an answer. Framing the work as a
question prevents shipping an unvalidated "fix" for a threat that was never
measured. Live-credential reads follow the harness's access settings (no per-read
approval is required); keep secret discipline — never print, log, write, or commit
credential values. For specs that integrate a model, name the skill and live-doc
source that C2 tasks must consult before implementation, and require live
validation artifacts before any `src/` change a C2 task proposes.

### Coupling Affinities

Beyond one-way `Dependencies:` lines, document **bi-directional couplings**. Add
a short "Coupling affinities" map near the cluster definitions; mark each link
bi-directional (`A ↔ B`) or one-way (`A → B`). Typical sources:

- A calibration decision that reshapes the surface another task measures (e.g. a
  threshold/band change alters which inputs reach a downstream stage).
- Two changes that each invalidate the same stored evaluation runs, forcing a
  shared re-score before reuse.
- A governance decision that determines whether a recurring re-validation task is
  needed.

Group coupled C2 tasks so their shared data/infrastructure and decision order are
apparent, and state which half of a hybrid task a coupling touches.

## Cascading Update Rules

When invoked to review or edit an *existing* spec, you MUST follow these cascading rules:

- **If `design.md` is edited**: You MUST subsequently update `requirements.md` and `tasks.md` to reflect the architectural changes.
- **If `requirements.md` is edited**: You MUST subsequently update `tasks.md` to reflect the new constraints. You DO NOT need to update `design.md`.
- **If `tasks.md` is edited**: You DO NOT need to update `design.md` or `requirements.md`. They may remain as is.

Always update in a "design-first" direction (Design -> Requirements -> Tasks). Never edit `tasks.md` first if the change requires an architectural shift; start at `design.md` and let the changes cascade down.
