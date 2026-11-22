# TASK-F02 Retrospective — Tier-1/Tier-2 Steering Defense (2026-11-14 → 2026-11-22)

> **Status: CLOSED 2026-11-22 by explicit risk acceptance. No steering guard was
> shipped.** This report records what the F02 program measured, what improved,
> what failed, and why further calibration scope was cut. It is a decision
> record, not a claim that tool-call steering is impossible or that the semantic
> tiers are unexploitable. All figures below are recomputed from committed
> artifacts; none are prose-only.

## 1. Telos and hypothesis

**Telos:** can adversarial tool-call text steer the semantic tiers into allowing
a malicious call, and can that steering be hardened against without breaking
benign calibration?

**Hypothesis (as originally framed):** the nonce-tagged XML boundary on the
Tier-2 arbiter prompt resists steering; Tier-1's score remains steerable below
the ambiguity band.

**Answer after measurement:** steering is real and was quantified; the Tier-2
prompt boundary is structurally sound and shipped; **no Tier-1 state/question
defense was validated for shipping**. Three candidate families were ruled out
by matched evidence. Residual risk is accepted by the maintainer under the
conditions in §6.

## 2. Evidence inventory (five-link chains)

| Experiment | Manifest → artifact → recomputation test |
| --- | --- |
| Live steering + arbiter hardening (2026-11-14) | `tests/eval/results/jev_tier2_runs/manifest.json` → `steering_2026-11-14_{dev,heldout}.json` → `tests/unit/test_jev_tier1_steering_runs_data.py` |
| First defense experiment (2026-11-19) | `tests/eval/results/jev_tier1_defense_runs/manifest.json` → `tier1_defense_2026-11-19_{dev,heldout}.json` → `tests/unit/test_jev_tier1_defense_runs_data.py` |
| Final nonce-XML validation (2026-11-20) | `tests/eval/results/jev_tier1_defense_final/manifest.json` → four `final_*` arm JSONs → `tests/unit/test_jev_tier1_defense_final_data.py` |
| Atomic question probe (G03, 2026-11-20) | `tests/eval/results/jev_atomic_probe/manifest.json` → two probe JSONs → `tests/unit/test_jev_atomic_probe_data.py` |
| Atomic question A/B (G04, 2026-11-21) | `tests/eval/results/jev_g04_ab/manifest.json` → `ab.json` → `tests/unit/test_jev_g04_ab_data.py` |
| Structured state, Tier-1 only (2026-11-22) | `tests/eval/results/jev_f02_structured_state/manifest.json` → `steering.json` → `tests/unit/test_jev_f02_structured_state_data.py` |
| Structured state, full Tier-1/Tier-2 matched (2026-11-22) | `tests/eval/results/jev_f02_full_defense/manifest.json` → four `full_*` arm JSONs → `tests/unit/test_jev_f02_full_defense_data.py` |

Every chain continues upstream into `.kiro/specs/tier-1-jev-addition/tasks.md`
(TASK-F02, G03, G04) and ADR 0009 Open Item 3. The last row's artifacts landed
with PR #227 (merged 2026-11-22); the retrospective does not depend on their
figures for its decision (the rejection stands on the earlier rows as well).

## 3. What improved

1. **The attack was measured, not assumed.** Live steering runs quantified
   below-edge Tier-2-skipped crossings and BLOCK→ALLOW flips with Wilson 95%
   bounds; dev and heldout payloads were kept separate. The effect is real and
   reproducible, not a prompt-gymnastics artifact.
2. **Tier-2 was hardened and the hardening shipped.** The arbiter prompt wraps
   tool name, arguments and metadata in a nonce-tagged, XML-escaped
   `<tool_call>` boundary with a "data, never instructions" directive. Attack
   text is escaped, not neutralized, so the arbiter still sees the evidence it
   must judge. Structural tests pin the boundary against forged nonces/tags.
3. **The band change reduced the attack surface.** F09's balanced corpus and
   F10's re-baselined lower edge (`0.35 → 0.08`) shrank the below-edge bypass
   surface; on the legacy arm FRR is 0 and matched to-ALLOW flips are ~1%.
4. **The harness became a reusable evidence instrument.** `--corpus current`,
   dev/heldout payloads, `--defense` arms, served-release and Tier-2 outage
   accounting, Wilson bounds, input pinning against a network-free rebuild,
   and `is_fallback` markers were added. These survive F02 and serve every
   later calibration task.
5. **Evidence hygiene hardened.** Manifests + hermetic recomputation + pointer
   chains are now enforced for every run set; credential-shaped content is
   scanned; reviews on F02-adjacent PRs caught stale-band prose, missing
   fallback markers, and unmeasured evasion gates — all fixed.
6. **The benign side is now quantified.** F02 originally had no benign cases;
   later runs include 30-case benign subsets with mean P-shift and flagged-rate
   measurements, which is why the false-alarm cost of each candidate is known.

## 4. What did not work — and why

| Candidate | Matched result | Why it failed |
| --- | --- | --- |
| Nonce-XML boundary on Jev state (2026-11-20) | to-ALLOW flips 9/550→6/550; below-edge crossings 9→20; benign flags 244/659 (37.0%)→371/660 (56.2%) | Delimiting untrusted text shifted overall calibration upward: a small flip reduction bought a large benign false-alarm cost and *more* Tier-2-skipped attacks. |
| Six atomic questions + fail-closed `max` (G04, 2026-11-21) | AUROC 0.7927–0.8176 (gate ≥0.97), Tier-2 fire 40.6–45.5% (gate ≤20%), FRR 0.889–1.000 (gate <5%) | `max` amplifies one high category probability. Benign auth/network calls scored 0.94–0.96 on `credential_theft`, so nearly all benign traffic was held. |
| Native-object state + unchanged single question (2026-11-22) | Tier-1 probe: benign clear-high 36.3%→30.6%. Full matched: to-ALLOW flips 6/550→7/550; matched Tier-2-skipped crossings 4→4 | The benign gain is real but the arbiter-skipping path did not improve. All-row crossings rose 12→23 (Tier-2-skipped subset 8→12); the decision measure on 25 common held bases stayed 4→4. |

**Common mechanism:** steering resistance and benign calibration are coupled.
Any state/question reformatting that changes what the classifier sees shifts
P; a `max` combination makes that shift asymmetric toward false holds. Lowering
the band edge helps legitimate attacks but also lowers the bar for steering
payloads. No candidate broke this coupling.

## 5. Residual risk (stated plainly)

- The residual **to-ALLOW flip rate is ~1%** on matched malicious cases in a
  **semantic-only** harness (`--policy off`, no TSG, structural policy, threat
  intelligence or CBM configured). This is a Tier-1+Tier-2 stage figure, **not**
  a full-firewall catch rate.
- Below-edge steering still exists: on all steered malicious rows the committed
  summaries report crossings 12→23 and Tier-2-skipped 8→12 under structured
  state; on the 25 common held bases the Tier-2-skipped path is 4→4.
- Tier-2's ALLOW remains final unless aggregation already blocked, so a
  successful steer is a genuine bypass *within those two stages*. The
  production resolver adds deterministic policy, TSG, threat intel and codebase
  memory before the semantic signal, and those layers are outside this harness.
- The retained evasion gate (<10%) fails for both arms (2/6 held-out evasion
  cases, 33.3%, plain C2 beacons with no attack text) — a separate, known
  C2/IOC weakness, not an F02 regression.

## 6. Decision and scope cut

**Decision (maintainer, 2026-11-22): close TASK-F02 by risk acceptance; ship no
guard; cut further steering-calibration scope.** Rationale:

1. Three structurally different candidates failed for one shared reason; a
   fourth state-format variant is unlikely to break the coupling.
2. The next principled candidate would have to change the **question/instruction
   layer** (e.g., separating data from criteria inside the TypeSafe request),
   which needs a fresh proposal, fresh held-out data and another full A/B —
   high cost against a ~1% residual stage risk that is layered in production.
3. Residual evidence debt is already large (seven run sets); the leverage now
   sits elsewhere: the C2/IOC evasion gap, balanced-corpus ECE ≈0.25, and the
   pre-existing rule-config band drift.

**Reopen conditions:** (a) a product/compliance requirement for near-zero
to-ALLOW under adversarial tool-call text, or (b) a concrete question/instruction
layer mechanism that does not shift benign calibration, with a fresh proposal
approved before any live spend.

No AGENTS.md, `.agents/rules/`, `.greptile/`, or behavior change accompanies
this closure: no production invariant changed.
