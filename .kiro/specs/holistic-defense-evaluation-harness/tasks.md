# Implementation Plan: Holistic Defense Evaluation Harness

## Overview

This plan implements the harness in `design.md` against `requirements.md`, in the design's four phases. Phase 1 is the pure library, observers, offline stage pass, Composer with its differential test, and the Run_Set schema and Run_Store. Phase 2 adds the run protocol, the live whole-system and Forced_Table runs, the comparison notebook, the recompute tests and the mutation guard. Phase 3 adds the optional layers (IOC corpus, threat intelligence, CBM fixture, W3 to W5). Phase 4 adds the band study, the recommendation gate, the cross-link cell and the ADR.

Task ids are the numbers below (for example 6.1). The repository convention of a "Dependencies:" line and a requirement reference is kept inside each task. Requirement references use `X.Y` for requirement X, criterion Y. "Validates" lines cite the numbered correctness properties of `design.md`.

## Conventions that apply to every task

- Strict TDD (repository rule): write the named failing test or reproduction first and watch it fail with an assertion that names the missing behavior (Requirement 30.1, 30.2), then implement.
- Every commit goes to a feature branch only. No task pushes, merges, or commits to `main` or `master`. Before staging, check that no `.env` file, key, credential or `.sqlite` WAL file is in the payload.
- No task edits, creates, prints or reads a real `.env` file. A live credential is read only after the human names that variable in the current conversation (Human_Grant), from the environment of the child process, never logged or written.
- No task executes, imports or fetches a payload. Payloads are inert strings.
- No task changes `src/` outside `src/blackwall/holistic_eval/`, except the conditional task 5.3. This change edits neither `AGENTS.md`, `.agents/rules/` nor `.greptile/`.
- Property tests use Hypothesis with at least 100 examples, strategies that generate valid values only, and no more than 50% discards. Async BDD steps use `run_async`, and background tasks are flushed in the same coroutine as the scheduling call (rules 2, 13, 16, 75).
- Every property test, every BDD scenario and the `LX-wave` support are required sub-tasks. The only experiment that is optional is running `LX-wave` itself, which happens only when the maintainer explicitly requests it (Requirement 17.25).
- Live and grant-gated tasks say so, name the variable, and stay unchecked with a deferral note until a measured Run_Set exists (rule 74, Requirements 22.10, 22.11). They are never simulated, stubbed or mocked to claim acceptance.

## Tasks

### Phase 1: Pure library, observers, offline stage pass, Composer, Run_Store

Phase 1 tasks open no network connection and read no credential variable (Requirement 31.6).

- [ ] 1. Package foundation and the definition of caught
  - [ ] 1.1 Create the package skeleton, shared test guards and hygiene scans
    - Dependencies: none
    - Failing test first: `tests/unit/test_holistic_foundation.py` asserts that `import blackwall.holistic_eval` does not import `blackwall.eval`, that no pure module imports from the rest of `blackwall`, that a socket attempt fails the running test naming the destination, that reading `TYPESAFE_API_KEY`, `BW_OTX_API_KEY` or `BW_ABUSECH_AUTH_KEY` fails a Phase 1 test, that no `filterwarnings` entry suppresses a first-party warning, that no harness document names a dependency with a comparison operator and version number, that a measured figure in a harness document carries a dated-evidence label, and that the configured MCP server set is unchanged.
    - Create `src/blackwall/holistic_eval/__init__.py` (light, no heavy imports) and the shared guard fixtures in `tests/unit/conftest.py` additions scoped to `test_holistic_*`.
    - Add a scope test that a diff of this change against its base shows no changed file under `src/` outside `src/blackwall/holistic_eval/` (skipped with a stated reason when no base ref exists).
    - _Requirements: 1.6, 12.17, 20.13, 20.14, 21.29, 23.19, 29.24, 29.25, 29.26, 29.27, 29.28, 30.35, 30.36, 30.38, 31.6_

  - [ ] 1.2 Implement `caught.py`: Reading table, `outcome`, `rates` and the stage-flag table
    - Dependencies: 1.1
    - Failing test first: `tests/unit/test_holistic_caught.py` with the full decision table for both Readings, `ERROR`, invalid-argument errors, undefined rates, the sensitivity values, and the single-definition source scan (design, "Single-definition scan"). The scan parses every harness source file with `ast` (parse only, nothing imported or run), skips `caught.py`, and fails (naming module path and line) only on duplicated caught-ness logic: (a) a set, tuple, list or frozenset literal, or a `set`, `tuple`, `list` or `frozenset` call, whose members include both `"BLOCK"` and `"QUARANTINE"` (or `Decision.BLOCK` and `Decision.QUARANTINE`), or an `in` or `not in` test whose right-hand side is such a literal or a module-level name bound to one; (b) an assignment or return of an Outcome value (`Outcome.CAUGHT`, `Outcome.MISSED`, `Outcome.FALSE_ALARM`, `Outcome.CORRECT_ALLOW`, an `Outcome(...)` call, or the strings `caught`, `missed`, `false_alarm`, `correct_allow` where the target or the return annotation is `Outcome`). Verdict construction is permitted and must not be flagged: a comparison of a decision with a single literal to build a verdict, to prevent a `BLOCK` downgrade or to assign a Quarantine_Cause, and a check of why a verdict was returned.
    - The failing-first test for the scan carries its own fixtures in a temporary module. Failing fixtures (each must fail the scan and name path and line): a planted `{"BLOCK", "QUARANTINE"}`, a planted `x in ("QUARANTINE", "BLOCK")`, a planted `decision in STOPPING` with `STOPPING` bound to such a literal in the same module, and a planted `return Outcome.CAUGHT`. Passing fixtures (each must pass the scan): `decision != "BLOCK"`, `decision == "ALLOW"`, a `cause = "tier2_unavailable"` assignment for a QUARANTINE, and a `cause == "tier2_unavailable"` or `decided_by == "tsg"` check. A final check runs the scan over the real harness modules, including `compose.py` and `replay.py` once they exist, and expects no finding.
    - Implement `Reading`, `STOPPING_DECISIONS` (the one table), `Outcome`, `outcome`, `rates` (catch rate, false-alarm rate, error count, case count, sensitivity values) and the single stage-flag table with the named `CBM_FLAG_BLAST_CUT` constant labeled a proposal.
    - `UNMEASURED` records are excluded from `outcome` and `rates` and counted as Not_Measured.
    - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.22, 3.23, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 6.15, 6.16, 6.17, 6.18, 6.19, 6.20, 6.21, 6.22, 6.23, 6.24, 6.25, 6.26, 7.15_

  - [ ] 1.3 Implement `stats.py`: Wilson interval, Pass_Spread and AUROC
    - Dependencies: 1.1
    - Failing test first: `tests/unit/test_holistic_stats.py` with worked Wilson values at k = 0 and k = n, the 30-case small-group threshold, spread over a single valid Pass (0), exclusion of discarded Passes and of Passes with a different concurrency, and a zero-case group returning Not_Measured.
    - _Requirements: 13.20, 13.21, 13.22, 13.23, 13.25_

  - [ ] 1.4 Write property test for `outcome` determinism and label symmetry
    - **Property 1: Caught is deterministic and label-symmetric**
    - **Validates: Requirements 6.1, 6.2, 6.5, 6.6, 6.7, 6.8, 6.9, 6.15, 6.16**
    - Dependencies: 1.2
    - File: `tests/property/test_holistic_caught_properties.py`. Also covers Requirements 30.4, 30.5. The property includes the single-definition scan of task 1.2 run over the harness modules, with the same passing and failing fixtures.

  - [ ] 1.5 Write property test that the Blocked reading is contained in the Stopped reading
    - **Property 2: The strict reading is contained in the primary reading**
    - **Validates: Requirements 6.10, 6.11**
    - Dependencies: 1.2
    - Also covers Requirement 30.6.

  - [ ] 1.6 Write property test for interval sanity and Pass_Spread
    - **Property 16: Intervals are sane**
    - **Validates: Requirements 13.20, 13.21, 13.25**
    - Dependencies: 1.3
    - Also covers Requirement 30.18.

  - [ ] 1.7 Write property test that `rates` excludes `ERROR` rows from numerator and denominator
    - Dependencies: 1.2
    - Validates the exclusion rule of the definition of caught (design, "Definition of Caught").
    - _Requirements: 6.18, 6.19, 6.20, 30.20_

- [ ] 2. Records, Jev comparison bounds, Run_Store and strategies
  - [ ] 2.1 Implement `records.py`: dataclasses, JSON codec, schema checks
    - Dependencies: 1.2
    - Failing test first: `tests/unit/test_holistic_records.py` for the round trip of `CaseRecord` and `RunSetManifest`, floats stored unrounded in the shortest decimal form that decodes to exactly the same binary float (a decoded float equals the written float exactly, with no rounding to 4 places or any other count), a non-finite float (`NaN`, `inf`) rejected on write with an error naming the field and the record and nothing written for that record, `schema_version` rejection, the `Tier2Out` invariants (`fired` with `decision is None` if and only if `unavailable_reason` is a non-empty string; a `decision` that is not `None` requires `fired`, no `unavailable_reason` and a `threat_score`; not `fired` requires `decision`, `threat_score`, `latency_ms`, `http_status` and `unavailable_reason` all `None` and trigger `none`; a violation on construction or on read is a loader error naming the file with nothing partial returned) and the three Tier-2 states distinguishable with `is None` and never by truthiness (a measured-outage `Tier2Out` is truthy and must still read as no verdict), `ERROR` with no `error` or `decided_by != "error"` rejected, `demo_mode=True` refused at write, `quarantine_cause` set only for `QUARANTINE`, `decided_by` recomputed from stage outputs using `evaluate()` precedence, and a recorded not-executed stage distinguishable from a recorded negative.
    - Implement `StructuralOut`, `ContextOut`, `TsgOut`, `CbmOut`, `TiOut` (with its `source_corpus`, `corpus` or `ioc_corpus`, never absent), `JevOut`, `Tier2Out`, `CaseRecord`, `RunSetManifest`, `RunEntry` (1-based `interleave_position`, per-Pass `concurrency`, `valid`, `comparison_exclusion`), `TiRunSource` (`config_id`, `source_corpus`, `fixtures_digest`, a non-empty `statement`), `ForcedTableSource`, `ForcedTablePass`, `IndexerAgreement`, `CbmFixtureSource` (optional on the manifest: present only for a fixture-backed CBM row), `NotMeasured`, `BillingStatement`, and `Band` (`lo <= hi`, edges 0.0 to 1.0, zero width valid).
    - _Requirements: 1.3, 5.9, 5.10, 7.5, 7.6, 7.9, 7.10, 7.11, 7.20, 7.21, 10.1, 10.2, 10.3, 10.4, 10.5, 10.10, 10.11, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 11.10, 11.11, 11.12, 11.13, 11.14, 11.15, 11.16, 19.1, 19.12, 19.13, 20.21, 21.9, 21.31, 24.4, 25.10, 25.11, 25.12, 25.13, 29.30_

  - [ ] 2.2 Implement `jev_bounds.py` and its comparison test
    - Dependencies: 1.1
    - Failing test first: `tests/unit/test_holistic_jev_bounds.py` pins the three constants (0.10, 0.015, 1) and exercises exact-bound pass and just-beyond fail cases, per-case rounding to 2 places, an unrounded mean, a violation report naming metric, observed value, bound and case ids, and a source scan that finds no assignment to the constants outside this module.
    - The constants are never derived from the run under test. A bound may be raised only in a change that adds new dated evidence.
    - _Requirements: 12.11, 12.12, 12.13_

  - [ ] 2.3 Implement `store.py`: atomic writes, strict loaders, validation, secret scan
    - Dependencies: 2.1
    - Failing test first: `tests/unit/test_holistic_store.py` for atomic temp-then-rename writes and cleanup on failure, truncated and corrupt-file loader errors, `schema_version` rejection, exactly-once `(config_id, pass_index, case_id)` completeness with `ERROR` counted as one row, Corpus_Hash binding with named differing case ids, unique ordered `interleave_position`, concurrency exclusion reasons, a Stage in neither `runs` nor `not_measured` rejected, one `ForcedTableSource` per release, plan and snapshot digest recomputation required only when the Run_Set holds a fixture-backed CBM row (I-CBM-fixture, I-CBM-permuted, W4, W5, the `sinks mapped` row or an Indexer_Agreement row; a differing recorded digest rejected) while a Run_Set whose only CBM row is the default-CBM row (I-CBM-default, or a Whole_System_Run using the default CBM client) records no digest and is not rejected for lacking a `cbm_fixture` entry, every `TiOut` carrying a `source_corpus` that equals its run's `ti_runs` entry (a mismatch, or a threat-intelligence run with no entry, makes the manifest invalid; an `I-TI-corpus` row has `corpus` and an `I-TI-ioc` row has `ioc_corpus`), floats written unrounded and non-finite floats rejected on write with nothing written for that record (round-trip through the store, with the worked case of task 6.5), stub and synthetic rows rejected from efficacy tables, existing target directory refused, discarded Passes recorded with no per-case data, and the ContextHygiene secret scan that names files but never the matched text.
    - Implement the Run_Store and the manifest validator. No payload body, exception message body or credential value is stored.
    - _Requirements: 10.5, 10.6, 10.7, 10.8, 10.9, 10.12, 10.13, 10.14, 10.15, 10.16, 10.17, 11.1, 11.2, 11.17, 11.18, 11.19, 11.20, 11.21, 11.22, 11.23, 11.24, 11.25, 11.26, 19.1, 20.21, 20.31, 21.31_

  - [ ] 2.4 Provide shared Hypothesis strategies with a discard-ratio test
    - Dependencies: 2.1
    - Failing test first: `tests/property/test_holistic_strategies.py` fails if any strategy yields a value rejected by model validation or discards more than 50% of its examples.
    - Strategies for stage outputs, bands, readings, records and run sets live in `tests/property/holistic_strategies.py`.
    - _Requirements: 30.3, 30.22, 30.23_

  - [ ] 2.5 Write property test for serialization round trips
    - **Property 14: Serialization round-trips**
    - **Validates: Requirements 10.3, 10.4, 10.5, 10.8**
    - Dependencies: 2.1, 2.4
    - Generated records and manifests with finite floats decode to values equal to the originals with no float changed (stored unrounded, shortest round-trip form), and a generated non-finite float is rejected on write naming the field and the record. The recompute clause of the property (a composed verdict from stored values equals the live verdict within 1e-9) is exercised by task 6.5.
    - Also covers Requirement 30.17.

  - [ ] 2.6 Write property test that no credential-shaped string is committed
    - **Property 15: No credential-shaped string is committed**
    - **Validates: Requirements 10.13, 10.14, 10.17, 11.15, 12.16, 23.10**
    - Dependencies: 2.3, 2.4

  - [ ] 2.7 Write property test for quarantine provenance
    - **Property 17: Quarantine provenance is a partition**
    - **Validates: Requirements 7.5, 7.6**
    - Dependencies: 2.1, 2.4
    - Also covers Requirement 30.19.

- [ ] 3. Corpus loader and payload safety
  - [ ] 3.1 Implement `corpus.py`: `CorpusCase`, `load_corpus`, `corpus_hash`
    - Dependencies: 1.1
    - Failing test first: `tests/unit/test_holistic_corpus.py` for loading through `build_cases(["security", "evasion_proof"])` only, null-not-omitted metadata fields, exact `MALICIOUS` and `BENIGN` handling with the excluded list reported, `_HIGH_RISK_TOOLS` read from the Resolver (including the empty tool name), the Family rule order, the post-sanitization arguments hash, hash change on a one-character edit, aborts naming the suite, duplicate `case_id` or missing field with no partial Corpus, a failing test naming each case altered by the ContextHygiene password or `sk-` over-match (TASK-F08), and no pooling with the earlier ADR 0009 end-to-end corpus.
    - Also provide the state-hash digest the Manifest records. Loading is offline.
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12, 11.6_

  - [ ] 3.2 Add payload, fixture and egress-allowlist safety scans
    - Dependencies: 3.1
    - Failing test first: `tests/unit/test_holistic_payload_safety.py` with a static scan that fails (file and line) if `eval`, `exec` or `subprocess` receives a corpus-derived value, `shlex` and `ast.parse` well-formedness of payloads without compiling or importing them, an attack-fixture host check (RFC 5737, private ranges, `.example` only) naming fixture and value, the Jev request-body key allowlist (`model`, `state`, `questions`), a canary-credential sanitization check on the outbound body, and a check that only `evaluate()` is called per case so no tool runs for any verdict.
    - _Requirements: 29.1, 29.2, 29.3, 29.4, 29.5, 29.6, 29.7, 29.8, 29.9, 29.10, 29.11, 29.12, 29.13, 29.14, 29.15, 29.17, 20.15_

  - [ ] 3.3 Write property test that Run_Sets are complete and bound to the Corpus
    - **Property 13: Run sets are complete and bound to the corpus**
    - **Validates: Requirements 10.1, 11.18, 11.19, 11.20, 11.21**
    - Dependencies: 2.3, 3.1

- [ ] 4. Isolated stage runners (offline)
  - [ ] 4.1 Implement the context, structural and stored-Jev stage runners
    - Dependencies: 2.1, 3.1
    - Failing test first: `tests/unit/test_holistic_stages.py` asserting `run_context` equals the Resolver's own `_score_tool_name`, `_score_argument_novelty`, `_score_context` and `_extract_indicator` (built with `client=None`, `enable_semantic_triage=False`), structural output from `StructuralGatingEngine` with `policy.yaml` and role `production` (an unreadable policy gives Not_Measured with no substitute), Jev P loaded from the committed class-blind runs with the source run key and a missing P giving Not_Measured, flag edges at `lo`, `hi` and 0.30 (`P == lo` on, `P == hi` off for `jev_high`), and the pinned offline-computed driver counts (indicator extraction, keyword novelty, Tool_Name_Group) that fail naming figure, pinned value and observed value after a Corpus edit.
    - A Stage that cannot produce an output is recorded Not_Measured with a reason and the run continues.
    - _Requirements: 3.1, 3.2, 3.4, 3.5, 3.8, 3.9, 3.14, 3.15, 3.16, 3.17, 3.18, 3.19, 3.20, 3.21, 26.14, 26.15_

  - [ ] 4.2 Implement `tsg_seed.py`: Seeding_Modes, seeds and leakage controls
    - Dependencies: 2.1, 3.1
    - Failing test first: `tests/unit/test_holistic_tsg_seed.py` for exactly three modes with an unknown mode rejected and nothing written, cold writing zero seeds, `parent_only` one seed per distinct Parent_Case, `held_out_parents` a deterministic hash split, seeds built from the Parent_Case's own arguments only (a variant edit leaves the seed byte-identical), generalization with `AgentBehavioralAnalytics._generalize_payload` truncated to 512 characters, neutral intent text, `mitigationAction` `BLOCK`, no label word, `attack_type`, `evasion_type`, parent id or variant value in any matcher-read field, `leakage="seeded_case"` only on parents seeded in the current mode, `ERROR` and marked rows excluded from rates, empty-set rates Not_Measured, match path and seed pattern length recorded, `metadata.seeded_from` unread by the matcher, static graph with background tasks dropped and signature count unchanged, an explicit temporary database path, an abort if the default `./blackwall.db` is resolved, deletion of the temporary database on completion, error or interruption, parameter-bound writes only, and a discarded Pass on a seeding error or a cold-mode match.
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8, 17.9, 17.10, 17.11, 17.12, 17.13, 17.14, 17.15, 17.16, 17.17, 17.18, 17.19, 17.20, 17.21, 17.22, 17.23, 17.24, 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.9, 18.10, 29.18, 29.19, 29.20, 29.21, 29.22_

  - [ ] 4.3 Implement the default-CBM isolated runner and its characterization tests
    - Dependencies: 4.1, 6.1
    - Failing test first: `tests/unit/test_holistic_cbm_default.py` pinning blast radius 2 and score 0.1 for every unknown tool name, identical scores for two queries with different arguments, `base_url` re-asserted `None` after resolver construction with a policy server, and a CBM-only contribution giving an aggregate below 0.50 and `ALLOW`.
    - Record `mapped_sinks` and `raw_sinks` for every CBM row. A tool with no `raw_sinks` gives Not_Measured for the `sinks mapped` what-if.
    - _Requirements: 3.11, 5.14, 5.15, 5.16, 21.8, 21.12, 21.15, 21.19, 21.22_

  - [ ] 4.4 Write property test that TSG results are order-independent
    - **Property 12: TSG results are order-independent**
    - **Validates: Requirements 18.8**
    - Dependencies: 4.2, 2.4. Also covers Requirement 30.16.

  - [ ] 4.5 Write property test that held-out seeding never leaks into the scored set
    - **Property 18: Held-out seeding never leaks into the scored set**
    - **Validates: Requirements 30.15, 17.19, 18.3, 18.4**
    - Dependencies: 4.2, 2.4

- [ ] 5. Stage_Recorder, configurations and the observer contingency
  - [ ] 5.1 Implement `configs.py`: `ConfigSpec`, `build_resolver`, `describe_layers`
    - Dependencies: 4.2, 4.3
    - Failing test first: `tests/unit/test_holistic_configs.py` asserting that `demo_mode=True` is refused at validation before any Resolver call or Run_Set, that a configuration differing from Production_Mode (thresholds 0.75 and 0.50) aborts before any case, that `metadata=None` is passed, that `describe_layers` prints each optional Layer as enabled or disabled, that every Manifest `ConfigSpec` value equals the value passed to `build_resolver`, that a construction failure is recorded Not_Measured and the run continues, that an empty-database TSG and `repo=None` give identical decisions and scores over every Corpus case with stubbed Jev and Tier-2 and no network, and that `base_url` is re-asserted `None` for CBM rows.
    - One Resolver per configuration and Pass, never shared across Passes or configurations.
    - _Requirements: 1.1, 1.2, 1.5, 1.8, 1.9, 1.11, 4.8, 4.9, 4.10, 4.11, 4.12, 4.13, 4.14, 4.21, 4.22, 4.23, 21.8_

  - [ ] 5.2 Implement `observers.py`: `ObservedResolver`, wrappers and per-task traces
    - Dependencies: 5.1, 4.1
    - Failing test first: `tests/unit/test_holistic_observers.py` asserting every wrapped component returns an equal value or raises the same exception type and arguments, per-task `ContextVar` Case_Traces stay separate under concurrent cases on a shared Resolver, a not-executed Stage is distinguishable from a negative output, `evaluate()` raising records `ERROR` plus the exception class with no message and keeps earlier Stage outputs, the TSG match path (`fts` or `substring`), CBM radius, mapped and raw sinks, Tier-2 trigger derived from recorded values and equal to `_maybe_escalate_tier2` over generated inputs including `lo`, `hi`, 0.2, 0.4 and one step either side, Tier-2 latency and HTTP status, a Tier-2 call that gave no verdict recorded as a measured outage (`fired` true, `decision` `None`, a non-empty `unavailable_reason`) and distinguishable from a Tier-2 call that never fired, a 429 recorded as class name and status only, background tasks (`_schedule_task`, `_schedule_attribution`) dropped with coroutines closed and no "never awaited" warning, no signature written, a ContextHygiene failure recorded as `ERROR` with nothing sent, an incomplete-trace count, and an empty diff of production source before and after a run.
    - Attribute assignment on the Resolver instance only, as `scripts/jev_tier2_eval.py` does.
    - _Requirements: 1.4, 1.10, 4.15, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 5.12, 5.13, 5.14, 5.15, 5.16, 5.17, 5.18, 5.19, 5.20, 5.21, 5.22, 5.23, 5.24, 5.25, 5.26, 5.27, 7.9, 7.10, 18.6, 18.7, 24.14, 24.15, 29.16_

  - [ ] 5.3 (CONDITIONAL) Add the optional `observer` argument to `SyncResolver.evaluate`
    - Dependencies: 5.2
    - Do this task only if 5.2 shows that wrapping cannot capture a Stage output. If wrapping suffices, leave it unchecked and remove it with a note. No seam is planned (Q9).
    - Failing tests first, delivered as their own change: a test that fails before the change, and a test that `evaluate()` with the default `observer=None` returns the same decision and confidence score as before. This is the only permitted edit under `src/` outside `src/blackwall/holistic_eval/`.
    - _Requirements: 1.7_

  - [ ] 5.4 Write property test that no tool executes for any verdict
    - Dependencies: 5.2, 2.4
    - Generated cases through the observed Resolver never invoke the named tool, including `ALLOW` and `QUARANTINE`.
    - _Requirements: 29.3, 30.21_

- [ ] 6. Composer and its fidelity to the Resolver
  - [ ] 6.1 Implement `compose.py`: `ComposeConfig`, `compose_verdict`, `UNMEASURED`
    - Dependencies: 2.1
    - Failing test first: `tests/unit/test_holistic_compose.py` with the decision table at aggregate scores 0.4999, 0.50, 0.7499 and 0.75, Jev P at 0.349, 0.35, 0.75 and 0.751 under the shipped Band, a zero-width Band composing, rejection naming the field for an unknown Tier-2 mode, a Band with `lo > hi` or an edge outside 0.0 to 1.0, a threshold outside 0.0 to 1.0, and a quarantine threshold above the block threshold, TSG and structural short-circuits, a structural BLOCK neither triggering Tier-2 nor reading its output, a BLOCK never downgraded in any Tier-2 mode, the three Tier-2 modes (`recorded`, `absent`, `unavailable`), `unavailable` turning a triggered ALLOW into `QUARANTINE` with cause `tier2_unavailable`, no Stage invocation or network call, and rejection of any Stage_Flag or flag policy input.
    - Failing-first cases for the three Tier-2 states of a triggered case under mode `recorded` (design, "`compose_verdict`"), the three branches mutually exclusive and each chosen by an explicit `is None` test and never by truthiness. Because a `Tier2Out` is a dataclass instance and always truthy, each case is built with real `Tier2Out` objects and the test fails if a measured outage is read as a verdict:
      - (a) no Tier-2 output (no forced entry and no `Tier2Out` with `fired` true, so no verdict and no recorded reason) and a prior decision that is not `BLOCK` returns `UNMEASURED` immediately, which is not an `ALLOW`, `QUARANTINE`, `BLOCK` or `ERROR`; a prior `BLOCK` returns `BLOCK` and reads nothing.
      - (b) a recorded measured outage (`decision=None` with a non-empty `unavailable_reason`) behaves exactly like mode `unavailable`: a prior `ALLOW` becomes `QUARANTINE` with cause `tier2_unavailable`, a prior `QUARANTINE` or `BLOCK` is unchanged, and the result is never `UNMEASURED`.
      - (c) a recorded verdict (`ALLOW` or `BLOCK` with a `threat_score`) is used as recorded, its `threat_score` is the semantic input, and a prior `BLOCK` is never downgraded by it.
      - The Tier-2 source order (the `forced` argument when it is not `None`, otherwise the row's own output when `fired` is true, otherwise nothing) is pinned, including that a Forced_Table replay that clears the row's own output and finds no forced entry is branch (a) and is never filled from the live run.
    - A recorded `ERROR` row is never passed in. The Composer restates only the aggregation and decision lines of `evaluate()` and the context-score arithmetic.
    - This task is the decision-table task that the differential test (6.2), the mutation guard (15.1) and the Property 10 test (8.5) refer to for the three Tier-2 states.
    - _Requirements: 3.22, 7.5, 7.6, 8.1, 8.2, 9.1, 9.2, 9.3, 9.4, 9.5, 9.7, 9.8, 9.9, 9.10, 9.11, 9.12, 9.13, 9.14, 9.16, 9.17, 21.22_

  - [ ] 6.2 Write the differential test of the Composer against the real Resolver
    - **Property 5: The composer matches the resolver**
    - **Validates: Requirements 9.4, 9.15, 9.16, 9.17**
    - Dependencies: 6.1, 2.4
    - NOT optional. Failing test first: `tests/property/test_holistic_compose_differential.py` builds a real `SyncResolver` with stubbed Stage components returning generated values and runs at least 200 generated cases per execution, failing with the generated inputs reported if decision differs or score differs by more than 1e-9. The generated Tier-2 stubs cover a verdict, a measured outage (no verdict with an unavailable reason) and Tier-2 not firing, so the three states of task 6.1 are compared against the Resolver.
    - Add the finding report for a Composed_Row that differs from a recorded Whole_System_Run decision (case id, configuration, both decisions) and zero findings when none differ, skipping recorded `ERROR` rows.
    - _Requirements: 9.6, 9.15, 9.18, 9.19, 30.9_

  - [ ] 6.3 Write property test that Stage_Flags never feed system verdicts
    - **Property 6: Stage flags never feed system verdicts**
    - **Validates: Requirements 8.1, 8.2, 3.22**
    - Dependencies: 6.1, 2.4. Also covers Requirement 30.10.

  - [ ] 6.4 Write property test that catch and false-alarm sets are monotone in the additive Stages
    - **Property 7: Catch and false-alarm sets are monotone in the additive stages**
    - **Validates: Requirements 9.7, 9.9, 9.11**
    - Dependencies: 6.1, 2.4. Also covers Requirement 30.11.

  - [ ] 6.5 Add the stored-float recompose test (unrounded storage survives store, load and recompose)
    - Dependencies: 2.3, 6.1
    - Failing test first: `tests/unit/test_holistic_store_recompose.py` takes the worked case from the design: a Tier-2 `threat_score` of 0.3333 and a `tool_score` of 0.1 with no other signal give a context score of `0.1*0.5 + 0.3333*0.5 = 0.21665` and an aggregate of 0.064995. The test writes the record through the Run_Store, loads it, recomposes through `compose_verdict` and requires the recomposed score to equal the live score within 1e-9 and the decision to be equal. It also asserts that every float read back equals the float written exactly, and that a store which rounds to 4 places (which turns 0.064995 into 0.0650) would fail this test.
    - Rounding is applied only when a figure is rendered, when a recomputed rate is compared with a cited figure, and when a per-case Jev P difference is rounded to 2 decimal places for the bound test of task 2.2. The test scans the store and codec modules and fails on any `round(` or formatting call applied to a stored calculation input or score.
    - _Requirements: 10.5, 9.6, 12.4, 12.11_

- [ ] 7. Ablation, comparison tables and report statements
  - [ ] 7.1 Implement `ablation.py`: Catch_Partition, leave-one-out and add-one-in
    - Dependencies: 6.1, 1.2, 1.3
    - Failing test first: `tests/unit/test_holistic_ablation.py` with worked examples of each partition class, `ERROR` and `UNMEASURED` cases excluded and counted separately, `unique` listing only enabled Stages with the Tier-2 form label (`absent` or `unavailable`, never merged), add-one-in for Jev, Tier-2 or aggregation reported Not_Measured because they are in B0, Jev-disabled recomposition labeled, a missing recomposition input giving Not_Measured with no partial assignment, and identical results under record reordering.
    - _Requirements: 8.6, 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8, 13.9, 13.10, 13.11, 13.12, 13.13, 13.14, 13.15, 13.16, 13.17, 13.24_

  - [ ] 7.2 Implement `report.py`: groupings, paired-reading tables and mandatory statements
    - Dependencies: 7.1
    - Failing test first: `tests/unit/test_holistic_report.py` for four groupings with `no_attack_type`, both Readings in adjacent cells, one-decimal percentages with denominators, quarantine fail-closed count columns showing 0, the fail-closed share rendered Not_Measured (never `0.0%`) when nothing is caught, the `ERROR` count and the sensitivity column only on Whole_System_Run and Composed_Row catch tables, `kind` labels with a Composed_Row never labeled whole-system, Stage_Gate versus Stage_Flag labels with Layers listed or `none`, the report header (`demo_mode`, Layers on and off, the `environment_role=production` sensitivity statement, the QUARANTINE-does-not-execute and no-human-review statements), the CBM-cut proposal label, and the maximum-aggregate statement with its non-zero exit when the maximum reaches 0.50.
    - _Requirements: 1.8, 1.11, 3.13, 3.21, 3.23, 4.24, 4.25, 6.25, 7.1, 7.2, 7.7, 7.8, 7.12, 7.13, 7.14, 7.16, 7.17, 7.18, 7.19, 8.3, 8.4, 8.5, 8.7, 8.8, 13.18, 13.19, 13.20, 13.21, 13.22, 13.23_

  - [ ] 7.3 Write property test that the attack partition is exact
    - **Property 8: The attack partition is exact**
    - **Validates: Requirements 8.6, 13.1, 13.2, 13.4, 13.5, 13.6, 13.7, 13.8, 27.27, 30.12**
    - Dependencies: 7.1, 2.4

  - [ ] 7.4 Write property test that aggregates are invariant under case reordering
    - **Property 3: Aggregates are invariant under case reordering**
    - **Validates: Requirements 13.24**
    - Dependencies: 7.1, 2.4. Also covers Requirement 30.7.

- [ ] 8. Band_Replayer, outage drill and held-out split
  - [ ] 8.1 Implement `replay.py`: `replay_band`, `outage_drill`, `split_by_group`
    - Dependencies: 6.1, 2.1
    - Two separate pieces, kept apart in code and in tests: `replay_identity` and `variation_report`. Only `replay_identity` can fail.
    - Failing test first for `replay_identity`: `tests/unit/test_holistic_replay.py` replays the run's OWN recorded Jev P and its OWN recorded Tier-2 output (a verdict or a recorded measured outage) at the recorded configuration and the shipped Band and requires, for every non-`ERROR` row, a verdict equal to the recorded `final_decision` and quarantine cause exactly, and a score within 1e-9 of the recorded `final_score`. A deliberately wrong Composer fixture makes it fail and list each differing case with its recorded and replayed verdicts. A recorded `ERROR` row is carried through unchanged at every Band (including the shipped Band), keeps its recorded `error` class, is never passed to the Composer, is excluded from every rate, is counted, and is never listed as a difference.
    - Failing test first for `variation_report`: a Forced_Table replay (the stored Jev P of the release run with the independently measured Forced_Table, clearing the row's own Tier-2 output before composing, so a case with no Forced_Table entry is `unmeasured` and never filled from the live run) is compared with the live run in a separate report that lists each case whose decision differs with its cause (Jev P difference, Tier-2 difference or both). A listed difference never makes `replay_identity` fail, never appears in the identity result and never fails a test.
    - Further cases in the same module: `lo > hi` skipped, `lo == hi` replayed, an edge outside 0.0 to 1.0 or a non-number rejecting the whole request with no cell, no network connection during replay, `n_unmeasured` for a missing Tier-2 entry or a missing Jev P with no imputation, a release replaying only its own P and Forced_Table (swap the other release in and the result must not change), the per-Pass error band (Not_Measured with fewer than two Passes), Tier-2 share with `ERROR` and unmeasured excluded from the denominator, per-Tool_Name_Group and per-Family rates, the outage count per cell (Not_Measured, not 0, when no case can be recomputed), the Clear_High_Variant labeled hypothetical, and a parent-grouped SHA-256 parity split that is order and process independent.
    - Production files stay byte-identical before and after any replay.
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9, 15.10, 15.11, 15.12, 15.13, 15.14, 15.15, 15.16, 15.17, 15.18, 15.19, 15.20, 15.22, 15.23, 15.24, 15.25, 15.26_

  - [ ] 8.2 Write property test that Tier-2 load is monotone in the Band
    - **Property 9: Tier-2 load is monotone in the band**
    - **Validates: Requirements 15.21, 30.13**
    - Dependencies: 8.1, 2.4

  - [ ] 8.3 Write property test that the held-out split keeps families together
    - **Property 11: The held-out split keeps families together**
    - **Validates: Requirements 15.22, 15.23, 15.24, 15.25**
    - Dependencies: 8.1

  - [ ] 8.4 Write property test that replay reproduces the shipped system
    - **Property 4: Replay reproduces the shipped system**
    - **Validates: Requirements 9.1, 9.6, 9.18, 9.19, 15.5, 15.6**
    - Dependencies: 8.1, 6.2. Also covers Requirement 30.8.
    - The property runs `replay_identity` over generated recorded runs using each run's own recorded Jev P and own recorded Tier-2 output (a verdict or a measured outage), and requires an exact decision and cause match and a score within 1e-9 for every non-`ERROR` row, with every `ERROR` row carried through unchanged at the shipped Band and at any other Band and never reported as a difference. It does not include a Forced_Table replay: a generated Forced_Table replay that differs from the live run appears only in `variation_report` and never fails the property.

  - [ ] 8.5 Write property test that Unmeasured is never imputed
    - **Property 10: Unmeasured is never imputed**
    - **Validates: Requirements 9.12, 9.13, 9.14, 15.1, 15.17, 15.18, 15.19, 15.20**
    - Dependencies: 8.1, 6.1. Also covers Requirement 30.14.
    - Exercises the three Tier-2 states of task 6.1 under mode `recorded`, each chosen by `is None` and never by truthiness: no Tier-2 output on a triggered case with a prior decision that is not `BLOCK` gives `UNMEASURED` (not a decision and not `ERROR`) and an `unmeasured` replay cell excluded from every numerator and denominator with no value substituted; a recorded measured outage (`decision=None` with an unavailable reason) is never `UNMEASURED` and behaves like mode `unavailable` (a prior `ALLOW` becomes `QUARANTINE` with cause `tier2_unavailable`, a prior `QUARANTINE` or `BLOCK` unchanged); a recorded verdict is used as recorded and never downgrades a `BLOCK`. A replay of a Jev release reads only that release's own stored P and Forced_Table.

- [ ] 9. Offline pipeline, first committed Run_Set and Phase 1 BDD
  - [ ] 9.1 Implement the hermetic launcher and the CLI skeleton with `stages` and `validate`
    - Dependencies: 2.3, 3.1, 4.1, 4.2, 4.3
    - Failing test first: `tests/unit/test_holistic_cli_offline.py` for `env -i` child launch with a fresh empty scratch `HOME`, `PYTHON_DOTENV_DISABLED=1`, an empty `CLOUDSDK_CONFIG`, HTTPS blocked where the platform allows it and a notice where it does not, deselection of `sla_benchmark`, `gcp_eval` and `vertex_evaluation` marks without a Human_Grant, refusal to create a Run_Set that exists, `demo_mode=True` refusal, seed validation (an integer from 0 to 4294967295 from the option or the single default constant, invalid values reported before any Pass with a non-zero exit and no Run_Set), the seed written to the Manifest, identical permutations and splits for the same seed and Corpus_Hash, and a Phase 1 guard that aborts naming the target on any Vertex, TypeSafe or OTX request or read of `TYPESAFE_API_KEY` or `BW_OTX_API_KEY`.
    - Create `scripts/holistic_eval.py` with the `stages` and `validate` subcommands. The scripts self-bootstrap `sys.path` (rule 76).
    - _Requirements: 1.2, 11.24, 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.13, 23.14, 23.21, 29.29, 29.30, 29.31, 29.32, 31.1, 31.6, 31.7_

  - [ ] 9.2 Run the offline stage pass and commit the first Run_Set (hermetic, no network)
    - Dependencies: 9.1
    - Failing test first: `tests/unit/test_holistic_offline_runset.py` validates the committed Run_Set against the Corpus and schema, records the structural, context, TSG (cold, `parent_only`, `held_out_parents`), default CBM and stored-Jev outputs for every case, and records every row that lacks a prerequisite (I-T2, I-TI, fixture-backed CBM rows) as Not_Measured with its reason. The default-CBM row (I-CBM-default) is recorded here and needs neither the Fixture_Plan nor the snapshot: the Run_Set carries no `cbm_fixture` entry and no plan or snapshot digest, and the test asserts the Run_Set validates without them. This task has no dependency on any Phase 3 fixture task (20.x to 23.x).
    - Commit the output to a new directory under `tests/eval/results/holistic/` on a feature branch. No existing results directory is touched.
    - _Requirements: 3.1, 3.2, 3.18, 3.19, 4.8, 4.16, 4.17, 4.18, 4.20, 11.1, 11.2, 11.16, 22.2, 22.3, 22.4, 22.5, 31.2, 31.4, 31.5_

  - [ ] 9.3 Write the Phase 1 BDD scenarios and step definitions
    - Dependencies: 1.2, 6.1, 8.1
    - Create `tests/features/holistic_defense_evaluation.feature` and `tests/step_defs/test_holistic_defense_evaluation_steps.py` with scenarios for a Stage_Flag never counted as a system catch, a QUARANTINE reported under both Readings with different caught results, and an identity replay of the run's own recorded Jev P and Tier-2 output at the shipped Band reproducing the recorded run with a recorded `ERROR` row carried through (a Forced_Table replay that differs from the live run is not part of this scenario and is never an identity failure). Async steps use `run_async` and flush background tasks in the same coroutine.
    - _Requirements: 30.24, 30.25, 30.28, 30.29, 30.30_

- [ ] 10. Checkpoint - Phase 1 acceptance
  - Ensure all tests pass, including every Phase 1 property test (Properties 1 to 18 of the design), ask the user if questions arise. Confirm the run made no network call and read no credential variable.

### Phase 2: Run protocol, live whole-system runs, Forced_Tables, notebook, recompute tests, mutation guard

- [ ] 11. Phase 2 entry gate
  - [ ] 11.1 Prepare the constitution proposal artifact (exact diffs), awaiting maintainer approval
    - Dependencies: 9.2, 9.3
    - Prepare a proposal artifact with exact diffs for the `AGENTS.md` section 2 spec list and for a testing rule that defines "caught", awaiting maintainer approval under `AGENTS.md` section 6.3 (Q7). It must exist before the first live Whole_System_Run (task 18.1).
    - This spec's change edits neither `AGENTS.md`, `.agents/rules/` nor `.greptile/`. The proposal is a document only, and nothing is staged against those paths.
    - _Requirements: 31.27, 31.28_

- [ ] 12. Run protocol, CLI live infrastructure, billing (all tested hermetically with stubs)
  - [ ] 12.1 Add the `plan` subcommand
    - Dependencies: 9.1, 5.1
    - Failing test first: `tests/unit/test_holistic_cli_plan.py` asserting zero network connections and exit 0 in under 5 seconds, each Layer enabled or disabled, the resolver mode, per-configuration planned call counts for Jev, Tier-2 and OTX, the Jev and Tier-2 model identifiers, the Vertex project that would be billed, every hostname, the variable names that need a Human_Grant (never values), and an unresolved project printed with its reason and a non-zero exit.
    - _Requirements: 25.1, 25.2, 25.3, 25.4, 25.5, 25.6, 25.7, 25.8, 25.9_

  - [ ] 12.2 Implement `grants.py`: Human_Grant gating, Named_Explicitly versus Default_Plan, `--concurrency`
    - Dependencies: 12.1
    - Failing test first: `tests/unit/test_holistic_grants.py` for a Named_Explicitly row (id in `--configs`) missing its credential exiting non-zero naming the variable before any client, network call or record (`GCP_PROJECT` and `GOOGLE_CLOUD_PROJECT` for Vertex, `TYPESAFE_API_KEY` for Jev, `BW_OTX_API_KEY` for threat intelligence), a Default_Plan row missing a credential, grant, fixture or transport recorded Not_Measured with a reason (beginning `no grant` and naming `BW_OTX_API_KEY` for threat intelligence) while the run continues, a missing fixture or transport Not_Measured even when Named_Explicitly, no stub substituted, only the granted variable passed to the child through its environment (never an argument or file), grants not carried into a new conversation, `--concurrency` non-integer or below 1 rejected naming the option and minimum before any case with 2 as default, and no read of any `.env` file other than `.env.example`.
    - _Requirements: 4.8, 19.16, 19.17, 22.1, 22.2, 22.3, 22.4, 22.5, 23.7, 23.8, 23.9, 23.10, 23.11, 23.12, 23.15, 23.16, 23.17, 23.18, 23.20, 31.11, 31.12, 31.14, 31.15_

  - [ ] 12.3 Implement `runner.py`: Pass orchestration, pacing, invalidation and re-runs
    - Dependencies: 5.2, 2.3
    - Failing test first: `tests/unit/test_holistic_runner.py` with a stubbed observed Resolver for at most N cases in flight and exactly N while N or more remain unstarted (N of 1, 2 and above the case count, order of completion never reaching a figure), N recorded per Pass, Passes with a different N excluded from the valid-Pass count, Pass_Spread and release comparisons with a reason, interleaving of Pass 1 across configurations in one fixed order before Pass 2, 1-based unique interleave positions with a re-run taking the next unused one, the default 30-second cool-down recorded, a Tier-2 429 (including one a retry completes) or any `rate_limit` row or a release mismatch invalidating the whole Pass with a `discarded_passes` entry and no per-case data, at most 3 re-runs then Not_Measured, fewer than two valid same-N Passes recorded Not_Measured, Jev failure and typed threat-intelligence errors recorded as `ERROR` rows with the Pass kept valid, `rate_limit` listed as a harness defect, release requested by explicit name, served release recorded, and between-release differences labeled real only above the larger within-release spread.
    - _Requirements: 4.12, 4.13, 4.14, 4.15, 11.10, 11.11, 11.25, 11.26, 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7, 24.8, 24.9, 24.10, 24.11, 24.12, 24.13, 24.14, 24.15, 24.16, 24.17, 24.18, 24.19, 24.20, 24.21, 24.22, 24.23_

  - [ ] 12.4 Implement the per-release Forced_Table builder
    - Dependencies: 12.3, 4.1
    - Failing test first: `tests/unit/test_holistic_forced_table.py` with a stubbed Tier-2 backend: one table per release (`jev-1.13.0` and `jev-1.14.0`) from run 1 of that release's stored class-blind run, Tier-2 run on every case with that Jev P, two Passes per table recorded by release name and `pass_index`, a release with no named run or a missing P Not_Measured with the other release unaffected, Tier-2 no-verdict recorded Not_Measured and never as BLOCK, and the Jev P shown to Tier-2 recorded.
    - _Requirements: 3.24, 3.25, 3.26, 3.27, 5.20, 11.9, 24.24, 24.25, 24.26_

  - [ ] 12.5 Wire the `run` subcommand and Manifest assembly
    - Dependencies: 12.2, 12.3, 12.4, 12.6
    - Failing test first: `tests/unit/test_holistic_cli_run.py` with stubbed clients asserting the configuration printed before any case, the Manifest content (construction per configuration, Jev and Tier-2 sources, run entries, discarded Passes, call and token counts for valid and discarded Passes, grant names and dates, Not_Measured entries, one `ti_runs` entry per threat-intelligence run naming its source corpus (`corpus` for I-TI-corpus, `ioc_corpus` for I-TI-ioc) with the statement that every indicator sent to OTX in that run comes from the committed fixtures of that corpus, a `cbm_fixture` entry only when a fixture-backed CBM row ran, dependency references to ADR 0008, ADR 0009, `tier-1-jev-addition` and rules 56, 58, 64, 70, 71, 72, 74, 77, 78 and 79), the billing statement stored before the first live call (no call when it cannot be stored), and an end-of-run statement.
    - _Requirements: 1.8, 4.10, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.12, 11.13, 11.14, 11.15, 11.16, 11.17, 20.21, 24.7, 25.17, 25.18, 25.19, 29.30, 31.29_

  - [ ] 12.6 Implement `billing.py`: billing, token counts and run-time cost
    - Dependencies: 12.1
    - Failing test first: `tests/unit/test_holistic_billing.py` for the Manifest billing fields (project or account, models, per-run call counts including `ERROR` cases, token counts with unavailable counts recorded Not_Measured and no estimate), the pricing source and UTC fetch date, cost computed at run time from token counts and the fetched list price, a failed price fetch giving Not_Measured with token counts printed, the gcloud-default-project statement (project used for billing, default project or unavailable, differences marked), and a source scan finding no numeric price literal in code.
    - _Requirements: 25.10, 25.11, 25.12, 25.13, 25.14, 25.15, 25.16, 25.17, 25.19, 25.20, 25.21, 25.22, 25.23_

- [ ] 13. Findings report and finding filing
  - [ ] 13.1 Implement `findings.py`: the per-Run_Set findings report
    - Dependencies: 7.2, 9.2, 4.1, 4.3
    - Failing test first: `tests/unit/test_holistic_findings.py` for indicator extraction counts per class and every unique returned value (a filename such as `main.py` listed if and only if the Corpus produced it, nothing filtered), keyword-novelty counts per class at or above 0.4, the disagreement-path triggers with case ids and matched keywords, the Tool_Name_Group counts and `high_risk_name` attack share with numerator and denominator, the default CBM score for an unknown tool and the dropped critical sinks by name, `cbm_client.base_url` before and after resolver construction with a policy server and whether it was overwritten, the clear-high ALLOW list (TASK-F06) under both Readings with its length, `ERROR` rows excluded and counted, and a missing figure recorded Not_Measured and never zero.
    - Findings are reported only. No production code changes.
    - _Requirements: 26.1, 26.2, 26.3, 26.4, 26.5, 26.6, 26.7, 26.8, 26.9, 26.10, 26.11, 26.12, 26.13, 26.14, 26.15, 26.17_

  - [ ] 13.2 File each reported finding as an unchecked task in its owning spec
    - Dependencies: 13.1
    - When this task is executed (and not before), add one unchecked task per finding to the owning spec on a feature branch: the CBM critical-sink mapping drop (`CriticalSinkType` to `SinkType`), indicator over-extraction (`_extract_indicator` treating filenames as domains), keyword-novelty substring matching and its Tier-2 disagreement trigger on benign cases, and the policy-server rewrite of `cbm_client.base_url`. For TASK-F06, TASK-F08, TASK-F09 and TASK-F10 in `tier-1-jev-addition`, add a pointer to this spec's evidence and do not duplicate them.
    - A test checks that each filed task is unchecked and names its finding. The diff contains no production code change.
    - _Requirements: 26.16, 26.17_

- [ ] 14. Recompute tests
  - [ ] 14.1 Implement the recompute, binding and registry tests
    - Dependencies: 9.2, 7.2, 8.1, 2.2
    - NOT optional. Failing test first: `tests/unit/test_holistic_recompute.py` recomputes every cited rate (rounded to the cited decimals, `ERROR` excluded, a zero denominator cited as Not_Measured), every Catch_Partition count and every shipped-Band replay cell from committed per-case files, with exact equality for counts and verdicts. It reports citing location, cited value and recomputed value, and fails for a cited figure with no recomputing test or a cited Pass with no committed per-case data.
    - Bind each committed Run_Set to the Corpus by Corpus_Hash and by row-for-row state hash, naming the first differing case. Scan committed per-case files for ContextHygiene secret patterns. Run from committed files with no network and no credential read. Keep a registry of cited figures (citing location, figure id, value, decimals).
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9, 12.10, 12.14, 12.15, 12.16, 12.17, 12.18_

- [ ] 15. Mutation guard
  - [ ] 15.1 Implement the mutation guard test
    - Dependencies: 6.2, 1.2
    - Failing test first: `tests/unit/test_holistic_mutation_guard.py` applies each mutation in a fixed list to a temporary copy of `compose.py` and `caught.py` (0.75 to 0.76, `>=` to `>`, dropping the Tier-2 override, dropping the BLOCK-never-downgraded guard, making `QUARANTINE` not count as stopped), runs the differential and decision-table tests against the copy, and fails and names the surviving mutation as a test gap if none of them fails. Committed sources are never modified.
    - _Requirements: 30.31, 30.32, 30.33, 30.34_

- [ ] 16. Comparison notebook `notebooks/holistic_defense_analytics.py`
  - [ ] 16.1 Create the notebook skeleton, loaders, controls and the executed-cell test module
    - Dependencies: 7.2, 8.1, 9.2
    - Failing test first: `tests/unit/test_holistic_notebook.py` parses the notebook with `ast`, runs each `@app.cell` once in source order with `mo`, `pd`, `go`, `json` and `repo_root` supplied, passes returned names forward, and fails naming a cell that raises or lacks a parameter. Assertions: empty state with the full `scripts/holistic_eval.py` command and no data panels when no Run_Set exists, an invalid Run_Set listed with its reason and excluded while others stay selectable, schema-version and Corpus_Hash errors showing expected and found values with no data panels, Not_Measured entries each shown with an em dash and reason (or text saying none), a Run_Set control defaulting to the latest created, a Reading highlight control that changes only the highlight and keeps both Readings visible, Band controls rejecting `lo > hi` or out-of-range values while keeping the last valid Band and naming the failed constraint, a clear-high control defaulting to production and labeling `block` "hypothetical, not production behavior", a Tier-2 mode control, recompute within 2 seconds with no live call, and the context header with an em dash and reason for any missing value.
    - Record the `marimo check` baseline before adding cells. The notebook imports only the pure modules named in the design.
    - _Requirements: 7.3, 7.4, 22.6, 22.7, 22.8, 22.9, 27.1, 27.2, 27.3, 27.4, 27.5, 27.6, 27.7, 27.8, 27.9, 27.10, 27.11, 27.12, 27.13, 27.14, 27.15, 27.16, 27.17, 27.18, 27.19, 27.20, 27.21, 28.1, 28.2, 28.3, 28.4, 28.8, 28.9, 28.10, 28.11_

  - [ ] 16.2 Add the comparison panels
    - Dependencies: 16.1
    - Failing test first: executed-cell assertions that every shown count equals the library's recomputed count exactly and every rate within 1e-9, `ERROR` rows excluded with the excluded count beside each rate, `0` denominators shown as an em dash with reason, and `UNMEASURED` and `ERROR` counts beside the attribution panel. Panels: what can stop a call, isolated versus whole-system rates (Stage_Gate labeled), catch attribution, band replay surface (Forced_Table Composed_Rows, with the cases whose Forced_Table decision differs from the live run listed from `variation_report` as expected variation with their cause, never as an identity failure, and the identity check of the run's own recorded outputs shown as a separate status) with a validity-limits box visible without interaction (Tier-2 ran once per case per Pass, error band from both Passes, the backing Jev run id or Not_Measured and "approximate", tuning and scoring circularity, exploratory status, attack and hand-written counts read from the Corpus, Jev releases per stored run, ADR 0008 band caveat, per-release surfaces, "input to TASK-F10 and TASK-F06, not a decision"), Outage_Drill in its own panel with fail-closed rows kept out of detection figures, stratified views including the `other` stratum, TSG per Seeding_Mode with leakage labels, optional-layer status tiles with the recorded reason unaltered, per-case drilldown, Tier-1 view read from `tests/eval/results/jev_runs_class_blind/` (Not_Measured placeholder when absent), CBM statements (ignores arguments, 0.30*0.5 + 0.30*1.0 = 0.45 below 0.50, real versus permuted shown together), a Plumbing_Only banner only when stub data is present, a caveats panel with links that resolve, escaped payload text (a `<script>` payload appears literally and creates no element), and threshold edges at 0.75, 0.50 and 0.35 asserted with the strict operators.
    - _Requirements: 7.18, 7.19, 14.7, 14.8, 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10, 16.11, 16.12, 16.13, 16.16, 16.17, 16.18, 19.14, 21.11, 21.20, 21.21, 22.6, 22.9, 27.22, 27.23, 27.24, 27.25, 27.26, 27.27, 27.28, 27.29, 27.30, 27.31, 27.32, 27.33, 27.34, 27.35, 27.36, 27.37, 27.38, 28.12, 28.13, 28.14, 28.17, 28.20, 28.21, 28.22, 28.23_

  - [ ] 16.3 Verify export, `marimo check`, isolation and dependencies
    - Dependencies: 16.2
    - Failing test first: tests that `marimo export html --no-sandbox <notebook> -o <tmp> < /dev/null` exits 0 within 120 seconds with zero failed cells and no live credential set (naming exit code and failing cells otherwise), that no new `marimo check` warning appears beyond the recorded baseline, that rendering with all sockets blocked, an empty environment and a read-only filesystem gives the same output, that no panel reads a credential variable or opens a socket (naming the panel), that the cross-link cell to `notebooks/benchmark_analytics.py` resolves, and that every dependency the notebook imports is in the `dev` extra of `pyproject.toml` with runtime dependencies unchanged.
    - _Requirements: 27.4, 27.5, 27.6, 27.37, 27.39, 28.5, 28.6, 28.7, 28.15, 28.16, 28.18, 28.19_

- [ ] 17. Phase 2 BDD scenarios
  - [ ] 17.1 Add the live-protocol BDD scenarios
    - Dependencies: 9.3, 12.2, 12.3
    - Extend `tests/features/holistic_defense_evaluation.feature` and its step definitions with: an unconfigured Layer in the Default_Plan recorded Not_Measured with a reason beginning "no grant" and naming `BW_OTX_API_KEY` and no stub used, a Named_Explicitly live row without its credential aborting with non-zero exit naming the variable and no client, call or record, and a Tier-2 429 invalidating the Pass with no per-case data committed. Steps use `run_async` and stub every live client.
    - _Requirements: 30.26, 30.27, 30.29, 30.30, 23.17, 19.17_

- [ ] 18. LIVE and grant-gated runs
  - [ ] 18.1 LIVE: run W0, W1, W2 and the per-release Forced_Tables in one interleaved run, two or more Passes
    - Dependencies: 12.5, 11.1
    - LIVE and GRANT-GATED. Needs a Human_Grant in the conversation naming `TYPESAFE_API_KEY` (paid TypeSafe account, Jev calls) and the Vertex project (`GCP_PROJECT` or `GOOGLE_CLOUD_PROJECT`, paid Tier-2 calls). `plan` prints and the billing statement states the billed Vertex project, the TypeSafe account, the models and the call counts before the first call, and notes that the gcloud default project can differ from the project in `.env`. The task 11.1 proposal artifact must exist first.
    - DEFERRAL NOTE: deferred until the human grants the named variables and a Vertex budget exists. Do not start, simulate, stub or mock. This task stays unchecked until a committed Run_Set holds a measured result (rule 74, Requirements 22.10, 22.11).
    - Run hermetically with `--configs W0,W1,W2,I-T2`, interleaved, default `--concurrency 2` and 30-second cool-down. Commit the Run_Set to a new directory on a feature branch only.
    - _Requirements: 4.1, 4.2, 4.3, 22.10, 22.11, 23.7, 23.15, 23.16, 24.1, 24.3, 24.6, 24.25, 25.17, 25.19, 31.8_

  - [ ] 18.2 Validate the live Run_Set against the fixed Jev bounds and the recompute tests
    - Dependencies: 18.1
    - GRANT-GATED by 18.1: it needs the committed live Run_Set and stays unchecked until one exists. Run the validator, the recompute tests, the Jev P comparison at the fixed constants (a violation fails and is never relaxed), the Composed_Row versus Whole_System_Run findings, and the findings report. Update every figure cited by an ADR, spec or the notebook in the same commit as the data.
    - _Requirements: 9.18, 9.19, 11.20, 11.21, 12.1, 12.2, 12.11, 12.13, 12.14, 12.15, 12.18, 31.9, 31.10_

- [ ] 19. Checkpoint - Phase 2 acceptance
  - Ensure all tests pass, ask the user if questions arise. Live tasks 18.1 and 18.2 stay unchecked until a measured Run_Set is committed.

### Phase 3: Optional layers (IOC corpus, threat intelligence, CBM fixture, W3 to W5)

- [ ] 20. IOC corpus builder and safety
  - [ ] 20.1 Implement `ioc_corpus.py`: schema, loader, validators and the Synthetic_Feed_Sample
    - Dependencies: 9.1
    - Failing test first: `tests/unit/test_holistic_ioc_corpus.py` for one shared template with identical tool names and argument keys across classes, a malicious entry missing feed name, snapshot date or category or sourced from OTX failing the build, an indicator in both classes failing, any scheme, port, path, query, fragment, credential or non-domain, non-IP form failing with the indicator named, `total_cases` equal to the number written with a load mismatch refusing to run and reporting both numbers, control entries carrying the Tranco list id, a synthetic-marked manifest refused as the corpus of a Whole_System_Run or I-TI-ioc, and the Synthetic_Feed_Sample committed under `tests/eval/ioc_corpus/synthetic/` with only `.example` names and documentation or private addresses.
    - _Requirements: 20.1, 20.2, 20.5, 20.6, 20.7, 20.8, 20.9, 20.10, 20.18, 20.19, 20.30, 20.31, 29.9, 29.10, 19.20_

  - [ ] 20.2 Implement the deterministic IOC_Selection
    - Dependencies: 20.1
    - Failing test first: `tests/unit/test_holistic_ioc_selection.py` on the Synthetic_Feed_Sample: byte-identical output for the same raw files, seed and parameters (also with rows reordered), a different seed changing the selection, largest-remainder allocation summing to the target with ties broken by stratum name ascending (worked exact-tie example), no malicious entry drawn twice, controls excluding malicious domains with no shared indicator, a source smaller than its target failing naming class, available count and target with no output, and a seed that is a string, float, bool, negative or 4294967296 rejected before any selection with no output and a non-zero exit.
    - Implement `validate_seed`, `rank_key`, `allocate`, `select_ioc` as designed.
    - _Requirements: 20.3, 20.7, 20.8, 20.24, 20.25, 20.26, 20.27, 20.28, 29.29, 29.32_

  - [ ] 20.3 Write property test that the IOC selection is deterministic and the classes never overlap
    - **Property 22: The IOC selection is deterministic and the classes never overlap**
    - **Validates: Requirements 20.8, 20.24, 20.25, 20.26, 20.27, 20.28**
    - Dependencies: 20.2, 2.4

  - [ ] 20.4 Implement the `fetch` step code (IOC_Authoring_Step) with mocked-transport tests
    - Dependencies: 20.1
    - Failing test first: `tests/unit/test_holistic_ioc_fetch.py` with a mocked transport asserting that `AUTHORING_HOSTS` holds exactly `threatfox.abuse.ch` and `tranco-list.eu` and none of the run-time hosts, any other host refused with the host name recorded, `BW_ABUSECH_AUTH_KEY` read only under a Human_Grant and sent in a request header only, the key and raw export never printed, logged or written to the repository (raw files go to a scratch directory outside it), zero threat-intelligence lookups, and no test module starting the step.
    - Create `scripts/build_ioc_corpus.py` with `fetch`. This task writes code only and never runs the step.
    - _Requirements: 20.4, 20.16, 20.17, 20.32, 23.10, 23.11_

  - [ ] 20.5 Implement the run-time egress guard, the per-run OTX send guard and `plan` indicator listing
    - Dependencies: 20.1, 12.2, 4.1
    - Failing test first: `tests/unit/test_holistic_egress.py` for connections only to the Jev, Vertex and OTX hosts in every Harness run, any other host refused and recorded with the case marked `ERROR`, a socket guard failing and naming any connection to an IOC indicator, no verdict (including `ALLOW` and `QUARANTINE`) causing a connection, `plan` printing every API host and every indicator to be sent to OTX one per line, each with its source corpus (`corpus` or `ioc_corpus`), with zero connections.
    - The OTX send guard is per run and is armed, before the first lookup, with the indicator set of the one committed corpus selected for that run: for an I-TI-corpus run, the indicators that `_extract_indicator` returns over the committed Corpus cases (documentation-range and private-range addresses and filename-shaped values included, unfiltered); for an I-TI-ioc run, the `IocEntry.indicator` values of the committed IOC_Corpus. Failing-first guard tests: an I-TI-corpus run sends a Corpus documentation address (for example in 192.0.2.0/24) and a Corpus filename-shaped value and the guard does not refuse them on the ground that they are absent from the IOC fixtures; an I-TI-ioc run sends an IOC_Corpus indicator; an indicator in neither committed corpus is refused before sending, the run fails naming the indicator and nothing is sent for it; an IOC_Corpus indicator in an I-TI-corpus run and a Corpus indicator in an I-TI-ioc run are each refused as not in that run's corpus.
    - The Corpus indicator set comes from the context stage of task 4.1 (`_extract_indicator` over the committed Corpus), which needs no network.
    - _Requirements: 19.1, 20.13, 20.14, 20.15, 20.16, 20.17, 20.21, 20.22, 20.23_

  - [ ] 20.6 Implement the offline `build` step and raw-digest verification
    - Dependencies: 20.2
    - Failing test first: `tests/unit/test_holistic_ioc_build.py` for an offline `build` that opens zero connections and reads no credential variable, passes every indicator through ContextHygiene as an un-redacted standalone hostname and fails listing every changed indicator with no output, writes the manifest (seed, selection parameters, target sizes, raw-file digests, exact total) and no raw file, and `verify_raw_digests` reporting each file as matching or differing without changing any committed IOC_Corpus file.
    - _Requirements: 20.4, 20.5, 20.11, 20.12, 20.18, 20.27, 20.29, 20.32_

  - [ ] 20.7 LIVE (maintainer-run): run the IOC_Authoring_Step and commit the IOC corpus
    - Dependencies: 20.4, 20.6
    - LIVE and GRANT-GATED. Needs a Human_Grant in the conversation naming `BW_ABUSECH_AUTH_KEY` (free abuse.ch Auth-Key, no billed account). Only the maintainer starts `fetch`, which contacts only `threatfox.abuse.ch` and `tranco-list.eu`, once. Then run the offline `build` with a recorded seed and commit only the selected indicators and manifest to a feature branch.
    - DEFERRAL NOTE: deferred until the grant is given. Do not start, simulate or stub. Stays unchecked until the corpus is committed. Without it every I-TI-ioc row is Not_Measured with a reason naming the missing fixture.
    - _Requirements: 20.3, 20.4, 20.16, 20.17, 22.10, 22.11, 31.15_

- [ ] 21. Threat-intelligence evaluation
  - [ ] 21.1 Implement the threat-intelligence stage runners
    - Dependencies: 12.4, 20.1, 4.1
    - Failing test first: `tests/unit/test_holistic_ti_stage.py` with a mocked OTX provider: the OTX-only orchestrator (`secondary_providers=[]`, cache neither read nor written) queried once per unique indicator, per-indicator queried flag, `is_malicious`, risk, pulse count, provider and error class (`none` on success, values absent on error), documentation and private ranges reported as a separate group with no expected value, the IOC headline share with numerator, denominator and the delisting statement, a zero denominator giving Not_Measured, `ERROR` rows excluded and counted (0 when none), `-stub` suffix and `stub_plumbing_only` source for stub providers with a Plumbing_Only banner and exclusion from efficacy views, no stub ever substituted for a missing grant, no multi-provider efficacy table that includes abuse.ch, and no IOC and Corpus rows in one aggregate.
    - Each threat-intelligence row and each run records its source corpus: every `TiOut` of I-TI-corpus carries `source_corpus` `corpus` and every `TiOut` of I-TI-ioc carries `ioc_corpus`, each run produces its `ti_runs` entry (`config_id`, `source_corpus`, `fixtures_digest` of that corpus's committed fixture files, and the statement that every indicator sent to OTX in the run comes from the committed fixtures of that corpus), and a test fails if a row's `source_corpus` differs from its run's entry. The runner arms the per-run send guard of task 20.5 with the indicators of that run's corpus.
    - _Requirements: 4.19, 10.12, 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 19.8, 19.9, 19.10, 19.11, 19.12, 19.13, 19.15, 19.18, 19.19, 19.20, 20.20, 20.21_

  - [ ] 21.2 LIVE: run I-TI-corpus and I-TI-ioc
    - Dependencies: 21.1, 20.7, 12.5
    - LIVE and GRANT-GATED. Each run records its source corpus in its `ti_runs` entry and on every row. Needs a Human_Grant in the conversation naming `BW_OTX_API_KEY` (AlienVault OTX, free key, 10,000 lookups per hour, no billed account but a stated quota). `plan` first prints every host and every indicator with its source corpus, and only indicators from the committed fixtures of each run's own corpus are sent (the Corpus for I-TI-corpus, the IOC_Corpus for I-TI-ioc).
    - DEFERRAL NOTE: deferred until the grant is given. Without it the rows are recorded Not_Measured with a reason beginning `no grant` and naming `BW_OTX_API_KEY`. Stays unchecked until a measured Run_Set exists.
    - _Requirements: 4.19, 19.1, 19.2, 19.6, 19.17, 20.21, 22.10, 22.11, 31.14_

- [ ] 22. CBM fixture, export and permuted control
  - [ ] 22.1 Author the Fixture_Plan and the fixture source text
    - Dependencies: 4.3
    - Failing test first: `tests/unit/test_holistic_cbm_plan.py` asserting every plan tool has a function of that name in the source (a missing function failing and naming the tool), the source holds between 10 and 14 function definitions, no rationale contains as a whole word (case-insensitive) a `case_id`, `ground_truth` value, scenario class, `attack_type` or Run_Set figure (failing with the tool and matched text, with a planted word proving the scan fires), and that the source is never imported or executed.
    - Hand-author `tests/eval/cbm_fixture/v1/fixture_source.py.txt` and `fixture_plan.json` per the design's table (covered tools with at least two cases, rationale from the tool's role only, chosen before any CBM result exists). The plan is committed before any Run_Set with a fixture-backed CBM row (I-CBM-fixture, I-CBM-permuted, W4, W5, the `sinks mapped` row or an Indexer_Agreement row). A default-CBM row (I-CBM-default, a Phase 1 row) needs neither the plan nor the snapshot.
    - _Requirements: 21.1, 21.2, 21.30, 21.31, 21.32, 21.33_

  - [ ] 22.2 Implement `cbm_fixture.py` and `scripts/build_cbm_fixture.py` (`export`, `check`)
    - Dependencies: 22.1
    - Failing test first: `tests/unit/test_holistic_cbm_export.py` for standard-library `ast` parsing only (no import, execution, network or credential, run with sockets blocked and an empty environment), byte-identical output on two runs with canonical JSON, the named `SINK_TABLE_V1` and its digest in the snapshot, a write-mode `open` as a sink and a read-mode `open` not, a cycle failing naming the functions, depth and sink kinds equal to the plan, and `check` failing non-zero and naming each differing function in a temporary copy (committed files never touched).
    - _Requirements: 21.3, 21.34, 21.35, 21.36_

  - [ ] 22.3 Produce the committed snapshot and add the drift test
    - Dependencies: 22.2
    - Run `export` to write `snapshot.json`; commit with the plan and source as one versioned directory. Failing test first: byte-for-byte reproduction of the committed snapshot, the Manifest of a Run_Set with a fixture-backed CBM row recording plan, snapshot and source digests, and the Run_Store rejecting a differing recorded digest or a fixture-backed CBM row with no digest. A Run_Set whose CBM rows are all default-CBM rows records no digest and is not rejected for it.
    - _Requirements: 21.3, 21.31, 21.35_

  - [ ] 22.4 Write property test that the fixture export is deterministic and never drifts
    - **Property 20: The fixture export is deterministic and the snapshot never drifts**
    - **Validates: Requirements 21.3, 21.34, 21.35, 21.36**
    - Dependencies: 22.2, 2.4

  - [ ] 22.5 Write property test that the fixture plan binds to source, snapshot and corpus labels
    - **Property 21: The fixture plan binds to the source, the snapshot and the corpus labels**
    - **Validates: Requirements 21.1, 21.30, 21.31, 21.32, 21.33**
    - Dependencies: 22.1, 22.3, 2.3
    - The digest binding applies only to a Run_Set with a fixture-backed CBM row (I-CBM-fixture, I-CBM-permuted, W4, W5, the `sinks mapped` row or an Indexer_Agreement row). Generated Run_Sets whose CBM rows are all default-CBM rows need neither the plan nor the snapshot, record no digest for them and are not rejected.

  - [ ] 22.6 Implement the Fixture_Adapter, characterization tests, permuted control and what-if row
    - Dependencies: 22.3, 5.1
    - Failing test first: `tests/unit/test_holistic_cbm_adapter.py` for `queryDependencyChain` and `identifyCriticalSinks` answering from the snapshot through the shipped `CodebaseMemoryClient.query` mapping (a snapshot sink is converted, not returned verbatim), zero sockets with socket creation blocked, `base_url` `None` after resolver construction, a characterization test pinning that the shipped `query` returns zero critical sinks for every fixture tool whose snapshot lists one (so a later fix is a visible failure), both `mapped_sinks` and `raw_sinks` recorded, the Permuted_Control giving an identical assignment for the same seed with the seed in the Manifest, real and permuted shown together, and the `sinks mapped` what-if row labeled hypothetical, excluded from production figures and Not_Measured where `raw_sinks` is missing.
    - _Requirements: 21.5, 21.6, 21.7, 21.8, 21.9, 21.10, 21.11, 21.13, 21.14, 21.15, 21.16, 21.17, 21.18_

  - [ ] 22.7 Implement the conformance probe and Indexer_Agreement rows
    - Dependencies: 22.3
    - Failing test first: `tests/unit/test_holistic_cbm_probe.py` with a stub server and a stub indexer: one request each for `trace_path`, `query_graph` and `get_architecture` with a 10-second timeout, conformant only if all three parse, a non-conforming, endpoint-less or slow server giving Not_Measured `transport mismatch` with fixture rows unchanged, indexing before probing, one `agree` or `disagree` row per function (with the differing facts, reported as a finding with no fixture value changed), a failed indexing or an unavailable indexer giving Not_Measured with the reason, and hermetic runs never requiring the indexer. No new MCP server is added.
    - The real probe runs only when a codebase-memory-mcp server is available (no credential involved). Otherwise every row is Not_Measured with the reason.
    - _Requirements: 21.23, 21.24, 21.25, 21.26, 21.27, 21.28, 21.29, 21.37, 21.38, 21.39_

- [ ] 23. Optional whole-system rows W3 to W5
  - [ ] 23.1 Add W3, W4 and W5 configurations and prerequisite handling
    - Dependencies: 21.1, 22.6, 12.5
    - Failing test first: `tests/unit/test_holistic_configs_optional.py` for W3 (W2 plus the OTX-only orchestrator), W4 (W2 plus the Fixture_Adapter, `base_url` re-asserted), W5 (both) over the Corpus and over the IOC_Corpus in separate rows, and an absent grant, fixture or transport recording the row Not_Measured with a reason naming it while the other rows run.
    - _Requirements: 4.4, 4.5, 4.6, 4.7, 4.8, 22.1, 22.2, 22.3, 31.13, 31.14, 31.15_

  - [ ] 23.2 LIVE: run W3, W4 and W5
    - Dependencies: 23.1, 18.1, 21.2, 20.7
    - LIVE and GRANT-GATED. Needs Human_Grants naming `TYPESAFE_API_KEY` and the Vertex project (billed paid accounts, disclosed as in 18.1) and, for W3 and W5, `BW_OTX_API_KEY`. W5 also runs on the IOC corpus once it is committed.
    - DEFERRAL NOTE: deferred until the grants and corpus exist. Do not simulate. Stays unchecked until a measured Run_Set exists. Commit to a new directory on a feature branch.
    - _Requirements: 4.4, 4.5, 4.6, 4.7, 22.10, 22.11, 31.13_

  - [ ] 23.3 Build the `LX-wave` learning-experiment support (offline, stubbed)
    - Dependencies: 12.5, 4.2
    - The experiment stays optional at run time (Requirement 17.25). Building its support is required.
    - Failing test first: `tests/unit/test_holistic_lx_wave.py` with stubbed clients asserting that `LX-wave` is absent from the Default_Plan and does not run unless it is requested explicitly (a run that does not request it opens no signature-generation call), that cases are processed one at a time with at most one case in flight, in an order that is recorded in the Manifest, that its results are written and reported apart from the Configuration_Matrix, and that every table, panel and file of its results carries the label `order-dependent`.
    - Implement the `LX-wave` handling in `runner.py` and the `run` subcommand. It uses the explicit temporary database path of Requirement 17 and reads no credential in this task.
    - _Requirements: 17.25, 17.26, 17.27_

  - [ ] 23.4 LIVE (only when explicitly requested): run the `LX-wave` learning experiment
    - Dependencies: 23.3, 18.1
    - LIVE and GRANT-GATED. It runs only when the maintainer explicitly requests it. It spends Vertex tokens on inline signature generation (a Gemini call per BLOCK), so it needs a Human_Grant in the conversation naming the Vertex project (`GCP_PROJECT` or `GOOGLE_CLOUD_PROJECT`) and the billed-project disclosure of task 18.1. Cases run one at a time in the recorded order, and results are reported apart from the Configuration_Matrix and labeled `order-dependent`.
    - DEFERRAL NOTE: deferred until the maintainer requests the experiment and grants the Vertex project. Do not start, simulate, stub or mock. This task stays unchecked until a committed Run_Set holds a measured result (rule 74, Requirements 22.10, 22.11).
    - _Requirements: 17.25, 17.26, 17.27, 22.10, 22.11_

- [ ] 24. Checkpoint - Phase 3 acceptance
  - Ensure all tests pass, including the Phase 3 property tests (Properties 20, 21 and 22) and the `LX-wave` support tests, ask the user if questions arise. Live tasks 20.7, 21.2, 23.2 and 23.4 stay unchecked until measured data is committed.

### Phase 4: Band study, recommendation gate, cross-link and ADR

- [ ] 25. Band study and close-out
  - [ ] 25.1 Implement `band_gate.py`: `check_recommendation`
    - Dependencies: 8.1, 2.1
    - Failing test first: `tests/unit/test_holistic_band_gate.py` for rejection when the held-out value differs from the tune value by more than the Pass spread for any metric and Reading (a `None` fails closed), the Fresh_Evidence check built on two kinds of exclusion. Record-level checks: a missing or incomplete Authoring_Record, or one whose statement of what the author was shown contains the replay results, the Jev or Tier-2 per-case outputs, the band surface or the miss lists, excludes every case in that record. Case-level checks: an authoring timestamp not after `surface_frozen_at`, a label the maintainer has not confirmed, a case identifier present in the tuning Corpus, or a case scored before the recommendation was drafted, excludes only that one case, and the remaining cases of the same record are still counted. Input integrity is the first check, evaluated before any case is checked or counted, and is not a per-case exclusion (`GateCheck.INPUT_INTEGRITY`; design, "`check_recommendation`"). Boundary tests, each written first: (1) one eligible attack case id submitted repeatedly (enough repeats that the repeated count would reach 30 attack cases) is rejected as `INPUT_INTEGRITY`, counts nothing and does not pass the count check; (2) one eligible benign case id submitted repeatedly is rejected the same way and does not pass the benign count; (3) an id listed more than once inside one Authoring_Record is rejected; (4) an id listed in two Authoring_Records is rejected and counted under neither; (5) a rejection for any duplicate has `INPUT_INTEGRITY` as its only failed check, zero counted cases, each duplicated id named with its kind, and no other check evaluated; (6) every submitted, counted and excluded total counts distinct case ids (30 distinct eligible ids of each class pass, and 29 distinct plus a repeat of one of them fails); (7) the rejection records the exclusion report, listing each distinct submitted id as not counted at level `submission`, naming the duplicates, with per-class totals; (8) a case id that no record lists has no known class and is reported as `unclassified` and excluded. Only when the input is sound do the record-level and case-level checks above decide whether a case counts. Further tests: one bad case among otherwise valid cases leaves the others counted and does not reject the recommendation by itself, an excluded case is never replaced and the set of case identifiers in a record is fixed at authoring time, no exclusion is decided from a score or a replay result, a report lists every submitted case as counted or excluded with the failed check for each excluded case and the submitted, counted and excluded totals for the attack class and for the benign class, the check passes only when at least 30 attack and at least 30 benign cases are counted after exclusions and no record-level check failed for any record that supplies those cases (exactly 30 of each, counted, passing and 29 of either failing), a rejection on this check carries that exclusion report, TASK-F09 open with the `other` stratum outside its spread rejected and F09 complete passing that check, every failed check named, evidence ids recorded on acceptance, and the shipped Band, thresholds and weights byte-identical before and after every call.
    - The fresh cases test authoring independence, not who typed them (Requirement 16.22). Who authors them is the maintainer's choice. The author may be the maintainer or an agent session that was not shown the replay results, the Jev or Tier-2 per-case outputs, the band surface or the miss lists. An agent that has seen any of these is disqualified. The author authors the cases after the `surface_frozen_at` timestamp and follows the class-blind construction rules: one shared template, the same tool names and argument keys in both classes, real payload syntax, no label words, and documentation-range and `.example` hosts only.
    - The maintainer reviews and confirms every label. The Authoring_Record (author, session identity or "maintainer", freeze timestamp, authoring timestamp, and a statement of what the author was and was not shown) is committed with the cases, and the maintainer's label confirmation is recorded in it.
    - This task implements and tests the check of the independence evidence (the Authoring_Record, the timestamps, absence from the tuning Corpus, not scored before the draft) as record-level and case-level exclusions with the exclusion report, and the check of the 30 attack and 30 benign thresholds on the counted cases. It does not itself author the cases. Authoring them is a separate maintainer action outside this task list, and until it is done no Band recommendation passes the gate.
    - Pure function only. It never writes a Band, threshold or weight to any file.
    - _Requirements: 16.21, 16.22, 16.23, 16.24, 16.25_

  - [ ] 25.2 Write property test that a recommendation needs the whole gate and changes nothing
    - **Property 19: A band recommendation needs the whole gate and changes nothing**
    - **Validates: Requirements 16.21, 16.22, 16.23, 16.24, 16.25**
    - Dependencies: 25.1, 2.4
    - Generated submissions of fresh cases and Authoring_Records first exercise input integrity: any case id that appears more than once in the submission, more than once in one record, or in more than one record (including one eligible id repeated until the repeat count would reach 30 of a class) rejects the whole submission with `INPUT_INTEGRITY` as the only failed check, names each duplicated id, counts nothing, carries the exclusion report, and every total in that report counts distinct case ids. For sound input the generated submissions exercise both exclusion kinds: a record-level failure excludes every case of that record, a case-level failure excludes only that case, no exclusion depends on a score or replay result, and the Fresh_Evidence check passes if and only if at least 30 attack and 30 benign distinct cases are counted and no record-level check failed for a supplying record. Every submitted case appears in the report as counted or excluded with the failed check, and the shipped Band, thresholds and weights are unchanged by every call.

  - [ ] 25.3 Implement the band study report and held-out comparison
    - Dependencies: 8.1, 7.2, 25.1
    - Failing test first: `tests/unit/test_holistic_band_study.py` for tune-half versus held-out-half catch and false-alarm rates under both Readings per Band cell with the split salt stated, a half with no attack or no benign case Not_Measured with a reason, `high_risk_name` and `other` strata with case counts, the "helps only high_risk_name" flag (never cleared when the `other` stratum has no attack cases), the Clear_High_Variant labeled hypothetical, every band result labeled "input to TASK-F10 and TASK-F06, not a decision", the statements that a QUARANTINE does not execute the tool and that TASK-F10 still needs fresh labeled cases, and that the shipped Band stays 0.35 and 0.75. No Band edge is recommended without the gate.
    - Computed from stored Jev P and the Forced_Tables with zero live calls.
    - _Requirements: 15.7, 15.8, 16.14, 16.15, 16.18, 16.19, 16.20, 16.25, 16.26, 31.22, 31.23, 31.24, 31.25, 31.26_

  - [ ] 25.4 Add the band-study panels to the notebook
    - Dependencies: 16.3, 25.3
    - Failing test first: extend `tests/unit/test_holistic_notebook.py` with executed-cell assertions for the tune and held-out curves, the stratum flag, the gate status and the labels of task 25.3. The `block` policy selection labels every affected panel "hypothetical, not production behavior".
    - _Requirements: 16.14, 16.15, 16.18, 16.19, 16.20, 16.26, 27.18, 31.22_

  - [ ] 25.5 Add the cross-link cell to the existing notebook (one added markdown cell)
    - Dependencies: 16.3
    - Failing test first: a test that the diff of `notebooks/benchmark_analytics.py` contains added lines only (one new markdown cell linking to `notebooks/holistic_defense_analytics.py`, link resolving), that `tests/unit/test_marimo_notebook_syntax.py` passes unmodified, and that no pinned line changed.
    - _Requirements: 27.2, 27.40, 27.41, 31.17_

  - [ ] 25.6 Write the ADR recording the first measured results
    - Dependencies: 18.2, 25.3
    - GRANT-GATED by 18.1: needs a committed measured Run_Set, so it stays unchecked until one exists. Write the next free ADR under `docs/adr/` that names the Corpus_Hash of the Run_Set the figures come from, states the layers and `demo_mode`, and cites only figures that the recompute tests cover. Update every citing location in the same commit as the data.
    - _Requirements: 12.7, 12.18, 31.17_

  - [ ] 25.7 Add the band-gate BDD scenario
    - Dependencies: 25.1, 17.1
    - Extend `tests/features/holistic_defense_evaluation.feature` with scenarios that (a) a band recommendation without enough counted fresh labeled evidence is rejected with the failed check named, the exclusion report attached, and the shipped Band, thresholds and weights unchanged, (b) a single case with an unconfirmed label or an authoring timestamp not after the freeze timestamp is excluded and reported while the other cases of the same record are still counted, (c) an Authoring_Record that states the author was shown replay results excludes every case in that record, (d) a submission that repeats one eligible attack case identifier (or one eligible benign case identifier) enough times to reach the 30-case threshold is rejected as an input-integrity failure (`INPUT_INTEGRITY`), the repeated identifier is named, no count is padded, and the rejection carries the exclusion report, and (e) a case identifier listed in two Authoring_Records is rejected as an input-integrity failure and counted under neither record.
    - _Requirements: 16.22, 16.24, 16.25_

  - [ ] 25.8 (CONDITIONAL, LIVE) Re-score after TASK-F08 or TASK-F09 lands
    - Dependencies: 18.2
    - Only if either task lands. LIVE and GRANT-GATED under the same grants as 18.1; stays unchecked and deferred until then. The Corpus_Hash changes, so write to a new Run_Set directory and leave every existing directory unmodified. After TASK-F08, re-score the stored Jev runs and every Run_Set in the same commit. `ERROR` rows stay excluded from every rate.
    - _Requirements: 31.18, 31.19, 31.20, 31.21_

- [ ] 26. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, including the band-gate property test (Property 19) and the band-gate BDD scenario, ask the user if questions arise. Confirm no task edited `AGENTS.md`, `.agents/rules/`, `.greptile/`, any `.env` file or any existing results directory.

## Out of scope

- No change to production scoring, aggregation weights, verdict thresholds, the Jev band (0.35 and 0.75), the Tier-2 trigger constants or any other production constant. A band change remains a spec amendment under `tier-1-jev-addition` needing fresh labeled evidence.
- No fallback path for Tier-1 (ADR 0009) and no substitute score.
- No fix for any defect the harness reports (the findings are reported and filed as tasks in their owning specs).
- No Enterprise Mesh evaluation, no new MCP server, no live infrastructure, no payload execution.
- No edit to `tests/eval/results/jev_runs/`, `tests/eval/results/jev_runs_class_blind/` or any dated ADR evidence.
- No edit to `AGENTS.md`, `.agents/rules/` or `.greptile/` in this change. Task 11.1 only prepares a proposal for maintainer approval.

## Notes

- No sub-task is marked optional. The property tests, the BDD scenarios and the `LX-wave` support are required. Running `LX-wave` (task 23.4) happens only on explicit request and is grant-gated.
- The Composer differential test (6.2) and the recompute tests (14.1) are required. So are the mutation guard (15.1) and the executed-cell notebook tests.
- The fresh labeled cases for a Band recommendation (at least 30 attack and 30 benign) are judged on authoring independence, not on who typed them. The maintainer chooses the author: the maintainer, or an agent session that was not shown the replay results, the Jev or Tier-2 per-case outputs, the band surface or the miss lists (an agent that has seen them is disqualified). The author writes after the freeze timestamp and follows the class-blind construction rules, the maintainer confirms every label, and the Authoring_Record is committed with the cases. Task 25.1 checks that evidence and the thresholds and does not author the cases. Exclusions are of two kinds: a record-level failure (missing or incomplete Authoring_Record, or a shown list containing withheld material) excludes every case in that record, and a case-level failure (timestamp not after the freeze, unconfirmed label, identifier in the tuning Corpus, scored before the draft) excludes only that case. Excluded cases are reported with the failed check and per-class submitted, counted and excluded totals, are never replaced, and are never decided from a score or replay result. The check passes only when enough distinct cases are counted and no record-level check failed. Before any exclusion check, a case identifier that is repeated in the submission, repeated in one record or listed in two records rejects the whole submission as an input-integrity failure and counts nothing.
- TASK-F09 gates only the band recommendation (task 25.1 input), not the first comparison. TASK-F08 and TASK-F09 landing changes the Corpus_Hash, which task 25.8 handles.
- Test tasks are placed in waves at or after the wave of the component they test (rule 19).
- New pure modules beyond the design's layout table (`grants.py`, `billing.py`, `findings.py`, `report.py`, `cbm_probe` code inside `cbm_fixture.py`) live under `src/blackwall/holistic_eval/` and import nothing from the rest of `blackwall`.
- The IOC_Authoring_Step (20.7) is run by the maintainer only. No test, notebook or agent run starts it.

## Execution Order

Phase 1 (tasks 1 to 10) runs with no network and no credential. Within a wave, tasks are independent and may run in parallel. Phase 2 starts with task 11.1 (the entry gate), which the live tasks require. Phase 2 and Phase 3 code tasks that have no live dependency can start as soon as their dependencies finish. The live tasks (18.1, 18.2, 20.7, 21.2, 23.2, 23.4, 25.6, 25.8) wait for the named Human_Grants and stay unchecked until measured data is committed.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "2.2", "3.1"] },
    { "id": 2, "tasks": ["1.4", "1.5", "1.6", "1.7", "2.1", "3.2"] },
    { "id": 3, "tasks": ["2.3", "2.4", "4.1", "4.2", "6.1"] },
    { "id": 4, "tasks": ["2.5", "2.6", "2.7", "3.3", "4.3", "4.4", "4.5", "6.2", "6.3", "6.4", "7.1", "8.1"] },
    { "id": 5, "tasks": ["5.1", "7.2", "7.3", "7.4", "8.2", "8.3", "8.4", "8.5", "9.1", "9.3", "15.1", "22.1", "25.1", "6.5"] },
    { "id": 6, "tasks": ["5.2", "9.2", "12.1", "20.1", "22.2", "25.2", "25.3"] },
    { "id": 7, "tasks": ["5.3", "5.4", "11.1", "12.2", "12.3", "12.6", "13.1", "14.1", "16.1", "20.2", "20.4", "22.3", "22.4"] },
    { "id": 8, "tasks": ["12.4", "13.2", "16.2", "17.1", "20.3", "20.5", "20.6", "22.5", "22.6", "22.7"] },
    { "id": 9, "tasks": ["12.5", "16.3", "20.7", "21.1", "25.7"] },
    { "id": 10, "tasks": ["18.1", "21.2", "23.1", "23.3", "25.4", "25.5"] },
    { "id": 11, "tasks": ["18.2", "23.2", "23.4"] },
    { "id": 12, "tasks": ["25.6", "25.8"] }
  ]
}
```
