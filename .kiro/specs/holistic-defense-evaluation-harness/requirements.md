# Requirements Document

## Introduction

Holistic Defense Evaluation Harness. Derived from `design.md` (Holistic Defense Evaluation Harness). Every measurement Blackwall Core has of its own defenses is a single-stage measurement: `scripts/jev_triage_eval.py` scores Tier-1 Jev alone, and `scripts/jev_tier2_eval.py` builds the `SyncResolver` with the Threat Signature Graph (TSG), threat intelligence and codebase-memory (CBM) layers absent. Those figures are stage gates, and `.agents/rules/testing_and_hygiene.md` section 79 states that a stage gate is not a system rate. The maintainer wants to change the Jev band (`tier-1-jev-addition`, TASK-F10 and TASK-F06) and cannot yet say what a band change does to the whole firewall.

This spec defines an evaluation harness in which every defensive stage is measured in isolation (its own positive output, scored against ground truth) and in tandem (the real `SyncResolver` verdict with a named set of layers enabled), and in which any isolated figure can be compared with the whole-system figure for the same cases. The harness records every stage's output for every case, composes verdicts offline with a pure function that is checked against the real resolver, replays Jev band edges over recorded data, attributes each catch to stages, and renders the comparison in a second marimo notebook that reads committed artifacts only.

The scope is Blackwall Core. The harness observes production behavior and does not alter it.

### Non-Goals and Out-of-Scope Items

The following are explicitly out of scope and no requirement below SHALL be read to include them:

- Changing production scoring, aggregation weights, verdict thresholds, the Jev band (`JEV_CLEAR_LOW_THRESHOLD` 0.35, `JEV_CLEAR_HIGH_THRESHOLD` 0.75), the Tier-2 trigger constants or any other production constant. A band change remains a spec amendment under `tier-1-jev-addition` that needs fresh labeled evidence.
- Adding a fallback path for Tier-1 (ADR 0009 forbids it) or any substitute score.
- Fixing the defects the harness reports (ContextHygiene over-matching, indicator over-extraction, keyword-novelty triggers, the CBM sink-mapping drop, the policy-server CBM URL rewrite, the tool-name tell). Each defect found becomes a separately tracked task.
- Enterprise Mesh evaluation, a new MCP server, live infrastructure, and the execution of any payload.
- Editing any existing results directory (`tests/eval/results/jev_runs/`, `tests/eval/results/jev_runs_class_blind/` and the dated ADR evidence).
- Editing `AGENTS.md`, `.agents/rules/` or `.greptile/`. The design proposes spec-list and rule changes; they follow the proposal workflow of `AGENTS.md` section 6.3 and are not part of these requirements.

### Open Questions and Assumptions

The design's open questions are carried forward as marked assumptions, not resolved, except Q12 to Q15, which the maintainer decided on 2026-11-13 and which the requirements now state without a tag. Each requirement that depends on an open question cites it as `[Open Question Qn]`. The full list is in the section "Open Questions and Assumptions" after the requirements.

## Glossary

- **Harness**: The evaluation system specified by this document: the `blackwall.holistic_eval` library, the `scripts/holistic_eval.py` CLI, the fixtures, the committed run sets and the Notebook.
- **Resolver**: `SyncResolver` in `src/blackwall/resolver.py`, the production interception path whose `evaluate()` method returns a decision and a confidence score.
- **Production_Mode**: The Resolver configured with `demo_mode=False`, block threshold 0.75 and quarantine threshold 0.50, as in `policy.yaml`.
- **Stage**: One defensive component: structural policy, context heuristics, TSG, threat intelligence (TI), CBM, Tier-1 Jev, Tier-2, or weighted aggregation.
- **Layer**: A Stage that a Resolver configuration enables or disables. The optional Layers are structural policy, TSG, threat intelligence and CBM.
- **Stage_Flag**: A Stage's own positive output scored against ground truth, defined in the single stage-flag table of the Caught_Module. A Stage_Flag is never a System_Verdict.
- **Stage_Gate**: A metric from a harness that exercises one Stage (for example Tier-1 accuracy, ECE, AUROC or escalation rate). A Stage_Gate is not a system catch rate.
- **System_Verdict**: The decision returned by the Resolver, or produced by the Composer for a named configuration. The decision values are `ALLOW`, `QUARANTINE`, `BLOCK`, and `ERROR` when `evaluate()` raised.
- **Reading**: A rule for counting a System_Verdict as caught. The Stopped_Reading counts `BLOCK` or `QUARANTINE`. The Blocked_Reading counts `BLOCK` only.
- **Caught_Module**: The single pure module (`src/blackwall/holistic_eval/caught.py`) that holds the definition of caught, the Reading table and the Stage_Flag table.
- **Outcome**: One of `CAUGHT`, `MISSED`, `FALSE_ALARM`, `CORRECT_ALLOW`, `ERROR`, computed from a ground truth, a decision and a Reading.
- **Quarantine_Cause**: The recorded reason for a `QUARANTINE` decision: `aggregate`, `tier2_unavailable` or `rate_limit`. The value is `none` for any other decision.
- **Corpus**: The set of `CorpusCase` records loaded by `build_cases(["security", "evasion_proof"])` with the added case metadata. The IOC_Corpus and the CBM_Fixture are separate corpora and are never pooled with it.
- **Corpus_Hash**: A content hash over every case's identifier, tool name, arguments and state hash.
- **Stage_Recorder**: The set of observer wrappers (`ObservedResolver` and its component wrappers) that record each Stage's output per case without changing any return value.
- **Case_Trace**: The per-case record of Stage outputs held in a `ContextVar` so that concurrent cases on a shared Resolver do not cross.
- **Composer**: The pure function `compose_verdict`, which computes the System_Verdict from recorded Stage outputs and a `ComposeConfig`.
- **Composed_Row**: A System_Verdict computed offline by the Composer rather than produced by a live Resolver run.
- **Whole_System_Run**: A live pass of the real Resolver over the Corpus with a named configuration, recorded by the Stage_Recorder.
- **Configuration_Matrix**: The set of isolated rows (I-...), whole-system rows (W0 to W5) and composed rows defined by the design.
- **Run_Set**: One directory under `tests/eval/results/holistic/` holding per-case records and a `manifest.json`, bound to a Corpus_Hash.
- **Manifest**: The `RunSetManifest` file of a Run_Set.
- **Pass**: One execution of one configuration over every case of a corpus. A Pass is valid or discarded.
- **Forced_Table**: The Tier-2 result recorded for every case, regardless of whether Tier-2 would have fired in the real Resolver, from one named Jev run.
- **Band**: The pair of Jev probability edges `lo` and `hi`. The shipped Band is 0.35 and 0.75.
- **Band_Replay**: The offline recomputation of verdicts for other Band edges, and for the clear-high variant, from stored Jev P values and the Forced_Table.
- **Clear_High_Variant**: The `clear_high_policy="block"` what-if of TASK-F06, in which a Jev P above the upper edge alone yields `BLOCK`. It is a labeled hypothetical and is not production behavior.
- **Outage_Drill**: The offline recomputation of verdicts in which every triggered Tier-2 call returns no verdict.
- **Catch_Partition**: The classification of each attack case in a configuration into exactly one of `system_only`, `unique`, `redundant`, `lost_by_system` or `missed_by_all`.
- **Ablation_Analyzer**: The pure module that computes leave-one-out and add-one-in results and the Catch_Partition.
- **TSG_Seeder**: The component that writes seed signatures into a temporary Threat Signature Graph database.
- **Seeding_Mode**: One of `cold`, `parent_only` or `held_out_parents`.
- **Parent_Case**: A case whose identifier is the `parent_case_id` of at least one evasion case.
- **Leakage**: A condition in which the data a stage is scored on was used to build that stage's seed or fixture.
- **IOC_Corpus**: The separate corpus of real publicly listed indicators used for threat-intelligence efficacy.
- **Plumbing_Only**: A label for data from a stub provider that exercises code paths and measures nothing about efficacy.
- **CBM_Fixture**: The committed hand-written codebase source text and call-graph snapshot used for CBM evaluation.
- **Fixture_Adapter**: `FixtureCodebaseMemoryClient`, which answers CBM queries from the CBM_Fixture snapshot without network access.
- **Permuted_Control**: The CBM row in which the same fixture graphs are assigned to tool names by a seeded permutation.
- **Not_Measured**: The recorded status of a Stage or configuration that lacks a prerequisite, rendered as an em dash with the reason.
- **Human_Grant**: An explicit statement by the human, in the current conversation, permitting one named credential variable to be read for a live run.
- **Runner**: The asynchronous orchestration module and the `scripts/holistic_eval.py` CLI.
- **Named_Explicitly**: The status of a live row (a Whole_System_Run, isolated live row or Forced_Table row that needs a credential, grant, fixture or transport) whose configuration identifier appears in the `--configs` list of a `scripts/holistic_eval.py run` invocation.
- **Default_Plan**: The set of rows that a `scripts/holistic_eval.py` subcommand (`plan`, `stages`, `run` or `validate`) plans or executes without the row's configuration identifier appearing in its `--configs` list, including every row that the Runner includes on its own account. A row is either Named_Explicitly or part of the Default_Plan, never both.
- **Notebook**: `notebooks/holistic_defense_analytics.py`, the marimo notebook that renders the comparison.
- **Tool_Name_Group**: `high_risk_name` when the tool name contains an entry of the Resolver's `_HIGH_RISK_TOOLS`, otherwise `other`.
- **Family**: `c2_ioc`, `payload` or `benign`, assigned by the rule in the design's Corpus loader.
- **Jev**: The Tier-1 TypeSafe classifier that returns P(threat).
- **Tier-2**: The Gemini escalation backend (`GeminiTier2Backend`).
- **ContextHygiene**: The sanitization middleware in `src/blackwall/resolver.py`.
- **Corpus_Loader**: The component that loads the Corpus through `build_cases` and attaches the case metadata and the Corpus_Hash.
- **Run_Store**: The component (`store.py`) that writes, reads and validates Run_Sets: schema version, Corpus_Hash, completeness, Pass validity and absence of credential-shaped strings.
- **Band_Replayer**: The pure component that performs the Band_Replay, the Outage_Drill and the parent-grouped held-out split from stored data.
- **CaseRecord**: The per-case, per-configuration, per-Pass record that the Run_Store writes, holding the Stage outputs, the System_Verdict and its provenance.
- **ConfigSpec**: The record that `build_resolver` takes to construct one Resolver configuration, holding the Layer choices, the Jev and Tier-2 sources and `demo_mode`.
- **ComposeConfig**: The record that the Composer takes, holding the enabled Layers, the `jev` flag, the Tier-2 mode, the Band, the `clear_high_policy`, the thresholds and the `cbm_sinks` mode.
- **ERROR row**: A CaseRecord whose decision is `ERROR`. An ERROR row has no usable Stage outputs for composition, is excluded from every rate, and is counted beside each affected figure [Open Question Q2].
- **UNMEASURED**: The value the Composer returns for a triggered case that has no Tier-2 output. It is not a decision value, is not an `ERROR`, is counted as Not_Measured, and is never imputed. The lowercase `unmeasured` marks the same condition in a replay cell.
- **Attack_Case**: A case whose `ground_truth` is `MALICIOUS`, that is, whose scenario class is malicious, evasion or evasion_proof.
- **Pass_Spread**: The maximum minus the minimum of a figure across the valid Passes, as defined in Requirement 13 criterion 21.

## Requirements

### Requirement 1: Production-Mode, Observe-Only Operation

**User Story:** As a maintainer, I want every harness measurement taken against the production resolver configuration without altering it, so that the figures transfer to the shipped firewall.

#### Acceptance Criteria

1. THE Harness SHALL run every Whole_System_Run with the Resolver in Production_Mode, meaning `demo_mode=False`, a block threshold of 0.75 and a quarantine threshold of 0.50.
2. IF a caller requests `demo_mode=True` for a Harness run, THEN THE Runner SHALL refuse the request at configuration validation, before any Resolver call is made and before any Run_Set is created. THE Runner SHALL exit with a non-zero status and report an error stating that `demo_mode=True` is not permitted.
3. IF a record with `demo_mode=True` is presented for writing, THEN THE Run_Store SHALL refuse to write it, raise an error stating that `demo_mode=True` records are not permitted, and leave every existing record and the Manifest of the Run_Set unchanged.
4. THE Stage_Recorder SHALL return from every wrapped Resolver component a value equal to the value the unwrapped component returns for the same inputs. THE Stage_Recorder SHALL raise from every wrapped Resolver component an exception of the same type and with the same arguments as the unwrapped component raises for the same inputs.
5. THE Harness SHALL pass `metadata=None` on every Resolver call, as the committed Jev runs did.
6. THE Harness SHALL place all new source under `src/blackwall/holistic_eval/`, `scripts/holistic_eval.py`, `notebooks/`, `tests/` and `tests/eval/`. THE Harness SHALL make no edit to any other file under `src/`, so that a diff of the Harness change against its base shows zero modified, added or deleted files under `src/` outside `src/blackwall/holistic_eval/`, except the single optional change that criterion 7 permits [Open Question Q6].
7. IF the Stage_Recorder cannot capture a Stage output without a change under `src/` outside `src/blackwall/holistic_eval/`, THEN THE Harness SHALL introduce at most one optional `observer` callback argument on `SyncResolver.evaluate` that defaults to `None`. THE Harness SHALL deliver that change on its own, with a test that fails before the change, and with a test showing that `evaluate()` called with the default `observer=None` returns the same decision and confidence score as before the change for the same inputs [Open Question Q9].
8. WHEN a Harness report is produced, THE Harness SHALL print in the report header the `demo_mode` value, the name of each optional Layer that was on (or `none`), the name of each optional Layer that was off (or `none`), and a statement that the verdicts exclude the Layers that were off.
9. IF the effective Resolver configuration at the start of a Whole_System_Run differs from Production_Mode in `demo_mode`, the block threshold or the quarantine threshold, THEN THE Runner SHALL abort the run before any case is evaluated, report each differing parameter with its expected and actual value, and write no per-case record.
10. IF the Stage_Recorder fails to record a Stage output for a case, THEN THE Stage_Recorder SHALL still return the wrapped component's value or raise its exception unchanged, SHALL mark that case's Case_Trace as incomplete, and THE Harness SHALL report the count of cases with an incomplete Case_Trace in the report header.
11. WHEN a Harness report is produced, THE Harness SHALL print in the report header a statement that an `environment_role=production` caller adds 0.15 to the context score and that this sensitivity was not run.

### Requirement 2: Corpus Loading and Case Metadata

**User Story:** As an evaluation engineer, I want each case loaded with the metadata the production-shaped states drop, so that results can be grouped and traced to ground truth.

#### Acceptance Criteria

1. WHEN the Corpus_Loader loads the Corpus, THE Corpus_Loader SHALL build every case through `scripts/jev_triage_eval.py::build_cases` for exactly the suites `security` and `evasion_proof`, and SHALL load no case from any other suite.
2. THE Corpus_Loader SHALL attach to each loaded case the fields `case_id`, `suite`, `ground_truth`, `scenario`, `tool_name`, sanitized `arguments`, `state_hash`, `attack_type`, `evasion_type`, `parent_case_id`, `expected_detection_path`, `Tool_Name_Group` and `Family`, plus the post-sanitization arguments hash required by criterion 7. For `attack_type`, `evasion_type`, `parent_case_id` and `expected_detection_path`, the loader SHALL record a null value, and not omit the field, when the source case has none.
3. THE Corpus_Loader SHALL treat a case as hostile if and only if its `ground_truth` string equals `MALICIOUS` (case-sensitive, no whitespace trimming). THE Corpus_Loader SHALL keep only cases whose `ground_truth` equals `BENIGN` or `MALICIOUS`, SHALL exclude every other case from the Corpus, and SHALL report the count and `case_id` list of excluded cases.
4. THE Corpus_Loader SHALL assign `Tool_Name_Group` exactly one of two values. The value is `high_risk_name` if the lower-cased tool name contains at least one entry of the Resolver's own `_HIGH_RISK_TOOLS` as a substring. Otherwise the value is `other`, including when the tool name is empty. The loader SHALL read `_HIGH_RISK_TOOLS` from the Resolver and SHALL NOT keep a separate copy.
5. THE Corpus_Loader SHALL assign each case exactly one `Family`, applying these rules in order: `c2_ioc` if `attack_type` equals `C2_IOC` (case-sensitive), or if `suite` is `evasion_proof` and `case_id` contains the lowercase substring `c2`; otherwise `payload` for any other case whose `ground_truth` is `MALICIOUS`; otherwise `benign`.
6. THE Corpus_Loader SHALL compute the Corpus_Hash over the `case_id`, tool name, arguments and `state_hash` of every loaded case, such that two loads of identical input produce identical hashes, and changing any single character of the tool name or arguments of any one case produces a different hash.
7. WHEN a corpus case is loaded, THE Corpus_Loader SHALL record, with that case's metadata, one hash of the case's arguments computed after ContextHygiene sanitization.
8. IF ContextHygiene produces sanitized arguments that differ from the case's loaded arguments through the password-redaction over-match or the `sk-` hyphenated-word over-match, THEN THE Harness test suite SHALL fail and the failure output SHALL name the `case_id` of every affected case [TASK-F08].
9. THE Harness SHALL load the current class-blind Corpus, identified by its Corpus_Hash, and SHALL NOT combine any figure with the end-to-end figures of ADR 0009 that were scored on the earlier Corpus, in any shared total, rate, table row or chart series.
10. IF `build_cases` raises an exception or returns zero cases for either the `security` or the `evasion_proof` suite, THEN THE Corpus_Loader SHALL abort the load with an error naming the failing suite and SHALL return no Corpus, not even a partial one.
11. IF two loaded cases share the same `case_id`, THEN THE Corpus_Loader SHALL abort the load with an error naming the duplicated `case_id` and SHALL return no Corpus.
12. IF a loaded case has no value for `case_id`, `suite`, `ground_truth`, `tool_name` or `state_hash`, THEN THE Corpus_Loader SHALL abort the load with an error naming the case and the missing field, and SHALL return no Corpus.

### Requirement 3: Isolated Stage Measurement

**User Story:** As a detection engineer, I want each defensive Stage measured alone with its own positive output, so that I can see what each Stage contributes before aggregation.

#### Acceptance Criteria

1. THE Harness SHALL compute, for every case in the Corpus, the output of the structural policy Stage, the context heuristics Stage, the TSG Stage, the CBM Stage, the Jev Stage and the Tier-2 Stage, independent of the Resolver's short-circuits, so that a case the Resolver allows, quarantines or blocks early still has an output from every Stage.
2. IF a Stage cannot produce an output for a case because a prerequisite is missing or the Stage raises an exception, THEN THE Harness SHALL record that Stage as Not_Measured with a reason for that case, SHALL NOT record a Stage_Flag value for that Stage on that case, and SHALL continue with the remaining Stages and cases.
3. THE Harness SHALL define each Stage_Flag exactly once, in the single stage-flag table of the Caught_Module, and SHALL NOT define any Stage_Flag condition or threshold in any other module.
4. WHEN the structural Stage output of a case is computed, THE Harness SHALL set the structural Stage_Flag on if the policy engine returns BLOCK, and off for any other decision.
5. WHEN the context Stage output of a case is computed, THE Harness SHALL set the context Stage_Flag on if `0.5*cbm_score + 0.5*context_score >= 0.30` with no semantic input, and off if the value is below 0.30, so that a value of exactly 0.30 is on.
6. WHEN the TSG Stage output of a case is computed, THE Harness SHALL set the TSG Stage_Flag on if `find_matching_signature` returns a match, and off if it returns no match.
7. WHEN the threat intelligence Stage output of a case is computed, THE Harness SHALL set the threat intelligence Stage_Flag on if the orchestrator's `is_malicious` is true, and off if it is false.
8. WHEN the Jev Stage output of a case is computed, THE Harness SHALL set `jev_low` on if `P >= lo` and off if `P < lo`, so that a P equal to `lo` is on.
9. WHEN the Jev Stage output of a case is computed, THE Harness SHALL set `jev_high` on if `P > hi` and off if `P <= hi`, so that a P equal to `hi` is off.
10. WHEN the Tier-2 Stage output of a case is computed, THE Harness SHALL set the Tier-2 Stage_Flag on if the Forced_Table decision for that case is BLOCK, and off for any other decision.
11. WHEN the CBM Stage output of a case is computed, THE Harness SHALL set the CBM Stage_Flag on if the blast radius is greater than or equal to `CBM_FLAG_BLAST_CUT` or at least one raw critical sink is present, and off otherwise.
12. THE Harness SHALL carry the `CBM_FLAG_BLAST_CUT` cut in one named constant with the value 6, and SHALL NOT use the literal value in any other place [Open Question Q4].
13. THE Harness SHALL label the `CBM_FLAG_BLAST_CUT` cut as a proposal in every reported figure that depends on the CBM Stage_Flag [Open Question Q4].
14. WHEN the context Stage is run, THE Harness SHALL build the Resolver with `client=None` and `enable_semantic_triage=False`.
15. WHEN the context Stage is run, THE Harness SHALL obtain tool score, novelty, context score and indicator by calling the Resolver's own `_score_tool_name`, `_score_argument_novelty`, `_score_context` and `_extract_indicator`, and SHALL NOT reimplement any of the four computations.
16. WHEN the structural Stage is run, THE Harness SHALL use the `StructuralGatingEngine` with `policy.yaml` and the default role `production`.
17. IF `policy.yaml` cannot be loaded, THEN THE Harness SHALL record the structural Stage as Not_Measured with a reason for every case and SHALL NOT substitute a default policy.
18. WHEN the Jev Stage is evaluated from stored data, THE Harness SHALL load P values from the committed class-blind Jev runs and SHALL NOT issue a live Jev call.
19. WHEN the Jev Stage is evaluated from stored data, THE Harness SHALL record the source run key for every case.
20. IF no committed class-blind Jev run holds a P value for a case, THEN THE Harness SHALL record the Jev Stage as Not_Measured with a reason for that case and SHALL NOT set `jev_low` or `jev_high` for it.
21. THE Harness SHALL label every isolated figure with the name of the Stage it measures and the names of the Layers that were on, and SHALL state "none" when no Layer was on.
22. THE Harness SHALL NOT add a Stage_Flag to a System_Verdict, so that the System_Verdict of every case is identical whether or not Stage_Flags are recorded.
23. THE Harness SHALL NOT report a Stage_Flag rate as a system catch rate, and SHALL show each Stage_Flag rate only in a row labeled as an isolated figure.
24. WHEN the Forced_Table is built, THE Runner SHALL run Tier-2 on every case, regardless of whether Tier-2 would have fired in the real Resolver.
25. WHEN the Forced_Table is built, THE Runner SHALL hand Tier-2 the Jev P of one named run for all cases [Open Question Q3].
26. WHEN the Forced_Table is built, THE Runner SHALL record the key of that run [Open Question Q3].
27. IF Tier-2 returns no verdict for a case, or the named run holds no Jev P for it, THEN THE Runner SHALL record the Tier-2 Stage as Not_Measured with a reason for that case and SHALL NOT record it as BLOCK or as a Tier-2 Stage_Flag that is off.

### Requirement 4: Whole-System Evaluation and Configuration Matrix

**User Story:** As a maintainer, I want the real Resolver run with chosen Layers enabled, so that I can compare the system verdict with each Stage's isolated figure.

#### Acceptance Criteria

1. THE Harness SHALL provide whole-system configuration W0, which enables Jev and Tier-2 and no optional Layer, as a required row in every whole-system table.
2. THE Harness SHALL provide whole-system configuration W1, which enables structural policy, Jev and Tier-2, as a required row in every whole-system table.
3. THE Harness SHALL provide whole-system configuration W2, which enables structural policy, TSG seeded in `parent_only` Seeding_Mode, Jev and Tier-2, as a required row in every whole-system table.
4. WHERE a `BW_OTX_API_KEY` Human_Grant exists, THE Harness SHALL provide configuration W3, which is W2 plus threat intelligence using the OTX-only orchestrator.
5. WHERE the CBM_Fixture exists, THE Harness SHALL provide configuration W4, which is W2 plus the Fixture_Adapter.
6. WHERE both the `BW_OTX_API_KEY` Human_Grant and the CBM_Fixture exist, THE Harness SHALL provide configuration W5, which is W2 plus threat intelligence and the Fixture_Adapter, run over the Corpus.
7. WHERE both the `BW_OTX_API_KEY` Human_Grant and the CBM_Fixture exist, THE Harness SHALL also run W5 over the IOC_Corpus, and SHALL report the IOC_Corpus results in rows separate from the Corpus results.
8. IF a prerequisite of W0, W1, W2, W3, W4, W5 or of an isolated row is absent, and the row is part of the Default_Plan or the absent prerequisite is a fixture or a transport, THEN THE Runner SHALL NOT execute that configuration, SHALL record it as Not_Measured with a reason naming the absent prerequisite, and SHALL continue with the remaining configurations. A credential or grant that is absent for a Named_Explicitly row is governed by Requirement 23 criteria 15, 16 and 17 and not by this criterion.
9. THE Harness SHALL construct every configuration through the single function `build_resolver(ConfigSpec, ...)` and through no other construction path.
10. WHEN a configuration is about to run, THE Harness SHALL print its layer description through `describe_layers`, stating for each optional Layer whether it is enabled or disabled, before any case of that configuration is evaluated.
11. IF `build_resolver` raises for a configuration, THEN THE Runner SHALL NOT execute that configuration's Pass, SHALL record the configuration as Not_Measured with a reason naming the construction failure, and SHALL continue with the remaining configurations.
12. WHEN a Whole_System_Run is executed, THE Runner SHALL build exactly one Resolver for each configuration and Pass.
13. WHEN a Whole_System_Run is executed, THE Runner SHALL evaluate every case of that Pass on the same Resolver instance, without resetting the front rate bucket or the Tier-2 rate bucket between cases, so that both buckets accumulate across the Pass as they do in production.
14. THE Runner SHALL NOT share a Resolver instance between two Passes or between two configurations.
15. IF `evaluate()` raises for a case during a Whole_System_Run, THEN THE Runner SHALL record the System_Verdict of that case as `ERROR` and SHALL continue with the remaining cases of the Pass.
16. THE Harness SHALL run the isolated rows I-JEV and I-T2, which exercise Tier-1 Jev and Tier-2 respectively, as defined in the design's Configuration Matrix.
17. THE Harness SHALL run the isolated rows I-STRUCT and I-CTX, which exercise structural policy and context heuristics respectively, as defined in the design's Configuration Matrix.
18. THE Harness SHALL run the isolated rows I-TSG-cold, I-TSG-parent and I-TSG-heldout, which correspond to the `cold`, `parent_only` and `held_out_parents` Seeding_Modes respectively, as defined in the design's Configuration Matrix.
19. THE Harness SHALL run the isolated rows I-TI-corpus and I-TI-ioc, which exercise threat intelligence over the Corpus and over the IOC_Corpus respectively, subject to the prerequisite rules of Requirement 22.
20. THE Harness SHALL run the isolated rows I-CBM-default, I-CBM-fixture and I-CBM-permuted, which correspond to the default CBM client, the Fixture_Adapter and the Permuted_Control respectively, subject to the prerequisite rules of Requirement 22.
21. THE Harness SHALL include an automated test that builds one Resolver with an empty temporary TSG database and another with `repo=None`, uses the same stubbed Jev and Tier-2 responses with no network access, evaluates every case of the Corpus on both, and fails if any case differs in decision or in confidence score.
22. THE Harness SHALL NOT run a live whole-system row for a cold TSG, relying on the test in criterion 21 as the equivalence evidence.
23. WHEN a Whole_System_Run is executed, THE Harness SHALL write into the Manifest the `ConfigSpec` field values that were passed to `build_resolver`, so that every field value read back from the Manifest equals the value used to build the Resolver, with no field omitted or altered.
24. THE Harness SHALL place isolated rows, Whole_System_Run rows and Composed_Rows in separate rows of every table, with no row combining results from more than one of those kinds.
25. THE Harness SHALL label every row in every table with its `kind`, identifying it as isolated, whole-system or composed, and SHALL NOT label a Composed_Row as whole-system.

### Requirement 5: Stage-First Recording

**User Story:** As an evaluation engineer, I want every Stage output recorded for every case, so that ablations and replays are computed offline on complete data.

#### Acceptance Criteria

1. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the hash of the sanitized arguments (the arguments after ContextHygiene) into the Case_Trace for that case.
2. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the structural-policy output into the Case_Trace for that case.
3. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the TSG output into the Case_Trace for that case.
4. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the CBM output into the Case_Trace for that case.
5. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the threat-intelligence output into the Case_Trace for that case.
6. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the Jev output into the Case_Trace for that case.
7. WHEN a case is run through an `ObservedResolver`, THE Stage_Recorder SHALL record the Tier-2 output into the Case_Trace for that case.
8. THE Stage_Recorder SHALL leave every value returned by a wrapped Resolver component, and the System_Verdict returned by `evaluate()`, identical to the value an unwrapped Resolver returns for the same case and state.
9. IF a Stage does not execute for a case (for example because its Layer is disabled or an earlier Stage ended the evaluation), THEN THE Stage_Recorder SHALL record that Stage's entry in the Case_Trace as not executed, and the entry SHALL be distinguishable from a recorded negative output.
10. IF `evaluate()` raises an exception for a case, THEN THE Stage_Recorder SHALL record the System_Verdict decision `ERROR` and the exception class name, SHALL keep every Stage output recorded before the exception, and SHALL NOT record the exception message text.
11. WHILE two or more cases run concurrently on a shared Resolver, THE Stage_Recorder SHALL keep their Case_Traces separate through a per-task `ContextVar`, so that each Case_Trace contains only entries produced by its own case.
12. WHEN the Stage_Recorder records a TSG match, THE Stage_Recorder SHALL record the signature identifier and the match path, where the match path is exactly `fts` or `substring`.
13. IF the TSG query returns no match for a case, THEN THE Stage_Recorder SHALL record the TSG output as no match, with no signature identifier and no match path.
14. WHEN the Stage_Recorder records the CBM output, THE Stage_Recorder SHALL record the blast radius value that `CodebaseMemoryClient.query` returned.
15. WHEN the Stage_Recorder records the CBM output, THE Stage_Recorder SHALL record the mapped sinks that `CodebaseMemoryClient.query` returned, in returned order.
16. WHEN the Stage_Recorder records the CBM output, THE Stage_Recorder SHALL record the raw sinks the backend reported before the enum mapping, in reported order and including any raw sink that the mapping did not map to an enum value.
17. WHEN the Stage_Recorder records the Tier-2 output, THE Stage_Recorder SHALL record whether Tier-2 fired (true or false), the trigger (exactly `ambiguity`, `disagreement` or `none`), the decision, the threat score, and the unavailable reason.
18. WHEN Tier-2 fired for a case, THE Stage_Recorder SHALL record the Tier-2 latency in milliseconds, measured from the start of the Tier-2 call to its return or failure.
19. WHEN a Gemini client call is observed during Tier-2, THE Stage_Recorder SHALL record the HTTP status code of that call.
20. WHEN the Stage_Recorder records the Tier-2 output, THE Stage_Recorder SHALL record the Jev P (P(threat), a value from 0.0 to 1.0) that was shown to Tier-2.
21. IF Tier-2 did not fire for a case, THEN THE Stage_Recorder SHALL record the trigger as `none`, and SHALL record the decision, threat score, latency and HTTP status as absent.
22. THE Stage_Recorder SHALL derive the Tier-2 trigger from recorded values, using `ambiguity` when `lo <= P <= hi`, using `disagreement` when `lo <= P <= hi` is false and the argument novelty score is at least 0.4 and `P < 0.2`, and using `none` otherwise.
23. THE Harness SHALL verify by test, over generated inputs that include the values `lo`, `hi`, 0.2 and 0.4 and values one step below and above each, that the derived trigger equals the trigger outcome of the Resolver's own `_maybe_escalate_tier2`.
24. WHILE a Harness measurement run executes, THE Stage_Recorder SHALL drop the Resolver's background tasks (`_schedule_task`, `_schedule_attribution`) without running them and SHALL close each dropped coroutine.
25. WHILE a Harness measurement run executes, THE Stage_Recorder SHALL ensure that no signature is written to the TSG database and no attribution call is made, and that no "coroutine was never awaited" warning is emitted.
26. IF a Tier-2 call returns HTTP status 429, THEN THE Stage_Recorder SHALL record only the exception class name and the status code 429, and SHALL NOT record a message body.
27. THE Stage_Recorder SHALL capture the structural, TSG, CBM, threat-intelligence, Jev and Tier-2 outputs by attribute assignment on the Resolver instance, as `jev_tier2_eval.py` does, and SHALL leave every production source file unmodified (an empty diff of production source before and after a run).

### Requirement 6: The Definition of Caught

**User Story:** As a maintainer, I want the definition of caught to live in one pure function, so that changing the definition is a one-line edit with tests.

#### Acceptance Criteria

1. THE Caught_Module SHALL expose a pure function `outcome(ground_truth, decision, reading)` that returns exactly one Outcome for every valid combination of its three arguments.
2. THE function `outcome` SHALL return the same Outcome for identical arguments on every call, independent of environment variables, files, network access, clock, random state and earlier calls, and SHALL NOT modify its arguments.
3. THE Caught_Module SHALL hold the mapping from each Reading to its set of stopping decisions in one table, with the Stopped_Reading mapped to `BLOCK` and `QUARANTINE` and the Blocked_Reading mapped to `BLOCK` alone.
4. THE Caught_Module SHALL derive every stopping-set membership test in `outcome` and `rates` from that table and from no other source, so that editing one table entry changes the results of both functions without any edit outside the table.
5. WHEN `decision` is `ERROR` and `ground_truth` is valid, THE Caught_Module SHALL return the Outcome `ERROR` for either Reading and for either ground truth, before applying any stopping-set test.
6. WHEN `ground_truth` is `MALICIOUS` and `decision` is `BLOCK`, `QUARANTINE` or `ALLOW` and is in the stopping set of the Reading, THE Caught_Module SHALL return `CAUGHT`.
7. WHEN `ground_truth` is `MALICIOUS` and `decision` is `BLOCK`, `QUARANTINE` or `ALLOW` and is not in the stopping set of the Reading, THE Caught_Module SHALL return `MISSED`.
8. WHEN `ground_truth` is `BENIGN` and `decision` is `BLOCK`, `QUARANTINE` or `ALLOW` and is in the stopping set of the Reading, THE Caught_Module SHALL return `FALSE_ALARM`.
9. WHEN `ground_truth` is `BENIGN` and `decision` is `BLOCK`, `QUARANTINE` or `ALLOW` and is not in the stopping set of the Reading, THE Caught_Module SHALL return `CORRECT_ALLOW`.
10. WHEN `outcome` returns `CAUGHT` under the Blocked_Reading for a given `ground_truth` and `decision`, THE Caught_Module SHALL return `CAUGHT` for the same `ground_truth` and `decision` under the Stopped_Reading.
11. WHEN `outcome` returns `FALSE_ALARM` under the Blocked_Reading for a given `ground_truth` and `decision`, THE Caught_Module SHALL return `FALSE_ALARM` for the same `ground_truth` and `decision` under the Stopped_Reading.
12. IF `ground_truth` is not exactly `BENIGN` or `MALICIOUS` (case-sensitive, including when `decision` is `ERROR`), THEN THE Caught_Module SHALL raise an error whose message contains the invalid value, and SHALL NOT return an Outcome.
13. IF `decision` is not exactly `ALLOW`, `QUARANTINE`, `BLOCK` or `ERROR` (case-sensitive), THEN THE Caught_Module SHALL raise an error whose message contains the invalid value, and SHALL NOT return an Outcome.
14. IF `reading` is neither the Stopped_Reading nor the Blocked_Reading, THEN THE Caught_Module SHALL raise an error whose message contains the invalid value, and SHALL NOT return an Outcome.
15. THE Harness test suite SHALL include a source-scan test that fails IF any Harness module other than the Caught_Module compares a decision value against the literal `"BLOCK"` or `"QUARANTINE"`, whether by equality, inequality or membership.
16. IF the source-scan test fails, THEN THE Harness test suite SHALL report the module path and line number of each offending comparison.
17. WHEN `rates` is called with a set of records and a Reading, THE Caught_Module SHALL return the catch rate, the false-alarm rate, the error count and the case count for that set under that Reading, computed from the Outcome of each record as returned by `outcome`.
18. THE Caught_Module SHALL compute the catch rate as the number of records with Outcome `CAUGHT` divided by the number of records with ground truth `MALICIOUS` and an Outcome other than `ERROR`, as a fraction from 0.0 to 1.0 inclusive without rounding, so that `ERROR` records are excluded from both the numerator and the denominator [Open Question Q2].
19. THE Caught_Module SHALL compute the false-alarm rate as the number of records with Outcome `FALSE_ALARM` divided by the number of records with ground truth `BENIGN` and an Outcome other than `ERROR`, as a fraction from 0.0 to 1.0 inclusive without rounding, so that `ERROR` records are excluded from both the numerator and the denominator [Open Question Q2].
20. THE Caught_Module SHALL report the error count as the number of records with Outcome `ERROR`, and the case count as the number of records in the set, including records with Outcome `ERROR`.
21. IF a set has no non-`ERROR` records with ground truth `MALICIOUS`, THEN THE Caught_Module SHALL report the catch rate as undefined, not as 0.0, and SHALL NOT raise an error.
22. IF a set has no non-`ERROR` records with ground truth `BENIGN`, THEN THE Caught_Module SHALL report the false-alarm rate as undefined, not as 0.0, and SHALL NOT raise an error.
23. IF a set is empty, THEN THE Caught_Module SHALL return an error count of 0 and a case count of 0, with both rates undefined.
24. IF any record in the set has an invalid `ground_truth` or `decision`, THEN THE Caught_Module SHALL raise the error defined for `outcome`, and SHALL NOT return partial results.
25. THE Caught_Module SHALL also return, from `rates`, a sensitivity catch rate and a sensitivity false-alarm rate in which each `ERROR` record is treated as stopped (an attack counts as caught and a benign case counts as a false alarm) and is included in the denominator, matching the gateway's fail-closed behavior [Open Question Q2]. The sensitivity values serve the catch tables that state a catch rate or a false-alarm rate for Whole_System_Run and Composed_Row System_Verdicts (Requirement 7 criterion 14); the Harness SHALL NOT show them for replay cells, TSG rates, threat-intelligence rates, IOC_Corpus rates or the CBM `sinks mapped` what-if row.
26. THE Caught_Module SHALL NOT receive a record whose composed decision is the value `UNMEASURED`. THE Harness SHALL exclude such records from `outcome` and `rates`, count them as Not_Measured, and report their number beside every affected figure.

### Requirement 7: Paired Readings, Quarantine Provenance and ERROR Handling

**User Story:** As a security operator, I want both readings and the cause of each QUARANTINE shown side by side, so that a fail-closed outage is not mistaken for a detection.

#### Acceptance Criteria

1. THE Harness SHALL show, in every table row that states a catch rate or a false-alarm rate, the Stopped_Reading value and the Blocked_Reading value in adjacent cells of that row. Each value SHALL be a percentage rounded to one decimal place, with the case count used as its denominator shown in the same row.
2. THE Harness SHALL show, in every chart and every report that states a catch rate or a false-alarm rate, the Stopped_Reading value and the Blocked_Reading value as visible labels. The labels SHALL be readable without hovering, clicking or expanding, and SHALL use the same percentage format as criterion 1.
3. WHEN the Notebook offers a Reading selector and the user changes the selected Reading, THE Notebook SHALL change only which Reading the chart highlights.
4. WHEN the user changes the selected Reading, THE Notebook SHALL keep the Stopped_Reading value and the Blocked_Reading value unchanged and visible, and SHALL NOT start a new Resolver run.
5. WHEN the decision of a case is `QUARANTINE`, THE Harness SHALL record for that case a `quarantine_cause` that is exactly one of `aggregate`, `tier2_unavailable` or `rate_limit`.
6. WHEN the decision of a case is `ALLOW`, `BLOCK` or `ERROR`, THE Harness SHALL record `quarantine_cause` as `none` for that case.
7. THE Harness SHALL provide in every catch table a column that reports, under the Stopped_Reading, the integer number of `CAUGHT` outcomes whose decision is `QUARANTINE` with `quarantine_cause` `tier2_unavailable` or `rate_limit`.
8. THE Harness SHALL provide in every catch table a column that reports, under the Stopped_Reading, the integer number of `FALSE_ALARM` outcomes whose decision is `QUARANTINE` with `quarantine_cause` `tier2_unavailable` or `rate_limit`. Each of these columns SHALL show `0` and SHALL NOT be blank when no such outcome exists.
9. IF `evaluate()` raises an exception for a case, THEN THE Harness SHALL record that case with decision `ERROR` and `decided_by` equal to `error`.
10. IF `evaluate()` raises an exception for a case, THEN THE Harness SHALL record the exception class name in that case's record and SHALL continue with the remaining cases.
11. IF `evaluate()` raises an exception for a case, THEN THE Harness SHALL keep that case in the Run_Set, so that the number of recorded cases equals the number of Corpus cases attempted.
12. WHERE the provisional ERROR handling of the design is in force, THE Harness SHALL exclude `ERROR` rows from both the numerator and the denominator of every catch rate and every false-alarm rate [Open Question Q2].
13. WHERE the provisional ERROR handling of the design is in force, THE Harness SHALL show in every table the integer number of `ERROR` rows, and SHALL show `0` when there are none [Open Question Q2].
14. WHERE the provisional ERROR handling of the design is in force, THE Harness SHALL provide in every catch table that states a catch rate or a false-alarm rate for Whole_System_Run or Composed_Row System_Verdicts (the catch tables of Requirements 6, 7 and 13) a sensitivity column in which each `ERROR` row is treated as stopped: an attack case counts as caught and a benign case counts as a false alarm, matching the gateway's fail-closed behavior [Open Question Q2]. Replay cells, TSG rates, threat-intelligence rates, IOC_Corpus rates and the CBM `sinks mapped` what-if row SHALL state the `ERROR` exclusion and the `ERROR` count only and SHALL carry no sensitivity column.
15. WHERE the Stopped_Reading is the primary reading, THE Harness SHALL count as caught every attack case whose decision is `QUARANTINE`, whatever its `quarantine_cause` [Open Question Q1].
16. WHERE the Stopped_Reading is the primary reading, THE Harness SHALL show separately the percentage, rounded to one decimal place, of caught attack cases whose decision is `QUARANTINE` with `quarantine_cause` `tier2_unavailable` or `rate_limit`. The denominator SHALL be all attack cases caught under the Stopped_Reading [Open Question Q1].
17. IF the number of caught attack cases under the Stopped_Reading is `0`, THEN THE Harness SHALL render the share of criterion 16 as Not_Measured with a stated reason, and SHALL NOT render it as `0.0%` or as a numeric error value [Open Question Q1].
18. THE Harness SHALL state, adjacent to every table, chart and report that shows the Stopped_Reading, that a `QUARANTINE` does not execute the tool in the MCP gateway or the ADK integration.
19. THE Harness SHALL state, adjacent to every table, chart and report that shows the Stopped_Reading, that the Harness does not model what a human review or a later retry decides.
20. THE Harness SHALL set the `decided_by` field of every case record from the recorded Stage outputs and the recorded verdict, using the same precedence as `evaluate()`.
21. WHEN the Harness recomputes `decided_by` for a case from its recorded Stage outputs and verdict, THE Harness SHALL obtain a value equal to the stored `decided_by`, and any difference SHALL be reported as a failure naming the case identifier.

### Requirement 8: Stage Flags Never Feed System Verdicts

**User Story:** As a reviewer, I want isolated Stage figures kept apart from system figures, so that a Stage_Gate is never reported as the firewall's catch rate.

#### Acceptance Criteria

1. IF a caller supplies a Stage_Flag, a flag cut or a flag policy as an input to the Composer, THEN THE Composer SHALL reject the call with an error that names the rejected input, SHALL return no System_Verdict, and SHALL leave all stored Stage outputs unchanged.
2. WHEN the Composer is called twice with identical Stage outputs and an identical `ComposeConfig`, and the Harness holds a different flag policy for each call, THE Composer SHALL return the same System_Verdict, including the same decision and the same Quarantine_Cause, for both calls.
3. THE Harness SHALL print the name of the Stage that produced the figure beside every Stage figure it reports.
4. THE Harness SHALL print beside every Stage figure the list of Layers that were enabled when the figure was produced, and SHALL print `none` when no Layer was enabled.
5. THE Harness SHALL label every Stage figure as either a Stage_Gate or a Stage_Flag rate, and SHALL NOT label a Stage figure as a catch rate or present it in a System_Verdict column.
6. IF an attack case has a Stage_Flag on in at least one enabled Stage, and the case's System_Verdict is not caught under the Reading in use (a decision of `ALLOW`, or a decision of `QUARANTINE` under the Blocked_Reading; a case whose decision is `ERROR` is excluded from the Catch_Partition per Requirement 13 [Open Question Q2]), THEN THE Ablation_Analyzer SHALL assign the case to `lost_by_system` and to no other Catch_Partition class.
7. WHEN the Harness writes a report for a configuration in which threat intelligence and CBM are both absent (disabled or Not_Measured), THE Harness SHALL include a statement that the weighted aggregate cannot reach the Production_Mode quarantine threshold of 0.50 from the Tier-1 Jev and Tier-2 signals alone, and SHALL include the maximum aggregate it computed, rounded to 2 decimal places, with every semantic signal set to 1.0 and every other Stage output absent.
8. IF the maximum aggregate computed for criterion 7 is greater than or equal to 0.50, THEN THE Harness SHALL omit the statement required by criterion 7, SHALL report the computed value, and SHALL exit with a non-zero status.

### Requirement 9: Composer Fidelity to the Resolver

**User Story:** As an evaluation engineer, I want the offline composer checked against the real resolver, so that every composed ablation and replay is anchored to production behavior.

#### Acceptance Criteria

1. THE Composer SHALL compute the System_Verdict from recorded Stage outputs and a `ComposeConfig`, and SHALL return equal output on two calls with identical inputs. A recorded `ERROR` row has no Stage outputs to compose from, so THE Composer SHALL NOT receive it; the caller carries it through unchanged as `ERROR` (Requirement 15 criterion 5).
2. THE `ComposeConfig` SHALL hold the enabled Layers (any subset of structural policy, TSG, threat intelligence and CBM), the `jev` flag (false models `enable_semantic_triage=False`), the Tier-2 mode (`recorded`, `absent` or `unavailable`), the Band (`lo` and `hi`), the `clear_high_policy`, the block threshold, the quarantine threshold and the `cbm_sinks` mode.
3. IF a `ComposeConfig` has a Tier-2 mode other than `recorded`, `absent` or `unavailable`, a Band with `lo` greater than `hi` (a zero-width Band with `lo` equal to `hi` is valid), a Band edge outside 0.0 to 1.0 inclusive, a threshold outside 0.0 to 1.0 inclusive, or a quarantine threshold greater than the block threshold, THEN THE Composer SHALL reject the configuration with an error that names the invalid field and SHALL return no System_Verdict.
4. THE Composer SHALL restate only the aggregation and decision lines of `evaluate()` and the context-score arithmetic.
5. WHEN the Composer computes a System_Verdict, THE Composer SHALL read every Stage's score from the recorded Stage outputs and SHALL NOT invoke any Stage component, network call or Tier-2 backend.
6. WHEN the `ComposeConfig` equals the recorded configuration, the shipped Band (0.35 and 0.75) and the recorded Tier-2 outputs, THE Composer SHALL return, for each case that is not a recorded `ERROR` row, a decision equal to the recorded `final_decision` and a score within 1e-9 (absolute) of the recorded `final_score`.
7. WHEN a TSG match is present and the TSG Layer is enabled, THE Composer SHALL return `BLOCK` with `decided_by` equal to `tsg`.
8. IF a TSG match is present and the TSG Layer is disabled, THEN THE Composer SHALL NOT return `decided_by` equal to `tsg` for that case.
9. WHEN the structural Layer is enabled and the structural output is blocked, THE Composer SHALL return `BLOCK`.
10. WHEN the structural Layer is enabled and the structural output is blocked, THE Composer SHALL NOT trigger Tier-2 for that case and SHALL NOT read that case's recorded Tier-2 output.
11. IF the decision from the TSG, the structural Layer or the aggregate is `BLOCK`, THEN THE Composer SHALL return `BLOCK` for that case in every Tier-2 mode and for every recorded Tier-2 decision, including `ALLOW`.
12. WHEN the Tier-2 mode is `recorded`, a case is triggered, the recorded Tier-2 output holds a decision, and the prior decision is not `BLOCK`, THE Composer SHALL return the recorded Tier-2 decision as the System_Verdict.
13. IF the Tier-2 mode is `unavailable`, a case is triggered and the aggregate decision is `ALLOW`, THEN THE Composer SHALL return `QUARANTINE` with Quarantine_Cause `tier2_unavailable`.
14. IF the Tier-2 mode is `recorded`, a case is triggered, the prior decision is not `BLOCK` and the case has no recorded Tier-2 output, THEN THE Composer SHALL return the value `UNMEASURED` and SHALL NOT return `ALLOW`, `QUARANTINE`, `BLOCK` or `ERROR` for that case. THE Harness SHALL count such a case as Not_Measured and exclude it from every rate (see Requirement 6).
15. THE Harness test suite SHALL include a differential test that builds a real Resolver with stubbed Stage components returning generated values, runs at least 200 generated cases per execution, and fails with the generated inputs reported if `evaluate()` and the Composer differ in decision or differ in score by more than 1e-9 (absolute) on any case.
16. THE Harness test suite SHALL pin the Composer's decision at the aggregate scores 0.4999, 0.50, 0.7499 and 0.75 under the block threshold 0.75 and the quarantine threshold 0.50, with each pinned decision equal to the Resolver's decision for the same score.
17. THE Harness test suite SHALL pin the Composer's Tier-2 trigger result at the Jev P values 0.349, 0.35, 0.75 and 0.751 under the shipped Band, with each pinned result equal to the Resolver's trigger result for the same value.
18. WHEN a Whole_System_Run exists for a configuration that also has a Composed_Row, THE Harness SHALL report, for each case that is not a recorded `ERROR` row and whose Composed_Row decision differs from the recorded decision, one finding that names the case identifier, the configuration, the composed decision and the recorded decision.
19. WHEN a Whole_System_Run and a Composed_Row exist for the same configuration and no case differs, THE Harness SHALL report zero findings for that configuration.

### Requirement 10: Per-Case Records and Serialization

**User Story:** As an evaluation engineer, I want one validated record per case per configuration per pass, so that every figure can be recomputed from the data.

#### Acceptance Criteria

1. WHEN a Pass completes a case under a configuration, THE Run_Store SHALL write exactly one `CaseRecord` for that case, configuration and pass index, and SHALL NOT write a second `CaseRecord` for the same combination within the same Run_Set.
2. THE Run_Store SHALL include in every `CaseRecord` the schema version, run set, run identifier, configuration identifier, pass index, Corpus_Hash, case identity fields, sanitized-arguments hash, Stage outputs, `final_decision`, `final_score`, `decided_by`, `quarantine_cause`, `error`, resolver mode and latency.
3. THE Run_Store SHALL decode every encoded `CaseRecord` through its JSON codec to a value equal to the value that was encoded.
4. THE Run_Store SHALL decode every encoded Manifest through its JSON codec to a value equal to the value that was encoded.
5. THE Run_Store SHALL round every float to 4 decimal places on write, so that a decoded float equals the written float rounded to 4 decimal places.
6. THE Run_Store SHALL write each file by first writing a temporary file in the same directory as the target file and then renaming it to the target name.
7. IF a file write fails before the rename completes, THEN THE Run_Store SHALL raise a write error that names the target file, SHALL leave any previously existing target file byte-identical to its prior content, and SHALL leave no temporary file in the target directory.
8. IF a file carries a `schema_version` that is absent or differs from the supported version, THEN THE Run_Store SHALL reject the file with an error that names the file and SHALL NOT return any data from that file.
9. IF a file is truncated or contains a corrupt line, THEN THE Run_Store SHALL raise a loader error that names the file and SHALL NOT return partial data from that file.
10. IF a record has `final_decision` equal to `ERROR` and `error` is absent, THEN THE Run_Store SHALL reject the record with an error that names the case and configuration, and SHALL NOT write the record.
11. IF a record has `final_decision` equal to `ERROR` and `decided_by` does not equal `error`, THEN THE Run_Store SHALL reject the record with an error that names the case and configuration, and SHALL NOT write the record.
12. WHEN an efficacy table is built, THE Run_Store SHALL exclude every record with source `stub_plumbing_only` from every count in that table.
13. WHEN a Run_Set is about to be committed, THE Run_Store SHALL scan every file in the Run_Set, including the Manifest, with the ContextHygiene secret patterns.
14. IF the scan of a Run_Set file finds a match, THEN THE Run_Store SHALL fail the commit with an error that names each matching file, SHALL NOT include the matched text in that error, and SHALL leave the Run_Set uncommitted.
15. THE Run_Store SHALL NOT store any payload response body in any Run_Set file.
16. THE Run_Store SHALL NOT store any exception message body in any Run_Set file.
17. THE Run_Store SHALL NOT store the value of any credential variable in any Run_Set file.

### Requirement 11: Manifest, Corpus Binding and Results Directory

**User Story:** As a reviewer, I want each Run_Set bound to the corpus it scored and stored in a new directory, so that stale or edited data cannot be mistaken for current evidence.

#### Acceptance Criteria

1. THE Harness SHALL commit every Run_Set under `tests/eval/results/holistic/<run-set>/`.
2. THE Harness SHALL leave every file under `tests/eval/results/jev_runs/` and `tests/eval/results/jev_runs_class_blind/` byte-identical before and after any Harness operation, with no file created, edited or deleted in either directory.
3. THE Manifest SHALL record the schema version as a single integer of 1 or greater, and the run set name as a non-empty string equal to the Run_Set directory name.
4. THE Manifest SHALL record a description that states, in text, that a Stage_Gate is not a system rate.
5. THE Manifest SHALL record the creation date as a UTC calendar date in `YYYY-MM-DD` form, and the git commit as the full 40-character hexadecimal identifier of the commit checked out when the Run_Set was created.
6. THE Manifest SHALL record the corpus name, the Corpus_Hash, and a digest of the state hashes of every case in the Corpus. The digest SHALL be identical on every recomputation over an unchanged Corpus.
7. THE Manifest SHALL record, for every configuration in the Configuration_Matrix that has a run entry, the resolver construction used for that configuration, keyed by `config_id`.
8. THE Manifest SHALL record the Jev source as the stored run keys and the served releases. Each served release SHALL be recorded as it was reported by the service at call time, or as a Not_Measured entry with a reason if none was reported.
9. THE Manifest SHALL record the Tier-2 source as the model, the pinned thinking level and the Forced_Table passes. Each Forced_Table pass SHALL be recorded by its `pass_index`.
10. THE Manifest SHALL record one run entry per executed Pass. Each run entry SHALL carry `config_id`, `pass_index`, an interleave position that is a 1-based integer (1 or greater), unique within the Run_Set and ordered by execution start, the `--concurrency` value the Pass used, and a validity of exactly `valid` or `discarded`.
11. THE Manifest SHALL record `discarded_passes` as the reason and the count of each discarded Pass, with the count an integer of 0 or greater and the reason a non-empty string for each entry.
12. THE Manifest SHALL record the call counts and the token counts as integers of 0 or greater for every Stage that made external calls. The call counts and token counts SHALL cover valid Passes and discarded Passes separately.
13. THE Manifest SHALL record a billing statement as non-empty text that states whether any paid call was made in the Run_Set.
14. THE Manifest SHALL record the credential grant notes as the name of each credential variable read and the Human_Grant date in `YYYY-MM-DD` form.
15. THE Manifest SHALL NOT record any credential value, and no file in the Run_Set SHALL contain the value of any credential variable named in the credential grant notes.
16. THE Manifest SHALL record every Stage that lacks a prerequisite as a Not_Measured entry carrying the Stage name and a non-empty reason.
17. IF a Stage appears in neither the run entries nor the Not_Measured entries, THEN THE Run_Store SHALL reject the Manifest as invalid. The rejection SHALL name each such Stage, SHALL load no results from the Run_Set, and SHALL leave the Run_Set files unchanged.
18. WHEN a Run_Set is validated, THE Run_Store SHALL check that each `(config_id, pass_index, case_id)` occurs exactly once in each valid run. A case whose decision is `ERROR` SHALL count as one occurrence. This is consistent with the provisional rule (Open Question Q2) that rates exclude `ERROR` rows from numerator and denominator, because the check counts rows and does not compute rates.
19. IF a `(config_id, pass_index, case_id)` occurs zero times or more than once in a valid run, THEN THE Run_Store SHALL reject the Run_Set. The rejection SHALL name each offending triple and its occurrence count, and SHALL load no results from the Run_Set.
20. WHEN a Run_Set is validated, THE Run_Store SHALL check that the `corpus_hash` of each per-case file equals the Corpus_Hash recomputed from the loaded Corpus.
21. IF the Corpus is edited after a run, THEN THE Run_Store validation and the Notebook loader SHALL each fail, SHALL name every case identifier whose recomputed contribution to the Corpus_Hash differs from the stored one, and SHALL present no results from that Run_Set.
22. WHEN the Corpus changes, THE Harness SHALL store re-scored results in a new Run_Set directory whose name differs from every existing Run_Set directory, and SHALL leave every existing Run_Set directory byte-identical.
23. WHERE two or more Run_Sets bound to different Corpus_Hash values exist, THE Harness SHALL load and validate each Run_Set independently, so that the result for one Run_Set does not depend on the presence of another.
24. IF the target Run_Set directory already exists when a run starts, THEN THE Harness SHALL refuse to write, SHALL leave the existing directory byte-identical, and SHALL exit with a non-zero status and an error indicating that the Run_Set already exists.
25. WHEN a Pass is discarded, THE Run_Store SHALL record its reason and count in `discarded_passes`.
26. WHEN a Pass is discarded, THE Run_Store SHALL commit zero per-case records from that Pass.

### Requirement 12: Committed Evidence and Recomputing Tests

**User Story:** As a reviewer, I want every cited figure backed by committed per-case data and a test that recomputes it, so that no figure exists only in prose.

#### Acceptance Criteria

1. THE Harness SHALL provide a unit test that recomputes, from the committed per-case files, every rate cited by an ADR, a spec or the Notebook, excluding ERROR rows from both numerator and denominator (provisional, Open Question Q2).
2. THE Harness SHALL provide a unit test that recomputes, from the committed per-case files, every Catch_Partition count and every Band_Replay cell at the shipped Band cited by an ADR, a spec or the Notebook.
3. WHEN the unit test compares a recomputed count or Band_Replay cell with a cited figure, THE Harness test suite SHALL require exact integer equality for counts and exact equality of the verdict for each replay cell.
4. WHEN the unit test compares a recomputed rate with a cited figure, THE Harness test suite SHALL require equality after rounding the recomputed rate to the number of decimal places shown in the cited figure.
5. IF the denominator of a cited rate is zero after ERROR rows are excluded, THEN THE Harness test suite SHALL require the cited figure to be rendered as Not_Measured with its reason, and SHALL fail the test if any numeric value is cited.
6. IF a recomputed figure differs from the cited figure, THEN THE Harness test suite SHALL fail and SHALL report the citing location, the cited value and the recomputed value.
7. IF a figure is cited by an ADR, a spec or the Notebook and no recomputing test covers it, THEN THE Harness test suite SHALL fail and SHALL report the citing location of that figure.
8. THE Harness SHALL provide a unit test that binds each committed Run_Set to the Corpus by recomputing the Corpus_Hash and comparing it with the Corpus_Hash recorded in that Run_Set's Manifest.
9. THE Harness SHALL provide a unit test that compares the scored states of each committed Run_Set with the Corpus row for row, requiring the same case identifiers and the same state hash for every row.
10. IF the recomputed Corpus_Hash differs from the Manifest value, or a Run_Set row is missing, extra or has a different state hash, THEN THE Harness test suite SHALL fail and SHALL report the Run_Set and the first differing case identifier.
11. WHEN the Jev P (a probability between 0 and 1) of each case in a Whole_System_Run row is compared with the committed Jev run, THE Harness test suite SHALL require that the absolute difference between the live Pass and the stored run is at most JEV_P_MAX_ABS_DELTA = 0.10 for every compared case, that the mean of those absolute differences over all compared cases is at most JEV_P_MEAN_ABS_DELTA = 0.015, and that the number of cases whose Jev band zone differs between the live Pass and the stored run is at most JEV_P_MAX_ZONE_FLIPS = 1, where the zones at the shipped Band of 0.35 and 0.75 are allow below the lower edge, escalate within the edges and block above the upper edge, and where the Harness test suite SHALL round each per-case difference to 2 decimal places before testing it against its bound, because stored Jev P values have a resolution of 0.01, and SHALL test the mean bound unrounded.
12. THE Harness SHALL define JEV_P_MAX_ABS_DELTA, JEV_P_MEAN_ABS_DELTA and JEV_P_MAX_ZONE_FLIPS once, as fixed constants in one named module, and SHALL NOT compute any of them from the run under test. The values rest on the following dated evidence: on 2026-11-13, same-release run-to-run differences in the committed class-blind Jev runs had a maximum of 0.06 and a mean of 0.0063 to 0.0073 with 0 zone flips, the live Pass against the stored run in ADR 0009 had a mean of 0.009 and a maximum of 0.06, and a different Jev release on the same states differed by a mean of 0.019, a maximum of 0.13 and 4 zone flips. A Harness test SHALL fail if any of the three constants differs from the values recorded in criterion 11 of this requirement, and raising any bound SHALL be made only in the same change that adds new dated evidence justifying the new value. The Harness test suite SHALL record the observed maximum, mean and zone-flip count, with the identifiers of the live Pass and the stored run, in the test report, and the observed values SHALL NOT change any bound.
13. IF the live Pass violates JEV_P_MAX_ABS_DELTA, JEV_P_MEAN_ABS_DELTA or JEV_P_MAX_ZONE_FLIPS, THEN THE Harness test suite SHALL fail and SHALL report the metric name, the observed value and the bound, and, for JEV_P_MAX_ABS_DELTA and JEV_P_MAX_ZONE_FLIPS, the case identifier of each violating case. These bounds detect drift in Jev P and do not identify a Jev release, because the Jev release is verified separately by the served-release check of Requirement 24.
14. THE Harness SHALL commit sanitized per-case data covering every case of the Corpus for every valid Pass on which a cited figure depends.
15. IF a cited figure depends on a Pass for which no committed per-case data exists, THEN THE Harness test suite SHALL fail and SHALL report the figure and the Pass.
16. THE Harness test suite SHALL fail if a committed per-case file contains a value matching the sensitive-variable patterns that ContextHygiene replaces, and SHALL report the file.
17. THE Harness SHALL run every test required by this requirement from committed files alone, with no network access and no credential variable read.
18. WHEN a figure cited in an ADR, a spec or the Notebook changes after a re-score, THE Harness change SHALL update every citing location in the same commit as the re-scored per-case data.

### Requirement 13: Comparison Metrics, Catch Attribution and Groupings

**User Story:** As a detection engineer, I want each attack case attributed to the Stages that caught it, so that I can see which Stage earns its place and which catches are redundant or lost.

#### Acceptance Criteria

1. WHEN the Ablation_Analyzer receives a configuration, the per-case System_Verdicts, the Stage_Flags and a Reading, THE Ablation_Analyzer SHALL assign every attack case whose System_Verdict is neither `ERROR` nor `UNMEASURED` exactly one category of the Catch_Partition: `system_only`, `unique`, `redundant`, `lost_by_system` or `missed_by_all`. An attack case is a case whose scenario class is malicious, evasion or evasion_proof.
2. IF the System_Verdict of a case is `ERROR` or `UNMEASURED`, THEN THE Ablation_Analyzer SHALL exclude that case from the Catch_Partition, from every leave-one-out and add-one-in set, and from the numerator and denominator of every rate, and SHALL NOT impute a verdict for it. THE Ablation_Analyzer SHALL also report the number of excluded `ERROR` cases and the number of excluded `UNMEASURED` cases separately beside each affected figure (provisional, Open Question Q2).
3. THE Ablation_Analyzer SHALL treat a case as caught when the given Reading, as defined in the Caught_Module, counts its System_Verdict as caught. THE Ablation_Analyzer SHALL name the Reading in every output it produces.
4. THE Ablation_Analyzer SHALL assign `system_only` to a case that is caught and has no enabled Stage_Flag on. An enabled Stage_Flag is the Stage_Flag of a Stage that the configuration enables.
5. THE Ablation_Analyzer SHALL assign `unique` to a case that is caught, has at least one enabled Stage_Flag on, and has at least one single-Stage removal after which the case is no longer caught.
6. THE Ablation_Analyzer SHALL assign `redundant` to a case that is caught, has at least one enabled Stage_Flag on, and has no single-Stage removal after which the case is no longer caught.
7. THE Ablation_Analyzer SHALL assign `lost_by_system` to a case that is not caught and has at least one enabled Stage_Flag on.
8. THE Ablation_Analyzer SHALL assign `missed_by_all` to a case that is not caught and has no enabled Stage_Flag on.
9. THE Ablation_Analyzer SHALL list for each `unique` case every enabled Stage whose single removal makes the case not caught. The list SHALL contain at least one Stage and SHALL contain only enabled Stages. Where the removal is a Tier-2 removal, the entry SHALL carry its form label, `absent` or `unavailable`.
10. THE Ablation_Analyzer SHALL compute the leave-one-out unique catch of a Stage X as the set of case identifiers that are caught in the configuration and not caught in the configuration without X. THE Ablation_Analyzer SHALL report the set together with its size.
11. THE Ablation_Analyzer SHALL compute the add-one-in catch of a Stage X as the set of case identifiers that are caught in the baseline B0 (Jev, Tier-2, aggregation) plus X and not caught in B0. THE Ablation_Analyzer SHALL report the set together with its size.
12. IF the Stage X of an add-one-in computation is Jev, Tier-2 or aggregation, THEN THE Ablation_Analyzer SHALL report that add-one-in result as Not_Measured with a reason stating that X is already part of B0, and SHALL NOT compute a set for it.
13. IF a Stage output that the Composer needs for a recomposition is absent from the recorded run, THEN THE Ablation_Analyzer SHALL report the affected leave-one-out, add-one-in or Catch_Partition result as Not_Measured with a reason naming the missing Stage output, and SHALL NOT assign categories from partial data.
14. WHEN a Stage is removed in an ablation and the Stage is Tier-2, THE Ablation_Analyzer SHALL compute the `absent` form, which is aggregation alone with no Tier-2 output.
15. WHEN a Stage is removed in an ablation and the Stage is Tier-2, THE Ablation_Analyzer SHALL compute the `unavailable` form. In this form every triggered Tier-2 call whose resulting decision would be `ALLOW` becomes `QUARANTINE` with Quarantine_Cause `tier2_unavailable`. A triggered call whose decision is not `ALLOW`, and every call that did not trigger Tier-2, keeps its decision.
16. THE Ablation_Analyzer SHALL label each Tier-2 removal result with its form name, `absent` or `unavailable`. THE Ablation_Analyzer SHALL NOT merge, sum, or take the union of the two forms into one result.
17. WHEN Jev is disabled in a recomposition, THE Ablation_Analyzer SHALL recompose with `jev=False`, which models `enable_semantic_triage=False`. THE Ablation_Analyzer SHALL label the result as Jev-disabled.
18. THE Harness SHALL present every comparison table once for each of four groupings: scenario class (`benign`, `malicious`, `evasion`, `evasion_proof`), `attack_type`, Tool_Name_Group (`high_risk_name`, `other`), and Family (`c2_ioc`, `payload`, `benign`).
19. THE Harness SHALL place every case in exactly one group of each grouping. A case with no `attack_type` value SHALL be placed in a group labeled `no_attack_type`.
20. THE Harness SHALL attach to every count a Wilson interval at 95% two-sided confidence (z = 1.96). The interval SHALL be computed from the number of cases in the group that are not `ERROR` rows as the sample size, and from the count as the number of successes.
21. WHERE a configuration is live, THE Harness SHALL attach to every figure the per-Pass spread. The spread is the maximum minus the minimum of that figure across the valid Passes, in the unit of the figure. A spread over a single valid Pass SHALL be 0. Discarded Passes and Passes whose concurrency differs from the other valid Passes of the configuration (Requirement 24 criterion 5) SHALL NOT enter the spread.
22. IF a live configuration has no valid Pass, or a group has zero cases that are not `ERROR` rows, THEN THE Harness SHALL report the affected figure as Not_Measured with a reason, SHALL show the case count 0, and SHALL NOT compute an interval or a spread.
23. WHEN a group has fewer than 30 cases that are not `ERROR` rows, THE Harness SHALL state that case count beside every figure of the group and SHALL mark the group as small. A group of 30 or more such cases SHALL NOT carry the small-group marker.
24. THE Harness SHALL return identical rates, Catch_Partition assignments, ablation sets and sizes, and necessary-Stage lists for any permutation of the records of a run. Identical means exactly equal values with no numeric tolerance, with sets ordered by case identifier and Stage lists ordered by the fixed Stage order.
25. WHEN the Harness computes a Wilson interval for a sample size n of at least 1 and a count k from 0 to n inclusive, THE Harness SHALL return a lower bound and an upper bound that satisfy 0 ≤ lower ≤ point estimate ≤ upper ≤ 1. This applies to the cases k = 0 and k = n.

### Requirement 14: Tier-2 Outage Drill

**User Story:** As a security operator, I want the cost of a Tier-2 outage computed from recorded data, so that I can see how many benign calls ADR 0009 Decision 6 quarantines.

#### Acceptance Criteria

1. WHEN the Outage_Drill is run on a Run_Set, THE Band_Replayer SHALL recompute the decision of every case in that Run_Set's Corpus with the Tier-2 mode set to `unavailable`, so that every triggered Tier-2 call returns no verdict, using only stored data and making no call to Jev, Tier-2 or any threat-intelligence provider.
2. WHEN the Outage_Drill is run, THE Band_Replayer SHALL report the benign-case count as a non-negative integer. The count covers each benign case whose baseline decision is not `QUARANTINE` and whose recomputed decision is `QUARANTINE` with Quarantine_Cause `tier2_unavailable`. The baseline is the decision recomputed from the same stored Jev P values and the Forced_Table with Tier-2 available.
3. WHEN the Outage_Drill is run, THE Band_Replayer SHALL report, for each attack case, the baseline decision, the recomputed decision and its Quarantine_Cause, and the Outcome under the Stopped_Reading and under the Blocked_Reading.
4. WHEN the Outage_Drill is run, THE Band_Replayer SHALL report, for each Band cell, the integer `outage_quarantine_benign`. It is the criterion 2 count computed with that cell's `lo` and `hi` edges, and it is between 0 and the number of benign cases in the Corpus, inclusive.
5. IF the baseline or recomputed decision of a case is `ERROR`, THEN THE Band_Replayer SHALL report that case with Outcome `ERROR`, exclude it from `outage_quarantine_benign` and from the numerator and denominator of every rate it reports, and report the number of excluded cases (provisional, Open Question Q2).
6. IF a case has no stored Jev P value or no Forced_Table entry, THEN THE Band_Replayer SHALL exclude that case from every count and rate, and list its case identifier as Not_Measured with the reason. IF no case can be recomputed, THEN THE Band_Replayer SHALL report `outage_quarantine_benign` as Not_Measured and not as 0.
7. THE Notebook SHALL present the Outage_Drill in its own panel, separate from every other panel.
8. THE Notebook SHALL label each `QUARANTINE` decision with Quarantine_Cause `tier2_unavailable` on that panel as fail-closed behavior, and SHALL show the attack-case outage Outcomes of criterion 3 in a column separate from any figure labeled as detection or catch, so that a fail-closed QUARANTINE is never counted as a detection in a figure labeled as detection or catch [Open Question Q1].

### Requirement 15: Band Replay

**User Story:** As a maintainer, I want any Jev Band replayed over recorded data, so that I can see the effect of a band change on the whole firewall without further live calls.

#### Acceptance Criteria

1. WHEN the caller supplies a list of lower edges and a list of upper edges, THE Band_Replayer SHALL replay a verdict for every case at every `(lo, hi)` combination of one lower edge and one upper edge where `lo <= hi`, using only the stored Jev P, the recorded Stage outputs and the Forced_Table.
2. WHEN a `(lo, hi)` combination has `lo > hi`, THE Band_Replayer SHALL skip that combination and SHALL NOT produce a replay cell for it.
3. IF a supplied edge is not a number in the range 0.0 to 1.0 inclusive, THEN THE Band_Replayer SHALL reject the whole request with an error that names the offending value, SHALL produce no replay cell, and SHALL leave all stored data unchanged.
4. WHILE a replay is running, THE Band_Replayer SHALL open zero network connections.
5. WHEN the replay is run at the shipped Band with the shipped `clear_high_policy` and the recorded configuration, THE Band_Replayer SHALL return, for every case, a verdict equal to the recorded verdict. A recorded `ERROR` row has no Stage outputs to compose from, so THE Band_Replayer SHALL carry it through unchanged as `ERROR` with its recorded `error` class, SHALL NOT pass it to the Composer, SHALL exclude it from every rate, and SHALL count it beside each affected figure [Open Question Q2]. WHEN the replay is run at any Band other than the shipped Band, THE Band_Replayer SHALL carry every recorded `ERROR` row through unchanged in the same way.
6. IF the replay at the shipped Band, the shipped `clear_high_policy` and the recorded configuration returns a verdict that differs from the recorded verdict for any case (a recorded `ERROR` row that was carried through unchanged does not differ), THEN THE Band_Replayer SHALL report that replay as failed and SHALL list the identifier of each differing case with its recorded and replayed verdicts.
7. WHERE the `clear_high_policy` is `block`, THE Band_Replayer SHALL replay the Clear_High_Variant.
8. WHERE the `clear_high_policy` is `block`, THE Band_Replayer SHALL label every output that uses the Clear_High_Variant, at both case level and cell level, as hypothetical.
9. WHEN a replay varies the Band edges or the Clear_High_Variant, THE Band_Replayer SHALL hold the aggregation weights, the disagreement constants, the block threshold (0.75) and the quarantine threshold (0.50) at their recorded values.
10. WHEN a replay cell is produced, THE Band_Replayer SHALL report the catch rate under the Stopped_Reading and under the Blocked_Reading, each as a fraction from 0.0 to 1.0, computed as the CAUGHT attack cases divided by the attack cases that are neither `unmeasured` nor ERROR.
11. WHEN a replay cell is produced, THE Band_Replayer SHALL report the false-alarm rate under the Stopped_Reading and under the Blocked_Reading, each as a fraction from 0.0 to 1.0, computed as the FALSE_ALARM benign cases divided by the benign cases that are neither `unmeasured` nor ERROR.
12. WHEN the Band_Replayer computes any rate, THE Band_Replayer SHALL exclude every ERROR row from both the numerator and the denominator [Open Question Q2].
13. IF the denominator of a reported rate is zero, THEN THE Band_Replayer SHALL record that rate as Not_Measured with the reason, and SHALL NOT report it as 0.0 or 1.0.
14. WHEN a replay cell is produced, THE Band_Replayer SHALL report the Tier-2 call count as the number of cases for which Tier-2 fires in that cell, and the Tier-2 share as that count divided by the number of cases that are neither `unmeasured` nor ERROR, as a fraction from 0.0 to 1.0.
15. WHEN a replay cell is produced, THE Band_Replayer SHALL report the outage exposure of Requirement 14 computed for that cell's Band and `clear_high_policy`.
16. WHEN a replay cell is produced, THE Band_Replayer SHALL report the catch rate, false-alarm rate, Tier-2 call count and Tier-2 share separately for each Tool_Name_Group value and each Family value.
17. IF a triggered case has no Forced_Table entry, THEN THE Band_Replayer SHALL mark the case `unmeasured` and SHALL exclude it from every numerator and denominator in that cell.
18. IF a triggered case has no Forced_Table entry, THEN THE Band_Replayer SHALL report the number of such cases in the cell as `n_unmeasured`.
19. IF a triggered case has no Forced_Table entry, THEN THE Band_Replayer SHALL NOT substitute any value for the missing Tier-2 result.
20. IF a case has no stored Jev P, THEN THE Band_Replayer SHALL mark the case `unmeasured` in every cell, count it in `n_unmeasured`, and SHALL NOT substitute a Jev P.
21. WHEN one Band interval contains another, so that the lower edge of the containing interval is less than or equal to the lower edge of the contained interval and the upper edge of the containing interval is greater than or equal to the upper edge of the contained interval, THE Band_Replayer SHALL return a set of Tier-2-firing case identifiers for the containing interval that includes every identifier in the set for the contained interval, for any fixed Stage outputs.
22. THE Band_Replayer SHALL provide a held-out split function that assigns each case to exactly one of two sides, using the parity of the SHA-256 digest of the caller-supplied salt and the case's group key, read as an unsigned integer (even to one side, odd to the other).
23. THE Band_Replayer SHALL use `parent_case_id` as the group key when the case has one, and `case_id` otherwise.
24. THE Band_Replayer SHALL place an evasion variant and its parent on the same side.
25. WHEN the split function is called more than once with the same corpus and the same salt, THE Band_Replayer SHALL return an identical assignment of every case identifier to a side, independent of case order and of the process that runs it.
26. THE Band_Replayer SHALL NOT write a Band, a threshold or a policy value to any production file, and every production file SHALL be byte-identical before and after any replay.

### Requirement 16: Band Replay Validity Limits and Recommendation Gate

**User Story:** As a maintainer, I want the limits of a replay stated next to every surface, so that an exploratory result is not mistaken for a recommendation.

#### Acceptance Criteria

1. WHEN the Notebook renders a replay surface (any table, chart or cell that shows Band_Replay output), THE Notebook SHALL render a validity-limits box in the same panel, visible without any user interaction.
2. THE Notebook SHALL state in the validity-limits box that Tier-2 ran once per case per Pass.
3. THE Notebook SHALL state in the validity-limits box that the spread between the two Forced_Table Passes is shown as an error band.
4. WHEN the Notebook renders a replayed rate, THE Notebook SHALL draw its error band from the minimum to the maximum of that rate across the two Forced_Table Passes.
5. IF the stored runs hold fewer than two Forced_Table Passes, THEN THE Notebook SHALL render the error band as Not_Measured with the reason and SHALL NOT draw a band.
6. THE Notebook SHALL compute every replayed rate with ERROR rows excluded from the numerator and the denominator, and SHALL state beside the rate the number of ERROR rows excluded [Open Question Q2].
7. THE Notebook SHALL state in the validity-limits box the identifier of the Jev run whose P backs the Forced_Table.
8. IF the identifier of the Jev run that backs the Forced_Table is not recorded in the stored runs, THEN THE Notebook SHALL render the identifier as Not_Measured with the reason and SHALL label every replay cell on that surface "approximate".
9. THE Notebook SHALL state in the validity-limits box that replaying with the P of a Jev run other than the one that backs the Forced_Table is approximate.
10. WHERE a replay uses the P of a Jev run other than the one that backs the Forced_Table, THE Notebook SHALL label every cell of that replay "approximate".
11. THE Notebook SHALL state in the validity-limits box that tuning and scoring on the same cases is circular.
12. THE Notebook SHALL state in the validity-limits box that the replay surface is exploratory.
13. THE Notebook SHALL state in the validity-limits box the number of attack cases in the Corpus as loaded and the number of those that are hand-written, taken from the loaded Corpus and not typed into the Notebook.
14. WHEN the Notebook renders the tune-half versus held-out-half curves, THE Notebook SHALL plot, for each Band cell, the catch rate and the false-alarm rate under both Readings, one series for the tune half and one for the held-out half, using the parent-grouped split of Requirement 15, and SHALL state the split salt beside the curves.
15. IF either half of the parent-grouped split holds zero attack cases or zero benign cases, THEN THE Notebook SHALL render the curves for that half as Not_Measured with the reason and SHALL NOT substitute a value.
16. THE Notebook SHALL state that a replay is tied to the Jev releases in the stored runs, and SHALL list the Jev release recorded in each stored run, or "unrecorded" where none is recorded.
17. THE Notebook SHALL state that the Jev band does not follow the model (ADR 0008).
18. WHEN the Notebook renders a replay result, THE Notebook SHALL show the `high_risk_name` stratum and the `other` stratum of the Tool_Name_Group of Requirement 13 side by side, with the case count of each stratum.
19. IF a Band's catch rate under either Reading exceeds the catch rate at the shipped Band by more than the Pass spread in the `high_risk_name` stratum and does not exceed it by more than the Pass spread in the `other` stratum, THEN THE Notebook SHALL flag that Band with the text "helps only high_risk_name", where the Pass spread is the maximum minus the minimum across Passes for that stratum and Reading.
20. IF the `other` stratum holds zero attack cases, THEN THE Notebook SHALL render the `other` stratum as Not_Measured with the reason and SHALL NOT mark any Band as free of the "helps only high_risk_name" flag.
21. WHERE a Band is proposed as a recommendation, THE Harness SHALL require that, for the catch rate and the false-alarm rate under both Readings, the absolute difference between the tune-half value and the held-out-half value at that Band is no greater than the Pass spread of that metric [Open Question Q11].
22. WHERE a Band is proposed as a recommendation, THE Harness SHALL require, before any spec amendment is drafted from it, fresh labeled evidence, meaning labeled cases whose identifiers are absent from the Corpus used for tuning, and SHALL record the identifiers of that evidence with the recommendation [Open Question Q11].
23. WHERE a Band recommendation is made, THE Harness SHALL require that either TASK-F09 is recorded as complete in the spec's task list or the check of criterion 21 holds in the `other` stratum on its own [Open Question Q8].
24. IF a proposed Band recommendation fails the check of criterion 21, 22 or 23, THEN THE Harness SHALL reject it, SHALL record the rejection with the name of the failed check, and SHALL leave the Band, the thresholds and the aggregation weights unchanged.
25. THE Harness SHALL NOT change the shipped Band edges (0.35 and 0.75), the block threshold (0.75), the quarantine threshold (0.50) or any aggregation weight, such that their values are identical before and after any Harness run.
26. THE Harness SHALL label every band result, in the Notebook and in every written output, "input to TASK-F10 and TASK-F06, not a decision".

### Requirement 17: Threat Signature Graph Evaluation Protocols

**User Story:** As a detection engineer, I want the TSG evaluated under cold, parent-only and held-out seeding, so that I can separate real transfer from a graph seeded to look perfect.

#### Acceptance Criteria

1. THE TSG_Seeder SHALL support exactly the Seeding_Modes `cold`, `parent_only` and `held_out_parents`.
2. IF a Seeding_Mode other than `cold`, `parent_only` or `held_out_parents` is requested, THEN THE TSG_Seeder SHALL reject the request with an error naming the requested value, and SHALL write no seed to the Threat Signature Graph.
3. WHEN the `cold` Seeding_Mode is run, THE TSG_Seeder SHALL write zero seeds.
4. WHEN the `parent_only` Seeding_Mode is run, THE TSG_Seeder SHALL write exactly one seed for each distinct Parent_Case and no seed for any other case.
5. WHEN the `held_out_parents` Seeding_Mode is run, THE TSG_Seeder SHALL write one seed for each Parent_Case in the half selected by a fixed hash split of the Parent_Case identifiers, and no seed for the unselected Parent_Cases or any other case.
6. THE TSG_Seeder SHALL produce the same `held_out_parents` selection on every run over the same Corpus_Hash.
7. WHEN the TSG_Seeder builds a seed from a Parent_Case, THE TSG_Seeder SHALL generalize the payload with the production `AgentBehavioralAnalytics._generalize_payload`.
8. WHEN the TSG_Seeder builds a seed from a Parent_Case, THE TSG_Seeder SHALL truncate the generalized pattern to at most 512 characters and SHALL leave a pattern of 512 characters or fewer unchanged.
9. WHEN the TSG_Seeder writes a seed, THE TSG_Seeder SHALL write it through `SQLiteThreatRepository.writeSignature`.
10. WHEN the TSG_Seeder writes a seed, THE TSG_Seeder SHALL set `attackerIntent` to the Resolver's neutral default intent text.
11. WHEN the TSG_Seeder writes a seed, THE TSG_Seeder SHALL set `targetTool` to the exact tool name of the seed's Parent_Case.
12. WHEN the TSG_Seeder writes a seed, THE TSG_Seeder SHALL set `mitigationAction` to `BLOCK`.
13. IF generalizing a payload or writing a seed raises an error, THEN THE Harness SHALL discard the Pass, SHALL record the Parent_Case identifier and the error reason, and SHALL report no match rate for that Pass.
14. WHEN the `cold` Seeding_Mode is run, THE Harness SHALL assert that zero Corpus cases produce a TSG match, excluding cases whose System_Verdict is `ERROR`.
15. IF any Corpus case produces a TSG match in the `cold` Seeding_Mode, THEN THE Harness SHALL discard the Pass and SHALL report the identifier of each matching case.
16. WHEN the `parent_only` Seeding_Mode is run, THE Harness SHALL report the transfer rate as the number of evasion variants with a TSG match divided by the number of evasion variants, with `ERROR` rows excluded from numerator and denominator (provisional, Open Question Q2), together with the numerator and denominator.
17. WHEN the `parent_only` Seeding_Mode is run, THE Harness SHALL report the false-match rate as the number of TSG matches in the false-match set divided by the number of cases in the false-match set, with `ERROR` rows excluded from numerator and denominator (provisional, Open Question Q2), together with the numerator and denominator. The false-match set SHALL consist of the benign cases and the attack cases that are neither Parent_Cases nor evasion variants.
18. WHEN the `parent_only` Seeding_Mode is run, THE Harness SHALL report the match rate over the `evasion_proof` cases as a separate result, using the same numerator and denominator definition and the same `ERROR` exclusion, and SHALL NOT include those cases in the transfer set or the false-match set.
19. WHEN the `held_out_parents` Seeding_Mode is run, THE Harness SHALL report the match rate over variants of seeded Parent_Cases and the match rate over variants of unseeded Parent_Cases as two separate results, each with its numerator and denominator and with `ERROR` rows excluded from numerator and denominator (provisional, Open Question Q2). THE Harness SHALL label the match rate over variants of seeded Parent_Cases as transfer from a seed and not as held-out evidence.
20. IF the denominator of a reported rate is zero after `ERROR` rows are excluded, THEN THE Harness SHALL record that rate as Not_Measured with a reason naming the empty set, and SHALL NOT report the rate as 0 or 1.
21. WHEN a Corpus case produces a TSG match, THE Harness SHALL record the match path as exactly `fts` or `substring`.
22. WHEN a Corpus case produces a TSG match, THE Harness SHALL record the length, in characters, of the seed pattern that matched.
23. THE Harness SHALL give the TSG an explicit temporary database path in every Seeding_Mode.
24. IF any Harness code constructs the threat repository without an explicit path, or with the default `./blackwall.db`, THEN THE Harness test suite SHALL fail, and the default database file SHALL remain unread, unwritten and uncreated.
25. WHERE the optional learning experiment `LX-wave` is requested explicitly, THE Harness SHALL run it, and SHALL NOT run it when it is not requested.
26. WHERE `LX-wave` is run, THE Harness SHALL process cases one at a time in a recorded order, with no concurrent case evaluation.
27. WHERE `LX-wave` is run, THE Harness SHALL report its results separately from the Configuration_Matrix, and SHALL label them `order-dependent` in the output.

### Requirement 18: TSG Leakage Controls and Static Graph

**User Story:** As a reviewer, I want leakage between seeds and scored cases controlled and the graph kept static, so that TSG results are order-independent and not circular.

#### Acceptance Criteria

1. THE TSG_Seeder SHALL build every seed from the Parent_Case's own arguments only, so that changing the arguments of any variant of that Parent_Case leaves the seed byte-identical.
2. THE TSG_Seeder SHALL write none of the following into any signature field that the matcher reads: a label word, the `attack_type` value, the `evasion_type` value, a parent identifier, or a variant argument value. A search of every matcher-read signature field after seeding SHALL find zero occurrences of each.
3. THE Harness SHALL mark with `leakage="seeded_case"` each Parent_Case row whose seed was written in the current Seeding_Mode, that is, every Parent_Case in `parent_only`, only the seeded half of the Parent_Cases in `held_out_parents`, and no Parent_Case in `cold`, and SHALL leave every unseeded Parent_Case row unmarked and scored.
4. THE Harness SHALL exclude every row marked `leakage="seeded_case"` (a Parent_Case whose seed was written in the current Seeding_Mode) from the numerator and the denominator of every TSG efficacy rate, and SHALL NOT exclude an unmarked row on account of leakage.
5. IF a row's outcome is `ERROR`, THEN THE Harness SHALL exclude that row from the numerator and the denominator of every TSG efficacy rate (provisional, Open Question Q2).
6. WHILE a Harness measurement runs, THE Harness SHALL schedule no background task, so that the count of signatures in the TSG is identical before and after every case is evaluated, whatever the decision (`ALLOW`, `QUARANTINE` or `BLOCK`).
7. IF a signature is written to the TSG during a Harness measurement, THEN THE Harness SHALL mark that Pass as discarded and SHALL NOT include its rows in any reported result.
8. THE Harness SHALL return an identical TSG match result for every case when the same Pass is run on a static graph in at least three evaluation orders: the original order, the reversed order, and one shuffle with a fixed recorded seed. A Harness test SHALL fail on any difference in any case.
9. THE Harness test suite SHALL pin that the matcher does not read the `metadata.seeded_from` field, by asserting that removing the field, or setting it to a different value, leaves the match result of every case unchanged.
10. IF a benign call matches a seed through the substring fallback, THEN THE Harness SHALL list that call in the false-match set with its case identifier, the match path value `substring`, and the seed pattern length in characters.

### Requirement 19: Threat-Intelligence Evaluation

**User Story:** As a threat-intelligence analyst, I want threat intelligence evaluated on real public indicators and kept apart from plumbing tests, so that its efficacy and its false flags are measured honestly.

#### Acceptance Criteria

1. THE Harness SHALL run threat-intelligence evaluation as two separate runs, I-TI-corpus on the indicators extracted from the Corpus and I-TI-ioc on the IOC_Corpus, and SHALL write each run's results to its own table.
2. WHEN I-TI-corpus is run, THE Runner SHALL query the OTX-only orchestrator exactly once for each unique extracted indicator, with the threat-intelligence cache neither read nor written during the query.
3. WHEN an indicator is queried in I-TI-corpus, THE Runner SHALL record for that indicator the queried flag, `is_malicious`, risk score, pulse count, provider and error class.
4. IF an OTX query for an indicator returns an error, THEN THE Runner SHALL record `is_malicious`, risk score and pulse count as absent (not as `false` or `0`) and SHALL record the error class.
5. IF an OTX query for an indicator succeeds, THEN THE Runner SHALL record the error class as `none`.
6. WHEN I-TI-ioc is run, THE Runner SHALL query the OTX-only orchestrator exactly once for each unique IOC_Corpus indicator, with the cache neither read nor written, and SHALL record the same per-indicator values as in I-TI-corpus.
7. THE Harness SHALL include every documentation-range and private-range address extracted from the Corpus in I-TI-corpus without filtering. The ranges are 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
8. THE Harness SHALL report the OTX result for those addresses as a separate group labeled by range class (documentation or private) and SHALL NOT apply an expected `is_malicious` value to that group.
9. THE Harness SHALL report as the headline of I-TI-ioc the percentage of IOC_Corpus indicators for which OTX returned `is_malicious` true, with ERROR rows excluded from both numerator and denominator (provisional, Open Question Q2), and SHALL show the numerator and denominator beside the percentage.
10. IF the I-TI-ioc denominator is zero, THEN THE Harness SHALL render the headline as Not_Measured with a reason stating that no valid rows exist, and SHALL NOT render a percentage.
11. THE Harness SHALL display, adjacent to the I-TI-ioc headline, a statement that an unrecognized indicator can be a delisting since the feed listed it, and SHALL NOT label an unrecognized indicator as an OTX error.
12. WHERE a stub provider is used, THE Harness SHALL end the configuration identifier with the exact suffix `-stub`.
13. WHERE a stub provider is used, THE Harness SHALL record the source of every row from that provider as `stub_plumbing_only`.
14. WHERE a stub provider is used, THE Notebook SHALL show a Plumbing_Only banner on every panel that includes rows from that provider.
15. WHERE a stub provider is used, THE Harness SHALL exclude its rows from every efficacy figure and efficacy view.
16. IF `BW_OTX_API_KEY` is unset, is an empty string, or has no Human_Grant in the current conversation, THEN THE Harness SHALL NOT substitute a stub provider for any threat-intelligence row.
17. IF `BW_OTX_API_KEY` is unset, is an empty string, or has no Human_Grant in the current conversation, and no threat-intelligence row is Named_Explicitly, THEN THE Runner SHALL make zero OTX queries and SHALL record every threat-intelligence row of the Default_Plan as Not_Measured with a reason that begins `no grant` and names `BW_OTX_API_KEY`, rendered as an em dash with that reason. A Named_Explicitly threat-intelligence row in the same condition is governed by Requirement 23 criterion 17.
18. IF an OTX typed error occurs for an indicator, THEN THE Runner SHALL record that row with Outcome `ERROR` and the exception class name, and SHALL exclude it from numerator and denominator of every rate (provisional, Open Question Q2).
19. THE Harness SHALL show the count of `ERROR` rows in every threat-intelligence table, including the value `0` when no `ERROR` rows exist.
20. THE Harness SHALL NOT include IOC_Corpus rows in any table, chart or aggregate figure that includes Corpus rows, and SHALL compute every aggregate figure from rows of one of the two corpora only.

### Requirement 20: IOC Corpus Construction and Safety

**User Story:** As a security engineer, I want the IOC corpus built from non-circular public feeds with no live infrastructure contacted, so that the corpus is safe and its efficacy figures are meaningful.

#### Acceptance Criteria

1. THE IOC_Corpus SHALL build every malicious case and every control case from one shared template.
2. THE IOC_Corpus SHALL use an identical set of tool names and an identical set of argument keys in its malicious cases and its control cases, so that tool name and argument keys carry no class information.
3. THE IOC_Corpus SHALL take malicious indicators from one public feed export other than OTX [Open Question Q5].
4. THE builder SHALL record the chosen feed name in the IOC_Corpus manifest and SHALL perform zero threat-intelligence lookups while building, so that the feed is chosen before any lookup [Open Question Q5].
5. THE IOC_Corpus SHALL record, for each malicious entry, the feed name, the snapshot date as a calendar date in YYYY-MM-DD form, and the category [Open Question Q5].
6. IF a malicious entry lacks a feed name, a snapshot date or a category, or its feed name is OTX, THEN THE builder SHALL fail with an error naming the entry and SHALL write no IOC_Corpus output.
7. THE IOC_Corpus SHALL take control indicators from well-known legitimate domains and SHALL record, for each control entry, the source name and the snapshot date in YYYY-MM-DD form.
8. IF any indicator appears in both the malicious class and the control class, THEN THE builder SHALL fail with an error naming the indicator and SHALL write no IOC_Corpus output.
9. THE IOC_Corpus SHALL contain only indicators that are either a domain name or an IP address, with no payload URL, no victim-identifying path and no victim data in any case field.
10. IF an indicator contains a URL scheme, a port, a path, a query string, a fragment or embedded credentials, or is neither a valid domain name nor a valid IP address, THEN THE builder SHALL fail with an error naming the indicator and SHALL write no IOC_Corpus output.
11. WHEN the IOC_Corpus is built, THE builder SHALL pass every indicator through ContextHygiene as an un-redacted standalone hostname and SHALL verify that the output string is identical to the input string.
12. IF ContextHygiene changes any indicator, THEN THE builder SHALL fail with an error listing every changed indicator and SHALL write no IOC_Corpus output.
13. THE Harness test suite SHALL install a socket guard before any test body runs.
14. IF any code path opens or attempts to open a connection to an IOC_Corpus indicator, THEN THE socket guard SHALL fail the running test with an error naming the indicator.
15. THE Harness SHALL evaluate IOC_Corpus cases without executing the tool call, so that no System_Verdict, including `ALLOW` and `QUARANTINE`, causes a connection to an indicator.
16. THE Harness SHALL open connections only to the hosts of the Jev API, the Vertex AI API and the OTX API.
17. IF the Harness is about to open a connection to any other host, THEN THE Harness SHALL refuse the connection, record the refused host name, and mark the affected case `ERROR`.
18. WHEN the IOC_Corpus is authored, THE builder SHALL record in the IOC_Corpus manifest the exact total number of cases as an integer equal to the number of cases written.
19. IF the number of cases loaded from the IOC_Corpus differs from the number recorded in its manifest, THEN THE Harness SHALL refuse to run and SHALL report both numbers.
20. WHEN IOC_Corpus efficacy rates are reported, THE Harness SHALL exclude `ERROR` rows from the numerator and the denominator and SHALL report the number of excluded `ERROR` rows next to each rate (provisional, Open Question Q2).
21. WHEN a Run_Set is written, THE Harness SHALL state in the Manifest that every indicator sent to OTX comes from the IOC_Corpus fixtures.
22. IF an indicator selected to be sent to OTX is not present in the IOC_Corpus fixtures, THEN THE Harness SHALL refuse to send it and SHALL fail the run with an error naming the indicator.
23. WHEN the human runs the `plan` command, THE Harness SHALL print every API host and every indicator to be sent to OTX, one per line, and SHALL open zero network connections while doing so.

### Requirement 21: Codebase-Memory Evaluation on a Fixture

**User Story:** As an evaluation engineer, I want CBM evaluated on a fixture codebase with honest labels, so that the figures show what the Stage can and cannot measure.

#### Acceptance Criteria

1. THE CBM_Fixture SHALL contain hand-written Python source text with between 10 and 14 function definitions.
2. THE CBM_Fixture SHALL be committed as text, and THE Harness SHALL NOT import or execute it; a Harness test SHALL assert that no function defined in the fixture source is ever called or imported during a Harness run.
3. THE CBM_Fixture SHALL include a committed JSON snapshot of the call-graph facts and the sink facts for every function in the fixture source.
4. IF the snapshot is missing, is not valid JSON, or lacks facts for a tool the Harness queries, THEN THE Harness SHALL record every fixture-based CBM row as Not_Measured with a reason indicating that the fixture is unreadable, SHALL name the offending item in the reason, and SHALL leave all non-CBM rows unchanged.
5. THE Fixture_Adapter SHALL override `queryDependencyChain` and `identifyCriticalSinks` so that both answer from the snapshot.
6. THE Fixture_Adapter SHALL route every answer through the shipped `CodebaseMemoryClient.query` mapping, and a Harness test SHALL assert that a snapshot sink is converted by that mapping and not returned verbatim.
7. THE Fixture_Adapter SHALL open zero sockets; a Harness test SHALL run the fixture rows with socket creation blocked and SHALL assert that zero connection attempts occur and that all fixture rows complete.
8. THE Harness test suite SHALL assert that `base_url` is `None` for every CBM row after Resolver construction, because `SyncResolver.__init__` overwrites `base_url` from `policy.yaml` when a policy server is given.
9. THE Harness SHALL run the Permuted_Control with the same graphs assigned to tool names by a permutation drawn from a fixed seed, and SHALL record that seed in the Manifest.
10. WHEN the Permuted_Control is run twice with the same seed, THE Harness SHALL produce an identical tool-to-graph assignment in both runs.
11. THE Harness SHALL display the real assignment and the Permuted_Control together in the same Notebook view, each labeled with its name.
12. WHEN the default `CodebaseMemoryClient()` is queried for a tool name absent from every graph, THE Harness test suite SHALL pin, as a characterization test, that the blast radius is 2 and the CBM score is 0.1, and SHALL assert the same pair for every unknown tool name queried.
13. THE Harness test suite SHALL pin, as a characterization test, that the current `CodebaseMemoryClient.query` returns zero critical sinks for every fixture tool whose snapshot lists at least one critical sink, because of the `CriticalSinkType`-to-`SinkType` mapping.
14. WHEN the mapping behavior pinned by criterion 13 changes, THE Harness test suite SHALL fail, so that the change is deliberate and visible.
15. THE Harness SHALL record both `mapped_sinks` and `raw_sinks` for every CBM row.
16. THE Harness SHALL provide a what-if row labeled `sinks mapped` that recomputes the CBM score from `raw_sinks` and is marked hypothetical in every place it is displayed.
17. THE Harness SHALL NOT include the `sinks mapped` row in any production-configuration figure or catch rate, and any rate shown beside it SHALL exclude ERROR rows from numerator and denominator (provisional, Open Question Q2).
18. IF `raw_sinks` is unavailable for a tool, THEN THE Harness SHALL record the `sinks mapped` row for that tool as Not_Measured with a reason naming the missing `raw_sinks`.
19. THE Harness test suite SHALL assert that two queries for the same tool with different arguments return identical CBM scores.
20. THE Harness SHALL state in the Notebook that CBM ignores arguments and that CBM can at best act as a per-tool prior.
21. THE Harness SHALL state in the Notebook that, as shipped, CBM alone cannot move a verdict, with the computation 0.30*0.5 + 0.30*1.0 = 0.45, which is below the Production_Mode quarantine threshold of 0.50.
22. THE Harness test suite SHALL assert that a case in which CBM is the only Stage with a nonzero contribution yields an aggregate score below 0.50 and the decision `ALLOW`; a `QUARANTINE` does not execute the tool, so `ALLOW` is the only decision at which the tool runs.
23. WHEN the live codebase-memory-mcp conformance probe is run, THE Harness SHALL send one request each for `trace_path`, `query_graph` and `get_architecture`, with a timeout of 10 seconds per request.
24. WHEN the probe responses are received, THE Harness SHALL check that each response has the shape the shipped client parses, and SHALL record the live-MCP row as conformant only if all three pass.
25. IF the live server does not conform, exposes no HTTP JSON-RPC endpoint, or does not answer a probe request within 10 seconds, THEN THE Harness SHALL record the live-MCP row as Not_Measured with reason `transport mismatch`.
26. IF the live-MCP row is Not_Measured, THEN THE Harness SHALL leave every fixture row's values identical to a run in which the probe was not requested.
27. WHEN the live conformance probe is run, THE Harness SHALL index the fixture source with codebase-memory-mcp, as the reserved stateful MCP tier, before sending the probe requests.
28. IF indexing the fixture source fails, THEN THE Harness SHALL record the live-MCP row as Not_Measured with a reason naming the indexing failure, and SHALL leave fixture rows unaffected.
29. THE Harness SHALL add no MCP server beyond those already configured, and a Harness test SHALL assert that the set of configured MCP servers is identical before and after a Harness run.

### Requirement 22: Not-Measured Status

**User Story:** As a reader of the report, I want an unmeasurable layer shown as not measured with a reason, so that no figure is simulated or imputed.

#### Acceptance Criteria

1. IF a Layer lacks its credential grant (Human_Grant) and the row is part of the Default_Plan, THEN THE Runner SHALL record every such row of that Layer in the Manifest with status Not_Measured and a non-empty reason that names the missing credential variable, and SHALL continue executing the rows of all other Layers. A Named_Explicitly row that lacks its credential grant is governed by Requirement 23 criteria 15, 16 and 17.
2. IF a Layer lacks its fixture, THEN THE Runner SHALL record every row of that Layer in the Manifest with status Not_Measured and a non-empty reason that names the missing fixture, and SHALL continue executing the rows of all other Layers.
3. IF a Layer lacks its transport, THEN THE Runner SHALL record every row of that Layer in the Manifest with status Not_Measured and a non-empty reason that names the missing transport, and SHALL continue executing the rows of all other Layers.
4. THE Harness SHALL NOT simulate, impute, stub or degrade a row to produce an efficacy figure in place of Not_Measured, so that a Not_Measured row carries no System_Verdict, no Outcome and no rate value.
5. THE Harness SHALL exclude every Not_Measured row from the numerator and the denominator of every rate, in the same way that ERROR rows are excluded (provisional, Open Question Q2), and SHALL NOT record a Not_Measured row as an `ERROR` decision.
6. WHEN the Notebook renders a case or cell that has no measurement, THE Notebook SHALL render a single em dash character (U+2014) in that case or cell.
7. WHEN the Notebook renders a case or cell that has no measurement, THE Notebook SHALL NOT display the expected verdict in place of the missing verdict.
8. WHEN the Notebook renders a case or cell that has no measurement, THE Notebook SHALL NOT count the missing verdict as a match, so that the case contributes to neither the numerator nor the denominator of any rate.
9. WHEN the Notebook renders a Layer that has at least one Not_Measured entry in the Manifest, THE Notebook SHALL render one status tile for that Layer that displays the reason string stored in the Manifest, unaltered.
10. WHEN a row requires a live credential and no Run_Set contains a measured result for that row, THE Harness SHALL record an explicit deferral note on that row before implementation of the row begins, and the note SHALL name the credential variable that is required [rule 74].
11. WHILE no Run_Set exists that contains a measured result for a live-credential row (status other than Not_Measured), THE Harness SHALL keep that row's acceptance checkbox unchecked [rule 74].

### Requirement 23: Hermetic Runs and Credential Handling

**User Story:** As a security-conscious maintainer, I want runs hermetic by default and credentials read only under a human grant, so that no key is leaked or silently spent.

#### Acceptance Criteria

1. WHEN the Runner starts a verification subcommand or an offline subcommand, THE Runner SHALL launch the child process through `env -i`, so that the child environment holds no inherited variable other than those the Runner sets explicitly.
2. WHEN the Runner starts a verification subcommand or an offline subcommand, THE Runner SHALL set `HOME` in the child environment to a newly created scratch directory that is empty at launch and is not the invoking user's home directory.
3. WHEN the Runner starts a verification subcommand or an offline subcommand, THE Runner SHALL set `PYTHON_DOTENV_DISABLED` to `1` in the child environment.
4. WHEN the Runner starts a verification subcommand or an offline subcommand, THE Runner SHALL set `CLOUDSDK_CONFIG` in the child environment to a directory that is empty at launch.
5. WHERE the platform supports blocking outbound HTTPS, THE Runner SHALL block outbound HTTPS for verification and offline subcommands, so that an HTTPS connection attempt from the child process fails.
6. IF the platform cannot block outbound HTTPS, THEN THE Runner SHALL print a notice stating that outbound HTTPS is not blocked and SHALL still run the subcommand.
7. WHEN a Human_Grant names a credential variable, THE Runner SHALL read only that named variable from its own environment and SHALL pass no other credential variable to the child process.
8. WHEN the Runner passes a granted credential variable to a child process, THE Runner SHALL place it in the child's environment and SHALL NOT place it in the child's command-line arguments or in any file.
9. WHEN a new conversation starts, THE Runner SHALL treat every credential variable as not granted until a new Human_Grant names it in that conversation.
10. THE Harness SHALL NOT print, log, echo or write any credential value to standard output, standard error, a log, a Run_Set file or any other file.
11. THE Harness SHALL NOT commit any credential value to version control.
12. THE Manifest SHALL record, for each Human_Grant, the credential variable name and the grant date as a UTC calendar date in `YYYY-MM-DD` form, and SHALL record no credential value.
13. THE Harness library, THE CLI and THE Notebook SHALL NOT open any file named `.env` or matching `.env.*`, other than `.env.example`.
14. THE Harness SHALL NOT create, overwrite or edit any file named `.env` or matching `.env.*`, other than `.env.example`.
15. IF a live Vertex row is Named_Explicitly and both `GCP_PROJECT` and `GOOGLE_CLOUD_PROJECT` are unset or empty, THEN THE CLI SHALL exit with a non-zero status and an error message naming both variables, before it builds any client, makes any network call or writes any record.
16. IF a live Jev row is Named_Explicitly and `TYPESAFE_API_KEY` is unset or empty, THEN THE CLI SHALL exit with a non-zero status and an error message naming `TYPESAFE_API_KEY`, before it builds any client, makes any network call or writes any record.
17. IF a threat-intelligence row is Named_Explicitly and `BW_OTX_API_KEY` is unset or empty, THEN THE CLI SHALL exit with a non-zero status and an error message naming `BW_OTX_API_KEY`, before it builds any client, makes any network call or writes any record.
18. IF `--concurrency` is not an integer or is below 1, THEN THE CLI SHALL exit with a non-zero status and an error message naming `--concurrency` and the accepted minimum of 1, before it runs any case. THE CLI SHALL use 2 as the value of `--concurrency` when the option is not given.
19. WHILE the Harness test suite runs, THE Harness SHALL make zero live calls, where a live call is any request to Vertex AI, TypeSafe or AlienVault OTX.
20. IF a live run is requested and no Human_Grant names the credential variable that the run needs, THEN THE Runner SHALL NOT start the live run and SHALL name the missing grant, by exiting as criteria 15, 16 and 17 require when the row is Named_Explicitly, and by reporting the row as deferred and recording it as Not_Measured when the row is part of the Default_Plan.
21. WHEN the Runner starts a verification run without a Human_Grant in effect, THE Runner SHALL deselect every test carrying the `sla_benchmark`, `gcp_eval` or `vertex_evaluation` mark, so that zero tests with those marks execute.

### Requirement 24: Interleaved Passes, Pacing and Pass Invalidation

**User Story:** As an evaluation engineer, I want repeated interleaved paced passes with invalid passes discarded, so that drift, rate limits and quota errors do not contaminate the figures.

#### Acceptance Criteria

1. THE Runner SHALL run at least 2 valid Passes for every live configuration, each Pass covering every case of the Corpus.
2. IF a live configuration has fewer than 2 valid Passes that used the same concurrency after all permitted re-runs, THEN THE Runner SHALL record that configuration as Not_Measured with a reason stating that valid Passes were insufficient, and SHALL leave the results of other configurations unchanged.
3. THE Runner SHALL interleave Passes across configurations, running Pass 1 of every configuration, in one fixed configuration order, before Pass 2 of any configuration.
4. THE Runner SHALL store in the Manifest, for every Pass executed including discarded Passes, an interleave position that is a 1-based integer (1 or greater), unique within the Run_Set and ordered by execution start.
5. WHILE live Whole_System_Runs are executing, THE Runner SHALL keep at most N cases in flight at any instant, where N is the configured `--concurrency` value (an integer of 1 or more, default 2), and SHALL keep exactly N in flight while N or more cases of the current Pass remain unstarted. THE Runner SHALL record in the Manifest the concurrency N used for every Pass. THE Runner SHALL compare Passes with each other (the valid Passes of one configuration, Pass_Spread calculations and Jev release comparisons) only when the Passes used the same concurrency, and SHALL record a Pass that used a different concurrency in the Manifest and exclude it from those comparisons with a stated reason.
6. WHEN one Pass finishes and the next Pass to run belongs to a different configuration, THE Runner SHALL wait at least the cool-down, 30 seconds as the starting value [Open Question Q10], between the completion of the last case of the finished Pass and the start of the first case of the next Pass.
7. THE Runner SHALL record in the Manifest the cool-down, in seconds, that it used.
8. IF any Tier-2 call attempt in a Pass returns HTTP status 429, including an attempt that a later retry completes successfully, THEN THE Runner SHALL invalidate the whole Pass and SHALL exclude every record of that Pass from all tables and rates.
9. WHEN a Pass is invalidated for HTTP status 429, THE Runner SHALL add an entry to `discarded_passes` naming the configuration, the Pass number, the interleave position and a reason identifying HTTP status 429.
10. WHEN a Pass is invalidated for HTTP status 429, THE Runner SHALL re-run that Pass, starting at least one cool-down after the invalidation, up to a maximum of 3 re-runs per Pass, with each re-run taking the next unused interleave position.
11. IF a Pass is still invalidated for HTTP status 429 after 3 re-runs, THEN THE Runner SHALL stop re-running it and SHALL record the configuration as Not_Measured with a reason stating that the re-run limit was reached.
12. IF any record in a Pass has Quarantine_Cause `rate_limit`, THEN THE Runner SHALL invalidate the whole Pass, SHALL exclude every record of that Pass from all tables and rates, and SHALL add an entry to `discarded_passes` naming the configuration, the Pass number, the interleave position and a reason identifying `rate_limit`.
13. IF any record in a Pass has Quarantine_Cause `rate_limit`, THEN THE Runner SHALL list the occurrence, with its configuration and Pass number, as a Harness defect in the run output.
14. WHEN Jev fails for a case, THE Runner SHALL record for that case an `ERROR` row containing the exception class name.
15. WHEN a typed threat-intelligence error propagates out of `evaluate()`, THE Runner SHALL record for that case an `ERROR` row containing the exception class name.
16. WHEN an `ERROR` row is recorded for a Jev failure or a typed threat-intelligence error, THE Runner SHALL keep the Pass valid and SHALL continue with the remaining cases of the Pass.
17. THE Runner SHALL show in every rendered table, for each table row, the count of `ERROR` rows behind that row, displaying 0 when there are none.
18. THE Runner SHALL exclude `ERROR` rows from both the numerator and the denominator of every rate it reports [Open Question Q2, provisional].
19. WHEN Jev release versions are compared, THE Runner SHALL request each release by its explicit release name and SHALL NOT request any release by a moving alias.
20. WHEN Jev release versions are compared, THE Runner SHALL record in each row the release identifier that the service reported as having answered.
21. IF the release identifier reported for a row differs from the requested release name, or is absent, THEN THE Runner SHALL invalidate the whole Pass and add an entry to `discarded_passes` with a reason identifying a release mismatch.
22. WHEN Jev release versions are compared, THE Runner SHALL report, next to each between-release difference in a rate, the within-release spread of that rate for each release, defined as the maximum minus the minimum of that rate across the release's valid Passes that used the same concurrency (Requirement 24 criterion 5), in percentage points.
23. IF the absolute value of a between-release difference in a rate is less than or equal to the larger of the two within-release spreads for that rate, THEN THE Runner SHALL NOT label the difference as real.
24. WHEN the Forced_Table is built, THE Runner SHALL record a Tier-2 result for every case of the Corpus from the Jev run named in the Manifest.
25. WHERE the maintainer has decided to build the Forced_Table for both Jev releases [Open Question Q3], THE Runner SHALL build one Forced_Table per release, each from the Jev run of that release.
26. IF the Manifest names no Jev run, or the named Jev run lacks a Jev P value for any case of the Corpus, THEN THE Runner SHALL NOT build the Forced_Table and SHALL record it as Not_Measured with a reason identifying the missing Jev run or values.

### Requirement 25: Plan, Billing and Cost Disclosure

**User Story:** As a maintainer, I want the spend and the billed account stated before and after a live run, so that no run spends unknowingly.

#### Acceptance Criteria

1. WHEN the `plan` subcommand is run, THE CLI SHALL make zero network connections and exit with status 0 within 5 seconds.
2. WHEN the `plan` subcommand is run, THE CLI SHALL print each Layer as enabled or disabled.
3. WHEN the `plan` subcommand is run, THE CLI SHALL print the resolver mode.
4. WHEN the `plan` subcommand is run, THE CLI SHALL print, for each configuration, the planned call count for Jev, Tier-2 and OTX as a non-negative integer.
5. WHEN the `plan` subcommand is run, THE CLI SHALL print the model identifier used for Jev and the model identifier used for Tier-2.
6. WHEN the `plan` subcommand is run, THE CLI SHALL print the Vertex project that would be billed.
7. WHEN the `plan` subcommand is run, THE CLI SHALL print every hostname that would be queried.
8. WHEN the `plan` subcommand is run, THE CLI SHALL print the name of each variable that needs a Human_Grant, and SHALL NOT print the value of any variable.
9. IF the `plan` subcommand cannot determine the Vertex project that would be billed, THEN THE CLI SHALL print the project as unresolved with the reason, make no live call, and exit with a non-zero status.
10. THE Manifest SHALL record the billing project or account, the Jev model identifier, the Tier-2 model identifier, the per-run call count for each of Jev, Tier-2 and OTX, and the per-run token count for each of Jev, Tier-2 and OTX.
11. THE Manifest SHALL count every billed call in the per-run call counts and token counts, including calls made for a case whose outcome is ERROR.
12. IF a token count is unavailable for a call, THEN THE Harness SHALL record that count as Not_Measured with the reason and SHALL NOT substitute an estimate.
13. THE Manifest SHALL record the pricing source and its fetch date as an ISO 8601 calendar date in UTC.
14. THE Harness SHALL NOT contain a numeric price literal in code or in the design.
15. WHEN a dollar cost is reported, THE Harness SHALL compute it at run time as the logged token counts multiplied by the vendor's list price that was current on the recorded fetch date.
16. IF the vendor's list price cannot be fetched, THEN THE Harness SHALL report the dollar cost as Not_Measured with the reason, print the token counts, and continue the run.
17. WHEN the Runner is about to make its first live call, THE Runner SHALL print and store a billing statement that contains the billing project, the models, and the planned call counts, before that call is made.
18. IF the Runner cannot store the billing statement before the first live call, THEN THE Runner SHALL make no live call, report the storage failure, and exit with a non-zero status.
19. WHEN a run ends, whether it completed, was aborted or failed, THE Runner SHALL print and store a billing statement that contains the billing project, the actual call counts, the token counts, and the dollar cost or its Not_Measured reason.
20. THE Harness SHALL print a statement that the gcloud default project can differ from the project in `.env`.
21. THE Harness SHALL print the name of the project it used for billing and the name of the gcloud default project.
22. IF the gcloud default project cannot be read, THEN THE Harness SHALL print the gcloud default project as unavailable and continue.
23. IF the project used for billing differs from the gcloud default project, THEN THE Harness SHALL mark the two names as different in the printed statement.

### Requirement 26: Reported Findings Without Production Fixes

**User Story:** As a maintainer, I want the measurable defects the design lists detected and reported with evidence, so that each becomes a tracked task without this spec changing production code.

#### Acceptance Criteria

1. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report for that Run_Set the number of attack cases and the number of benign cases of the Corpus for which `_extract_indicator` returned an indicator, each as an integer with the total cases of that class as the denominator.
2. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report every unique indicator value that `_extract_indicator` returned over the Corpus, each value with the number of attack cases and benign cases that produced it, so that a value such as `main.py` or `config.yaml` is listed if and only if the Corpus produced it.
3. IF `_extract_indicator` returned a value that has no file-extension-only or hostname form in the Corpus, THEN THE Harness SHALL still list it under criterion 2 and SHALL NOT filter any returned value out of the findings report.
4. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report, for each class (attack and benign), the number of cases whose keyword novelty is greater than or equal to 0.4.
5. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report, for each class, the number of cases with keyword novelty greater than or equal to 0.4 that would trigger Tier-2 through the disagreement path, and for each such case the case identifier and the list of keywords that matched.
6. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report, for each Tool_Name_Group (`high_risk_name` and `other`), the number of attack cases and the number of benign cases.
7. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report the share of attack cases in the `high_risk_name` Tool_Name_Group, as a percentage rounded to one decimal place, together with its numerator and denominator (the denominator being all attack cases in the Corpus).
8. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report the numeric CBM score that the CBM Stage returns for a tool name absent from the CBM_Fixture, and the critical sinks that the CBM Stage drops, each identified by sink name, as established by the characterization tests of Requirement 21.
9. WHEN the Runner completes a Run_Set, THE Harness SHALL include in the findings report the `cbm_client.base_url` value before and after constructing `SyncResolver` with a policy server, and a yes or no statement of whether `SyncResolver.__init__` overwrote it from `policy.yaml`.
10. WHEN the Runner completes a Run_Set that contains a Production_Mode Whole_System_Run, THE Harness SHALL include in the findings report (TASK-F06) the attack cases whose Jev P is greater than the upper Band edge (0.75) and whose System_Verdict is not caught, listed by case identifier, separately under the Stopped_Reading and the Blocked_Reading, with each list's length.
11. WHILE a Whole_System_Run row has the decision `ERROR`, THE Harness SHALL exclude that row from the numerator and the denominator of every rate and share in the findings report (provisional, Open Question Q2), and SHALL report the number of excluded `ERROR` rows next to each affected figure.
12. WHEN the Harness evaluates a `QUARANTINE` System_Verdict for the finding of criterion 10, THE Harness SHALL count it as not caught under the Blocked_Reading and as caught under the Stopped_Reading, and SHALL treat the tool as not executed.
13. IF the Corpus cannot be loaded or a figure required by criteria 1 to 10 cannot be computed, THEN THE Harness SHALL record that figure as Not_Measured with the reason, SHALL NOT report it as zero, and SHALL still report every other figure that can be computed.
14. THE Harness SHALL include in a unit test the pinned expected values that the design computed offline for the indicator extraction counts (criteria 1 and 2), the keyword-novelty counts (criteria 4 and 5) and the Tool_Name_Group counts (criteria 6 and 7).
15. IF a Corpus edit changes any pinned value of criterion 14, THEN THE unit test SHALL fail with a message that names the changed figure, its pinned value and its observed value.
16. IF a finding is reported, THEN THE Harness change SHALL file it as a separate unchecked task in the tasks of the owning spec, identified by its finding name (for example TASK-F06 for the clear-high ALLOW finding).
17. IF a finding is reported, THEN THE Harness change SHALL contain no modification to production code outside the Harness, so that the diff of this spec's change shows zero changed lines in the affected production code.

### Requirement 27: Comparison Notebook

**User Story:** As a maintainer, I want a second marimo notebook that compares isolated and whole-system results from committed artifacts, so that the comparison can be reviewed without credentials or network access.

#### Acceptance Criteria

1. THE Notebook SHALL be the file `notebooks/holistic_defense_analytics.py`.
2. THE Notebook SHALL leave `notebooks/benchmark_analytics.py` byte-for-byte unchanged in the first phase of this spec.
3. THE Notebook SHALL read only Run_Set directories committed under `tests/eval/results/holistic/`.
4. THE Notebook SHALL complete loading, rendering and every control interaction without calling a model, reading a credential variable, or opening a network socket. A test with all sockets blocked and an empty environment SHALL produce the same rendered output as a normal run.
5. THE Notebook SHALL complete loading, rendering and every control interaction without creating, modifying or deleting any file. A test on a read-only filesystem SHALL produce the same rendered output as a normal run.
6. THE Notebook SHALL import from `blackwall.holistic_eval` only the pure modules named in the design, and SHALL NOT import the Runner, the Stage_Recorder, the TSG_Seeder or the Fixture_Adapter. An import check over the Notebook source SHALL verify this.
7. WHEN no Run_Set directory exists under `tests/eval/results/holistic/`, THE Notebook SHALL render an empty state that shows the full `scripts/holistic_eval.py` command that produces a Run_Set. The Notebook SHALL render no data panels and SHALL raise no exception.
8. IF a Run_Set directory has a missing or unparseable Manifest, THEN THE Notebook SHALL list that directory as invalid with an indication of the reason and SHALL exclude it from the Run_Set control. The Notebook SHALL keep every other Run_Set selectable.
9. WHEN the Notebook loads a Run_Set, THE Notebook SHALL compare the Manifest schema version with the schema version the Notebook supports.
10. IF the schema version differs, THEN THE Notebook SHALL render no data panels for that Run_Set and SHALL show an error naming the expected and the found version. The previously selected Run_Set and control values SHALL stay unchanged.
11. WHEN the Notebook loads a Run_Set, THE Notebook SHALL compare the Corpus_Hash in the Manifest with the Corpus_Hash recomputed from the Run_Set's per-case records.
12. IF the two Corpus_Hash values differ, THEN THE Notebook SHALL render no data panels for that Run_Set and SHALL show an error that displays both values.
13. WHEN the Notebook loads a Run_Set that passes both validations, THE Notebook SHALL list every Not_Measured entry in the Manifest. Each entry SHALL show an em dash and its recorded reason. IF the Manifest has no Not_Measured entry, THEN THE Notebook SHALL show text stating that none was recorded.
14. THE Notebook SHALL provide a Run_Set control that lists the valid Run_Sets, with the Run_Set having the latest creation time recorded in its Manifest selected by default.
15. THE Notebook SHALL provide a Reading highlight control with the values `Stopped_Reading` and `Blocked_Reading`, defaulting to `Stopped_Reading`. Both Readings SHALL stay visible, and the selected Reading SHALL be visually marked.
16. THE Notebook SHALL provide Band controls for `lo` and `hi`, defaulting to 0.35 and 0.75, each accepting values from 0.00 to 1.00 inclusive.
17. IF the entered Band has `lo` greater than `hi` (a zero-width Band with `lo` equal to `hi` is accepted), or has a value outside 0.00 to 1.00, THEN THE Notebook SHALL keep the previous valid Band, SHALL leave all panels unchanged, and SHALL show an error indicating which constraint failed.
18. THE Notebook SHALL provide a clear-high policy control with the values `block` (the Clear_High_Variant) and the production policy, defaulting to the production policy. WHILE `block` is selected, every panel affected by it SHALL display the label "hypothetical, not production behavior".
19. THE Notebook SHALL provide a Tier-2 mode control with the values `recorded`, `unavailable` and `absent`, defaulting to `recorded`.
20. WHEN the user changes any control value to a valid value, THE Notebook SHALL recompute every dependent panel from stored Run_Set values only, within 2 seconds on the committed Run_Sets, without a live Resolver, Jev or Tier-2 call.
21. THE Notebook SHALL render a context header for the selected configuration showing `demo_mode`, the names of the Layers on and the Layers off, the Jev releases, the Tier-2 model and level, the Pass count, and the discarded passes with their identifiers. IF the Run_Set lacks a value, THEN THE Notebook SHALL show an em dash and the reason in place of that value instead of leaving it blank.
22. THE Notebook SHALL render a "what can stop a call" panel that lists, for each Stage, whether it can contribute to a `BLOCK` or a `QUARANTINE`. The panel SHALL state that a `QUARANTINE` does not execute the tool.
23. THE Notebook SHALL render an "isolated versus whole-system rates" panel that shows each rate for the selected Reading as a percentage with one decimal place, together with its numerator and denominator.
24. THE Notebook SHALL exclude rows whose System_Verdict is `ERROR` from both the numerator and the denominator of every rate, and SHALL show the number of excluded `ERROR` rows next to each rate (provisional, Open Question Q2).
25. IF a rate has a denominator of 0, THEN THE Notebook SHALL show an em dash with the reason instead of a number.
26. THE Notebook SHALL label every Stage_Gate value in the rates panel as a Stage_Gate and SHALL NOT present it as a system catch rate.
27. THE Notebook SHALL render a catch attribution panel that places each attack case of the selected configuration in exactly one Catch_Partition class: `system_only`, `unique`, `redundant`, `lost_by_system` or `missed_by_all`. The class totals SHALL equal the number of attack cases that are neither `ERROR` nor `UNMEASURED`, and the panel SHALL show the number of excluded `ERROR` cases and the number of excluded `UNMEASURED` cases.
28. THE Notebook SHALL render a band replay surface panel whose rows are Composed_Rows computed offline from stored Jev P values and the Forced_Table for the current Band and clear-high policy, and SHALL label them as Composed_Rows.
29. THE Notebook SHALL render an Outage_Drill panel that shows, for the selected configuration, the System_Verdict of each case when every triggered Tier-2 call returns no verdict, and the Quarantine_Cause of each `QUARANTINE`.
30. THE Notebook SHALL render stratified views that report each rate with its case count for each Family (`c2_ioc`, `payload`, `benign`) and each Tool_Name_Group, including the `other` stratum (the "other tool name" stratum).
31. THE Notebook SHALL render a TSG results panel with one row for each Seeding_Mode (`cold`, `parent_only`, `held_out_parents`), and SHALL mark each row on which Leakage applies with a visible label.
32. THE Notebook SHALL render an optional layers panel with one status tile for each of structural policy, TSG, threat intelligence and CBM. Each tile SHALL show one of `on`, `off`, Not_Measured or Plumbing_Only.
33. THE Notebook SHALL render a per-case drilldown panel that, for a case selected by case identifier, shows the ground truth, the tool name, the Family, each Stage's Stage_Flag, the System_Verdict, the Outcome, and the Quarantine_Cause.
34. IF the input for a panel is missing from the Run_Set, THEN THE Notebook SHALL show a Not_Measured placeholder with the reason in that panel only, and SHALL render the other panels normally.
35. THE Notebook SHALL render the Tier-1 isolated view by reading the stored results in `tests/eval/results/jev_runs_class_blind/`, and SHALL NOT re-run the Tier-1 evaluation.
36. IF `tests/eval/results/jev_runs_class_blind/` is missing or contains no result files, THEN THE Notebook SHALL show a Not_Measured placeholder with the reason in the Tier-1 view and SHALL render the other panels normally.
37. THE Notebook SHALL render a caveats panel containing the Corpus size, the tool-name tell, Tier-2 variance, circularity, the Jev release, what was not measured, and links to the ADRs and tasks. Every link SHALL resolve to an existing file in the repository, and a link test SHALL verify this.
38. THE Notebook SHALL render payload text and Tier-2 reasoning only as escaped text in table cells. A payload containing the text `<script>alert(1)</script>` SHALL appear literally and SHALL create no HTML element. Pipe and newline characters SHALL NOT break the table structure.
39. THE Notebook SHALL include a cell that links to `notebooks/benchmark_analytics.py`, and the link SHALL resolve to the existing file.
40. WHEN a later phase of this spec adds a cross-reference to `notebooks/holistic_defense_analytics.py` in `notebooks/benchmark_analytics.py`, THE later phase SHALL add it as one new markdown cell. The diff of that file SHALL contain added lines only.
41. THE later phase SHALL leave every line that `tests/unit/test_marimo_notebook_syntax.py` pins unchanged, and that test SHALL pass without modification.

### Requirement 28: Notebook Conventions and Verification

**User Story:** As a reviewer, I want the notebook to follow the repository's marimo conventions and be verified by executed-cell tests and a clean export, so that it does not break in a fresh environment.

#### Acceptance Criteria

1. THE Notebook SHALL end every `@app.cell` function with a display expression.
2. THE Notebook SHALL contain no bare `return` statement as the final statement of a cell, except the single-return pattern, which is one `return` statement whose value is the tuple of names that cell exports to later cells.
3. THE Notebook SHALL begin with an underscore the name of every binding created in a cell that is not exported to a later cell.
4. THE Notebook SHALL end every markdown-only cell with a bare `mo.md(...)` expression. A markdown-only cell is a cell whose only call is to `mo.md`.
5. WHEN a new cell is added, THE Notebook SHALL produce no `marimo check` warning that is absent from the baseline recorded before the cell was added.
6. WHEN the Notebook is exported with `marimo export html --no-sandbox <notebook> -o <tmp> < /dev/null` in an environment where no live credential variable is set, THE export SHALL exit with code 0 within 120 seconds and SHALL report zero failed cells.
7. IF the export exits with a nonzero code, exceeds 120 seconds, or reports a failed cell, THEN THE export test SHALL fail and SHALL report the exit code and the name of each failed cell.
8. THE Harness SHALL provide a test module that parses the Notebook with `ast` and executes each `@app.cell` function once, in source order, with `mo`, `pd`, `go`, `json` and `repo_root` supplied.
9. WHEN the test module executes a cell, THE test module SHALL pass each name returned by an earlier cell to every later cell whose parameter has that name.
10. IF a cell raises an exception or declares a parameter that is neither supplied nor returned by an earlier cell, THEN THE test module SHALL fail and SHALL report the cell name and the exception or the missing parameter name.
11. WHEN no Run_Set exists, THE executed-cell tests SHALL assert that the Notebook renders its empty state, renders no figure, and raises no exception.
12. WHEN the Notebook is executed on the committed Run_Set, THE executed-cell tests SHALL assert that every count shown in each panel equals the library's recomputed count exactly, and that every rate shown equals the library's recomputed rate within an absolute tolerance of 1e-9.
13. THE Notebook SHALL exclude ERROR rows from both the numerator and the denominator of every rate it shows (provisional, Open Question Q2).
14. WHEN a panel cell is Not_Measured, THE Notebook SHALL render the single character `—` (U+2014) in that cell together with the recorded reason.
15. WHILE the executed-cell tests run, THE test module SHALL assert that no panel reads a credential environment variable and that no panel opens a network socket.
16. IF a panel reads a credential environment variable or attempts a socket connection during the executed-cell tests, THEN THE test module SHALL fail and SHALL report the panel name.
17. WHEN stub-provider data is present in the Run_Set, THE Notebook SHALL render a Plumbing_Only banner. WHEN no stub-provider data is present, THE Notebook SHALL render no Plumbing_Only banner.
18. THE Harness SHALL declare every dependency the Notebook imports in the `dev` extra of `pyproject.toml`.
19. THE Harness SHALL leave the set of runtime dependencies in `pyproject.toml` unchanged by the addition of the Notebook.
20. THE Notebook SHALL treat a case as hostile only when its `ground_truth` value is exactly the string `MALICIOUS` (case-sensitive). THE Notebook SHALL treat every other value as not hostile [rules 64 and 70].
21. WHEN a case has no recorded verdict, THE Notebook SHALL render the single character `—` (U+2014) for that case's verdict [rules 64 and 70].
22. WHERE the Notebook renders a threshold comparison, THE Notebook SHALL use the strict inequality operator (`<` or `>`) that the authoritative contract for that threshold defines.
23. WHEN a compared value equals the threshold exactly, THE Notebook SHALL place it on the side of the comparison that the authoritative contract assigns. The executed-cell tests SHALL assert this at 0.75 and 0.50, the Production_Mode thresholds, and at 0.35 and 0.75, the Band edges.

### Requirement 29: Security and Safety

**User Story:** As a security engineer, I want the harness to handle attack payloads and credentials safely, so that evaluating the firewall does not endanger the host or the repository.

#### Acceptance Criteria

1. THE Harness SHALL hold every payload as an inert string for its whole lifetime.
2. THE Harness SHALL NOT evaluate, import, execute or fetch any payload.
3. THE Harness SHALL call only the Resolver's `evaluate()` method on a case and SHALL NOT invoke the tool named in that case under any System_Verdict, including `ALLOW` and `QUARANTINE`.
4. THE Harness test suite SHALL statically scan every Python source file of the Harness and SHALL fail if a call to `eval`, `exec` or any `subprocess` function receives an argument that is, or is derived from, a field of a corpus case (tool name, arguments or state).
5. IF the source scan finds such a call, THEN THE Harness test suite SHALL report the file path and line number of each call found.
6. THE Harness test suite SHALL check the well-formedness of each payload by static parsing only, using `shlex` for shell-style payloads and `ast.parse` for Python-style payloads.
7. IF a payload fails static parsing, THEN THE Harness test suite SHALL fail and SHALL list the case identifier of each payload that failed.
8. THE Harness test suite SHALL NOT run, compile for execution or import any payload while checking well-formedness.
9. THE attack fixtures SHALL contain only hosts that are in the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), in the private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), or are names under the reserved `.example` top-level domain.
10. THE IOC_Corpus SHALL be the only fixture that contains real public indicators.
11. IF a host or indicator in any attack fixture violates criterion 9 or criterion 10, THEN THE Harness test suite SHALL fail and SHALL list the fixture and the offending value.
12. THE Harness SHALL keep the keys of every Jev request body to exactly `model`, `state` and `questions`.
13. IF a Jev request body contains a key outside that allowlist, THEN THE Harness test suite SHALL fail, and no such request SHALL be sent to the TypeSafe AI service.
14. THE Harness SHALL NOT alter the Jev backend, and every Stage_Recorder wrapper SHALL return a value equal to the value returned by the component it wraps.
15. WHEN the Harness sends a state to any external service, THE Harness SHALL send only the output of ContextHygiene for that state.
16. IF ContextHygiene fails on a state, THEN THE Harness SHALL NOT send that state, SHALL record the case as `ERROR` with the failure reason, and SHALL continue with the remaining cases; rates exclude `ERROR` rows from numerator and denominator (provisional, Open Question Q2).
17. THE Harness test suite SHALL verify the sanitization by submitting a state that contains a canary credential value and asserting that the outbound request body contains the `[[VARIABLE_NAME]]` placeholder and does not contain the canary value.
18. THE Harness SHALL write TSG seeds only through repository calls that bind values as query parameters and SHALL NOT build SQL text from seed content.
19. WHEN the TSG_Seeder starts a run, THE TSG_Seeder SHALL create a new temporary database in the operating system's temporary directory and SHALL write every seed signature to that database only.
20. WHEN a run ends by completion, error or interruption, THE Runner SHALL delete the temporary database before the process exits.
21. IF the temporary database cannot be deleted, THEN THE Runner SHALL report the database path and SHALL exit with a non-zero status.
22. IF the TSG_Seeder resolves its target database to the product's default database path, THEN THE Runner SHALL abort before any write to that database, SHALL report the conflict, and SHALL exit with a non-zero status.
23. THE Harness SHALL perform every version-control, pull-request, cloud and build operation through the native CLI tools `git`, `gh`, `gcloud`, `uv` and `marimo`.
24. THE Harness change set SHALL add no MCP server definition and no MCP client dependency.
25. THE Harness test suite SHALL scan every Harness document, rule text and source file, and SHALL fail if any dependency name is followed by a comparison operator (`==`, `>=`, `<=`, `~=`, `<`, `>`) and a version number.
26. THE Harness SHALL refer to dependencies by series only (for example, "the legacy pytest major line").
27. WHEN a Harness document or rule text cites a figure that was measured by a run or taken from an external vendor and can change over time, THE Harness document SHALL label the figure as dated evidence and SHALL give the date in `YYYY-MM-DD` form in the same sentence or table row.
28. IF a measured figure in a Harness document or rule text has no such label and date, THEN THE Harness test suite SHALL fail and SHALL report the document path and line number.
29. WHEN the Runner starts a run, THE Runner SHALL use one integer seed in the range 0 to 4294967295 for every permutation and split, taken from the command-line option or, if none is given, from the Harness's single default seed constant.
30. THE Runner SHALL write the seed to the Manifest of the Run_Set.
31. WHEN two runs use the same seed and the same Corpus_Hash, THE Runner SHALL produce identical permutations and identical splits in both runs.
32. IF the supplied seed is not an integer or is outside the range 0 to 4294967295, THEN THE Runner SHALL reject it before any Pass starts, SHALL report the invalid value, SHALL write no Run_Set, and SHALL exit with a non-zero status.

### Requirement 30: Test-First Verification

**User Story:** As a maintainer, I want every requirement verified by tests written before the code, so that the harness itself is trustworthy.

#### Acceptance Criteria

1. WHEN a Harness component is implemented, THE implementer SHALL write a failing unit test or reproduction script before the code is staged.
2. IF the pre-implementation test or script is run before the code exists, THEN it SHALL exit non-zero with an assertion failure that names the missing behavior, and not with an import, syntax or collection error.
3. THE Harness SHALL provide Hypothesis property tests, each run with at least 100 examples, and each test SHALL fail on the first counterexample and report it.
4. THE Harness SHALL provide a property test that `outcome` returns the same Outcome on repeated calls with the same ground truth, decision and Reading, for every combination of ground truth, decision and Reading.
5. THE Harness SHALL provide a property test of label symmetry that asserts an attack ground truth never yields `FALSE_ALARM` or `CORRECT_ALLOW`, and a benign ground truth never yields `CAUGHT` or `MISSED`.
6. THE Harness SHALL provide a property test that a decision counted as caught under the Blocked_Reading is also counted as caught under the Stopped_Reading, and that the only decision counted under the Stopped_Reading and not under the Blocked_Reading is `QUARANTINE`.
7. THE Harness SHALL provide a property test that reordering the cases of a Corpus leaves every computed rate and every Catch_Partition class assignment unchanged.
8. THE Harness SHALL provide a property test that replaying a recorded Run_Set at the shipped Band reproduces every recorded System_Verdict.
9. THE Harness SHALL provide a property test that the Composer returns the same System_Verdict as the Resolver in Production_Mode for every generated set of Stage outputs.
10. THE Harness SHALL provide a property test that changing any Stage_Flag value, with all Stage outputs held fixed, leaves the System_Verdict unchanged.
11. THE Harness SHALL provide a property test that enabling an additional Layer in a Composer configuration never decreases the number of attack cases counted as caught.
12. THE Harness SHALL provide a property test that each attack case in a configuration falls into exactly one Catch_Partition class and that the class sizes sum to the number of attack cases that are neither `ERROR` nor `UNMEASURED`.
13. THE Harness SHALL provide a property test that widening the Band, by lowering `lo` or raising `hi`, never decreases the number of cases that trigger Tier-2.
14. THE Harness SHALL provide a property test that a Stage or configuration recorded as Not_Measured yields no numeric rate and no imputed value.
15. THE Harness SHALL provide a property test that, in Seeding_Mode `held_out_parents`, no case identifier and no `parent_case_id` of a case in the scored set, which is the unseeded Parent_Cases and their variants, appears among the seed signatures.
16. THE Harness SHALL provide a property test that seeding the TSG_Seeder with the same signatures in any order produces identical System_Verdicts for every case.
17. THE Harness SHALL provide a property test that deserializing the serialized form of a per-case record or a Manifest returns a value equal to the original.
18. THE Harness SHALL provide a property test that every reported confidence interval satisfies 0 ≤ lower ≤ point estimate ≤ upper ≤ 1.
19. THE Harness SHALL provide a property test that every `QUARANTINE` decision carries exactly one Quarantine_Cause from `aggregate`, `tier2_unavailable` and `rate_limit`, and every other decision carries `none`.
20. THE Harness SHALL provide a property test that every computed rate excludes rows with decision `ERROR` from both numerator and denominator (provisional, Open Question Q2).
21. THE Harness SHALL provide a property test that no tool is executed for a case whose System_Verdict is `QUARANTINE`.
22. THE Harness strategies SHALL generate only values that satisfy the model's invariants, so that no generated stage output is rejected by model validation.
23. IF a Hypothesis strategy discards more than 50% of its generated examples through filtering, THEN the test run SHALL fail.
24. THE Harness SHALL provide the BDD feature file `tests/features/holistic_defense_evaluation.feature` containing a scenario in which a Stage_Flag is not counted as a system catch.
25. THE feature file SHALL contain a scenario in which a `QUARANTINE` is reported under both the Stopped_Reading and the Blocked_Reading, with a different caught result under each.
26. THE feature file SHALL contain a scenario in which an unconfigured Layer is reported as Not_Measured and not as a numeric result.
27. THE feature file SHALL contain a scenario in which a Tier-2 HTTP 429 response invalidates the Pass.
28. THE feature file SHALL contain a scenario in which a replay at the shipped Band reproduces the recorded run.
29. WHEN a BDD step drives async code, THE step SHALL use `run_async`.
30. WHEN a BDD step schedules background tasks, THE step SHALL flush those tasks inside the same coroutine as the scheduling call, before the step returns.
31. THE Harness SHALL provide a mutation guard test that applies each mutation in a fixed list, one at a time, to a temporary copy of the Composer and the Caught_Module, and never modifies the committed source files.
32. THE fixed mutation list SHALL include changing 0.75 to 0.76, changing `>=` to `>`, dropping the Tier-2 override, dropping the guard that a `BLOCK` is never downgraded, and making `QUARANTINE` not count as stopped.
33. WHEN a mutation is applied, THE mutation guard SHALL run the differential tests and the decision-table tests against the mutated copy and SHALL assert that at least one of them fails.
34. IF a mutation survives because no differential or decision-table test fails, THEN THE mutation guard SHALL fail, exit non-zero, and report the surviving mutation as a test gap.
35. WHEN a first-party warning is raised during a test run, THE Harness SHALL resolve it by changing the code that emits it.
36. THE Harness SHALL contain no `filterwarnings` entry that suppresses a first-party warning, and a test run SHALL emit zero first-party warnings.
37. THE Harness verification commands SHALL run hermetically as in Requirement 23.
38. THE Harness unit suite SHALL make no network call, and IF a test attempts a network connection, THEN the test SHALL fail with an error that identifies the attempted destination.

### Requirement 31: Dependencies and Phasing

**User Story:** As a maintainer, I want the phases and the dependencies on the open Tier-1 Jev tasks stated, so that the first comparison is not delayed and no recommendation rests on a known defect.

#### Acceptance Criteria

1. THE Harness SHALL deliver in Phase 1 the pure library and the observers (the Stage_Recorder wrappers), where the pure library performs no network access and no credential read.
2. THE Harness SHALL deliver in Phase 1 an offline stage pass that records, for every case of the Corpus, the output of structural policy, of context heuristics, of the TSG in each of the Seeding_Modes `cold`, `parent_only` and `held_out_parents`, and of CBM in its default configuration.
3. THE Harness SHALL deliver in Phase 1 the Composer and a differential test that compares the System_Verdict of the Composer with the decision of the Resolver for the same recorded Stage outputs, and the differential test SHALL fail on any mismatch.
4. THE Harness SHALL deliver in Phase 1 the Run_Set schema, which binds each Run_Set to exactly one Corpus_Hash.
5. THE Harness SHALL deliver in Phase 1 the Run_Store, which writes and reads Run_Sets under the Run_Set schema.
6. WHILE the Runner executes a Phase 1 deliverable, THE Harness SHALL make 0 requests to the Vertex, TypeSafe AI and AlienVault OTX services and SHALL read 0 of the variables `TYPESAFE_API_KEY` and `BW_OTX_API_KEY`.
7. IF a Phase 1 deliverable attempts a request to the Vertex, TypeSafe AI or AlienVault OTX service or a read of `TYPESAFE_API_KEY` or `BW_OTX_API_KEY`, THEN the Runner SHALL abort the run, SHALL report an error that names the attempted target, SHALL exit with a non-zero status and SHALL write no Run_Set.
8. THE Harness SHALL deliver in Phase 2 the live Whole_System_Runs W0, W1 and W2 and the Tier-2 Forced_Table.
9. THE Harness SHALL deliver in Phase 2 the Notebook, the recompute tests and the mutation guard.
10. WHEN the Notebook renders a rate for a Phase 2 configuration, THE Harness SHALL exclude ERROR rows from both the numerator and the denominator of that rate and SHALL display the number of excluded ERROR rows beside the rate [Open Question Q2, provisional].
11. IF the Vertex project grant is absent, THEN the Runner SHALL record each Phase 2 live run of the Default_Plan that needs the Vertex project as Not_Measured with a reason that names the missing grant and SHALL make 0 live calls for those runs. A Named_Explicitly Phase 2 live run that needs the Vertex project is governed by Requirement 23 criterion 15.
12. IF no Human_Grant for `TYPESAFE_API_KEY` exists in the current conversation, THEN the Runner SHALL record each Phase 2 live run of the Default_Plan that needs Jev as Not_Measured with a reason that names `TYPESAFE_API_KEY`, SHALL NOT read that variable and SHALL make 0 live calls for those runs. A Named_Explicitly Phase 2 live run that needs Jev is governed by Requirement 23 criterion 16.
13. THE Harness SHALL deliver in Phase 3 the optional Layers: threat intelligence on the Corpus hosts and the IOC_Corpus, the CBM_Fixture with its snapshot and the Permuted_Control, and the Whole_System_Runs W3, W4 and W5.
14. IF no Human_Grant for `BW_OTX_API_KEY` exists in the current conversation, THEN the Runner SHALL record each Phase 3 row of the Default_Plan that needs threat intelligence as Not_Measured with a reason that names `BW_OTX_API_KEY`, SHALL NOT read that variable and SHALL make 0 live calls for those rows. A Named_Explicitly Phase 3 threat-intelligence row is governed by Requirement 23 criterion 17.
15. IF an authored fixture that a Phase 3 row needs (the CBM_Fixture or its snapshot) is absent, THEN the Runner SHALL record that row as Not_Measured with a reason that names the missing fixture.
16. THE Harness SHALL deliver in Phase 4 the band study with the held-out protocol and the Clear_High_Variant.
17. THE Harness SHALL deliver in Phase 4 the cross-link cell in the existing Notebook, which links to the Notebook's Phase 2 comparison, and an ADR that records the first measured results and names the Corpus_Hash of the Run_Set they come from.
18. WHILE TASK-F09 or TASK-F08 is open, THE Harness SHALL complete and run every Phase 1, Phase 2 and Phase 3 deliverable without refusing, skipping or delaying any of them on account of that task.
19. WHEN TASK-F09 lands first and the Corpus_Hash computed by the Runner differs from the Corpus_Hash in the Manifest of an existing Run_Set, THE Runner SHALL write its results to a new Run_Set directory for the changed Corpus_Hash and SHALL leave every existing Run_Set directory unmodified.
20. WHEN TASK-F08 lands, THE Harness SHALL re-score the stored Jev runs and every Run_Set in the same commit, because the sanitized states change.
21. WHEN the Harness re-scores after TASK-F08, THE Harness SHALL exclude ERROR rows from both the numerator and the denominator of every rate [Open Question Q2, provisional].
22. THE Harness SHALL present TASK-F06 only as the Clear_High_Variant and SHALL label every Clear_High_Variant output as a hypothetical that is not production behavior.
23. THE Harness SHALL make 0 changes to files under `src/` for TASK-F06 and SHALL leave the decision on TASK-F06 to the maintainer.
24. THE Harness SHALL provide the Band_Replay and its held-out comparison, computed from stored Jev P values and the Forced_Table with 0 live calls, as the evidence TASK-F10 asked for.
25. WHEN the Band_Replay reports a verdict, THE Harness SHALL count a `QUARANTINE` as caught under the Stopped_Reading only and SHALL state that a `QUARANTINE` does not execute the tool.
26. THE Harness SHALL state in the Band_Replay output that TASK-F10 still needs fresh labeled cases before a Band changes, and SHALL leave the shipped Band at 0.35 and 0.75.
27. WHERE a change to `AGENTS.md` section 2 (the spec list) is wanted, THE Harness SHALL leave `AGENTS.md` unmodified and SHALL list the wanted change as a proposal for the maintainer under the proposal workflow of `AGENTS.md` section 6.3 [Open Question Q7].
28. WHERE a new testing rule for the definition of caught is wanted, THE Harness SHALL leave `.agents/rules/testing_and_hygiene.md` unmodified and SHALL list the wanted rule as a proposal for the maintainer under the proposal workflow of `AGENTS.md` section 6.3 [Open Question Q7].
29. WHEN the Runner starts a Phase 2 Whole_System_Run, THE Runner SHALL record in the Manifest of the resulting Run_Set references to ADR 0008, ADR 0009, `tier-1-jev-addition` and `.agents/rules/testing_and_hygiene.md` rules 56, 58, 64, 70, 71, 72, 74, 77, 78 and 79 as its dependencies.

## Open Questions and Assumptions

Q1 to Q11 are open. Each requirement above states a provisional behavior marked with the question; none of them is resolved by this document. Q12 to Q15 are decided (2026-11-13) and are kept here, under their original numbers, so that the design can still cite them. The maintainer's answer may change the cited requirement.

- **Q1. The definition of caught.** Assumed: the Stopped_Reading (BLOCK or QUARANTINE) is the primary reading and the Blocked_Reading sits beside it. Open: whether fail-closed QUARANTINEs count as catches or only appear separately. Affects Requirements 6 and 7.
- **Q2. ERROR rows.** Assumed: excluded from the rates and shown in a sensitivity column that treats them as stopped. Open: whether that is acceptable. Affects Requirement 7.
- **Q3. The Jev run behind the Forced_Table.** Assumed: run 1 of the release behind `jev-latest` at run time, two Passes. Open: whether to build the table for both releases and how many Passes. Affects Requirements 3 and 24.
- **Q4. CBM.** Open: (a) whether the blast radius cut of 6 or more is acceptable as a labeled proposal; (b) whether the critical-sink mapping drop is tracked as its own task. Affects Requirements 3, 21 and 26.
- **Q5. IOC corpus.** Open: which public feed export, about how many entries, and whether sending popular legitimate hosts and feed-listed indicators to OTX as lookups is acceptable. Affects Requirement 20.
- **Q6. Library location.** Assumed: `src/blackwall/holistic_eval/`. Open: whether the maintainer prefers a `tests/`-side package. Affects Requirement 1.
- **Q7. Constitution and rules.** Open: whether the proposal artifact for `AGENTS.md` section 2 and a testing rule for the definition of caught is prepared now or after Phase 2. Affects Requirement 31.
- **Q8. TASK-F09 as a prerequisite.** Assumed: a gate for the band recommendation, not for the first comparison. Open: whether the maintainer agrees. Affects Requirements 16 and 31.
- **Q9. A `src/` observer seam.** Assumed: none is planned. Open: whether a single optional `observer` argument on `SyncResolver.evaluate` is acceptable as its own tested change. Affects Requirement 1.
- **Q10. Pacing and cool-down.** Assumed: concurrency 2 and a 30-second cool-down. Open: whether 30 seconds is right. Affects Requirement 24.
- **Q11. Held-out evidence.** Assumed: a parent-grouped split of this corpus is exploratory. Open: whether the band study waits for fresh hand-written wave cases before it may recommend an edge. Affects Requirement 16.
- **Q12. Missing-grant behavior. Decided 2026-11-13.** A live row that the caller names explicitly in the `--configs` list of a `run` invocation (Named_Explicitly) and whose credential or grant is missing aborts: the CLI exits non-zero with an error naming the missing variable, before it builds any client, makes any network call or writes any record. A row that is part of the Default_Plan and whose credential, fixture or transport is missing is recorded as Not_Measured with the reason, and the run continues. A missing fixture or transport on a Named_Explicitly row is also recorded as Not_Measured, because the abort applies to credentials and grants only. Shaped criteria 15, 16, 17 and 20 of Requirement 23, criterion 8 of Requirement 4, criterion 17 of Requirement 19, criterion 1 of Requirement 22, criteria 11, 12 and 14 of Requirement 31, and the Glossary terms Named_Explicitly and Default_Plan.
- **Q13. Concurrency. Decided 2026-11-13.** The configured `--concurrency` value (an integer of 1 or more, default 2) is the in-flight limit of criterion 5 of Requirement 24: at most that many cases in flight, and exactly that many while at least that many cases of the current Pass remain unstarted. The Manifest records the concurrency used for every Pass. Passes that are compared with each other (the valid Passes of one configuration, Pass_Spread calculations and release comparisons) must have used the same concurrency; a Pass with a different concurrency is recorded and excluded from those comparisons with a reason. The cool-down of criterion 6 of Requirement 24 keeps its Q10 tag. Shaped criterion 18 of Requirement 23, criteria 2, 5 and 22 of Requirement 24, criterion 10 of Requirement 11 and criterion 21 of Requirement 13.
- **Q14. Held-out property. Decided 2026-11-13.** In `held_out_parents` mode the scored set for the leakage property is the unseeded-parent half (the unseeded Parent_Cases and their variants). Criterion 15 of Requirement 30 requires that no case identifier and no `parent_case_id` of a case in that scored set appears among the seed signatures. Criterion 19 of Requirement 17 keeps reporting the seeded-parent-variant match rate and the unseeded-parent-variant match rate separately, and labels the first as transfer from a seed and not as held-out evidence. Criterion 3 of Requirement 18 marks `leakage="seeded_case"` only on the Parent_Cases whose seed was written in the current Seeding_Mode (every Parent_Case in `parent_only`, the seeded half in `held_out_parents`, none in `cold`); unseeded parents are scored and not marked. Criterion 4 of Requirement 18 excludes only the marked rows. Shaped Requirements 17, 18 and 30.
- **Q15. ERROR sensitivity scope. Decided 2026-11-13.** The treat-ERROR-as-stopped sensitivity column of criterion 14 of Requirement 7 (and the sensitivity values of criterion 25 of Requirement 6) applies to the catch tables that state a catch rate or a false-alarm rate for Whole_System_Run and Composed_Row System_Verdicts, which are the catch tables of Requirements 6, 7 and 13. Replay cells, TSG rates, threat-intelligence rates, IOC_Corpus rates and the CBM `sinks mapped` what-if row state the ERROR exclusion and the ERROR count only and carry no sensitivity column. Shaped criteria 25 of Requirement 6 and 14 of Requirement 7.

Unconfirmed technical facts carried forward from the design and measured, not assumed, by this spec: OTX behavior on documentation and private addresses (Requirement 19), and conformance of a real codebase-memory-mcp server with the client's HTTP JSON-RPC shapes (Requirement 21).
