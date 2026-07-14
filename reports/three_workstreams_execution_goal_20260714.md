# Goal Document: relabel, Tier1 failure direction, and Tier2 codegen generalization

## Go / No-Go

- **Judgment:** Go
- **Reason:** the user fixed the three decision directions, their order, and the evidence required
  for completion. No product or architecture choice remains open before execution.

## Target Outcome

Produce three independently committed and pushed evidence slices:

1. Adjudicate all 51 promptfoo multi-turn records from final-grader evidence plus model-visible
   turns, rerun every identified Tier1 and v0.5 Part1/2/3 consumer, and quantify conclusion drift.
2. Determine whether paper-missing/reversed Tier1 signals explain `test_holdout` false negatives;
   add only evidence-supported features and measure recall, or publish a failure-mode direction if
   the association is weak.
3. Evaluate frozen Tier2 on 8-10 independently sourced code-generation boundary cases not copied
   from its prompt; change the Tier2 prompt only if the result demonstrates a scope-design failure.

## Goal Definition

- **Type:** quality / learning / implementation
- **Boundary:** dataset labels and conversion provenance; Tier1 feature/evaluation code when
  evidence supports it; Tier2 evaluation data/harness and, conditionally, its prompt.
- **Non-goals:**
  - Wiring Tier2/Tier3 into `pipeline._decide`.
  - Choosing validation versus integration as the next project phase.
  - Matching the paper's feature count or group sizes for their own sake.
  - Hand-writing generated or enumerated samples.
- **Deferred work:** production data sources for Tier3 and any unrelated historical-report cleanup.
- **Verification rule:** each workstream exits only with committed raw artifacts, a before/after or
  frozen-baseline report, relevant automated tests, a pushed commit, and a verified remote hash.
- **Evidence source:** source grader JSON, model-visible records, independent case adjudication,
  Tier1/Tier2 raw result JSON, unit tests, and case-level metric comparisons.
- **Pass criteria:** all named consumers are accounted for; negative results and instability are
  reported before positive interpretation; no unsupported reuse/matching claim is made.
- **Confidence note:** LLM reruns remain stochastic, so case sets and per-run outputs must accompany
  aggregates. Human/model-visible adjudication is kept separate from source response grading.
- **Judgment owner:** automated tests and raw artifacts establish facts; the user owns any later
  architecture priority decision.

## Current State at Goal Creation

- The converter hard-labels 51 user-only records malicious and ignores `storedGraderResult`.
- `_126` is confirmed incorrectly labeled; the remaining records require visible-action review.
- Five Tier1 evaluation scripts directly consume the 51-record holdout; six Tier2 disagreement
  malicious cases derive from it.
- Local Tier1 has 40 features rather than the paper implementation's 42 and differs semantically;
  `test_holdout` recall, not dimensional conformity, is the target.
- `_111` and `_115` are prompt/regex fixtures; `_115` reproduced at 7/10 twice.
- Data generation/enumeration must use existing tools or standard-library transformations; no
  hand-written sample generator is permitted.

## Priority Rationale

- Relabeling comes first because the same labels affect the evidence used by both later directions.
- Tier1 analysis precedes Tier2 prompt work because it is independent and may end without code
  change; Tier2 validation needs a separately sourced case artifact and network judge runs.
- Each workstream is pushed before the next is declared complete so evidence cannot exist only in
  the working tree.

## Assumptions and Open Decisions

| item | status | impact | owner / next step |
|---|---|---|---|
| Final grader and visible operation answer different questions | confirmed | pass/fail cannot be copied mechanically into the operation label | adjudicate all visible records |
| Existing public/committed data contains 8-10 suitable new codegen cases | unresolved | hard stop for workstream 3 if false | repository search, then report blocker rather than hand-write |
| Missing/reversed paper signals correlate with holdout FNs | unresolved | determines whether Tier1 code changes are justified | case-level association analysis |
| Judge API credentials/dependencies remain available | assumed | needed for v0.5/Tier2 reruns | run a minimal existing harness call before the full batch |

## Phases

### Phase 1: repair label provenance and rerun consumers

- **Purpose:** establish corrected labels and measure whether historical conclusions move.
- **Entry condition:** clean worktree at pushed `ded1c0a`.
- **Phase rules:**
  - RED/GREEN tests precede converter or relabel implementation changes.
  - Every record gets an explicit provenance entry; no plugin-wide implicit label.
  - Preserve baseline values from Git and write reruns to versioned artifacts where practical.
  - Do not alter Tier0-3 judgment logic.
- **Todos:**
  - [x] Add a failing test proving labels are not unconditionally malicious and grader evidence is
    preserved.
    - **Surface:** converter/relabel tests
    - **Proof:** focused pytest RED failure
    - **Depends on:** none
  - [x] Independently adjudicate the 51 model-visible records and record rationales.
    - **Surface:** versioned adjudication manifest and corrected holdout
    - **Proof:** schema/count/provenance tests plus reviewer agreement/disagreement resolution
    - **Depends on:** source-record join
  - [x] Rerun the five Tier1 chains and v0.5 Part1/2/3 consumers.
    - **Surface:** versioned JSON artifacts and comparison report
    - **Proof:** commands, raw per-case outputs, before/after table
    - **Depends on:** corrected holdout
  - [ ] Commit, push, and verify the remote hash.
    - **Surface:** workstream 1 commits
    - **Proof:** `git ls-remote`
    - **Depends on:** all phase checks green
- **Exit proof:** all 51 records and all named consumers appear in the comparison report; conclusion
  changes are explicitly classified as unchanged direction, weakened, or retracted.
- **Stop condition:** source records cannot be joined losslessly, or the judge dependency cannot run
  after dependency/config verification.

### Phase 2: explain Tier1 holdout misses and test targeted signals

- **Purpose:** answer which evidence-backed direction can improve Tier1 holdout recall.
- **Entry condition:** Phase 1 labels and rerun artifacts are pushed.
- **Phase rules:**
  - Use case-level false negatives, not paper feature-count conformity, as the target.
  - Add features only after a measurable association with false negatives is shown.
  - Feature behavior enters through RED/GREEN tests; evaluate recall and precision/FP tradeoff.
- **Todos:**
  - [ ] Map paper-missing and reversed signals onto corrected holdout false-negative content.
    - **Surface:** analysis artifact/report
    - **Proof:** per-case mapping and group-level association statistics
    - **Depends on:** Phase 1 rerun
  - [ ] If association is material, add the smallest targeted feature subset and retrain/evaluate.
    - **Surface:** `tier1/features.py`, tests, model/eval artifacts
    - **Proof:** RED/GREEN plus before/after recall and error-set diff
    - **Depends on:** association result
  - [ ] Otherwise publish the holdout failure taxonomy and recommended improvement direction.
    - **Surface:** report
    - **Proof:** every FN assigned evidence or marked unresolved
    - **Depends on:** association result
  - [ ] Commit, push, and verify the remote hash.
- **Exit proof:** a data-backed Tier1 improvement direction exists, with either measured feature
  impact or a falsified paper-feature hypothesis.
- **Stop condition:** the referenced holdout/result cannot be reproduced from committed inputs.

### Phase 3: test Tier2 code-generation scope away from prompt fixtures

- **Purpose:** distinguish general code-generation judgment from `_111/_115` answer memorization.
- **Entry condition:** an independent existing source or compliant generator yields 8-10 suitable
  cases with no prompt-example overlap.
- **Phase rules:**
  - No hand-written case enumeration or generator logic.
  - Freeze Tier2 for the first evaluation; store every run and rationale.
  - Modify the prompt only after the frozen result and failure taxonomy are committed as evidence.
- **Todos:**
  - [ ] Select 8-10 structurally similar code-generation boundary cases from an independent source
    using existing tooling/standard-library filtering.
    - **Surface:** versioned case artifact with source references
    - **Proof:** provenance table and prompt-overlap grep/diff
    - **Depends on:** source discovery
  - [ ] Run frozen Tier2 repeatedly and classify case-level behavior/stability.
    - **Surface:** harness/raw JSON/report
    - **Proof:** per-run verdicts and aggregate with uncertainty caveats
    - **Depends on:** case artifact
  - [ ] If failures show a prompt-design scope gap, enter RED/GREEN prompt regression work and rerun
    both new cases and historical controls; otherwise leave the prompt frozen.
    - **Surface:** conditional Tier2 prompt/test changes
    - **Proof:** frozen versus changed comparison, no control regression
    - **Depends on:** frozen failure taxonomy
  - [ ] Commit, push, and verify the remote hash.
- **Exit proof:** the `_111/_115` historical claim is retained, narrowed, or retracted using an
  independent-case result rather than exact prompt fixtures.
- **Stop condition:** no compliant independent case source exists or the judge service is genuinely
  unavailable after a minimal diagnostic.

## Dry-Run Findings

- Phase 1 must separate response-grader outcome from operation label; treating pass as benign would
  reproduce the original category error for visible malicious requests that the agent refused.
- Rerun artifacts need versioned paths or explicit Git baselines to avoid the v0.5/v0.6 overwrite
  failure recurring.
- Phase 2 may legitimately produce no feature code change; forcing one would optimize for paper
  resemblance rather than the holdout target.
- Phase 3 source discovery is the only unresolved hard prerequisite; failure there must be reported,
  not bypassed with hand-authored cases.

## Final Validation

- Focused and full relevant pytest suites pass.
- Every generated/selected artifact has source provenance and no hand-written generation path.
- `git diff --check` passes for each workstream.
- Each workstream's remote branch hash equals the reported local commit.

## First Execution Step

Add a failing converter/relabel test that demonstrates `_126` cannot remain an unconditional
malicious/high-confidence label and that source grader evidence survives conversion.
