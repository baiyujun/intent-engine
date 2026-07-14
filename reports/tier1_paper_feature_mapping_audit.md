# Tier1 feature mapping audit against arXiv:2605.01143

> Audit date: 2026-07-14
> Project revision inspected: `5fe8403`
> Scope: `tier1/features.py`, tracked XGBoost model metadata, arXiv v2 Section 3.3 / Table 4,
> and the paper authors' linked implementation at commit
> `acd51089d05cc13fcb29644170db764a94d936f6`.

## Audit conclusion

- **Verdict: FAIL.** The current Tier1 is not an implementation of the paper's experimental
  42-feature vector. It is a 40-column project-specific heuristic adaptation.
- **Finding count:** P1: 4, P2: 1, needs-evidence: 0.
- The paper gives group-level prose and Table 4 gives only group dimensions. It does NOT contain
  a 42-row feature-definition table. The exact experimental columns are recoverable from the
  authors' code repository explicitly linked by the paper.
- Against those 42 official experimental columns: **exact 0, approximate proxy 31, missing in
  this project 11**. "Approximate" means the concept is related but the source field, prefix
  window, or formula differs; it does not mean reproduced.
- This does not show that the current XGBoost has no predictive value. It invalidates the narrower
  claims of paper-feature reproduction and paper-compatible group ablation/importance.

## Sources of truth

1. Paper: [arXiv v2 Section 3.3](https://arxiv.org/html/2605.01143v2#S3.SS3).
2. Paper: [Table 4](https://arxiv.org/html/2605.01143v2#S4.T4) reports
   prompt/session/tool/context/trajectory dimensions `11/8/6/6/11`, total 42.
3. The paper links the authors' repository in its abstract. Official feature lists at commit
   `acd51089d05cc13fcb29644170db764a94d936f6`:
   [four groups](https://github.com/Yunicorn228/A-Low-Latency-Fraud-Detection/blob/acd51089d05cc13fcb29644170db764a94d936f6/agent_fraud/config.py#L1553-L1592),
   [trajectory list](https://github.com/Yunicorn228/A-Low-Latency-Fraud-Detection/blob/acd51089d05cc13fcb29644170db764a94d936f6/agent_fraud/fraud_features.py#L102-L114),
   [base formulas](https://github.com/Yunicorn228/A-Low-Latency-Fraud-Detection/blob/acd51089d05cc13fcb29644170db764a94d936f6/agent_fraud/features.py#L122-L224), and
   [trajectory formulas](https://github.com/Yunicorn228/A-Low-Latency-Fraud-Detection/blob/acd51089d05cc13fcb29644170db764a94d936f6/agent_fraud/fraud_features.py#L153-L224).
4. Local implementation: `tier1/features.py:177-209` (columns/groups) and
   `tier1/features.py:212-426` (formulas).
5. Provenance ordering: official commit date is 2026-05-01; local initial Tier1 implementation
   `7aa842e` is 2026-07-09. The official list predates the local implementation.

## Dimension check

| group | paper Table 4 / official code | current code | result |
|---|---:|---:|---|
| prompt | 11 | 11 | same count, different columns/semantics |
| session | 8 | 8 | same count, different columns/semantics |
| tool | 6 | 6 | same count, current prefix multi-hot is not current-action one-hot |
| context | 6 | 6 | same count, external-input direction is not preserved |
| trajectory | 11 | 9 | 4 official columns missing; 2 duplicate project-only scores added |
| **total** | **42** | **40** | **not the same feature vector** |

Runtime checks at the audited revision:

```text
len(FEATURE_NAMES) = 40
FEATURE_GROUPS = prompt 11 / session 8 / tool 6 / context 6 / fraud 9
len(extract_features(empty_record)) = 40
xgboost_full.json num_feature = 40
xgboost_ablated.json num_feature = 31
```

The two `31` values can create a false match: the paper's leave-trajectory-out dimension is
`42 - 11 = 31`; the current ablated model is `40 - 9 = 31`. They are different feature spaces.

## Field-by-field mapping

Classification:

- **exact**: same source field, prefix/current-turn window, and formula.
- **proxy**: related concept, but source, window, category set, or formula differs.
- **missing**: no usable current signal for the official experimental feature.

### Prompt group (official 11; exact 0 / proxy 7 / missing 4)

| official experimental feature | current candidate | class | concrete mismatch |
|---|---|---|---|
| `turn_index` | `session_length` (session group) | proxy | Equal only on a fully retained prefix; moved across groups. |
| `current_prompt_len` | `prompt_length` | proxy | Current sums every turn's `raw_text`, not the current prompt. |
| `current_external_len` | none | missing | No prompt/external input length separation. |
| `current_token_count` | `token_count` | proxy | Current sums the whole prefix. |
| `current_prompt_entropy` | none | missing | Token entropy is not implemented. |
| `current_override_hits` | `has_system_override`, `has_ignore_instruction` | proxy | Whole-prefix booleans, not current-prompt hit count. |
| `current_secret_hits` | `suspicious_keyword_count` | proxy | Mixed keyword families; counts matching turns, not secret hits. |
| `current_action_hits` | `suspicious_keyword_count` / action regexes | proxy | Mixed signal and different count semantics. |
| `current_probe_hits` | none | missing | No probing-pattern feature. |
| `current_rule_score` | `prompt_suspicion_score` | proxy | Locally invented weights, not the prompt-filter rule score. |
| `prompt_filter_block` | none | missing | No current prompt-filter decision input. |

Project-only prompt columns such as `suspicious_keyword_max_weight`, `has_new_instruction`,
`instruction_conflict_flag`, `override_attempt_flag`, and `privilege_escalation_signal` are
reasonable project heuristics, but they are not the official experimental 11 columns.

### Session group (official 8; exact 0 / proxy 5 / missing 3)

| official experimental feature | current candidate | class | concrete mismatch |
|---|---|---|---|
| `retry_count` | `retry_count` | proxy | Official compares current prompt with all prior prompts; current counts adjacent Jaccard > 0.9. |
| `repeated_request_ratio` | none | missing | Not implemented. |
| `denied_action_count` | `denied_tool_call_count` | missing | Column exists but is hard-coded zero; it carries no denial signal. |
| `recent_untrusted_turns` | `has_external_content_recently` | proxy | Official counts prior external input; current checks outbound network-action text in last two turns. |
| `probe_turn_ratio` | none | missing | Not implemented. |
| `semantic_drift` | `semantic_drift_score` | proxy | Official hashing-vector cosine vs prior-three mean; current adjacent token-set Jaccard average. |
| `tool_switch_count` | `tool_transition_count` | proxy | Official cumulative switches; current number of distinct transition pairs. |
| `distinct_tool_count_so_far` | `tool_diversity_score` | proxy | Official proposed-tool count; current coarse text-derived action count divided by turns. |

`failed_tool_call_count` is another hard-coded-zero project column. The v0 schema may explain the
absence of denial/failure data, but a reserved zero column is not a reproduction of the signal.

### Tool group (official 6; exact 0 / proxy 6 / missing 0)

| official experimental feature | current candidate | class | concrete mismatch |
|---|---|---|---|
| `task_tool_mismatch` | `task_tool_mismatch_flag` | proxy | Official compares the selected tool to the request; current flags a turn containing >=2 action-word groups. |
| `proposed_tool_web_fetch` | `tool_web_fetch` | proxy | Current scans any text in the full prefix, not the current proposed tool. |
| `proposed_tool_summarize` | `tool_summarize` | proxy | Same prefix-text vs current-action mismatch. |
| `proposed_tool_read_local_file` | `tool_file_read` | proxy | Same; inferred from text rather than a proposed-tool field. |
| `proposed_tool_send_email` | `tool_network_request` | proxy | Merges email/upload/post/pipe and scans the full prefix. |
| `proposed_tool_run_shell` | `tool_exec` | proxy | Inferred by regex over the full prefix. |

The paper explicitly defines this group as a one-hot encoding of the **currently proposed
action** and separates trajectory history for ablation. Current code uses `any(...)` over the
entire prefix, so a two-turn read-then-send record sets both `tool_file_read=1` and
`tool_network_request=1`. The tool group therefore contains trajectory history and cannot support
the paper's action-identity-vs-trajectory ablation interpretation.

### Context group (official 6; exact 0 / proxy 5 / missing 1)

| official experimental feature | current candidate | class | concrete mismatch |
|---|---|---|---|
| `external_override_hits` | `suspicious_pattern_in_context` | proxy | Whole-prefix mixed keyword boolean; not external-input override hits. |
| `external_secret_hits` | `sensitive_resource_involved` | proxy | Whole-prefix sensitive-text boolean; not external-input secret hits. |
| `external_action_hits` | `suspicious_pattern_in_context` | proxy | Partial regex overlap; no external-input action count. |
| `suspicious_external_flag` | `suspicious_pattern_in_context` | proxy | Does not isolate retrieved/tool-mediated content. |
| `untrusted_external_flag` | `has_external_content` | proxy | Current treats outbound send/email/upload text as "external content". Direction is reversed. |
| `follows_recent_retrieval` | none | missing | No actual retrieval-history signal; the similarly named local rule is based on outbound network text. |

Minimal runtime probe:

```text
ordinary turn with role=retrieved_doc, instruction_origin=retrieved_content:
  has_external_content=0, external_content_count=0
user text "Email this report to ops@example.com":
  has_external_content=1, external_content_count=1
```

The record schema already exposes `role` and `instruction_origin`, but Tier1 reads only
`turns[*].raw_text`. This group mostly models outbound action words, not ingestion of untrusted
context as defined by the paper.

### Trajectory group (official 11; exact 0 / proxy 8 / missing 3)

| official experimental feature | current candidate | class | concrete mismatch |
|---|---|---|---|
| `cumulative_tool_risk` | `cumulative_risk_sum` | proxy | Text-derived action classes and different risk map. |
| `tool_risk_delta` | `risk_delta` | proxy | Same formula shape, different action/risk input. |
| `tool_risk_monotone_flag` | `monotonicity_flag` | proxy | Same concept, but current single-turn value is 0 while official `all(empty)` is 1. |
| `distinct_tool_ratio` | `tool_diversity_score` (session group) | proxy | Moved group; text-derived coarse actions rather than proposed tools. |
| `sensitive_read_count_so_far` | none | missing | Not implemented. |
| `external_recipient_count` | none | missing | `external_content_count` counts network-like turns, not external recipients. |
| `sensitive_read_then_send` | none | missing | The official split-exfil binary feature is absent. |
| `recipient_novelty_flag` | `novelty_recipient_flag` | proxy | Scans all prefix text; official uses current `send_email` argument. |
| `file_novelty_flag` | `novelty_filepath_flag` | proxy | Scans all prefix text; official uses current `read_local_file` argument. |
| `action_burst_score` | `action_burst_score` | proxy | Formula shape matches, but official risks are read=2/send=3; current risks are read=1/network=2. |
| `context_exfil_gap` | `context_exfil_gap` | proxy | Text-inferred actions and `-1` missing sentinel vs official `0`. |

The paper prose explicitly enumerates 7 trajectory concepts/features: cumulative risk + delta +
monotonicity (3), burst (1), two novelty flags (2), and context-exfil gap (1). Table 4 says the
experimental group has 11. The remaining official columns are visible in the linked code:
`distinct_tool_ratio`, `sensitive_read_count_so_far`, `external_recipient_count`, and
`sensitive_read_then_send`.

The current explanation that the prose defines 9 relies on turning each novelty **flag** into a
flag plus a score. In code, `novelty_recipient_score` is exactly equal to
`novelty_recipient_flag`, and the filepath pair is also identical. They are two duplicate
project-only columns, not paper features.

Runtime probe for `read sensitive -> read sensitive -> send external`:

```text
current risk map [1,1,2]: cumulative_risk_sum=4, action_burst_score=1/3
official risk map [2,2,3]: cumulative_tool_risk=7, action_burst_score=3/3
```

## Findings

### 1. "Implements the paper feature set" is false

- **Severity:** P1
- **Location:** documentation/code claim `tier1/features.py:3`; implementation
  `tier1/features.py:177-209`; paper Table 4 and official lists linked above.
- **Evidence:** paper/official vector is 42 (`11/8/6/6/11`); code and both model artifacts are
  40 (`11/8/6/6/9`). Full field mapping finds no exact reproduction.
- **Impact:** readers can incorrectly treat local results as a reproduction or compare local
  feature importance/ablation directly with Table 4.
- **Minimal correction:** describe Tier1 as "a 40-dimensional heuristic feature set inspired by
  the paper's five signal groups and adapted to this project's text-only schema."
- **Repair value:** keeps local model results useful without assigning unsupported paper fidelity.
- **Principle:** evidence before judgment; code is truth.

### 2. Prompt/tool/context boundaries do not preserve the paper's ablation contract

- **Severity:** P1
- **Location:** `tier1/features.py:228-341`; paper Section 3.3.
- **Evidence:** prompt features aggregate the full prefix, tool bits are prefix multi-hot rather
  than current-action one-hot, and context treats outbound send text as external input.
- **Impact:** group-level importance cannot be interpreted as prompt vs action identity vs
  untrusted context vs trajectory in the paper's sense.
- **Minimal correction:** stop using paper group semantics for local ablation interpretation;
  label the groups by their actual local inputs until a separate implementation decision is made.
- **Repair value:** prevents cross-group leakage from being presented as a paper finding.
- **Principle:** contracts first; explain repair value.

### 3. The context group reverses the indirect-input direction

- **Severity:** P1
- **Location:** `tier1/features.py:319-341`; schema fields at
  `dataset/src/schema.py:65-74`; paper Section 3.3 context paragraph.
- **Evidence:** retrieved content produces zeros, while a direct outbound email request sets the
  external-content fields to one.
- **Impact:** the group cannot support claims about indirect injection or untrusted retrieved
  content, despite carrying that name.
- **Minimal correction:** correct documentation immediately; any later behavior change must be a
  separately authorized Tier1 task using source-aware schema fields.
- **Repair value:** stops an outbound-action proxy from being mistaken for indirect-input defense.
- **Principle:** code is truth; safety claims require concrete evidence.

### 4. The trajectory explanation is neither the paper prose nor the official 11

- **Severity:** P1
- **Location:** `tier1/features.py:13-23,343-425`; local note
  `notes/xgboost_paper_features.md:62-84`; official trajectory list/formulas linked above.
- **Evidence:** prose enumerates 7; official experiment has 11; current code has 9, omits three
  official signals after moving one to session, and adds two duplicate novelty scores.
- **Impact:** the history of "padding to 11 then honestly dropping two" still identifies the
  wrong missing features and hides the official split-exfil/count signals.
- **Minimal correction:** replace the inferred list in the note with the official list and mark
  all current substitutions/missing fields explicitly.
- **Repair value:** future work starts from the actual gap instead of inventing more fillers.
- **Principle:** contracts first; evidence before judgment.

### 5. Four columns are structurally non-informative before dataset-specific degeneracy

- **Severity:** P2
- **Location:** `tier1/features.py:263-264,365-390`.
- **Evidence:** denied/failed counts are always zero; both novelty scores are exact copies of their
  flags. Thus 40 columns contain at most 36 non-trivial, non-duplicate signals in general.
- **Impact:** raw feature count overstates independent information and can confuse importance
  reporting.
- **Minimal correction:** document the two reserved constants and two aliases as such; do not call
  them independent features.
- **Repair value:** makes dimensionality and model interpretation honest without changing logic.
- **Principle:** code is truth; evidence before judgment.

## Verified but not changed

- Current extraction, model metadata, and group indices are internally consistent at 40 columns.
- The repository already admits the 40-vs-42 count difference; this audit corrects the deeper
  claim that the surviving columns faithfully correspond to the paper.
- No Tier1 logic, model, feature order, or report metric was changed by this audit.

## Final disposition

- [ ] Pass
- [ ] Conditional pass
- [x] Fail: paper-reproduction and paper-compatible ablation claims are unsupported.

| severity | count |
|---|---:|
| P0 | 0 |
| P1 | 4 |
| P2 | 1 |
| P3 | 0 |
| needs evidence | 0 |

| change area | required by this audit | note |
|---|---|---|
| documentation / historical claims | yes | Replace reproduction wording with adaptation wording. |
| Tier1 feature logic | no | Frozen by current task boundary; requires separate authorization. |
| model retraining | no | Not implied unless feature logic is later changed. |
| evaluation interpretation | yes | Do not compare local group ablation as Table 4 reproduction. |

Recommended order: correct the documentation/claims first; only after the project direction is
chosen should a separate task decide whether to preserve the local 40-dimensional model or build
a source-aware implementation of the official 42 features.
