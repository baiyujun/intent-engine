# Tier1 holdout failure-direction analysis

> **Verdict (negative result first): do not add the paper-gap features.** The
> previous “missing 11” audit count itself contained one classification error;
> the corrected count is **missing 10**. Nine of those ten signals are structurally
> zero on this holdout. The only exposed signal, prompt entropy, changes holdout
> recall by only **2/793 = 0.25 percentage points** in a same-parameter in-memory
> retrain. The reversed external-context group also has no FN association here.
>
> Tier1's data-supported improvement direction is instead: separate the
> out-of-scope content-safety portion of the benchmark, then improve current-action
> representation for the operation-safety subset. A shell-interpreter probe is
> promising but **not ready to merge** because no known benign evaluation record
> exposes it.

## Metric provenance

`reports/tier1_prefix_eval.json` is stale relative to the current saved model. Both
numbers are real measurements, but they belong to different revisions and their FN
sets must not be mixed:

| model/report contract | TP | FN | Recall |
|---|---:|---:|---:|
| historical `tier1_prefix_eval.json` | 508 | 285 | 0.6406 |
| current `tier1/models/xgboost_full.json` | **520** | **273** | **0.6557** |

The historical synthetic-prefix AUC 0.934 / Recall 0.906 is not retracted. It used
3,200 synthetic records; the current source has 6,400 and the saved model changed
at `7bbfa03`, so it is historical rather than a current regression baseline.

Raw current evidence is
`reports/tier1_holdout_failure_analysis_20260714.json`. The analyzer runs the saved
model directly; it does not infer case identities from aggregate reports.
Its same-parameter baseline retrain matches that saved model on all 793 holdout
probabilities (maximum and mean absolute difference 0; threshold disagreements 0).
Exact retrain tables below were reproduced with XGBoost 3.3.0; `requirements.txt`
does not pin an exact version, so cross-version byte-for-byte equality is not claimed.

## Official-source check

The comparison is pinned to the paper authors' repository commit
`acd51089d05cc13fcb29644170db764a94d936f6`:

- Official 42-column lists: `agent_fraud/config.py:1553-1592` and
  `agent_fraud/fraud_features.py:102-114`.
- Entropy formula: `agent_fraud/features.py:20-30, 183-192`.
- Pattern lists, weights, and threshold: `agent_fraud/config.py:38,54-116`;
  counting/scoring: `agent_fraud/rule_filter.py:11-48`.
- Prior/current trajectory boundaries:
  `agent_fraud/fraud_features.py:141-224`.

The analyzer's canonical JSON snapshot of the official patterns, weights, and
threshold has SHA-256
`4eaee81ca809961957e4607b83a72f5438e46859a6e56ac17624dc2b30938dba`.
Importing those objects from the fixed upstream checkout produces the same hash.
The analysis-only snapshot matches objects imported from that fixed checkout
field-for-field and hash-for-hash; production Tier1 does not reproduce the official
vector.

### “Missing 11” correction

`follows_recent_retrieval` was incorrectly classified as missing. Under the prior
audit's own proxy rule, local `tool_web_fetch` is a proxy:

| feature | official implementation | local proxy | classification |
|---|---|---|---|
| `follows_recent_retrieval` | either prior-two `proposed_tool` values equals exact `web_fetch` | full-prefix `fetch|pull|retrieve|browse ... URL` text regex | proxy, not exact |

The corrected mapping is **exact 0 / proxy 32 / missing 10**. The proxy is zero on
all 793 holdout records, so this correction changes audit accuracy, not model
performance.

## Gap-feature exposure

All 793 holdout records are single-turn and have `instruction_origin=user_direct`.
Roles are not uniform: AdvBench contributes 510 `user` records; GTFOBins contributes
283 `agent_plan` records. No record contains retrieved/tool-mediated external input.

| audited local-missing feature | nonzero records | FN nonzero | TP nonzero |
|---|---:|---:|---:|
| `current_external_len` | 0 | 0 | 0 |
| `current_prompt_entropy` | **782** | 273 | 509 |
| `current_probe_hits` | 0 | 0 | 0 |
| `prompt_filter_block` | 0 | 0 | 0 |
| `repeated_request_ratio` | 0 | 0 | 0 |
| `denied_action_count` | 0 | 0 | 0 |
| `probe_turn_ratio` | 0 | 0 | 0 |
| `sensitive_read_count_so_far` | 0 | 0 | 0 |
| `external_recipient_count` | 0 | 0 | 0 |
| `sensitive_read_then_send` | 0 | 0 | 0 |

This is a structural non-exposure result, not evidence that those features are bad
in general. Most are prior-state or external-input signals, while this split has
neither history nor external input.

## Entropy experiment

Entropy has source-specific association, but not a stable common direction:

| slice | FN mean | TP mean | Mann-Whitney p | direction |
|---|---:|---:|---:|---|
| all 793 | 3.277 | 2.865 | 0.0925 | weak aggregate; medians both 3.322 |
| AdvBench | 3.369 | 3.609 | 2.04e-20 | FN lower |
| GTFOBins | 2.471 | 2.092 | 0.0167 | FN higher |

Overall entropy AUC for distinguishing FN is 0.536. The opposite source directions
make a one-direction rule indefensible, so the decisive check is a same-parameter
XGBoost experiment. The candidate is last-visible-turn entropy: exact for this
single-turn holdout, but only a schema proxy for multi-turn training records.

| split | 40-col baseline | + entropy | change |
|---|---:|---:|---:|
| holdout recall | 520/793 = 65.57% | 522/793 = 65.83% | **+0.25 pp** |
| test_indist recall | 206/223 = 92.38% | 209/223 = 93.72% | +1.35 pp |
| test_indist AUC | 0.8475 | 0.8508 | +0.0033 |
| test_indist benign FP | 32/52 | 32/52 | unchanged |

The holdout gain is not material. Entropy is therefore not added to production
features or saved model weights.

## External-direction hypothesis

The semantic audit remains valid: local `has_external_content` detects outbound
network-like text, not ingested external content. But it does not explain current
holdout misses:

| local outbound proxy | FN | TP |
|---|---:|---:|
| exposed | 9 | 22 |
| unexposed | 264 | 498 |

Fisher odds ratio is 0.772, `p=0.569`. Correct source-aware external features are
zero on all 793 records. Fixing this group is still necessary for indirect-input
coverage, but must be validated on a split that actually contains retrieved/tool
content; it cannot be presented as a fix for this holdout recall.

## What the 273 misses are

| source | records | FN | interpretation |
|---|---:|---:|---|
| AdvBench | 510 | **245** | all 245 carry the dataset note `domain-gap: general content-safety ... not Agent action-risk` |
| GTFOBins | 283 | **28** | operation-relevant shell-spawn actions |

Thus 89.7% of current FNs are explicitly marked as a content-safety/domain mismatch
for this operation-safety guardrail. Optimizing Tier1 against those cases would
silently broaden the product contract rather than improve action-risk detection.

For the 28 GTFOBins FNs:

| local `tool_exec` | FN | TP |
|---|---:|---:|
| absent | 27 | 213 |
| present | 1 | 42 |

Absence has odds ratio 5.32 but `p=0.0938`; it is a useful case pattern, not a
statistically strong standalone explanation. Representative misses include
`flock ... /bin/sh -p`, SSH `ProxyCommand=/bin/sh`, and `capsh --uid=0 --`.
Case IDs, text, probabilities, and feature values are in the JSON artifact.

Role cannot be used as a shortcut: all 283 GTFOBins rows are `agent_plan`, but the
training set's 820 `agent_plan` records are **820 malicious / 0 benign**. Adding a
role flag would encode source/label identity rather than action semantics.

## Shell-action probe

An analysis-only column detects a standalone `sh` or `/bin/sh` interpreter token.
It explicitly excludes file suffixes such as `scripts/build.sh`; that negative case
was added after an earlier regex falsely matched 350 benign synthetic records.

| split | baseline | + shell token | change |
|---|---:|---:|---:|
| all holdout recall | 520/793 = 65.57% | 545/793 = 68.73% | +3.15 pp |
| GTFOBins recall | 255/283 = 90.11% | 280/283 = 98.94% | +8.83 pp |
| test_indist recall | 206/223 = 92.38% | 209/223 = 93.72% | +1.35 pp |
| test_indist AUC | 0.8475 | 0.8494 | +0.0019 |
| test_indist benign FP | 32/52 | 31/52 | -1 case |

This is a post-hoc diagnostic signal, not independent generalization evidence: the
pattern was selected after inspecting this same holdout's false negatives. The
apparent FP result is also not validation:

- train exposure: 202 malicious / **0 benign**;
- test_indist exposure: 3 malicious / **0 benign**;
- known benign exposure in val, on-target, legacy/reviewed multi-turn: **0**.

The model has never seen or been tested on a legitimate operation that actually
invokes `sh`. The production feature and model remain unchanged. The next valid
step is an independently sourced benign-shell control set plus a source-aware
current-action contract; generating hand-written controls is outside the project's
data discipline.

## Direction answer

Tier1 should improve in this order:

1. **Keep benchmark scope explicit.** Report AdvBench separately as content-safety
   domain gap; use GTFOBins and future operation-safety cases for Tier1 action-risk
   decisions.
2. **Improve current-action representation, not paper dimensional conformity.** A
   structured proposed-tool/current-command signal can address `/bin/sh`, `capsh`,
   and similar execution semantics without relying on source role.
3. **Require benign action coverage before merging.** Shell parsing needs legitimate
   shell invocations in an independent evaluation source and an explicit FP stop
   rule.
4. **Repair external-input semantics on its own validation split.** Use role/origin
   fields and actual retrieved/tool content; do not claim this holdout proves its
   recall value.
5. **Do not add the ten missing columns or entropy now.** Nine are unexposed and
   entropy's measured holdout gain is negligible.

## TDD and reproducibility

RED evidence:

- analysis module missing;
- current-model analysis entry missing;
- full experiment entry missing;
- `.sh` file paths incorrectly matched as shell interpreters;
- standalone CLI lacked the repo import path;
- NumPy `int64` prevented JSON serialization;
- embedding the pre-commit `HEAD` made the artifact change after its own commit.

GREEN evidence:

- pure upstream-formula/source/shell tests pass;
- integration test reproduces 793 / 520 / 273 and the case taxonomy;
- `.sh` negative fixture passes;
- CLI writes valid, sorted JSON without changing models;
- exact candidate counts and zero-difference saved-model reproduction are pinned,
  while the runtime XGBoost version is recorded instead of a volatile git revision.

Commands:

```bash
.venv/bin/pytest -q tests/test_tier1_holdout_failure_analysis.py
.venv/bin/python tier1/holdout_failure_analysis.py \
  reports/tier1_holdout_failure_analysis_20260714.json
```

No Tier1 judgment logic, feature order, or model artifact was changed. The only
Tier1 source edits outside the analyzer correct previously false reproduction
claims in comments/report metadata.

## Limitations

- `test_holdout_family` is all malicious, so it cannot measure false positives.
- Entropy on multi-turn local records is a last-visible-turn proxy, not an exact
  reconstruction of the official paired prompt/external turn object.
- Association tests are observational and multiple related signals were inspected;
  p-values are context, not a merge criterion.
- The shell probe was selected on this holdout and has zero benign exposure. Its
  measured gain is subject to feature-selection bias, not a production patch or an
  independently validated improvement.
