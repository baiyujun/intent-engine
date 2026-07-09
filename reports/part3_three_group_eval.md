# Part 3 — Three-Group Comparison Evaluation

## Executive Summary

**v0.1 data diversity + rebuilt feature did NOT improve aug_holdout AUC.** The metric went from 0.5407 (baseline) → 0.5266 (Part1-only) → 0.5334 (Part1+2). The fundamental bottleneck is a **structural feature/eval mismatch**: the model learns multi-turn template fingerprints that are degenerate on the 100% single-turn holdout.

## Three-Group Results

| Group | Data | task_tool_mismatch | aug_holdout AUC | F1 | Prec | Rec | FN |
|-------|------|--------------------|-----------------|------|------|------|------|
| 3 (baseline) | Old (3200+240) | reserved-0 | **0.5407** | 0.765 | 0.950 | 0.641 | 285 |
| 1 (Part1-only) | Expanded (6400+3864) | reserved-0 | 0.5266 | 0.772 | 0.945 | 0.652 | 276 |
| 2 (Part1+2) | Expanded (6400+3864) | rebuilt (WB) | 0.5334 | 0.780 | 0.948 | 0.663 | 267 |

- **Data expansion (Part 1) regressed** aug_holdout AUC by -0.0141
- **Rebuilt feature (Part 2) recovered** +0.0068 but still -0.0073 below baseline
- **All deltas are within noise range** (~0.01-0.02) — no genuine improvement

## Root Cause: Structural Feature/Eval Mismatch

### The Holdout Is 100% Single-Turn

```
Holdout turn-count distribution:
  1-turn: 793 records (100.0%)
  2-turn: 0 records
  3-turn: 0 records
  4-turn: 0 records
```

### The Model's Top Features Are Multi-Turn Template Fingerprints

| Feature | Train Gain | Holdout AUC | Why Degenerate |
|---------|-----------|-------------|----------------|
| tool_diversity_score | 0.419 | 0.500 | =1.0 constant for n=1 |
| action_burst_score | 0.281 | 0.486 | worse than random for n=1 |
| risk_delta | 0.138 | 0.500 | =0.0 constant (needs ≥2 turns) |
| semantic_drift_score | 0.074 | 0.500 | =0.0 constant (needs ≥2 turns) |
| novelty_recipient_flag | 0.007 | 0.500 | =0.0 constant (no network_request) |
| task_tool_mismatch_flag | 0.008 | 0.501 | ≈0 constant on single-turn |

**~80% of model gain** comes from features that carry zero information on single-turn holdout. The model's entire discriminative power on holdout comes from ONE feature:

| Feature | Holdout AUC | What It Captures |
|---------|-------------|------------------|
| context_suspicion_score | **0.537** | Text-level suspicious keywords + sensitive resources + risky-after-external |
| tool_file_read | 0.528 | Simple indicator for "read" in text |
| novelty_filepath_flag | 0.504 | Mild signal from novel paths |

### Why Data Expansion Hurt

Adding 3,624 promptfoo records (all malicious, single-turn) increased the malicious class dominance (58% → 71%), making the model more confident on the majority class but not better at detecting novel families. The expanded synth vocab (55 sensitive files, 30 endpoints, GTFOBins commands) improved template diversity, but those templates are still multi-turn, so the new "diverse" features don't help on single-turn holdout either.

### Why the Rebuilt Feature Didn't Help Enough

The rebuilt `task_tool_mismatch_flag` (within-turn multi-tool bundle check, word-boundary regex) is a genuine, non-leaking feature with moderate train AUC (0.556). On holdout, its single-feature AUC is 0.501 — near-random because single-turn instructions rarely bundle read+send in one sentence in the holdout set. The 15.73 gain it contributes is entirely from synth/promptfoo patterns, not holdout generalization.

## Overfitting Evidence

| Group | test_indist AUC | aug_holdout AUC | Gap |
|-------|----------------|-----------------|-----|
| 3 (baseline) | N/A (not measured) | 0.541 | — |
| 1 (Part1-only) | N/A | 0.527 | — |
| 2 (Part1+2) | **0.842** | 0.533 | **0.309** |

The 0.31 generalization gap indicates the model memorizes in-distribution template structure rather than learning transferable detection. test_indist even has 48/271 IDs overlapping with train, inflating its AUC.

## What Would Actually Help aug_holdout AUC

The diagnosis points to a clear path:

1. **Single-turn features**: The model needs features that work on single-turn text content. Currently only `context_suspicion_score` (AUC 0.537) does. Options:
   - N-gram / TF-IDF features (but these are Tier 0's domain)
   - Better keyword-combination features (e.g., "read sensitive + send external" in one sentence)
   - Semantic similarity to known attack patterns

2. **Balanced holdout**: The current holdout (793 mal, 49 ben = 94% mal) makes AUC noisy. A holdout with both malicious and benign single-turn records would be more informative.

3. **Multi-turn holdout**: If the guardrail must detect multi-turn attacks, the holdout should include multi-turn records. The current 100% single-turn holdout tests a different scenario than the training optimizes for.

4. **Class balance**: The 2.45:1 malicious dominance pushes the model toward majority-class prediction. `scale_pos_weight` in XGBoost or balanced training data would help.

5. **Reduce synth dominance**: The training data is 82% synthetic. More real data would improve generalization.

## Files Produced

- `tier1/models/xgboost_full.json` — retrained final model (Group 2)
- `reports/part1_diversity_stats.md` — Part 1 diversity statistics
- This report — Part 3 evaluation

## Honest Conclusion

The v0.1 engineering work (data diversity fix, promptfoo scaling, rebuilt feature) was methodologically correct — it removed real template leaks and added genuine features. But it did not move the aug_holdout AUC needle because the fundamental bottleneck is the single-turn vs. multi-turn structural mismatch. The work was **necessary but not sufficient**. To actually improve aug_holdout AUC from ~0.54, the next iteration should focus on single-turn text features and/or a more balanced holdout set.
