# Part 4 — Turn-Awareness (session_length)

## Check: Does an explicit turn-count feature exist as a direct XGBoost input?

**YES.** `session_length` is at **index 18** (session group), a direct 1-dim feature in the 40-element feature vector returned by `extract_features()`. It is NOT merely an intermediate computation — it is fed straight to XGBoost.

```python
FEATURE_NAMES[18] == "session_length"   # in the session group (11-18)
# extract_features returns it as the 19th element of the 40-vector
```

No new feature was needed. The user's hypothesis was that the model could learn "few turns → rely on these signals, many turns → rely on those" via tree splitting on `session_length`.

## Ablation: WITH vs WITHOUT session_length

Two models trained identically except `session_length` (index 18) is forced to 0.0 in the WITHOUT model (both training and eval).

### Track 1 — Single-Turn

| Set | WITH AUC | WITHOUT AUC | ΔAUC |
|-----|----------|-------------|------|
| test_indist | 0.8420 | 0.8463 | -0.0044 |
| aug_holdout | 0.5334 | 0.5291 | +0.0043 |

session_length is **degenerate on single-turn** (constant 1.0), so ablating it can't matter — and it doesn't (±0.004, noise).

### Track 2 — Multi-Turn

| Set | WITH AUC | WITHOUT AUC | ΔAUC | ΔF1 |
|-----|----------|-------------|------|-----|
| prefix level | 0.9049 | 0.9072 | -0.0023 | -0.0041 |
| record level | 0.9348 | 0.9279 | +0.0069 | +0.0072 |

### session_length gain

| Model | session_length gain | rank |
|-------|---------------------|------|
| WITH | 0.002220 | 12 of 40 |
| WITHOUT | 0.000000 | — (forced to constant) |

## Honest Finding

**session_length exists and IS used (gain 0.002, rank 12/40), but its marginal contribution is negligible (~±0.004 AUC, within run-to-run noise) on BOTH tracks.**

The user's hypothesis — that explicit turn-awareness would let the model condition on turn count — is **not strongly supported**. The model achieves AUC 0.90 on multi-turn through the *trajectory* features (`tool_diversity_score`, `action_burst_score`, `risk_delta`, `semantic_drift_score`), **not** through `session_length` itself.

**Why?** `session_length` is largely redundant with the trajectory features at the prefix level. `tool_diversity_score = distinct_actions / n` already encodes "how many turns we've seen," and `action_burst_score`/`risk_delta` are turn-indexed. The tree doesn't need a separate `session_length` to know it's early vs late — the trajectory features implicitly carry that. Adding/revealing turn count does not unlock new conditional logic the other features don't already provide.

## What This Means for Part 5

The model does **not** need an explicit turn-count feature to handle multi-turn — the trajectory features suffice (0.90 AUC). The single-turn aug_holdout 0.53 is a **distribution-shift** problem (AdvBench novel family), not a turn-count problem. So turn-awareness is present but is **not the lever**; the lever is the multi-turn track itself. See Part 5.
